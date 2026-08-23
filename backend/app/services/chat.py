from __future__ import annotations

import logging
from collections import Counter
from uuid import uuid4

from app.agent.conversation_context import (
    ConversationContext,
    ConversationContextStore,
    QueryObject,
)
from app.agent.intent_router import DeterministicIntentRouter
from app.agent.safety import ChatSafetyGuard
from app.agent.react_agent import BoundedComplianceReActAgent
from app.models.chat import (
    ChatConfigurationView,
    ChatIntent,
    ChatRequest,
    ChatResponse,
    ChatStage,
    ConfigurationOutputFormat,
    IntentDecision,
    KnowledgeResultView,
    ReportSummary,
)
from app.models.contracts import FindingResult
from app.models.reports import AuditFinding, AuditReport, ReportFilter
from app.models.retrieval import KnowledgeSearchFilters
from app.providers.interfaces import KnowledgeRetriever
from app.providers.deepseek import DeepSeekAgent
from app.services.configuration import ConfigurationService
from app.services.reports import ReportService


logger = logging.getLogger(__name__)


class ChatService:
    def __init__(
        self,
        *,
        report_service: ReportService,
        configuration_service: ConfigurationService,
        knowledge_retriever: KnowledgeRetriever,
        router: DeterministicIntentRouter | None = None,
        safety_guard: ChatSafetyGuard | None = None,
        deepseek_agent: DeepSeekAgent | None = None,
        context_store: ConversationContextStore | None = None,
    ) -> None:
        self._report_service = report_service
        self._configuration_service = configuration_service
        self._knowledge_retriever = knowledge_retriever
        self._router = router or DeterministicIntentRouter()
        self._safety_guard = safety_guard or ChatSafetyGuard()
        self._deepseek_agent = deepseek_agent
        self._context_store = context_store or ConversationContextStore()

    async def handle(self, request: ChatRequest) -> ChatResponse:
        conversation_id = request.conversation_id or f"conv:{uuid4()}"
        safety = self._safety_guard.inspect(request.message)
        if not safety.allowed:
            return ChatResponse(
                conversation_id=conversation_id,
                intent=ChatIntent.UNSUPPORTED,
                stage=ChatStage.SAFETY_BLOCKED,
                content=safety.message or "请求被安全策略拒绝。",
                active_report_id=request.active_report_id,
                error_code=safety.code,
            )

        configuration_candidate = self._configuration_candidate(request.message)
        if configuration_candidate is not None:
            bundled_configuration = await self._configuration_service.get_original_config()
            if self._normalize_configuration(configuration_candidate) != (
                self._normalize_configuration(bundled_configuration)
            ):
                return ChatResponse(
                    conversation_id=conversation_id,
                    intent=ChatIntent.UNSUPPORTED,
                    stage=ChatStage.COMPLETED,
                    content=(
                        "已识别到防火墙 CLI 配置，但当前版本只检测项目内置 Mock，"
                        "不会解析、保存或发送用户粘贴的其他配置。"
                    ),
                    active_report_id=request.active_report_id,
                    error_code="USER_CONFIGURATION_UNSUPPORTED",
                )

        context = self._context_store.get(request.conversation_id)
        degradation_notices: list[str] = []
        decision = (
            IntentDecision(intent=ChatIntent.RUN_ASSESSMENT)
            if configuration_candidate is not None
            else self._resolve_contextual_follow_up(request.message, context)
        )
        if self._deepseek_agent is not None:
            if decision is None:
                decision = await self._deepseek_agent.classify_intent(
                    request.message,
                    finding_id=request.finding_id,
                )
                degradation_notices.extend(self._consume_deepseek_notices())
        if decision is None:
            decision = self._router.route(
                request.message,
                finding_id=request.finding_id,
            )
        if decision.intent is ChatIntent.GET_CURRENT_CONFIG:
            normalized_message = request.message.lower()
            explicitly_requests_json = (
                "json" in normalized_message or "结构化" in request.message
            )
            decision = decision.model_copy(
                update={
                    "configuration_output_format": (
                        ConfigurationOutputFormat.STRUCTURED_JSON
                        if explicitly_requests_json
                        else ConfigurationOutputFormat.ORIGINAL_CLI
                    )
                }
            )
        try:
            response = await self._dispatch(conversation_id, request, decision)
            degradation_notices.extend(self._consume_deepseek_notices())
            combined_notices = tuple(
                dict.fromkeys((*response.notices, *degradation_notices))
            )
            if combined_notices != response.notices:
                response = response.model_copy(
                    update={"notices": combined_notices}
                )
            self._context_store.record(
                conversation_id=conversation_id,
                user_message=(
                    "[内置 Mock CLI 配置]"
                    if configuration_candidate is not None
                    else request.message
                ),
                response=response,
            )
            return response
        except Exception:
            logger.exception(
                "chat operation failed",
                extra={
                    "conversation_id": conversation_id,
                    "intent": decision.intent.value,
                },
            )
            return ChatResponse(
                conversation_id=conversation_id,
                intent=decision.intent,
                stage=ChatStage.FAILED,
                content="本次操作未完成。请确认本地索引和数据库已经初始化。",
                active_report_id=request.active_report_id,
                error_code="CHAT_OPERATION_FAILED",
            )

    def _consume_deepseek_notices(self) -> tuple[str, ...]:
        if self._deepseek_agent is None:
            return ()
        consume = getattr(self._deepseek_agent, "consume_notices", None)
        return tuple(consume()) if callable(consume) else ()

    @staticmethod
    def _configuration_candidate(message: str) -> str | None:
        candidate = message.strip()
        if candidate.startswith("```"):
            lines = candidate.splitlines()
            if lines and lines[-1].strip() == "```":
                candidate = "\n".join(lines[1:-1]).strip()

        lowered_lines = tuple(
            line.strip().lower() for line in candidate.splitlines() if line.strip()
        )
        signals = (
            "sysname ",
            "security-policy",
            "firewall zone ",
            "interface ",
            "info-center ",
            "aaa",
        )
        matched_signals = sum(
            any(line == signal or line.startswith(signal) for line in lowered_lines)
            for signal in signals
        )
        return candidate if len(lowered_lines) >= 10 and matched_signals >= 3 else None

    @staticmethod
    def _normalize_configuration(configuration: str) -> str:
        return "\n".join(
            line.rstrip()
            for line in configuration.replace("\r\n", "\n").strip().splitlines()
        )

    @staticmethod
    def _resolve_contextual_follow_up(
        message: str,
        context: ConversationContext | None,
    ) -> IntentDecision | None:
        if context is None or context.last_query_object is not QueryObject.CURRENT_CONFIG:
            return None
        normalized = " ".join(message.lower().split())
        if any(
            subject in normalized
            for subject in ("报告", "条款", "标准", "finding", "检查", "检测", "符合")
        ):
            return None
        if "json" in normalized or "结构化" in normalized:
            return IntentDecision(
                intent=ChatIntent.GET_CURRENT_CONFIG,
                configuration_output_format=ConfigurationOutputFormat.STRUCTURED_JSON,
            )
        if "原始" in normalized or "cli" in normalized:
            return IntentDecision(
                intent=ChatIntent.GET_CURRENT_CONFIG,
                configuration_output_format=ConfigurationOutputFormat.ORIGINAL_CLI,
            )
        return None

    async def _dispatch(
        self,
        conversation_id: str,
        request: ChatRequest,
        decision: IntentDecision,
    ) -> ChatResponse:
        if decision.intent is ChatIntent.RUN_ASSESSMENT:
            agent_request = (
                "检测当前内置 Mock 防火墙配置"
                if self._configuration_candidate(request.message) is not None
                else request.message
            )
            agent_result = await BoundedComplianceReActAgent(
                configuration_service=self._configuration_service,
                report_service=self._report_service,
                knowledge_retriever=self._knowledge_retriever,
                deepseek_agent=self._deepseek_agent,
            ).run(agent_request)
            report = agent_result.report
            configuration = agent_result.configuration
            model_summary = None
            if self._deepseek_agent is not None:
                model_summary = await self._deepseek_agent.summarize_assessment(
                    configuration=configuration,
                    report=report,
                )
            candidate_note = (
                f"ReAct Agent 对 {len(agent_result.candidates)} 条 RAG 候选完成了"
                "模型判断与证据门控；未被确定性规则覆盖的条款可进入正式报告。"
                if agent_result.candidates
                else ""
            )
            return self._response(
                conversation_id,
                decision.intent,
                (model_summary + (f" {candidate_note}" if candidate_note else ""))
                if model_summary
                else (
                    f"检测完成，报告状态为 {report.status.value}。"
                    + (
                        "所有适用 Finding 已绑定审核通过的标准原文。"
                        if report.status.value == "Completed"
                        else "部分标准依据未通过引用校验。"
                    )
                    + (f" {candidate_note}" if candidate_note else "")
                ),
                report=report,
                active_report_id=report.report_id,
                agent_trace=agent_result.trace,
                agent_candidate_findings=agent_result.candidates,
                notices=agent_result.notices,
            )
        if decision.intent is ChatIntent.GET_CURRENT_CONFIG:
            configuration = await self._configuration_service.get_current_config()
            target = configuration.configuration.target
            output_format = (
                decision.configuration_output_format
                or ConfigurationOutputFormat.ORIGINAL_CLI
            )
            wants_json = output_format is ConfigurationOutputFormat.STRUCTURED_JSON
            return self._response(
                conversation_id,
                decision.intent,
                (
                    f"已读取默认 Mock 目标 {configuration.target_id} 的结构化配置 JSON。"
                    if wants_json
                    else f"已读取默认 Mock 目标 {configuration.target_id} 的原始配置快照。"
                ),
                configuration=ChatConfigurationView(
                    snapshot_id=configuration.snapshot_id,
                    target_id=configuration.target_id,
                    display_name=target.display_name,
                    vendor=target.vendor,
                    model=target.model,
                    software_version=target.software_version,
                    snapshot_sha256=configuration.content_sha256,
                    output_format=output_format,
                    original_config_format=(
                        None if wants_json else configuration.original_config_format
                    ),
                    original_config_content=(
                        None if wants_json else configuration.original_config_content
                    ),
                    original_config_sha256=(
                        None if wants_json else configuration.original_config_sha256
                    ),
                    structured_configuration=(
                        configuration.configuration if wants_json else None
                    ),
                ),
                active_report_id=request.active_report_id,
            )
        if decision.intent is ChatIntent.LIST_REPORTS:
            reports = self._report_service.query(ReportFilter())
            summaries = tuple(self._summary(report) for report in reports)
            return self._response(
                conversation_id,
                decision.intent,
                f"共找到 {len(summaries)} 份不可变报告。",
                report_summaries=summaries,
                active_report_id=request.active_report_id,
            )
        if decision.intent is ChatIntent.FILTER_FINDINGS:
            report = self._select_report(request.active_report_id)
            if report is None:
                return self._response(
                    conversation_id,
                    decision.intent,
                    "还没有可筛选的报告，请先运行合规检测。",
                )
            findings = self._filter_findings(report, decision)
            return self._response(
                conversation_id,
                decision.intent,
                f"在当前报告中找到 {len(findings)} 条匹配结果。",
                findings=findings,
                active_report_id=report.report_id,
            )
        if decision.intent is ChatIntent.EXPLAIN_FINDING:
            report = self._select_report(request.active_report_id)
            finding = (
                self._find_finding(report, request.finding_id)
                if report and request.finding_id
                else None
            )
            if finding is None:
                return self._response(
                    conversation_id,
                    decision.intent,
                    "未找到指定 Finding。请从报告结果中选择一条后再询问依据或整改建议。",
                    active_report_id=report.report_id if report else None,
                )
            return self._response(
                conversation_id,
                decision.intent,
                self._explain(finding),
                findings=(finding,),
                active_report_id=report.report_id,
            )
        if decision.intent is ChatIntent.SEARCH_STANDARDS:
            filters = (
                KnowledgeSearchFilters(standard_code=decision.standard_code_filter)
                if decision.standard_code_filter
                else None
            )
            results = await self._knowledge_retriever.search(
                query=request.message,
                filters=filters,
                limit=8,
            )
            views = tuple(
                KnowledgeResultView(
                    record_id=result.chunk.record_id,
                    standard_code=result.chunk.standard_code,
                    clause_ids=result.chunk.clause_ids,
                    title=result.chunk.title,
                    content=result.chunk.text,
                    text_kind=result.chunk.text_kind,
                    citation_eligible=result.chunk.citation_eligible,
                    score=result.score,
                    retrieval_sources=result.retrieval_sources,
                )
                for result in results
            )
            all_citable = bool(views) and all(item.citation_eligible for item in views)
            retrieval_notices = tuple(
                dict.fromkeys(
                    notice
                    for result in results
                    for notice in result.degradation_notices
                )
            )
            return self._response(
                conversation_id,
                decision.intent,
                (
                    f"召回 {len(views)} 条标准目录记录。"
                    + (
                        "本次结果均为审核通过的可引用原文。"
                        if all_citable
                        else "其中不可引用的记录仅用于检索参考。"
                    )
                ),
                knowledge_results=views,
                notices=retrieval_notices,
                active_report_id=request.active_report_id,
            )
        if decision.intent is ChatIntent.HELP:
            return self._response(
                conversation_id,
                decision.intent,
                "你可以查询当前配置、运行合规检测、查看历史报告、筛选 Passed/Failed/NeedsReview/NotApplicable、解释指定 Finding，或检索标准目录。",
                active_report_id=request.active_report_id,
            )
        return self._response(
            conversation_id,
            decision.intent,
            "当前版本支持配置查询、合规检测、报告查询与筛选、Finding 解释和标准目录检索。",
            active_report_id=request.active_report_id,
        )

    @staticmethod
    def _response(
        conversation_id: str,
        intent: ChatIntent,
        content: str,
        **values: object,
    ) -> ChatResponse:
        return ChatResponse(
            conversation_id=conversation_id,
            intent=intent,
            stage=ChatStage.COMPLETED,
            content=content,
            **values,
        )

    def _select_report(self, report_id: str | None) -> AuditReport | None:
        if report_id:
            return self._report_service.get(report_id)
        reports = self._report_service.query(ReportFilter())
        return reports[0] if reports else None

    @staticmethod
    def _filter_findings(
        report: AuditReport,
        decision: IntentDecision,
    ) -> tuple[AuditFinding, ...]:
        return tuple(
            finding
            for level in report.levels
            for finding in level.findings
            if (
                decision.result_filter is None
                or finding.result is decision.result_filter
            )
            and (
                decision.severity_filter is None
                or finding.severity == decision.severity_filter
            )
            and (
                decision.standard_code_filter is None
                or any(
                    reference.standard_code == decision.standard_code_filter
                    for reference in finding.standard_references
                )
            )
        )

    @staticmethod
    def _find_finding(
        report: AuditReport,
        finding_id: str,
    ) -> AuditFinding | None:
        return next(
            (
                finding
                for level in report.levels
                for finding in level.findings
                if finding.finding_id == finding_id
            ),
            None,
        )

    @staticmethod
    def _explain(finding: AuditFinding) -> str:
        citation_details = "\n\n".join(
            (
                f"{reference.standard_code} {reference.clause_id}：\n"
                f"{reference.standard_text}"
                if reference.standard_text
                else (
                    f"{reference.standard_code} {reference.clause_id}："
                    f"{reference.validation_status.value}"
                )
            )
            for reference in finding.standard_references
        ) or "无适用标准引用"
        limitations = ("；".join(finding.limitations) or "无额外限制").rstrip("。")
        return (
            f"{finding.check_title} 的规则结果是 {finding.result.value}。"
            f"判断说明：{finding.explanation} "
            f"标准依据：\n{citation_details}\n限制：{limitations}。"
        )

    @staticmethod
    def _summary(report: AuditReport) -> ReportSummary:
        counts = Counter(
            finding.result
            for level in report.levels
            for finding in level.findings
        )
        return ReportSummary(
            report_id=report.report_id,
            snapshot_id=report.snapshot_id,
            target_id=report.target_id,
            status=report.status.value,
            created_at=report.created_at.isoformat(),
            counts={result: counts[result] for result in FindingResult},
        )
