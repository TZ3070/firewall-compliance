from __future__ import annotations

from dataclasses import dataclass

from app.models.agent import (
    AgentCandidateFinding,
    AgentTrace,
    ModelCandidateAssessment,
    ReActAction,
    ReActObservation,
    ReActTool,
)
from app.models.contracts import (
    CurrentConfigResponse,
    FindingResult,
    VerificationStatus,
)
from app.models.reports import AuditReport
from app.models.retrieval import (
    KnowledgeSearchFilters,
    RetrievedKnowledge,
)
from app.providers.deepseek import DeepSeekAgent
from app.providers.interfaces import KnowledgeRetriever
from app.services.configuration import ConfigurationService
from app.services.reports import ReportService


MAX_REACT_STEPS = 6
MAX_STANDARD_RETRIEVALS = 2


@dataclass(frozen=True)
class ReActRunResult:
    report: AuditReport
    configuration: CurrentConfigResponse
    trace: AgentTrace
    candidates: tuple[AgentCandidateFinding, ...]
    notices: tuple[str, ...]


class BoundedComplianceReActAgent:
    """A bounded tool loop with deterministic priority and evidence-gated model findings."""

    def __init__(
        self,
        *,
        configuration_service: ConfigurationService,
        report_service: ReportService,
        knowledge_retriever: KnowledgeRetriever,
        deepseek_agent: DeepSeekAgent | None,
    ) -> None:
        self._configuration_service = configuration_service
        self._report_service = report_service
        self._knowledge_retriever = knowledge_retriever
        self._deepseek_agent = deepseek_agent

    async def run(self, user_request: str) -> ReActRunResult:
        configuration: CurrentConfigResponse | None = None
        knowledge: tuple[RetrievedKnowledge, ...] = ()
        candidates: tuple[AgentCandidateFinding, ...] = ()
        report: AuditReport | None = None
        observations: list[ReActObservation] = []
        notices: list[str] = []
        retrieval_count = 0
        evaluation_attempted = False
        stop_reason = "maximum steps reached"

        for step in range(1, MAX_REACT_STEPS + 1):
            allowed = self._allowed_tools(
                configuration=configuration,
                knowledge=knowledge,
                evaluation_attempted=evaluation_attempted,
                report=report,
                retrieval_count=retrieval_count,
            )
            action = await self._next_action(
                user_request=user_request,
                allowed=allowed,
                observations=tuple(observations),
            )
            notices.extend(self._consume_notices())
            if action.action not in allowed:
                notices.append("模型返回了非法工具步骤，已按受控状态机纠正。")
                action = self._fallback_action(allowed)

            if action.action is ReActTool.GET_CURRENT_CONFIG:
                configuration = await self._configuration_service.get_current_config()
                scopes = sorted(
                    {
                        item.field.split(".", maxsplit=1)[0]
                        for item in configuration.evidence
                    }
                )
                summary = (
                    f"已获取并解析 {configuration.configuration.target.vendor} Mock CLI；"
                    f"配置完整度 {configuration.completeness:.2f}，"
                    f"可用证据 {len(configuration.evidence)} 项；"
                    f"可选检查范围：{', '.join(scopes)}。"
                )
            elif action.action is ReActTool.RETRIEVE_STANDARDS:
                assert configuration is not None
                retrieval_count += 1
                query = self._retrieval_query(configuration, action)
                retrieved = await self._knowledge_retriever.search(
                    query=query,
                    filters=KnowledgeSearchFilters(
                        review_status="HumanReviewed",
                        citation_eligible=True,
                    ),
                    limit=12,
                )
                # Multiple reviewed verbatim excerpts may share one catalog record.
                # The model contract judges records, so keep the highest-ranked first
                # excerpt per record instead of sending ambiguous duplicate IDs.
                by_record_id = {item.chunk.record_id: item for item in knowledge}
                for item in retrieved:
                    by_record_id.setdefault(item.chunk.record_id, item)
                knowledge = tuple(by_record_id.values())[:20]
                notices.extend(
                    notice
                    for item in knowledge
                    for notice in item.degradation_notices
                )
                summary = (
                    f"从审核知识库召回 {len(knowledge)} 条可引用标准候选；"
                    + "、".join(item.chunk.record_id for item in knowledge[:6])
                )
            elif action.action is ReActTool.EVALUATE_CANDIDATES:
                assert configuration is not None
                evaluation_attempted = True
                candidates = await self._evaluate_candidates(configuration, knowledge)
                notices.extend(self._consume_notices())
                summary = (
                    f"模型对 {len(candidates)} 条候选形成初步建议；"
                    "在确定性规则未覆盖时可进入报告，证据不足时已门控为 NeedsReview。"
                )
            elif action.action is ReActTool.CREATE_REPORT:
                assert configuration is not None
                report = await self._report_service.create_from_configuration(
                    configuration,
                    model_candidates=candidates,
                    retrieved_knowledge=knowledge,
                )
                summary = (
                    f"已由确定性规则和引用校验器生成不可变报告；"
                    f"状态 {report.status.value}。"
                )
            else:
                if report is None or configuration is None:
                    notices.append("模型提前结束，已拒绝并继续完成必需工具。")
                    action = self._fallback_action(
                        self._allowed_tools(
                            configuration=configuration,
                            knowledge=knowledge,
                            evaluation_attempted=evaluation_attempted,
                            report=report,
                            retrieval_count=retrieval_count,
                        )
                    )
                    continue
                observations.append(
                    ReActObservation(
                        step=step,
                        tool=ReActTool.FINISH,
                        success=True,
                        summary="已完成受控 ReAct 检测链路。",
                    )
                )
                stop_reason = "finish action accepted"
                break

            observations.append(
                ReActObservation(
                    step=step,
                    tool=action.action,
                    success=True,
                    summary=summary,
                )
            )

        if configuration is None:
            configuration = await self._configuration_service.get_current_config()
        if report is None:
            report = await self._report_service.create_from_configuration(
                configuration,
                model_candidates=candidates,
                retrieved_knowledge=knowledge,
            )
            observations.append(
                ReActObservation(
                    step=min(len(observations) + 1, 8),
                    tool=ReActTool.CREATE_REPORT,
                    success=True,
                    summary="达到步数上限，已使用确定性安全收尾生成报告。",
                )
            )
            notices.append("受控 Agent 达到步数上限，已由本地确定性流程安全收尾。")

        return ReActRunResult(
            report=report,
            configuration=configuration,
            trace=AgentTrace(
                max_steps=MAX_REACT_STEPS,
                observations=tuple(observations),
                completed=True,
                stop_reason=stop_reason,
            ),
            candidates=candidates,
            notices=tuple(dict.fromkeys(notices)),
        )

    @staticmethod
    def _allowed_tools(
        *,
        configuration: CurrentConfigResponse | None,
        knowledge: tuple[RetrievedKnowledge, ...],
        evaluation_attempted: bool,
        report: AuditReport | None,
        retrieval_count: int,
    ) -> tuple[ReActTool, ...]:
        if configuration is None:
            return (ReActTool.GET_CURRENT_CONFIG,)
        if not knowledge and retrieval_count == 0:
            return (ReActTool.RETRIEVE_STANDARDS,)
        if knowledge and not evaluation_attempted:
            tools = [ReActTool.EVALUATE_CANDIDATES]
            if retrieval_count < MAX_STANDARD_RETRIEVALS:
                tools.append(ReActTool.RETRIEVE_STANDARDS)
            return tuple(tools)
        if report is None:
            return (ReActTool.CREATE_REPORT,)
        return (ReActTool.FINISH,)

    async def _next_action(
        self,
        *,
        user_request: str,
        allowed: tuple[ReActTool, ...],
        observations: tuple[ReActObservation, ...],
    ) -> ReActAction:
        if len(allowed) == 1:
            return self._fallback_action(allowed)
        planner = getattr(self._deepseek_agent, "decide_react_action", None)
        if callable(planner):
            action = await planner(
                user_request=user_request,
                allowed_tools=allowed,
                observations=observations,
            )
            if action is not None:
                return action
        return self._fallback_action(allowed)

    @staticmethod
    def _fallback_action(allowed: tuple[ReActTool, ...]) -> ReActAction:
        preferred = next(
            (
                tool
                for tool in (
                    ReActTool.GET_CURRENT_CONFIG,
                    ReActTool.RETRIEVE_STANDARDS,
                    ReActTool.EVALUATE_CANDIDATES,
                    ReActTool.CREATE_REPORT,
                    ReActTool.FINISH,
                )
                if tool in allowed
            )
        )
        return ReActAction(
            thought_summary="按受控依赖关系执行下一个必需工具。",
            action=preferred,
        )

    @staticmethod
    def _retrieval_query(
        configuration: CurrentConfigResponse,
        action: ReActAction,
    ) -> str:
        model_query = action.action_input.get("query")
        if isinstance(model_query, str) and model_query.strip():
            model_query = model_query.strip()[:500]
        else:
            model_query = ""
        groups = {item.field.split(".", maxsplit=1)[0] for item in configuration.evidence}
        labels = {
            "access_control": "访问控制 默认拒绝",
            "management": "远程管理 来源限制 多因素认证",
            "logging": "审计日志 集中收集 留存",
            "time_sync": "时间同步",
            "threat_prevention": "入侵防范 恶意代码",
            "high_availability": "高可用 冗余",
            "network_stack": "IPv4 IPv6",
            "vpn": "VPN 安全通信",
        }
        if model_query:
            return f"防火墙配置合规 {model_query}".strip()
        local_topics = " ".join(labels[group] for group in sorted(groups) if group in labels)
        return f"防火墙配置合规 {local_topics}".strip()

    async def _evaluate_candidates(
        self,
        configuration: CurrentConfigResponse,
        knowledge: tuple[RetrievedKnowledge, ...],
    ) -> tuple[AgentCandidateFinding, ...]:
        # The public model boundary is deliberately mock-only. Keep this runtime
        # guard even though the current contract narrows source_type to "mock",
        # so a future real-device provider cannot silently cross that boundary.
        if configuration.source_type != "mock":
            return ()
        evaluator = getattr(self._deepseek_agent, "evaluate_compliance_candidates", None)
        if not callable(evaluator) or not knowledge:
            return ()
        model_items = await evaluator(configuration=configuration, knowledge=knowledge)
        if not model_items:
            return ()
        chunks = {item.chunk.record_id: item.chunk for item in knowledge}
        evidence = {item.field: item for item in configuration.evidence}
        results: list[AgentCandidateFinding] = []
        seen: set[str] = set()
        for item in model_items:
            if item.record_id in seen or item.record_id not in chunks:
                continue
            seen.add(item.record_id)
            bound = [evidence.get(field) for field in item.configuration_fields]
            verified = bool(bound) and all(
                value is not None
                and value.verification_status is VerificationStatus.CONFIGURATION_VERIFIED
                for value in bound
            )
            if item.suggested_result in (FindingResult.PASSED, FindingResult.FAILED):
                gated_result = item.suggested_result if verified else FindingResult.NEEDS_REVIEW
            elif item.suggested_result is FindingResult.NOT_APPLICABLE:
                # Applicability cannot be inferred from a model statement alone.
                # Explicit level metadata is applied later by the report builder.
                gated_result = FindingResult.NEEDS_REVIEW
            else:
                gated_result = item.suggested_result
            chunk = chunks[item.record_id]
            results.append(
                AgentCandidateFinding(
                    record_id=chunk.record_id,
                    standard_code=chunk.standard_code,
                    clause_ids=chunk.clause_ids,
                    title=chunk.title,
                    model_suggestion=item.suggested_result,
                    gated_result=gated_result,
                    configuration_fields=item.configuration_fields,
                    evidence_gate=(
                        "ConfigurationVerified"
                        if verified
                        else "InsufficientEvidence"
                        if item.configuration_fields
                        else "ModelOnly"
                    ),
                    explanation=item.explanation,
                    official_report_effect=(
                        "EvidenceGated"
                        if verified
                        and gated_result in (FindingResult.PASSED, FindingResult.FAILED)
                        else "NeedsReview"
                    ),
                )
            )
        return tuple(results)

    def _consume_notices(self) -> tuple[str, ...]:
        consume = getattr(self._deepseek_agent, "consume_notices", None)
        return tuple(consume()) if callable(consume) else ()
