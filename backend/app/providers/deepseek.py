from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from typing import Any

import httpx
from pydantic import ValidationError

from app.models.chat import ChatIntent, IntentDecision
from app.models.agent import (
    CandidateAssessmentBatch,
    ModelCandidateAssessment,
    ReActAction,
    ReActObservation,
    ReActTool,
)
from app.models.contracts import CurrentConfigResponse
from app.models.reports import AuditReport
from app.models.retrieval import RetrievedKnowledge


logger = logging.getLogger(__name__)


class DeepSeekAgent:
    """DeepSeek adapter for bounded planning, candidate analysis and wording."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        timeout_seconds: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key.strip()
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._notices: ContextVar[tuple[str, ...]] = ContextVar(
            f"deepseek_notices_{id(self)}",
            default=(),
        )

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    def consume_notices(self) -> tuple[str, ...]:
        notices = self._notices.get()
        self._notices.set(())
        return notices

    def _start_call(self) -> None:
        self._notices.set(())

    def _add_notice(self, notice: str) -> None:
        self._notices.set((*self._notices.get(), notice))

    async def classify_intent(
        self,
        message: str,
        *,
        finding_id: str | None = None,
    ) -> IntentDecision | None:
        self._start_call()
        if not self.enabled:
            self._add_notice(
                "智能模型 API 未配置，已使用本地规则完成意图识别。"
            )
            return None
        system_prompt = """
你是银行防火墙合规 Chatbot 的意图分类器。只输出 JSON，不回答用户问题。
intent 只能是 RunAssessment、GetCurrentConfig、ListReports、FilterFindings、
ExplainFinding、SearchStandards、Help、Unsupported 之一。
result_filter 只能是 Passed、Failed、NeedsReview、NotApplicable 或 null。
severity_filter 只能是 critical、high、medium、low 或 null。
standard_code_filter 只能是用户明确提到的 GB/T 或 JR/T 标准号，否则为 null。
configuration_output_format 只能是 original_cli、structured_json 或 null。
“检查、检测、评估当前配置”等表达属于 RunAssessment；
查询当前配置默认 configuration_output_format=original_cli；只有用户明确要求 JSON 或
结构化格式时才设为 structured_json。
“有哪些符合、通过的项目”属于 FilterFindings 且 result_filter=Passed；
“不符合、失败项”对应 Failed；“证据不足、人工复核、无法确认”对应 NeedsReview。
不要输出 SQL、工具参数、解释文字或额外字段。
JSON 示例：
{"intent":"FilterFindings","configuration_output_format":null,"result_filter":"Passed","severity_filter":null,"standard_code_filter":null}
""".strip()
        payload = {
            "message": message,
            "finding_id": finding_id,
        }
        try:
            content = await self._completion(
                messages=(
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": "请输出 JSON：" + json.dumps(payload, ensure_ascii=False),
                    },
                ),
                json_output=True,
                max_tokens=300,
            )
            decision = IntentDecision.model_validate_json(content)
            if decision.intent is ChatIntent.EXPLAIN_FINDING and not finding_id:
                return None
            return decision
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValidationError, ValueError):
            logger.warning("DeepSeek intent classification failed; using deterministic fallback")
            self._add_notice(
                "智能模型 API 暂时不可用，已使用本地规则完成意图识别。"
            )
            return None

    async def summarize_assessment(
        self,
        *,
        configuration: CurrentConfigResponse,
        report: AuditReport,
    ) -> str | None:
        self._start_call()
        if not self.enabled:
            self._add_notice(
                "智能模型 API 未配置，已使用固定模板生成检测说明。"
            )
            return None
        analysis_payload = {
            "mock_configuration": configuration.configuration.model_dump(mode="json"),
            "report": report.model_dump(mode="json"),
        }
        system_prompt = """
你是银行防火墙配置检查结果说明助手。输入只包含 Mock JSON 和确定性规则报告。
用不超过 180 个中文字符概述：报告状态、各等级四态数量、主要 Failed/NeedsReview 主题。
不得改变任何 Finding 结果，不得给出报告级总体合规结论，不得新增标准号、条款、页码或配置事实。
不得声称摘要是标准原文。只输出最终说明，不输出思维过程。
""".strip()
        try:
            return await self._completion(
                messages=(
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": json.dumps(analysis_payload, ensure_ascii=False),
                    },
                ),
                json_output=False,
                max_tokens=300,
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
            logger.warning("DeepSeek assessment summary failed; using fixed wording")
            self._add_notice(
                "智能模型 API 暂时不可用，已使用固定模板生成检测说明。"
            )
            return None

    async def decide_react_action(
        self,
        *,
        user_request: str,
        allowed_tools: tuple[ReActTool, ...],
        observations: tuple[ReActObservation, ...],
    ) -> ReActAction | None:
        self._start_call()
        if not self.enabled:
            self._add_notice(
                "智能模型 API 未配置，ReAct 工具选择已使用本地受控回退。"
            )
            return None
        system_prompt = """
你是银行防火墙合规 ReAct Agent 的受控规划器。只输出 JSON，不输出思维过程。
action 必须从 allowed_tools 中选择，不得创造工具。
thought_summary 只写一句可审计的决策摘要，不得包含隐藏思维链。
action_input 只允许 retrieve_standards 提供 query；query 应从已观察到的可选配置领域中选择本次检查范围。
可在需要时进行第二次不同范围的检索；其他工具的 action_input 应为空对象。
不得输出 SQL、shell、URL、标准原文或配置内容。
""".strip()
        payload = {
            "user_request": user_request[:500],
            "allowed_tools": [tool.value for tool in allowed_tools],
            "observations": [item.model_dump(mode="json") for item in observations],
        }
        try:
            content = await self._completion(
                messages=(
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                ),
                json_output=True,
                max_tokens=250,
            )
            return ReActAction.model_validate_json(content)
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValidationError, ValueError):
            logger.warning("DeepSeek ReAct planning failed; using controlled fallback")
            self._add_notice(
                "智能模型 ReAct 规划暂时不可用，已使用本地受控回退。"
            )
            return None

    async def evaluate_compliance_candidates(
        self,
        *,
        configuration: CurrentConfigResponse,
        knowledge: tuple[RetrievedKnowledge, ...],
    ) -> tuple[ModelCandidateAssessment, ...]:
        self._start_call()
        if not self.enabled:
            self._add_notice(
                "智能模型 API 未配置，已跳过 RAG 候选的模型初步判断。"
            )
            return ()
        system_prompt = """
你是防火墙配置合规候选分析器。只评估输入中的候选标准，只输出 JSON 对象。
根对象键 assessments 是数组。每项只允许 record_id、suggested_result、configuration_fields、explanation。
对输入的每个候选恰好输出一项，不得遗漏、重复或输出未提供的 record_id。
suggested_result 只能是 Passed、Failed、NeedsReview、NotApplicable。
configuration_fields 只能引用 available_evidence_fields 中的完整字段名。
标准要求无法仅由配置证明、字段缺失、只能证明功能存在而不能证明运行效果时，必须输出 NeedsReview。
不得编造标准、配置字段或证据。未被确定性规则覆盖的建议可在证据门控后进入正式报告；
你的输出不得声称是高置信度或确定性规则结论。
""".strip()
        payload = {
            "mock_configuration": configuration.configuration.model_dump(mode="json"),
            "available_evidence_fields": [item.field for item in configuration.evidence],
            "candidates": [
                {
                    "record_id": item.chunk.record_id,
                    "standard_code": item.chunk.standard_code,
                    "clause_ids": item.chunk.clause_ids,
                    "title": item.chunk.title,
                    "verbatim_text": item.chunk.text,
                }
                for item in knowledge[:8]
            ],
        }
        try:
            content = await self._completion(
                messages=(
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                ),
                json_output=True,
                max_tokens=3000,
            )
            return CandidateAssessmentBatch.model_validate_json(content).assessments
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValidationError, ValueError):
            logger.warning("DeepSeek candidate evaluation failed")
            self._add_notice(
                "RAG 候选的模型初步判断失败，正式确定性报告不受影响。"
            )
            return ()
    async def _completion(
        self,
        *,
        messages: tuple[dict[str, str], ...],
        json_output: bool,
        max_tokens: int,
    ) -> str:
        body: dict[str, Any] = {
            "model": self._model,
            "messages": list(messages),
            "stream": False,
            "thinking": {"type": "disabled"},
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        if json_output:
            body["response_format"] = {"type": "json_object"}
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._api_key}"},
            timeout=self._timeout_seconds,
            transport=self._transport,
        ) as client:
            response = await client.post("/chat/completions", json=body)
            response.raise_for_status()
            payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("DeepSeek returned empty content")
        return content.strip()
