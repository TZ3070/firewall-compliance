from __future__ import annotations

import re

from app.models.chat import ChatIntent, ConfigurationOutputFormat, IntentDecision
from app.models.contracts import FindingResult


class DeterministicIntentRouter:
    """Maps user text to a closed intent set; never emits code or SQL."""

    _standard_code = re.compile(
        r"(GB/T|JR/T)\s*(\d+(?:\.\d+)?)(?:[—-](\d{4}))?",
        re.IGNORECASE,
    )

    def route(self, message: str, *, finding_id: str | None = None) -> IntentDecision:
        text = " ".join(message.strip().split())
        lowered = text.lower()

        if finding_id or any(word in text for word in ("为什么", "依据", "整改", "解释")):
            if finding_id:
                return IntentDecision(intent=ChatIntent.EXPLAIN_FINDING)

        result_filter = self._result_filter(lowered)
        severity_filter = self._severity_filter(lowered)
        standard_match = self._standard_code.search(text)
        standard_code = self._canonical_standard_code(standard_match)
        if result_filter or severity_filter:
            return IntentDecision(
                intent=ChatIntent.FILTER_FINDINGS,
                result_filter=result_filter,
                severity_filter=severity_filter,
                standard_code_filter=standard_code,
            )

        if any(
            word in text
            for word in (
                "开始检测",
                "触发检测",
                "合规检测",
                "执行检测",
                "评估当前",
                "做一下检查",
                "检查一下",
                "检查当前",
            )
        ):
            return IntentDecision(intent=ChatIntent.RUN_ASSESSMENT)
        if any(word in text for word in ("当前配置", "查看配置", "查询配置", "防火墙配置")):
            output_format = (
                ConfigurationOutputFormat.STRUCTURED_JSON
                if "json" in lowered or "结构化" in text
                else ConfigurationOutputFormat.ORIGINAL_CLI
            )
            return IntentDecision(
                intent=ChatIntent.GET_CURRENT_CONFIG,
                configuration_output_format=output_format,
            )
        if any(word in text for word in ("历史报告", "报告列表", "所有报告", "最近报告")):
            return IntentDecision(intent=ChatIntent.LIST_REPORTS)
        if (
            standard_code
            or any(word in text for word in ("标准", "条款", "测评要求", "控制要求"))
        ):
            return IntentDecision(
                intent=ChatIntent.SEARCH_STANDARDS,
                standard_code_filter=standard_code,
            )
        if any(word in lowered for word in ("help", "帮助", "能做什么", "怎么用")):
            return IntentDecision(intent=ChatIntent.HELP)
        return IntentDecision(intent=ChatIntent.UNSUPPORTED)

    @staticmethod
    def _canonical_standard_code(match: re.Match[str] | None) -> str | None:
        if match is None:
            return None
        prefix, number, year = match.groups()
        return f"{prefix.upper()} {number}{f'—{year}' if year else ''}"

    @staticmethod
    def _result_filter(text: str) -> FindingResult | None:
        if any(word in text for word in ("不符合", "失败项", "failed")):
            return FindingResult.FAILED
        if any(
            word in text
            for word in (
                "证据不足",
                "无法确认",
                "人工复核",
                "待复核",
                "需要复核",
                "needsreview",
                "insufficientevidence",
            )
        ):
            return FindingResult.NEEDS_REVIEW
        if any(word in text for word in ("不适用", "notapplicable")):
            return FindingResult.NOT_APPLICABLE
        if any(
            word in text
            for word in ("符合项", "有哪些符合", "符合的", "通过项", "passed")
        ):
            return FindingResult.PASSED
        return None

    @staticmethod
    def _severity_filter(text: str) -> str | None:
        for value in ("critical", "high", "medium", "low"):
            if value in text:
                return value
        aliases = {"严重": "critical", "高危": "high", "中危": "medium", "低危": "low"}
        return next((value for key, value in aliases.items() if key in text), None)
