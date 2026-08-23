from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from app.models.contracts import FindingResult, FrozenConfigModel, NormalizedFirewallConfig
from app.models.agent import AgentCandidateFinding, AgentTrace
from app.models.reports import AuditFinding, AuditReport
from app.models.retrieval import KnowledgeTextKind, RetrievalSource


class ChatIntent(StrEnum):
    RUN_ASSESSMENT = "RunAssessment"
    GET_CURRENT_CONFIG = "GetCurrentConfig"
    LIST_REPORTS = "ListReports"
    FILTER_FINDINGS = "FilterFindings"
    EXPLAIN_FINDING = "ExplainFinding"
    SEARCH_STANDARDS = "SearchStandards"
    HELP = "Help"
    UNSUPPORTED = "Unsupported"


class ChatStage(StrEnum):
    ROUTING = "Routing"
    SAFETY_BLOCKED = "SafetyBlocked"
    COMPLETED = "Completed"
    FAILED = "Failed"


class ConfigurationOutputFormat(StrEnum):
    ORIGINAL_CLI = "original_cli"
    STRUCTURED_JSON = "structured_json"


class ChatRequest(FrozenConfigModel):
    message: str = Field(min_length=1, max_length=16000)
    conversation_id: str | None = Field(default=None, max_length=128)
    active_report_id: str | None = Field(default=None, max_length=512)
    finding_id: str | None = Field(default=None, max_length=512)


class IntentDecision(FrozenConfigModel):
    intent: ChatIntent
    configuration_output_format: ConfigurationOutputFormat | None = None
    result_filter: FindingResult | None = None
    severity_filter: str | None = None
    standard_code_filter: str | None = None


class ReportSummary(FrozenConfigModel):
    report_id: str
    snapshot_id: str
    target_id: str
    status: str
    created_at: str
    counts: dict[FindingResult, int]


class KnowledgeResultView(FrozenConfigModel):
    record_id: str
    standard_code: str
    clause_ids: tuple[str, ...]
    title: str
    content: str
    text_kind: KnowledgeTextKind
    citation_eligible: bool
    score: float
    retrieval_sources: tuple[RetrievalSource, ...]


class ChatConfigurationView(FrozenConfigModel):
    """Chat-safe projection containing only the explicitly requested representation."""

    snapshot_id: str
    target_id: str
    display_name: str
    vendor: str
    model: str
    software_version: str
    snapshot_sha256: str
    output_format: ConfigurationOutputFormat
    original_config_format: Literal["vendor_cli_mock"] | None = None
    original_config_content: str | None = None
    original_config_sha256: str | None = None
    structured_configuration: NormalizedFirewallConfig | None = None


class ChatResponse(FrozenConfigModel):
    conversation_id: str
    intent: ChatIntent
    stage: ChatStage
    content: str
    notices: tuple[str, ...] = ()
    active_report_id: str | None = None
    report: AuditReport | None = None
    configuration: ChatConfigurationView | None = None
    report_summaries: tuple[ReportSummary, ...] = ()
    findings: tuple[AuditFinding, ...] = ()
    knowledge_results: tuple[KnowledgeResultView, ...] = ()
    agent_trace: AgentTrace | None = None
    agent_candidate_findings: tuple[AgentCandidateFinding, ...] = ()
    error_code: str | None = None
