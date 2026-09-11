from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from app.models.contracts import (
    AssessmentClauseReference,
    AssessmentStatus,
    ConfigurationEvidence,
    FindingResult,
    FrozenConfigModel,
)
from app.models.retrieval import KnowledgeTextKind


class CitationValidationStatus(StrEnum):
    VALID = "Valid"
    MISSING = "Missing"
    NOT_CITABLE = "NotCitable"
    PAYLOAD_MISMATCH = "PayloadMismatch"
    RETRIEVER_UNAVAILABLE = "RetrieverUnavailable"


class ValidatedStandardReference(FrozenConfigModel):
    standard_code: str
    clause_id: str
    classified_protection_level: int = Field(ge=2, le=4)
    printed_pages: tuple[int, ...] = ()
    pdf_page_indexes: tuple[int, ...] = ()
    validation_status: CitationValidationStatus
    validation_message: str
    record_id: str | None = None
    point_id: str | None = None
    source_catalog_id: str | None = None
    source_record_pointer: str | None = None
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    text_kind: KnowledgeTextKind | None = None
    standard_text: str | None = None

    @model_validator(mode="after")
    def prevent_unverified_text(self) -> "ValidatedStandardReference":
        if self.validation_status is CitationValidationStatus.VALID:
            if not self.standard_text or not self.content_sha256:
                raise ValueError("valid citations require verified text and content hash")
            if self.text_kind is not KnowledgeTextKind.VERBATIM:
                raise ValueError("valid citations must contain verbatim text")
        elif self.standard_text is not None:
            raise ValueError("unverified citations must not expose standard text")
        return self


class StandardSourceFile(FrozenConfigModel):
    standard_code: str
    title: str
    file_name: str
    file_size_bytes: int = Field(gt=0)
    pdf_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FindingOrigin(StrEnum):
    DETERMINISTIC = "deterministic"
    AGENT_ASSISTED = "agent_assisted"
    HYBRID = "hybrid"


class ControlAssessmentFindingDraft(FrozenConfigModel):
    finding_id: str
    control_key: str
    control_title: str
    check_title: str
    rule_id: str
    result: FindingResult
    severity: str
    explanation: str
    applicable_protection_levels: tuple[int, ...] = ()
    standard_references: tuple[AssessmentClauseReference, ...] = ()
    configuration_evidence: tuple[ConfigurationEvidence, ...] = ()
    limitations: tuple[str, ...] = ()
    coverage: Literal["full", "partial"]
    origin: FindingOrigin = FindingOrigin.DETERMINISTIC


class ControlAssessmentDraft(FrozenConfigModel):
    assessment_id: str
    snapshot_id: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: str
    vendor: str
    parser_version: str
    rule_pack_version: str
    findings: tuple[ControlAssessmentFindingDraft, ...]
    disclaimer: str


class ComplianceFinding(FrozenConfigModel):
    finding_id: str
    control_key: str
    control_title: str
    check_title: str
    rule_id: str
    result: FindingResult
    severity: str
    explanation: str
    applicable_protection_levels: tuple[int, ...] = ()
    standard_references: tuple[ValidatedStandardReference, ...] = ()
    configuration_evidence: tuple[ConfigurationEvidence, ...] = ()
    limitations: tuple[str, ...] = ()
    coverage: Literal["full", "partial"]
    origin: FindingOrigin


class ComplianceReport(FrozenConfigModel):
    schema_version: Literal["2.0.0"] = "2.0.0"
    report_id: str
    assessment_id: str
    snapshot_id: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: str
    vendor: str
    status: AssessmentStatus
    created_at: datetime
    agent_runtime: Literal["agent-compose"] = "agent-compose"
    agent_run_id: str
    parser_version: str
    rule_pack_version: str
    counts: dict[FindingResult, int]
    findings: tuple[ComplianceFinding, ...]
    standard_sources: tuple[StandardSourceFile, ...] = ()
    disclaimer: str
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def calculate_compliance_report_sha256(report: ComplianceReport) -> str:
    payload = report.model_dump(mode="json", exclude={"report_sha256"})
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_compliance_report_integrity(report: ComplianceReport) -> None:
    expected = calculate_compliance_report_sha256(report)
    if report.report_sha256 != expected:
        raise ValueError(f"compliance report SHA-256 mismatch: expected {expected}")
