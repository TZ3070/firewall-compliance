from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from app.models.contracts import (
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


class AuditFinding(FrozenConfigModel):
    finding_id: str
    classified_protection_level: int = Field(ge=2, le=4)
    control_id: str
    control_title: str
    check_title: str
    rule_id: str
    result: FindingResult
    severity: str
    explanation: str
    standard_references: tuple[ValidatedStandardReference, ...] = ()
    configuration_evidence: tuple[ConfigurationEvidence, ...] = ()
    limitations: tuple[str, ...] = ()
    control_coverage: Literal["full", "partial"]
    control_conclusion_allowed: Literal[False] = False


class AuditLevelSummary(FrozenConfigModel):
    classified_protection_level: int = Field(ge=2, le=4)
    counts: dict[FindingResult, int]
    findings: tuple[AuditFinding, ...]


class StandardSourceFile(FrozenConfigModel):
    standard_code: str
    title: str
    file_name: str
    file_size_bytes: int = Field(gt=0)
    pdf_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditReport(FrozenConfigModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: str
    assessment_id: str
    snapshot_id: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_id: str
    status: AssessmentStatus
    created_at: datetime
    rule_pack_version: str
    rule_pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    control_catalog_id: str
    control_catalog_version: str
    control_catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    knowledge_catalog_id: str
    knowledge_catalog_version: str
    knowledge_catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    standard_sources: tuple[StandardSourceFile, ...] = ()
    levels: tuple[AuditLevelSummary, ...]
    disclaimer: str
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReportFilter(FrozenConfigModel):
    report_id: str | None = None
    result: FindingResult | None = None
    severity: str | None = None
    standard_code: str | None = None
    finding_id: str | None = None


def calculate_report_sha256(report: AuditReport) -> str:
    payload = report.model_dump(mode="json", exclude={"report_sha256"})
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_report_integrity(report: AuditReport) -> None:
    expected = calculate_report_sha256(report)
    if report.report_sha256 != expected:
        raise ValueError(f"report SHA-256 mismatch: expected {expected}")
