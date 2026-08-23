from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from app.models.contracts import FindingResult, FrozenConfigModel


class ReActTool(StrEnum):
    GET_CURRENT_CONFIG = "get_current_config"
    RETRIEVE_STANDARDS = "retrieve_standards"
    EVALUATE_CANDIDATES = "evaluate_compliance_candidates"
    CREATE_REPORT = "create_report"
    FINISH = "finish"


class ReActAction(FrozenConfigModel):
    thought_summary: str = Field(min_length=1, max_length=240)
    action: ReActTool
    action_input: dict[str, Any] = Field(default_factory=dict)


class ReActObservation(FrozenConfigModel):
    step: int = Field(ge=1, le=8)
    tool: ReActTool
    success: bool
    summary: str = Field(min_length=1, max_length=1000)


class ModelCandidateAssessment(FrozenConfigModel):
    record_id: str = Field(min_length=1, max_length=256)
    suggested_result: FindingResult
    configuration_fields: tuple[str, ...] = ()
    explanation: str = Field(min_length=1, max_length=800)


class CandidateAssessmentBatch(FrozenConfigModel):
    assessments: tuple[ModelCandidateAssessment, ...] = Field(max_length=20)


class AgentCandidateFinding(FrozenConfigModel):
    record_id: str
    standard_code: str
    clause_ids: tuple[str, ...]
    title: str
    model_suggestion: FindingResult
    gated_result: FindingResult
    configuration_fields: tuple[str, ...]
    evidence_gate: Literal[
        "ConfigurationVerified",
        "InsufficientEvidence",
        "ModelOnly",
    ]
    explanation: str
    official_report_effect: Literal[
        "EvidenceGated",
        "NeedsReview",
    ]

    @model_validator(mode="after")
    def prevent_ungated_model_verdict(self) -> "AgentCandidateFinding":
        if (
            self.official_report_effect == "EvidenceGated"
            and self.evidence_gate != "ConfigurationVerified"
        ):
            raise ValueError("model verdict requires configuration-verified evidence")
        if (
            self.official_report_effect == "NeedsReview"
            and self.gated_result is not FindingResult.NEEDS_REVIEW
        ):
            raise ValueError("insufficient model evidence must become NeedsReview")
        return self


class AgentTrace(FrozenConfigModel):
    mode: Literal["bounded-react"] = "bounded-react"
    max_steps: int = Field(ge=1, le=8)
    observations: tuple[ReActObservation, ...]
    completed: bool
    stop_reason: str
