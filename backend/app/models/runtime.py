from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from app.models.contracts import FrozenConfigModel
from app.models.compliance import ControlAssessmentDraft


class AgentRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


class StartAssessmentRequest(FrozenConfigModel):
    system_id: str = Field(default="bank-core-001", min_length=1, max_length=128)
    configuration_source_id: str = Field(
        default="mock-huawei-001",
        min_length=1,
        max_length=128,
    )
    client_request_id: str | None = Field(default=None, min_length=1, max_length=128)


class StartAssessmentResponse(FrozenConfigModel):
    assessment_id: str
    run_id: str
    status: AgentRunStatus
    started: bool
    status_url: str


class AssessmentRunView(FrozenConfigModel):
    assessment_id: str
    run_id: str
    status: AgentRunStatus
    report_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    warnings: tuple[str, ...] = ()


class AgentComposeRun(FrozenConfigModel):
    run_id: str
    status: AgentRunStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict[str, object] | None = None
    error: str | None = None
    warnings: tuple[str, ...] = ()


class AgentComposeStartResult(FrozenConfigModel):
    run: AgentComposeRun
    started: bool


class AssessmentSession(FrozenConfigModel):
    assessment_id: str
    run_id: str
    system_id: str
    configuration_source_id: str
    status: AgentRunStatus
    acquisition_id: str | None = None
    snapshot_id: str | None = None
    draft: ControlAssessmentDraft | None = None
    prepared: bool = False
    report_id: str | None = None
    steps: tuple[str, ...] = ()
    error: str | None = None
    created_at: datetime
    updated_at: datetime


class ConversationAgentRequest(FrozenConfigModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = Field(default=None, max_length=128)
    client_request_id: str | None = Field(default=None, max_length=128)


class ConversationRunResponse(FrozenConfigModel):
    conversation_id: str
    run_id: str
    status: AgentRunStatus
    started: bool
    status_url: str


class ConversationRunView(FrozenConfigModel):
    run_id: str
    status: AgentRunStatus
    response: dict[str, object] | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    warnings: tuple[str, ...] = ()
