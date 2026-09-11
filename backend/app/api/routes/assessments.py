from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.routes.agent_tools import get_assessment_sessions
from app.api.dependencies import get_knowledge_store
from app.core.config import get_settings
from app.models.compliance import ComplianceReport
from app.models.runtime import (
    AssessmentRunView,
    StartAssessmentRequest,
    StartAssessmentResponse,
)
from app.providers.agent_compose import (
    AgentComposeClient,
    AgentComposeProtocolError,
    AgentComposeUnavailableError,
)
from app.repositories.sqlite_compliance_report import (
    SQLiteComplianceReportRepository,
)
from app.services.assessments import AssessmentService
from app.services.citations import CitationValidator
from app.services.compliance_reports import ComplianceReportService


router = APIRouter(tags=["assessments"])


@lru_cache
def get_agent_compose_client() -> AgentComposeClient:
    settings = get_settings()
    return AgentComposeClient(
        base_url=settings.agent_compose_base_url,
        project_id=settings.agent_compose_project_id,
        auth_token=settings.agent_compose_auth_token,
        timeout_seconds=settings.agent_compose_timeout_seconds,
        enabled=settings.agent_compose_enabled,
    )


@lru_cache
def get_compliance_report_service() -> ComplianceReportService:
    settings = get_settings()
    knowledge = get_knowledge_store()
    return ComplianceReportService(
        citation_validator=CitationValidator(
            knowledge,
            enforce_review_status=settings.rag_enforce_review_status,
        ),
        repository=SQLiteComplianceReportRepository(settings.resolved_database_path),
    )


@lru_cache
def get_assessment_service() -> AssessmentService:
    settings = get_settings()
    return AssessmentService(
        runtime=get_agent_compose_client(),
        sessions=get_assessment_sessions(),
        reports=get_compliance_report_service(),
        settings=settings,
    )


@router.post(
    "/api/v1/assessments",
    response_model=StartAssessmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_assessment(
    request: StartAssessmentRequest,
    service: Annotated[AssessmentService, Depends(get_assessment_service)],
) -> StartAssessmentResponse:
    try:
        return await service.start(request)
    except AgentComposeUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AGENT_RUNTIME_UNAVAILABLE", "message": str(exc)},
        ) from exc
    except AgentComposeProtocolError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "AGENT_RUNTIME_PROTOCOL_ERROR", "message": str(exc)},
        ) from exc


@router.get("/api/v1/runs/{run_id}", response_model=AssessmentRunView)
async def get_assessment_run(
    run_id: str,
    service: Annotated[AssessmentService, Depends(get_assessment_service)],
) -> AssessmentRunView:
    try:
        result = await service.get_run(run_id)
    except AgentComposeUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AGENT_RUNTIME_UNAVAILABLE", "message": str(exc)},
        ) from exc
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "RUN_NOT_FOUND", "message": "检测任务不存在"},
        )
    return result


@router.get(
    "/api/v1/compliance-reports",
    response_model=tuple[ComplianceReport, ...],
)
def list_compliance_reports(
    service: Annotated[
        ComplianceReportService,
        Depends(get_compliance_report_service),
    ],
) -> tuple[ComplianceReport, ...]:
    return service.list()


@router.get(
    "/api/v1/compliance-reports/latest",
    response_model=ComplianceReport,
)
def latest_compliance_report(
    service: Annotated[
        ComplianceReportService,
        Depends(get_compliance_report_service),
    ],
) -> ComplianceReport:
    report = service.latest()
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_NOT_FOUND", "message": "尚无合规报告"},
        )
    return report


@router.get(
    "/api/v1/compliance-reports/{report_id:path}",
    response_model=ComplianceReport,
)
def get_compliance_report(
    report_id: str,
    service: Annotated[
        ComplianceReportService,
        Depends(get_compliance_report_service),
    ],
) -> ComplianceReport:
    report = service.get(report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_NOT_FOUND", "message": "报告不存在"},
        )
    return report
