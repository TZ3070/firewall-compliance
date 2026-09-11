from __future__ import annotations

from uuid import uuid4

from app.core.config import Settings
from app.models.runtime import (
    AgentRunStatus,
    AssessmentRunView,
    StartAssessmentRequest,
    StartAssessmentResponse,
)
from app.providers.agent_compose import AgentComposeClient
from app.repositories.sqlite_assessment_session import (
    SQLiteAssessmentSessionRepository,
)
from app.services.compliance_reports import ComplianceReportService


COMPLIANCE_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["assessmentId", "prepared", "summary"],
    "properties": {
        "assessmentId": {"type": "string"},
        "prepared": {"type": "boolean", "const": True},
        "summary": {"type": "string"},
    },
}


class AssessmentService:
    def __init__(
        self,
        *,
        runtime: AgentComposeClient,
        sessions: SQLiteAssessmentSessionRepository,
        reports: ComplianceReportService,
        settings: Settings,
    ) -> None:
        self._runtime = runtime
        self._sessions = sessions
        self._reports = reports
        self._settings = settings

    async def start(
        self,
        request: StartAssessmentRequest,
    ) -> StartAssessmentResponse:
        assessment_id = f"assessment-{uuid4().hex}"
        client_request_id = request.client_request_id or assessment_id
        provisional_run_id = f"pending:{assessment_id}"
        self._sessions.create(
            assessment_id=assessment_id,
            run_id=provisional_run_id,
            system_id=request.system_id,
            configuration_source_id=request.configuration_source_id,
            status=AgentRunStatus.QUEUED,
        )
        prompt = (
            "执行一次银行防火墙配置合规检测。"
            f" assessmentId={assessment_id}。"
            "必须依次调用 configuration.fetch、vendor.detect、"
            "configuration.parse、rules.evaluate、standards.search、"
            "report.prepare；不得要求或使用等保级别作为扫描入口。"
            "所有配置事实和条款必须来自工具结果，不得自行编造。"
        )
        try:
            started = await self._runtime.start_run(
                agent_name=self._settings.agent_compose_compliance_agent,
                prompt=prompt,
                payload={
                    "assessmentId": assessment_id,
                    "systemId": request.system_id,
                    "configurationSourceId": request.configuration_source_id,
                },
                output_schema=COMPLIANCE_OUTPUT_SCHEMA,
                client_request_id=client_request_id,
            )
        except Exception as exc:
            self._sessions.update(
                assessment_id,
                status=AgentRunStatus.FAILED,
                error=str(exc),
            )
            raise
        self._sessions.update(
            assessment_id,
            run_id=started.run.run_id,
            status=started.run.status,
        )
        return StartAssessmentResponse(
            assessment_id=assessment_id,
            run_id=started.run.run_id,
            status=started.run.status,
            started=started.started,
            status_url=f"/api/v1/runs/{started.run.run_id}",
        )

    async def get_run(self, run_id: str) -> AssessmentRunView | None:
        session = self._sessions.get_by_run(run_id)
        if session is None:
            return None
        runtime_run = await self._runtime.get_run(run_id)
        status = runtime_run.status
        error_code = None
        error_message = runtime_run.error
        report_id = session.report_id

        if status is AgentRunStatus.SUCCEEDED:
            result = runtime_run.result or {}
            result_assessment_id = result.get("assessmentId")
            refreshed = self._sessions.get(session.assessment_id)
            assert refreshed is not None
            if (
                result_assessment_id != session.assessment_id
                or result.get("prepared") is not True
                or not isinstance(result.get("summary"), str)
                or not result["summary"].strip()
            ):
                status = AgentRunStatus.FAILED
                error_code = "AGENT_OUTPUT_INVALID"
                error_message = "Agent 最终输出不符合检测结果契约"
            elif not refreshed.prepared or refreshed.draft is None:
                status = AgentRunStatus.FAILED
                error_code = "AGENT_WORKFLOW_INCOMPLETE"
                error_message = "Agent 未完成 report.prepare 工具步骤"
            elif report_id is None:
                report = await self._reports.create(
                    refreshed.draft,
                    agent_run_id=run_id,
                )
                report_id = report.report_id
                self._sessions.update(
                    session.assessment_id,
                    report_id=report_id,
                )

        self._sessions.update(
            session.assessment_id,
            status=status,
            error=error_message,
        )
        return AssessmentRunView(
            assessment_id=session.assessment_id,
            run_id=run_id,
            status=status,
            report_id=report_id,
            error_code=error_code,
            error_message=error_message,
            created_at=session.created_at,
            started_at=runtime_run.started_at,
            completed_at=runtime_run.completed_at,
            warnings=runtime_run.warnings,
        )
