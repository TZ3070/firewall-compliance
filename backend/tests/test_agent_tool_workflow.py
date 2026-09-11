import asyncio
from pathlib import Path

import pytest

from app.models.compliance import (
    CitationValidationStatus,
    ValidatedStandardReference,
)
from app.models.retrieval import KnowledgeTextKind
from app.models.runtime import AgentRunStatus
from app.repositories.sqlite_acquisition import SQLiteAcquisitionRepository
from app.repositories.sqlite_assessment_session import (
    SQLiteAssessmentSessionRepository,
)
from app.repositories.sqlite_compliance_report import (
    SQLiteComplianceReportRepository,
)
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.agent_tools import AgentToolSequenceError, ComplianceAgentToolService
from app.services.compliance_reports import ComplianceReportService
from app.services.configuration import ConfigurationService


class EmptyKnowledgeRetriever:
    async def search(self, **_kwargs):
        return ()

    async def retrieve_exact(self, **_kwargs):
        return ()


class ValidCitationValidator:
    async def validate(self, reference):
        return ValidatedStandardReference(
            standard_code=reference.standard_code,
            clause_id=reference.clause_id,
            classified_protection_level=reference.classified_protection_level,
            printed_pages=reference.printed_pages,
            pdf_page_indexes=reference.pdf_page_indexes,
            validation_status=CitationValidationStatus.VALID,
            validation_message="test validated",
            record_id=reference.record_id,
            point_id="point-1",
            source_catalog_id="test",
            source_record_pointer="/test",
            content_sha256="a" * 64,
            text_kind=KnowledgeTextKind.VERBATIM,
            standard_text="经过审核的测试标准原文。",
        )


def build_services(tmp_path: Path):
    database = tmp_path / "agent-tools.db"
    sessions = SQLiteAssessmentSessionRepository(database)
    sessions.create(
        assessment_id="assessment-1",
        run_id="run-1",
        system_id="bank-core-001",
        configuration_source_id="mock-huawei-001",
        status=AgentRunStatus.RUNNING,
    )
    configuration = ConfigurationService(
        repository=SQLiteSnapshotRepository(database),
        acquisition_repository=SQLiteAcquisitionRepository(database),
    )
    tools = ComplianceAgentToolService(
        configuration_service=configuration,
        rule_engine=P0CurrentConfigRuleEngine(),
        knowledge_retriever=EmptyKnowledgeRetriever(),
        sessions=sessions,
    )
    return database, sessions, tools


def test_agent_tool_gateway_enforces_order(tmp_path: Path) -> None:
    _database, _sessions, tools = build_services(tmp_path)

    with pytest.raises(AgentToolSequenceError, match="configuration.fetch"):
        asyncio.run(tools.detect_vendor("assessment-1"))


def test_agent_tool_workflow_creates_one_finding_per_control(tmp_path: Path) -> None:
    database, sessions, tools = build_services(tmp_path)

    asyncio.run(tools.fetch_configuration("assessment-1"))
    asyncio.run(tools.detect_vendor("assessment-1"))
    asyncio.run(tools.parse_configuration("assessment-1"))
    evaluation = asyncio.run(tools.evaluate_rules("assessment-1"))
    asyncio.run(tools.search_standards("assessment-1", "防火墙访问控制 安全审计"))
    prepared = asyncio.run(tools.prepare_report("assessment-1"))

    session = sessions.get("assessment-1")
    assert session is not None and session.draft is not None
    assert evaluation["findingCount"] == 12
    assert len({item.control_key for item in session.draft.findings}) == 12
    assert prepared["prepared"] is True
    assert session.prepared is True
    assert session.steps == (
        "configuration.fetch",
        "vendor.detect",
        "configuration.parse",
        "rules.evaluate",
        "standards.search",
        "report.prepare",
    )

    report_service = ComplianceReportService(
        citation_validator=ValidCitationValidator(),
        repository=SQLiteComplianceReportRepository(database),
        standard_sources=(),
    )
    report = asyncio.run(
        report_service.create(session.draft, agent_run_id="run-1")
    )
    assert report.agent_runtime == "agent-compose"
    assert report.agent_run_id == "run-1"
    assert len(report.findings) == 12
    assert sum(report.counts.values()) == 12
    assert all(item.finding_id.count(":L") == 0 for item in report.findings)
