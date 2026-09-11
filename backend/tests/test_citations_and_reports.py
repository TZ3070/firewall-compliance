from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.compliance import (
    CitationValidationStatus,
    ComplianceReport,
    ValidatedStandardReference,
    calculate_compliance_report_sha256,
    verify_compliance_report_integrity,
)
from app.models.contracts import (
    AssessmentClauseReference,
    AssessmentStatus,
    FindingResult,
)
from app.models.retrieval import (
    KnowledgeChunk,
    KnowledgeTextKind,
    RetrievedKnowledge,
    RetrievalSource,
    knowledge_point_id,
)
from app.repositories.sqlite_compliance_report import (
    SQLiteComplianceReportRepository,
)
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.citations import CitationValidator
from app.services.compliance_reports import ComplianceReportService
from app.services.configuration import ConfigurationService
from app.services.knowledge_index import build_knowledge_chunks


def _knowledge_chunk(
    *,
    text: str = "标准原文",
    text_kind: KnowledgeTextKind = KnowledgeTextKind.VERBATIM,
    review_status: str = "HumanReviewed",
    citation_eligible: bool = True,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        point_id=knowledge_point_id(
            catalog_id="test-catalog",
            catalog_version="1.0.0",
            record_id="control-1",
        ),
        catalog_id="test-catalog",
        catalog_version="1.0.0",
        record_id="control-1",
        record_type="requirement-control",
        source_catalog_id="source-1",
        source_record_pointer="/controls/0",
        source_catalog_sha256="a" * 64,
        standard_code="GB/T TEST—2026",
        clause_ids=("8.1",),
        title="测试控制项",
        text=text,
        search_text=text,
        text_kind=text_kind,
        content_sha256=sha256(text.encode()).hexdigest(),
        citation_eligible=citation_eligible,
        review_status=review_status,
        classified_protection_levels=(3,),
        printed_pages=(10,),
        pdf_page_indexes=(12,),
    )


class FakeRetriever:
    def __init__(self, chunks: tuple[KnowledgeChunk, ...]) -> None:
        self._chunks = chunks

    async def retrieve_exact(self, *, lookup: object) -> tuple[RetrievedKnowledge, ...]:
        return tuple(
            RetrievedKnowledge(
                chunk=chunk,
                score=1.0,
                retrieval_sources=(RetrievalSource.EXACT,),
            )
            for chunk in self._chunks
        )

    async def search(self, **_: object) -> tuple[RetrievedKnowledge, ...]:
        return ()


class ExactCatalogRetriever(FakeRetriever):
    async def retrieve_exact(self, *, lookup: object) -> tuple[RetrievedKnowledge, ...]:
        standard_code = getattr(lookup, "standard_code")
        clause_id = getattr(lookup, "clause_id")
        return tuple(
            RetrievedKnowledge(
                chunk=chunk,
                score=1.0,
                retrieval_sources=(RetrievalSource.EXACT,),
            )
            for chunk in self._chunks
            if chunk.standard_code == standard_code and clause_id in chunk.clause_ids
        )


class AlwaysNotCitableValidator:
    async def validate(
        self,
        reference: AssessmentClauseReference,
    ) -> ValidatedStandardReference:
        return ValidatedStandardReference(
            standard_code=reference.standard_code,
            clause_id=reference.clause_id,
            classified_protection_level=reference.classified_protection_level,
            printed_pages=reference.printed_pages,
            pdf_page_indexes=reference.pdf_page_indexes,
            validation_status=CitationValidationStatus.NOT_CITABLE,
            validation_message="测试目录没有可引用原文。",
        )


def _reference() -> AssessmentClauseReference:
    return AssessmentClauseReference(
        standard_code="GB/T TEST—2026",
        clause_id="8.1",
        classified_protection_level=3,
        printed_pages=(10,),
        pdf_page_indexes=(12,),
    )


def test_citation_validator_releases_canonical_verbatim_text() -> None:
    canonical = _knowledge_chunk()
    validator = CitationValidator(
        FakeRetriever((canonical,)),
        canonical_chunks=(canonical,),
    )

    result = asyncio.run(validator.validate(_reference()))

    assert result.validation_status is CitationValidationStatus.VALID
    assert result.standard_text == "标准原文"
    assert result.content_sha256 == canonical.content_sha256


def test_citation_validator_blocks_unreviewed_text_in_formal_mode() -> None:
    candidate = _knowledge_chunk(review_status="Candidate")
    validator = CitationValidator(
        FakeRetriever((candidate,)),
        canonical_chunks=(candidate,),
        enforce_review_status=True,
    )

    result = asyncio.run(validator.validate(_reference()))

    assert result.validation_status is CitationValidationStatus.NOT_CITABLE
    assert result.standard_text is None


def test_citation_validator_fails_closed_on_payload_mismatch() -> None:
    canonical = _knowledge_chunk()
    tampered = _knowledge_chunk(text="被篡改的内容")
    validator = CitationValidator(
        FakeRetriever((tampered,)),
        canonical_chunks=(canonical,),
    )

    result = asyncio.run(validator.validate(_reference()))

    assert result.validation_status is CitationValidationStatus.PAYLOAD_MISMATCH
    assert result.standard_text is None


def test_citation_validator_does_not_quote_candidate_summary() -> None:
    candidate = _knowledge_chunk(
        text="整理摘要",
        text_kind=KnowledgeTextKind.SUMMARY,
        review_status="Candidate",
        citation_eligible=False,
    )
    validator = CitationValidator(
        FakeRetriever((candidate,)),
        canonical_chunks=(candidate,),
    )

    result = asyncio.run(validator.validate(_reference()))

    assert result.validation_status is CitationValidationStatus.NOT_CITABLE
    assert result.standard_text is None


def _empty_report() -> ComplianceReport:
    draft = ComplianceReport(
        report_id="rpt2:test",
        assessment_id="assessment-test",
        snapshot_id="snapshot-test",
        snapshot_sha256="d" * 64,
        original_config_sha256="e" * 64,
        target_id="target-test",
        vendor="Huawei",
        status=AssessmentStatus.COMPLETED,
        created_at=datetime.now(timezone.utc),
        agent_run_id="run-test",
        parser_version="huawei-vrp-cli/1.0.0",
        rule_pack_version="p0-current-config/1.0.0",
        counts={result: 0 for result in FindingResult},
        findings=(),
        disclaimer="测试报告",
        report_sha256="0" * 64,
    )
    return draft.model_copy(
        update={"report_sha256": calculate_compliance_report_sha256(draft)}
    )


def test_v2_reports_are_hash_checked_and_immutable(tmp_path: Path) -> None:
    database_path = tmp_path / "reports.db"
    repository = SQLiteComplianceReportRepository(database_path)
    report = _empty_report()
    repository.save(report)

    loaded = repository.get(report.report_id)
    assert loaded == report
    assert loaded is not None
    verify_compliance_report_integrity(loaded)

    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            connection.execute(
                "UPDATE compliance_reports_v2 SET status = 'Incomplete' WHERE report_id = ?",
                (report.report_id,),
            )


def test_v2_report_is_incomplete_when_citations_are_not_citable(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "incomplete.db"
    current = asyncio.run(
        ConfigurationService(
            repository=SQLiteSnapshotRepository(database_path)
        ).get_current_config()
    )
    draft = P0CurrentConfigRuleEngine().evaluate_controls(current)
    service = ComplianceReportService(
        citation_validator=AlwaysNotCitableValidator(),  # type: ignore[arg-type]
        repository=SQLiteComplianceReportRepository(database_path),
    )

    report = asyncio.run(service.create(draft, agent_run_id="run-incomplete"))

    assert report.status is AssessmentStatus.INCOMPLETE
    assert len(report.standard_sources) == 4
    assert all(len(source.pdf_sha256) == 64 for source in report.standard_sources)


def test_v2_report_is_completed_with_reviewed_verbatim_catalog(
    tmp_path: Path,
) -> None:
    _, chunks = build_knowledge_chunks()
    database_path = tmp_path / "completed.db"
    current = asyncio.run(
        ConfigurationService(
            repository=SQLiteSnapshotRepository(database_path)
        ).get_current_config()
    )
    draft = P0CurrentConfigRuleEngine().evaluate_controls(current)
    service = ComplianceReportService(
        citation_validator=CitationValidator(
            ExactCatalogRetriever(chunks),
            canonical_chunks=chunks,
            enforce_review_status=True,
        ),
        repository=SQLiteComplianceReportRepository(database_path),
    )

    report = asyncio.run(service.create(draft, agent_run_id="run-completed"))

    assert report.status is AssessmentStatus.COMPLETED
    assert report.agent_runtime == "agent-compose"
    assert report.agent_run_id == "run-completed"
    assert len(report.findings) == 12


def test_direct_report_creation_route_is_not_exposed() -> None:
    client = TestClient(app)

    assert client.post("/api/v1/compliance-reports").status_code == 405
