from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.routes.reports import get_report_repository
from app.main import app
from app.models.contracts import (
    AssessmentClauseReference,
    AssessmentStatus,
)
from app.models.reports import (
    AuditReport,
    CitationValidationStatus,
    ReportFilter,
    ValidatedStandardReference,
    calculate_report_sha256,
    verify_report_integrity,
)
from app.models.retrieval import (
    KnowledgeChunk,
    KnowledgeTextKind,
    RetrievedKnowledge,
    RetrievalSource,
    knowledge_point_id,
)
from app.repositories.sqlite_report import SQLiteReportRepository
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.citations import CitationValidator
from app.services.configuration import ConfigurationService
from app.services.knowledge_index import build_knowledge_chunks
from app.services.reports import ReportService


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


def test_p0_citation_validator_does_not_block_candidate_verbatim_text() -> None:
    candidate = _knowledge_chunk(review_status="Candidate")
    validator = CitationValidator(
        FakeRetriever((candidate,)),
        canonical_chunks=(candidate,),
    )

    result = asyncio.run(validator.validate(_reference()))

    assert result.validation_status is CitationValidationStatus.VALID
    assert result.standard_text == "标准原文"
    assert "当前未启用审核状态门禁" in result.validation_message


def test_formal_citation_validator_blocks_candidate_verbatim_text() -> None:
    candidate = _knowledge_chunk(review_status="Candidate")
    validator = CitationValidator(
        FakeRetriever((candidate,)),
        canonical_chunks=(candidate,),
        enforce_review_status=True,
    )

    result = asyncio.run(validator.validate(_reference()))

    assert result.validation_status is CitationValidationStatus.NOT_CITABLE
    assert result.standard_text is None
    assert "正式审核状态门禁" in result.validation_message


def test_formal_citation_validator_accepts_reviewed_verbatim_text() -> None:
    reviewed = _knowledge_chunk(review_status="HumanReviewed")
    validator = CitationValidator(
        FakeRetriever((reviewed,)),
        canonical_chunks=(reviewed,),
        enforce_review_status=True,
    )

    result = asyncio.run(validator.validate(_reference()))

    assert result.validation_status is CitationValidationStatus.VALID
    assert result.standard_text == "标准原文"
    assert "审核状态校验" in result.validation_message


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


def _empty_report() -> AuditReport:
    draft = AuditReport(
        report_id="rpt:test",
        assessment_id="asm:test",
        snapshot_id="snp:test",
        snapshot_sha256="d" * 64,
        target_id="target:test",
        status=AssessmentStatus.INCOMPLETE,
        created_at=datetime.now(timezone.utc),
        rule_pack_version="rules/1.0.0",
        rule_pack_sha256="e" * 64,
        control_catalog_id="control-catalog-v1",
        control_catalog_version="1.0.0",
        control_catalog_sha256="f" * 64,
        knowledge_catalog_id="knowledge-catalog-v1",
        knowledge_catalog_version="1.0.0",
        knowledge_catalog_sha256="c" * 64,
        levels=(),
        disclaimer="测试报告",
        report_sha256="0" * 64,
    )
    return draft.model_copy(
        update={"report_sha256": calculate_report_sha256(draft)}
    )


def test_sqlite_reports_are_hash_checked_and_immutable(tmp_path: Path) -> None:
    database_path = tmp_path / "reports.db"
    repository = SQLiteReportRepository(database_path)
    report = _empty_report()
    repository.save(report)

    loaded = repository.get(report.report_id)
    assert loaded == report
    assert loaded is not None
    verify_report_integrity(loaded)

    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            connection.execute(
                "UPDATE reports SET status = 'Completed' WHERE report_id = ?",
                (report.report_id,),
            )


def test_report_list_skips_one_invalid_historical_payload(tmp_path: Path) -> None:
    database_path = tmp_path / "reports.db"
    repository = SQLiteReportRepository(database_path)
    report = _empty_report()
    repository.save(report)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO reports (
                report_id, assessment_id, snapshot_id, target_id, status,
                created_at, report_sha256, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "rpt:invalid-history",
                "asm:invalid-history",
                "snp:invalid-history",
                "target:test",
                "Incomplete",
                datetime.now(timezone.utc).isoformat(),
                "0" * 64,
                report.model_copy(
                    update={
                        "report_id": "rpt:invalid-history",
                        "report_sha256": "0" * 64,
                    }
                ).model_dump_json(),
            ),
        )

    assert repository.query(ReportFilter()) == (report,)


class AlwaysNotCitableValidator:
    async def validate(
        self, reference: AssessmentClauseReference
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


def test_current_report_is_saved_as_incomplete_when_citations_are_not_citable(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "app.db"
    repository = SQLiteReportRepository(database_path)
    configuration_service = ConfigurationService(
        repository=SQLiteSnapshotRepository(database_path)
    )
    service = ReportService(
        rule_engine=P0CurrentConfigRuleEngine(),
        citation_validator=AlwaysNotCitableValidator(),  # type: ignore[arg-type]
        repository=repository,
    )

    current = asyncio.run(configuration_service.get_current_config())
    report = asyncio.run(service.create_from_configuration(current))

    assert report.status is AssessmentStatus.INCOMPLETE
    assert len(report.standard_sources) == 4
    assert all(len(source.pdf_sha256) == 64 for source in report.standard_sources)
    assert repository.get(report.report_id) == report
    assert any(
        reference.validation_status is CitationValidationStatus.NOT_CITABLE
        for level in report.levels
        for finding in level.findings
        for reference in finding.standard_references
    )
    assert all(
        reference.standard_text is None
        for level in report.levels
        for finding in level.findings
        for reference in finding.standard_references
    )


def test_current_report_is_completed_with_reviewed_verbatim_catalog(
    tmp_path: Path,
) -> None:
    _, chunks = build_knowledge_chunks()
    database_path = tmp_path / "reviewed.db"
    configuration_service = ConfigurationService(
        repository=SQLiteSnapshotRepository(database_path)
    )
    service = ReportService(
        rule_engine=P0CurrentConfigRuleEngine(),
        citation_validator=CitationValidator(
            ExactCatalogRetriever(chunks),
            canonical_chunks=chunks,
            enforce_review_status=True,
        ),
        repository=SQLiteReportRepository(database_path),
    )

    current = asyncio.run(configuration_service.get_current_config())
    report = asyncio.run(service.create_from_configuration(current))

    assert report.status is AssessmentStatus.COMPLETED
    applicable_references = [
        reference
        for level in report.levels
        for finding in level.findings
        if finding.result.value != "NotApplicable"
        for reference in finding.standard_references
    ]
    assert applicable_references
    assert all(
        reference.validation_status is CitationValidationStatus.VALID
        and reference.standard_text
        for reference in applicable_references
    )


def test_report_api_reads_the_same_immutable_payload(tmp_path: Path) -> None:
    database_path = tmp_path / "api.db"
    repository = SQLiteReportRepository(database_path)
    configuration_service = ConfigurationService(
        repository=SQLiteSnapshotRepository(database_path)
    )
    service = ReportService(
        rule_engine=P0CurrentConfigRuleEngine(),
        citation_validator=AlwaysNotCitableValidator(),  # type: ignore[arg-type]
        repository=repository,
    )
    current = asyncio.run(configuration_service.get_current_config())
    report = asyncio.run(service.create_from_configuration(current))
    app.dependency_overrides[get_report_repository] = lambda: repository
    client = TestClient(app)
    try:
        loaded = client.get(f"/api/v1/reports/{report.report_id}")
    finally:
        app.dependency_overrides.clear()

    assert loaded.status_code == 200
    assert AuditReport.model_validate(loaded.json()) == report
    assert loaded.json()["status"] == "Incomplete"


def test_report_creation_and_direct_assessment_bypass_routes_are_not_exposed() -> None:
    client = TestClient(app)

    assert client.get("/api/v1/assessments/current").status_code == 404
    assert client.post("/api/v1/reports").status_code == 405
