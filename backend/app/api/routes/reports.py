from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.config import get_settings
from app.models.contracts import FindingResult
from app.models.reports import AuditReport, ReportFilter
from app.providers.qdrant_knowledge import QdrantKnowledgeStore
from app.providers.retrieval_factory import (
    create_knowledge_embedder,
    create_knowledge_reranker,
)
from app.repositories.sqlite_report import SQLiteReportRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.citations import CitationValidator
from app.services.knowledge_index import build_knowledge_chunks
from app.services.reports import ReportService


router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@lru_cache
def get_knowledge_store() -> QdrantKnowledgeStore:
    settings = get_settings()
    manifest, _ = build_knowledge_chunks(
        collection_name=settings.qdrant_collection,
        dense_model=settings.effective_dense_model,
        sparse_model=settings.rag_sparse_model,
    )
    return QdrantKnowledgeStore(
        path=settings.resolved_qdrant_path,
        collection_name=settings.qdrant_collection,
        embedder_factory=lambda: create_knowledge_embedder(settings),
        reranker=create_knowledge_reranker(settings),
        prefetch_limit=settings.rag_prefetch_limit,
        expected_manifest=manifest,
    )


@lru_cache
def get_report_repository() -> SQLiteReportRepository:
    settings = get_settings()
    return SQLiteReportRepository(settings.resolved_database_path)


@lru_cache
def get_report_service() -> ReportService:
    settings = get_settings()
    knowledge_store = get_knowledge_store()
    return ReportService(
        rule_engine=P0CurrentConfigRuleEngine(),
        citation_validator=CitationValidator(
            knowledge_store,
            enforce_review_status=settings.rag_enforce_review_status,
        ),
        repository=get_report_repository(),
    )


@router.get("", response_model=tuple[AuditReport, ...])
async def query_reports(
    repository: Annotated[
        SQLiteReportRepository, Depends(get_report_repository)
    ],
    result: Annotated[FindingResult | None, Query()] = None,
    severity: Annotated[str | None, Query(max_length=32)] = None,
    standard_code: Annotated[str | None, Query(max_length=64)] = None,
    finding_id: Annotated[str | None, Query(max_length=256)] = None,
) -> tuple[AuditReport, ...]:
    return repository.query(
        ReportFilter(
            result=result,
            severity=severity,
            standard_code=standard_code,
            finding_id=finding_id,
        )
    )


@router.get("/{report_id:path}", response_model=AuditReport)
async def get_report(
    report_id: str,
    repository: Annotated[
        SQLiteReportRepository, Depends(get_report_repository)
    ],
) -> AuditReport:
    report = repository.get(report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_NOT_FOUND", "message": "报告不存在"},
        )
    return report
