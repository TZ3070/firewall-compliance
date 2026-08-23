from hashlib import sha256

import pytest
from pydantic import ValidationError

from app.core.config import BACKEND_ROOT, Settings
from app.models.retrieval import (
    KnowledgeChunk,
    KnowledgeLookup,
    KnowledgeTextKind,
    knowledge_point_id,
)


def _chunk(**overrides: object) -> KnowledgeChunk:
    text = "仅用于检索的标准摘要"
    values: dict[str, object] = {
        "point_id": knowledge_point_id(
            catalog_id="catalog-v1",
            catalog_version="1.0.0",
            record_id="control-1",
        ),
        "catalog_id": "catalog-v1",
        "catalog_version": "1.0.0",
        "record_id": "control-1",
        "record_type": "requirement-control",
        "source_catalog_id": "source-v1",
        "source_record_pointer": "/controls/0",
        "source_catalog_sha256": "a" * 64,
        "standard_code": "GB/T TEST-2026",
        "clause_ids": ("8.1",),
        "title": "测试控制项",
        "text": text,
        "search_text": f"测试控制项 {text}",
        "text_kind": KnowledgeTextKind.SUMMARY,
        "content_sha256": sha256(text.encode("utf-8")).hexdigest(),
        "citation_eligible": False,
        "review_status": "Candidate",
    }
    values.update(overrides)
    return KnowledgeChunk.model_validate(values)


def test_qdrant_path_resolves_under_backend() -> None:
    settings = Settings(qdrant_path="./data/qdrant-test")

    assert settings.resolved_qdrant_path == (BACKEND_ROOT / "data/qdrant-test").resolve()


def test_point_id_is_stable_and_qdrant_compatible() -> None:
    first = knowledge_point_id(
        catalog_id="catalog-v1",
        catalog_version="1.0.0",
        record_id="control-1",
    )
    second = knowledge_point_id(
        catalog_id="catalog-v1",
        catalog_version="1.0.0",
        record_id="control-1",
    )

    assert first == second
    assert len(first) == 36


def test_candidate_summary_cannot_be_marked_as_citation() -> None:
    with pytest.raises(ValidationError, match="only verbatim"):
        _chunk(citation_eligible=True)


def test_candidate_verbatim_text_can_be_marked_as_citation_for_p0() -> None:
    chunk = _chunk(
        text_kind=KnowledgeTextKind.VERBATIM,
        citation_eligible=True,
    )

    assert chunk.citation_eligible is True
    assert chunk.review_status == "Candidate"


def test_human_reviewed_verbatim_text_can_be_cited() -> None:
    chunk = _chunk(
        text_kind=KnowledgeTextKind.VERBATIM,
        review_status="HumanReviewed",
        citation_eligible=True,
    )

    assert chunk.citation_eligible is True


def test_review_status_gate_is_enabled_by_default() -> None:
    assert Settings().rag_enforce_review_status is True


def test_exact_lookup_requires_a_stable_identity() -> None:
    with pytest.raises(ValidationError, match="record_id"):
        KnowledgeLookup()

    assert KnowledgeLookup(record_id="control-1").record_id == "control-1"
    assert KnowledgeLookup(standard_code="GB/T TEST-2026", clause_id="8.1").clause_id == "8.1"
