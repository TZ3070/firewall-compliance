from hashlib import sha256
import asyncio

from app.models.retrieval import KnowledgeTextKind
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.configuration import ConfigurationService
from app.services.knowledge_index import (
    DEFAULT_CATALOG_PATH,
    SUMMARY_CATALOG_PATH,
    build_knowledge_chunks,
)


def test_catalog_builds_complete_deterministic_search_documents() -> None:
    first_manifest, first_chunks = build_knowledge_chunks()
    second_manifest, second_chunks = build_knowledge_chunks()

    assert first_manifest == second_manifest
    assert first_chunks == second_chunks
    assert first_manifest.point_count == 688
    assert len(first_chunks) == 688
    assert len({chunk.point_id for chunk in first_chunks}) == 688


def test_manifest_binds_index_to_exact_catalog_bytes() -> None:
    manifest, _ = build_knowledge_chunks()

    assert manifest.catalog_sha256 == sha256(DEFAULT_CATALOG_PATH.read_bytes()).hexdigest()


def test_reviewed_verbatim_data_is_citable() -> None:
    _, chunks = build_knowledge_chunks()

    assert {chunk.text_kind for chunk in chunks} == {KnowledgeTextKind.VERBATIM}
    assert all(chunk.citation_eligible for chunk in chunks)
    assert all(chunk.review_status == "HumanReviewed" for chunk in chunks)
    assert all(chunk.content_sha256 for chunk in chunks)
    assert all(chunk.source_catalog_sha256 for chunk in chunks)


def test_control_and_measurement_keep_provenance_and_levels() -> None:
    _, chunks = build_knowledge_chunks()
    control = next(chunk for chunk in chunks if chunk.record_type == "requirement-control")
    measurement = next(chunk for chunk in chunks if chunk.record_type == "measurement-unit")

    assert control.source_record_pointer.startswith("/")
    assert control.clause_ids
    assert control.search_text
    assert measurement.classified_protection_levels in {(2,), (3,), (4,)}
    assert measurement.text.startswith("测评单元（")
    assert "单元判定：" in measurement.text


def test_summary_catalog_remains_an_explicit_non_citable_fallback() -> None:
    manifest, chunks = build_knowledge_chunks(SUMMARY_CATALOG_PATH)

    assert manifest.point_count == 440
    assert not any(chunk.citation_eligible for chunk in chunks)
    assert {chunk.text_kind for chunk in chunks} == {
        KnowledgeTextKind.SUMMARY,
        KnowledgeTextKind.MEASUREMENT,
    }


def test_all_p0_references_have_an_exact_reviewed_verbatim_chunk() -> None:
    current = asyncio.run(ConfigurationService().get_current_config())
    assessment = P0CurrentConfigRuleEngine().evaluate(current)
    expected = {
        (reference.standard_code, reference.clause_id)
        for level in assessment.levels
        for finding in level.findings
        for reference in finding.standard_references
    }
    _, chunks = build_knowledge_chunks()
    indexed = {
        (chunk.standard_code, clause_id)
        for chunk in chunks
        for clause_id in chunk.clause_ids
        if chunk.citation_eligible
    }

    assert len(expected) == 32
    assert expected <= indexed
