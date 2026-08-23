from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from app.models.catalog import (
    ClauseReference,
    UnifiedControl,
    UnifiedFirewallCatalog,
    UnifiedMeasurementUnit,
)
from app.models.retrieval import (
    KnowledgeChunk,
    KnowledgeIndexManifest,
    KnowledgeTextKind,
    knowledge_point_id,
)


SUMMARY_CATALOG_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "catalog"
    / "unified-firewall-catalog-v1.json"
)
REVIEWED_VERBATIM_CATALOG_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "catalog"
    / "reviewed-verbatim-catalog-v1.json"
)
DEFAULT_CATALOG_PATH = (
    REVIEWED_VERBATIM_CATALOG_PATH
    if REVIEWED_VERBATIM_CATALOG_PATH.exists()
    else SUMMARY_CATALOG_PATH
)
INDEX_VERSION = "knowledge-index/1.1.0"


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _pages(
    references: tuple[ClauseReference, ...],
    attribute: str,
) -> tuple[int, ...]:
    values: list[int] = []
    for reference in references:
        values.extend(getattr(reference, attribute))
    return tuple(dict.fromkeys(values))


def _content_sha256(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _control_chunk(
    control: UnifiedControl,
    *,
    catalog: UnifiedFirewallCatalog,
    source_sha256: str,
) -> KnowledgeChunk:
    text = control.summary.strip()
    return KnowledgeChunk(
        point_id=knowledge_point_id(
            catalog_id=catalog.catalog_id,
            catalog_version=catalog.catalog_version,
            record_id=control.record_id,
        ),
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.catalog_version,
        record_id=control.record_id,
        record_type=control.record_type,
        source_catalog_id=control.source_catalog_id,
        source_record_pointer=control.source_record_pointer,
        source_catalog_sha256=source_sha256,
        standard_code=control.standard_code,
        clause_ids=_unique(ref.clause_id for ref in control.source_references),
        title=control.title.strip(),
        text=text,
        search_text=control.search_text.strip(),
        text_kind=KnowledgeTextKind.SUMMARY,
        content_sha256=_content_sha256(text),
        citation_eligible=False,
        review_status=control.review_status,
        topic=control.topic,
        context=control.context,
        classified_protection_levels=control.classified_protection_levels,
        printed_pages=_pages(control.source_references, "printed_pages"),
        pdf_page_indexes=_pages(control.source_references, "pdf_page_indexes"),
    )


def _measurement_text(unit: UnifiedMeasurementUnit) -> str:
    steps = "；".join(unit.assessment_steps)
    return "\n".join(
        (
            f"测评指标：{unit.measurement_indicator.strip()}",
            f"测评对象：{unit.assessment_objects.strip()}",
            f"测评步骤：{steps}",
            f"判定规则：{unit.decision_rule.strip()}",
        )
    )


def _measurement_chunk(
    unit: UnifiedMeasurementUnit,
    *,
    catalog: UnifiedFirewallCatalog,
    source_sha256: str,
) -> KnowledgeChunk:
    text = _measurement_text(unit)
    return KnowledgeChunk(
        point_id=knowledge_point_id(
            catalog_id=catalog.catalog_id,
            catalog_version=catalog.catalog_version,
            record_id=unit.record_id,
        ),
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.catalog_version,
        record_id=unit.record_id,
        record_type=unit.record_type,
        source_catalog_id=unit.source_catalog_id,
        source_record_pointer=unit.source_record_pointer,
        source_catalog_sha256=source_sha256,
        standard_code=unit.standard_code,
        clause_ids=_unique((unit.guide_clause_id, unit.requirement_clause_id)),
        title=f"{unit.canonical_measurement_unit_id} 测评单元",
        text=text,
        search_text=unit.search_text.strip(),
        text_kind=KnowledgeTextKind.MEASUREMENT,
        content_sha256=_content_sha256(text),
        citation_eligible=False,
        review_status=unit.mapping_review_status,
        context=unit.context,
        classified_protection_levels=(unit.classified_protection_level,),
        printed_pages=unit.printed_pages,
        pdf_page_indexes=unit.pdf_page_indexes,
    )


def _reviewed_clause_ids(excerpt: dict[str, object]) -> tuple[str, ...]:
    measurement_unit_id = str(excerpt.get("measurement_unit_id") or "").strip()
    guide_clause_id = str(excerpt.get("guide_clause_id") or "").strip()
    if measurement_unit_id:
        return _unique((guide_clause_id, measurement_unit_id))
    clause_id = str(excerpt.get("clause_id") or "").strip()
    selector = str(excerpt.get("requested_item_selector") or "").strip()
    selected_clause_id = " ".join(
        part for part in (clause_id, selector) if part
    )
    return _unique((clause_id, selected_clause_id))


def _reviewed_chunks(
    payload: dict[str, object],
) -> tuple[KnowledgeChunk, ...]:
    catalog_id = str(payload["catalog_id"])
    catalog_version = str(payload["catalog_version"])
    chunks: list[KnowledgeChunk] = []
    for record in payload["records"]:  # type: ignore[union-attr]
        if record["review_status"] != "HumanReviewed":
            raise ValueError(f"reviewed catalog contains unreviewed record: {record['record_id']}")
        if record["text_kind"] != "verbatim" or not record["citation_eligible"]:
            raise ValueError(f"reviewed catalog contains non-citable record: {record['record_id']}")
        for excerpt_index, excerpt in enumerate(record["excerpts"]):
            text = str(excerpt["text"]).strip()
            content_hash = _content_sha256(text)
            if content_hash != excerpt["content_sha256"]:
                raise ValueError(f"reviewed excerpt hash mismatch: {record['record_id']}")
            clause_ids = _reviewed_clause_ids(excerpt)
            level = excerpt.get("classified_protection_level")
            search_text = "\n".join(
                _unique(
                    (
                        str(record["standard_code"]),
                        str(record["title"]),
                        " ".join(clause_ids),
                        str(record["search_text"]),
                        text,
                    )
                )
            )
            chunks.append(
                KnowledgeChunk(
                    point_id=knowledge_point_id(
                        catalog_id=catalog_id,
                        catalog_version=catalog_version,
                        record_id=f"{record['record_id']}:excerpt:{excerpt_index}",
                    ),
                    catalog_id=catalog_id,
                    catalog_version=catalog_version,
                    record_id=str(record["record_id"]),
                    record_type=record["record_type"],
                    source_catalog_id=str(record["source_catalog_id"]),
                    source_record_pointer=str(record["source_record_pointer"]),
                    source_catalog_sha256=str(record["source_catalog_sha256"]),
                    standard_code=str(record["standard_code"]),
                    clause_ids=clause_ids,
                    title=str(record["title"]).strip(),
                    text=text,
                    search_text=search_text,
                    text_kind=KnowledgeTextKind.VERBATIM,
                    content_sha256=content_hash,
                    citation_eligible=True,
                    review_status="HumanReviewed",
                    topic=record.get("topic"),
                    context=record.get("context"),
                    classified_protection_levels=(int(level),) if level else (),
                    printed_pages=tuple(excerpt.get("printed_pages", ())),
                    pdf_page_indexes=tuple(excerpt.get("pdf_page_indexes", ())),
                )
            )
    if len(chunks) != int(payload["excerpt_count"]):
        raise ValueError("reviewed catalog excerpt count does not match records")
    return tuple(chunks)


def build_knowledge_chunks(
    catalog_path: Path = DEFAULT_CATALOG_PATH,
    *,
    collection_name: str = "firewall-standard-knowledge-v1",
    dense_model: str = "BAAI/bge-small-zh-v1.5",
    sparse_model: str = "Qdrant/bm25",
) -> tuple[KnowledgeIndexManifest, tuple[KnowledgeChunk, ...]]:
    raw_catalog = catalog_path.read_bytes()
    raw_payload = json.loads(raw_catalog)
    if raw_payload.get("catalog_id") == "bank-firewall-reviewed-verbatim-v1":
        chunks = _reviewed_chunks(raw_payload)
        catalog_id = raw_payload["catalog_id"]
        catalog_version = raw_payload["catalog_version"]
    else:
        catalog = UnifiedFirewallCatalog.model_validate(raw_payload)
        source_hashes = {source.catalog_id: source.sha256 for source in catalog.sources}

        chunks = tuple(
            [
                _control_chunk(
                    control,
                    catalog=catalog,
                    source_sha256=source_hashes[control.source_catalog_id],
                )
                for control in catalog.controls
            ]
            + [
                _measurement_chunk(
                    unit,
                    catalog=catalog,
                    source_sha256=source_hashes[unit.source_catalog_id],
                )
                for unit in catalog.measurement_units
            ]
        )
        catalog_id = catalog.catalog_id
        catalog_version = catalog.catalog_version
    point_ids = {chunk.point_id for chunk in chunks}
    if len(point_ids) != len(chunks):
        raise ValueError("catalog produced duplicate Qdrant point IDs")

    manifest = KnowledgeIndexManifest(
        index_version=INDEX_VERSION,
        collection_name=collection_name,
        catalog_id=catalog_id,
        catalog_version=catalog_version,
        catalog_sha256=sha256(raw_catalog).hexdigest(),
        dense_model=dense_model,
        sparse_model=sparse_model,
        point_count=len(chunks),
    )
    return manifest, chunks
