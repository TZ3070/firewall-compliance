from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.models.catalog import (
    CatalogAlias,
    CatalogException,
    CatalogRelationship,
    CatalogSource,
    CatalogStatistics,
    ClauseReference,
    ReviewDecision,
    ReviewGate,
    UnifiedControl,
    UnifiedFirewallCatalog,
    UnifiedMeasurementUnit,
)


CATALOG_DIR = BACKEND_ROOT / "data" / "catalog"
OUTPUT_PATH = CATALOG_DIR / "unified-firewall-catalog-v1.json"
DECISION_PATH = CATALOG_DIR / "unified-catalog-review-decisions.json"
SOURCE_FILES = (
    "gb-t-22239-2019-firewall-candidates.json",
    "gb-t-20281-2020-firewall-candidates.json",
    "jr-t-0071-2-2020-firewall-candidates.json",
    "jr-t-0072-2020-firewall-test-methods.json",
)


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source_file:
        return json.load(source_file)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_strings(values: Iterable[str | None]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def _search_text(*values: Any) -> str:
    flattened: list[str] = []
    for value in values:
        if isinstance(value, str):
            flattened.append(value)
        elif isinstance(value, list | tuple):
            flattened.extend(str(item) for item in value if item is not None)
    return re.sub(r"\s+", " ", " ".join(flattened)).strip()


def _pages(value: Any) -> tuple[int, ...]:
    if value is None:
        return ()
    if isinstance(value, int):
        return (value,)
    return tuple(int(page) for page in value)


def _levels_from_refs(refs: list[dict[str, Any]]) -> tuple[int, ...]:
    return tuple(sorted({int(ref["level"]) for ref in refs if ref.get("level")}))


def _normalize_context(raw_context: str, *, conditional: bool) -> tuple[str, bool]:
    suffix = "-conditional"
    context = (
        raw_context[: -len(suffix)] if raw_context.endswith(suffix) else raw_context
    )
    return context, conditional or raw_context.endswith(suffix)


def _normalize_requirement_refs(refs: list[dict[str, Any]]) -> tuple[ClauseReference, ...]:
    return tuple(
        ClauseReference(
            clause_id=ref["clause_id"],
            item=ref.get("item"),
            classified_protection_level=ref.get("level"),
            printed_pages=_pages(ref.get("printed_pages", ref.get("printed_page"))),
            pdf_page_indexes=_pages(
                ref.get("pdf_page_indexes", ref.get("pdf_page_index"))
            ),
        )
        for ref in refs
    )


def _normalize_string_refs(refs: list[str]) -> tuple[ClauseReference, ...]:
    return tuple(ClauseReference(clause_id=ref) for ref in refs)


def _normalize_gb22239(catalog: dict[str, Any]) -> list[UnifiedControl]:
    controls: list[UnifiedControl] = []
    standard_code = catalog["source"]["standard_code"]
    catalog_id = catalog["catalog_id"]
    groups = (
        ("general_control_families", "general", False),
        ("conditional_extension_candidates", None, True),
    )
    for group_name, default_context, is_conditional in groups:
        for index, source in enumerate(catalog[group_name]):
            raw_refs = source["references"]
            refs = (
                _normalize_requirement_refs(raw_refs)
                if raw_refs and isinstance(raw_refs[0], dict)
                else _normalize_string_refs(raw_refs)
            )
            summary = source.get("requirement_summary", source["title"])
            context, conditional = _normalize_context(
                source.get("context", default_context or "general"),
                conditional=is_conditional,
            )
            controls.append(
                UnifiedControl(
                    record_id=source["control_id"],
                    record_type="requirement-control",
                    source_catalog_id=catalog_id,
                    source_record_pointer=f"/{group_name}/{index}",
                    standard_code=standard_code,
                    title=source["title"],
                    topic=source.get("topic", context),
                    context=context,
                    conditional=conditional,
                    priority=source.get("priority"),
                    classified_protection_levels=_levels_from_refs(
                        raw_refs if raw_refs and isinstance(raw_refs[0], dict) else []
                    ),
                    assessment_modes=(source["assessment_mode"],),
                    summary=summary,
                    source_references=refs,
                    evidence_selectors=tuple(source.get("evidence_selectors", [])),
                    applicability_condition=source.get("applicability_condition"),
                    review_status=catalog["review_status"],
                    search_text=_search_text(
                        source["control_id"], source["title"], summary,
                        source.get("topic"), context, source.get("evidence_selectors", [])
                    ),
                )
            )
    return controls


def _normalize_gb20281(catalog: dict[str, Any]) -> list[UnifiedControl]:
    controls: list[UnifiedControl] = []
    standard_code = catalog["source"]["standard_code"]
    for index, source in enumerate(catalog["control_candidates"]):
        refs = (
            ClauseReference(
                relation="requirement",
                clause_id=source["requirement_clause_id"],
                printed_pages=_pages(source.get("printed_pages")),
                pdf_page_indexes=_pages(source.get("pdf_page_indexes")),
            ),
            ClauseReference(
                relation="test",
                clause_id=source["test_clause_id"],
                printed_pages=_pages(source.get("printed_pages")),
                pdf_page_indexes=_pages(source.get("pdf_page_indexes")),
            ),
        )
        summary = source.get("requirement_summary", source["title"])
        controls.append(
            UnifiedControl(
                record_id=source["control_id"],
                record_type="product-control",
                source_catalog_id=catalog["catalog_id"],
                source_record_pointer=f"/control_candidates/{index}",
                standard_code=standard_code,
                title=source["title"],
                topic=source["topic"],
                context="general",
                conditional=False,
                assessment_modes=(source["assessment_mode"],),
                summary=summary,
                source_references=refs,
                evidence_selectors=tuple(source.get("evidence_selectors", [])),
                applicability_condition=source.get("applicability_condition"),
                review_status=catalog["review_status"],
                search_text=_search_text(
                    source["control_id"], source["title"], summary, source["topic"],
                    source.get("evidence_selectors", [])
                ),
            )
        )
    return controls


def _normalize_jr0071(catalog: dict[str, Any]) -> list[UnifiedControl]:
    controls: list[UnifiedControl] = []
    standard_code = catalog["source"]["standard_code"]
    groups = (
        ("control_candidates", False),
        ("conditional_extension_candidates", True),
    )
    for group_name, is_conditional in groups:
        for index, source in enumerate(catalog[group_name]):
            raw_refs = source["source_refs"]
            summary = source.get("requirement_summary", source["title"])
            context, conditional = _normalize_context(
                source.get("context", "general"), conditional=is_conditional
            )
            controls.append(
                UnifiedControl(
                    record_id=source["control_id"],
                    record_type="requirement-control",
                    source_catalog_id=catalog["catalog_id"],
                    source_record_pointer=f"/{group_name}/{index}",
                    standard_code=standard_code,
                    title=source["title"],
                    topic=source.get("topic", context),
                    context=context,
                    conditional=conditional,
                    classified_protection_levels=_levels_from_refs(raw_refs),
                    assessment_modes=(source["assessment_mode"],),
                    summary=summary,
                    source_references=_normalize_requirement_refs(raw_refs),
                    evidence_selectors=tuple(source.get("evidence_selectors", [])),
                    applicability_condition=source.get("applicability_condition"),
                    review_status=catalog["review_status"],
                    search_text=_search_text(
                        source["control_id"], source["title"], summary,
                        source.get("topic"), context, source.get("evidence_selectors", [])
                    ),
                )
            )
    return controls


def _measurement_record_id(
    source: dict[str, Any], measurement_unit_id: str | None = None
) -> str:
    return "|".join(
        (
            f"L{source['classified_protection_level']}",
            source["guide_clause_id"],
            measurement_unit_id or source["measurement_unit_id"],
            str(source["pdf_page_indexes"][0]),
        )
    )


def _normalize_measurements(
    catalog: dict[str, Any],
    known_control_ids: set[str],
    decisions: dict[str, ReviewDecision],
) -> tuple[
    list[UnifiedMeasurementUnit],
    list[CatalogRelationship],
    list[CatalogAlias],
    list[CatalogException],
]:
    measurements: list[UnifiedMeasurementUnit] = []
    relationships: list[CatalogRelationship] = []
    aliases: list[CatalogAlias] = []
    exceptions: list[CatalogException] = []
    composite_ids: set[str] = set()

    for index, source in enumerate(catalog["measurement_units"]):
        source_record_id = _measurement_record_id(source)
        source_alias_decision = decisions["DEC-SOURCE-001"]
        canonical_unit_id = source["measurement_unit_id"]
        record_aliases: tuple[str, ...] = ()
        if source_record_id in source_alias_decision.applies_to:
            canonical_unit_id = "L4-ABS3-03"
            record_aliases = (source_record_id,)
        record_id = _measurement_record_id(source, canonical_unit_id)
        if record_id in composite_ids:
            raise ValueError(f"重复测评单元复合键：{record_id}")
        composite_ids.add(record_id)
        target_ids = tuple(source["requirement_ref"]["control_ids"])
        unknown_ids = set(target_ids) - known_control_ids
        if unknown_ids:
            raise ValueError(f"测评单元 {record_id} 存在悬空控制项引用：{unknown_ids}")
        context, conditional = _normalize_context(
            source["context"], conditional=False
        )
        mapping_decision: ReviewDecision | None = None
        for decision in decisions.values():
            if (
                decision.decision_type.startswith("mapping-")
                and record_id in decision.applies_to
            ):
                mapping_decision = decision
                break
        effective_review_status = (
            "HumanReviewed" if mapping_decision else source["mapping_review_status"]
        )
        coverage = (
            "partial"
            if mapping_decision
            and mapping_decision.decision_type == "mapping-partial-coverage"
            else "full"
        )
        measurements.append(
            UnifiedMeasurementUnit(
                record_id=record_id,
                source_catalog_id=catalog["catalog_id"],
                source_record_pointer=f"/measurement_units/{index}",
                standard_code=catalog["source"]["standard_code"],
                canonical_measurement_unit_id=canonical_unit_id,
                source_measurement_unit_id=source["measurement_unit_id"],
                record_aliases=record_aliases,
                classified_protection_level=source["classified_protection_level"],
                context=context,
                conditional=conditional,
                guide_clause_id=source["guide_clause_id"],
                printed_pages=tuple(source["printed_pages"]),
                pdf_page_indexes=tuple(source["pdf_page_indexes"]),
                requirement_standard_code=source["requirement_ref"]["standard_code"],
                requirement_clause_id=source["requirement_ref"]["clause_id"],
                requirement_bullet=source["requirement_ref"].get("bullet"),
                requirement_control_ids=target_ids,
                measurement_indicator=source["measurement_indicator"],
                assessment_objects=source["assessment_objects"],
                assessment_steps=tuple(source["assessment_steps"]),
                decision_rule=source["decision_rule"],
                assessment_methods=tuple(source["assessment_methods"]),
                mapping_confidence=source["mapping_confidence"],
                mapping_review_status=effective_review_status,
                search_text=_search_text(
                    canonical_unit_id, source["measurement_unit_id"],
                    source["guide_clause_id"],
                    source["measurement_indicator"], source["assessment_objects"],
                    source["assessment_steps"], source["decision_rule"], target_ids
                ),
            )
        )
        for target_id in target_ids:
            relationships.append(
                CatalogRelationship(
                    relationship_id=f"measures:{record_id}:{target_id}",
                    relationship_type="measures",
                    source_record_id=record_id,
                    target_record_id=target_id,
                    source_standard_code=catalog["source"]["standard_code"],
                    target_standard_code=source["requirement_ref"]["standard_code"],
                    confidence=source["mapping_confidence"],
                    review_status=effective_review_status,
                    coverage=coverage,
                    blocks_standalone_pass=coverage == "partial",
                )
            )
        if source["mapping_review_status"] == "NeedsReview":
            if mapping_decision is None:
                resolution_status = "unresolved"
                resolution_decision_id = None
                blocks_final_determination = True
            else:
                resolution_status = "resolved"
                resolution_decision_id = mapping_decision.decision_id
                blocks_final_determination = False
            exceptions.append(
                CatalogException(
                    exception_id=f"mapping-needs-review:{record_id}",
                    exception_type="mapping-needs-review",
                    source_catalog_id=catalog["catalog_id"],
                    record_id=record_id,
                    details={
                        "source_measurement_unit_id": source["measurement_unit_id"],
                        "canonical_measurement_unit_id": canonical_unit_id,
                        "guide_clause_id": source["guide_clause_id"],
                        "requirement_control_ids": list(target_ids),
                        "mapping_confidence": source["mapping_confidence"],
                    },
                    resolution_status=resolution_status,
                    resolution_decision_id=resolution_decision_id,
                    blocks_final_determination=blocks_final_determination,
                )
            )

        if record_aliases:
            aliases.append(
                CatalogAlias(
                    alias_id="alias:source:L4-ABS3-03",
                    alias_type="source-record-id",
                    alias_record_id=source_record_id,
                    canonical_record_id=record_id,
                    decision_id=source_alias_decision.decision_id,
                )
            )

    for index, anomaly in enumerate(catalog.get("source_anomalies", []), start=1):
        anomaly_source_record_id = "|".join(
            (
                f"L{anomaly['classified_protection_level_from_chapter']}",
                anomaly["guide_clause_id"],
                anomaly["measurement_unit_id_as_printed"],
                str(anomaly["pdf_page_index"]),
            )
        )
        anomaly_decision = decisions["DEC-SOURCE-001"]
        resolved = anomaly_source_record_id in anomaly_decision.applies_to
        exceptions.append(
            CatalogException(
                exception_id=f"source-anomaly:{index}",
                exception_type="source-anomaly",
                source_catalog_id=catalog["catalog_id"],
                details=anomaly,
                resolution_status="resolved" if resolved else "unresolved",
                resolution_decision_id=anomaly_decision.decision_id if resolved else None,
                blocks_final_determination=not resolved,
            )
        )

    expected = catalog["statistics"]
    checks = {
        "selected_measurement_unit_count": len(measurements),
        "control_unit_link_count": len(relationships),
        "mapping_needs_review_count": sum(
            item.exception_type == "mapping-needs-review" for item in exceptions
        ),
        "source_anomaly_count": sum(
            item.exception_type == "source-anomaly" for item in exceptions
        ),
    }
    for key, actual in checks.items():
        if expected[key] != actual:
            raise ValueError(f"JR/T 0072 统计不一致：{key} 期望 {expected[key]}，实际 {actual}")
    return measurements, relationships, aliases, exceptions


def _load_review_decisions() -> tuple[ReviewDecision, ...]:
    payload = _load(DECISION_PATH)
    decisions = tuple(
        ReviewDecision.model_validate(item) for item in payload["decisions"]
    )
    ids = [item.decision_id for item in decisions]
    if len(ids) != len(set(ids)):
        raise ValueError("人工复核 decision_id 重复")
    required_ids = {
        "DEC-CONTEXT-001",
        "DEC-MAPPING-001",
        "DEC-MAPPING-002",
        "DEC-MAPPING-003",
        "DEC-SOURCE-001",
    }
    if set(ids) != required_ids:
        raise ValueError(f"人工复核决定集合异常：{sorted(set(ids) ^ required_ids)}")
    return decisions


def build_catalog() -> UnifiedFirewallCatalog:
    review_decisions = _load_review_decisions()
    decisions_by_id = {item.decision_id: item for item in review_decisions}
    source_paths = [CATALOG_DIR / filename for filename in SOURCE_FILES]
    source_catalogs = [_load(path) for path in source_paths]
    by_id = {catalog["catalog_id"]: catalog for catalog in source_catalogs}
    if len(by_id) != len(source_catalogs):
        raise ValueError("源目录 catalog_id 重复")

    controls = [
        *_normalize_gb22239(by_id["gb-t-22239-2019-firewall-candidates"]),
        *_normalize_gb20281(by_id["gb-t-20281-2020-firewall-candidates"]),
        *_normalize_jr0071(by_id["jr-t-0071-2-2020-firewall-candidates"]),
    ]
    control_ids = [control.record_id for control in controls]
    duplicates = [item for item, count in Counter(control_ids).items() if count > 1]
    if duplicates:
        raise ValueError(f"统一控制项 ID 重复：{duplicates}")

    measurements, relationships, aliases, exceptions = _normalize_measurements(
        by_id["jr-t-0072-2020-firewall-test-methods"],
        set(control_ids),
        decisions_by_id,
    )
    known_record_ids = set(control_ids) | {item.record_id for item in measurements}
    for relationship in relationships:
        if (
            relationship.source_record_id not in known_record_ids
            or relationship.target_record_id not in known_record_ids
        ):
            raise ValueError(f"关系存在悬空引用：{relationship.relationship_id}")

    source_entries: list[CatalogSource] = []
    source_record_counts = {
        "gb-t-22239-2019-firewall-candidates": 47,
        "gb-t-20281-2020-firewall-candidates": 47,
        "jr-t-0071-2-2020-firewall-candidates": 63,
        "jr-t-0072-2020-firewall-test-methods": 283,
    }
    for path, catalog in zip(source_paths, source_catalogs, strict=True):
        source_entries.append(
            CatalogSource(
                catalog_id=catalog["catalog_id"],
                path=str(path.relative_to(BACKEND_ROOT)),
                sha256=_sha256(path),
                standard_code=catalog["source"]["standard_code"],
                title=catalog["source"]["title"],
                review_status=catalog["review_status"],
                record_count=source_record_counts[catalog["catalog_id"]],
            )
        )

    by_standard = Counter(control.standard_code for control in controls)
    by_standard.update(item.standard_code for item in measurements)
    by_context = Counter(control.context for control in controls)
    by_context.update(item.context for item in measurements)
    unresolved_ids = tuple(
        item.exception_id for item in exceptions if item.resolution_status == "unresolved"
    )
    all_sources_reviewed = all(item.review_status == "Reviewed" for item in source_entries)
    final_allowed = all_sources_reviewed and not unresolved_ids
    if final_allowed:
        gate_reason = "所有源目录均已审核且不存在未解决异常。"
    elif unresolved_ids:
        gate_reason = (
            "存在未解决异常；统一目录仅可用于检索和候选评估，不能形成最终合规结论。"
        )
    else:
        gate_reason = (
            "已确认异常均已解决，但源目录仍为 Candidate；统一目录仅可用于检索和候选评估，不能形成最终合规结论。"
        )

    return UnifiedFirewallCatalog(
        catalog_version="1.0.0",
        generated_on="2026-08-23",
        scope="仅整合四份标准目录中的防火墙相关控制项和测评单元。",
        sources=tuple(source_entries),
        controls=tuple(controls),
        measurement_units=tuple(measurements),
        relationships=tuple(relationships),
        aliases=tuple(aliases),
        review_decisions=review_decisions,
        exceptions=tuple(exceptions),
        statistics=CatalogStatistics(
            source_catalog_count=len(source_entries),
            control_count=len(controls),
            requirement_control_count=sum(
                item.record_type == "requirement-control" for item in controls
            ),
            product_control_count=sum(
                item.record_type == "product-control" for item in controls
            ),
            measurement_unit_count=len(measurements),
            relationship_count=len(relationships),
            exception_count=len(exceptions),
            unresolved_exception_count=len(unresolved_ids),
            alias_count=len(aliases),
            review_decision_count=len(review_decisions),
            by_standard=dict(sorted(by_standard.items())),
            by_context=dict(sorted(by_context.items())),
        ),
        review_gate=ReviewGate(
            final_determination_allowed=final_allowed,
            reason=gate_reason,
            unresolved_exception_ids=unresolved_ids,
        ),
    )


def main() -> None:
    catalog = build_catalog()
    payload = catalog.model_dump(mode="json")
    OUTPUT_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"generated {OUTPUT_PATH}: "
        f"{len(catalog.controls)} controls, "
        f"{len(catalog.measurement_units)} measurement units, "
        f"{len(catalog.relationships)} relationships, "
        f"{catalog.statistics.unresolved_exception_count} unresolved exceptions"
    )


if __name__ == "__main__":
    main()
