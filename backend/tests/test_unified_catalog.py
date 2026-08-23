import json
from pathlib import Path

from app.models.catalog import UnifiedFirewallCatalog
from scripts.build_unified_catalog import OUTPUT_PATH, build_catalog


def test_unified_catalog_has_complete_source_coverage() -> None:
    catalog = build_catalog()

    assert catalog.statistics.source_catalog_count == 4
    assert catalog.statistics.control_count == 157
    assert catalog.statistics.requirement_control_count == 110
    assert catalog.statistics.product_control_count == 47
    assert catalog.statistics.measurement_unit_count == 283
    assert catalog.statistics.relationship_count == 291
    assert catalog.statistics.by_standard == {
        "GB/T 20281—2020": 47,
        "GB/T 22239—2019": 47,
        "JR/T 0071.2—2020": 63,
        "JR/T 0072—2020": 283,
    }
    assert catalog.statistics.by_context == {
        "cloud": 61,
        "general": 322,
        "industrial-control": 4,
        "iot": 24,
        "mobile": 29,
    }
    assert all(
        not item.context.endswith("-conditional") for item in catalog.controls
    )
    assert all(
        not item.context.endswith("-conditional")
        for item in catalog.measurement_units
    )


def test_relationships_have_no_dangling_records() -> None:
    catalog = build_catalog()
    record_ids = {item.record_id for item in catalog.controls}
    record_ids.update(item.record_id for item in catalog.measurement_units)

    assert len({item.relationship_id for item in catalog.relationships}) == 291
    assert all(item.source_record_id in record_ids for item in catalog.relationships)
    assert all(item.target_record_id in record_ids for item in catalog.relationships)


def test_approved_exceptions_remain_auditable_but_are_resolved() -> None:
    catalog = build_catalog()

    assert catalog.statistics.exception_count == 4
    assert sum(
        item.exception_type == "source-anomaly" for item in catalog.exceptions
    ) == 1
    assert sum(
        item.exception_type == "mapping-needs-review" for item in catalog.exceptions
    ) == 3
    assert catalog.statistics.unresolved_exception_count == 0
    assert catalog.statistics.review_decision_count == 5
    assert all(item.resolution_status == "resolved" for item in catalog.exceptions)
    assert all(not item.blocks_final_determination for item in catalog.exceptions)
    assert catalog.review_gate.final_determination_allowed is False
    assert catalog.review_gate.unresolved_exception_ids == ()
    assert "Candidate" in catalog.review_gate.reason


def test_source_typo_has_canonical_id_and_searchable_alias() -> None:
    catalog = build_catalog()
    corrected = next(
        item
        for item in catalog.measurement_units
        if item.canonical_measurement_unit_id == "L4-ABS3-03"
    )

    assert corrected.source_measurement_unit_id == "L3-ABS3-03"
    assert corrected.record_id == "L4|8.3.3.3|L4-ABS3-03|296"
    assert corrected.record_aliases == ("L4|8.3.3.3|L3-ABS3-03|296",)
    assert catalog.statistics.alias_count == 1
    assert catalog.aliases[0].alias_record_id in corrected.record_aliases
    assert catalog.aliases[0].canonical_record_id == corrected.record_id


def test_approved_mapping_decisions_are_applied() -> None:
    catalog = build_catalog()
    relationships = {item.source_record_id: item for item in catalog.relationships}

    assert relationships["L2|6.3.3.3|L2-ABS3-07|68"].review_status == (
        "HumanReviewed"
    )
    assert relationships["L4|8.3.3.3|L4-ABS3-07|296"].review_status == (
        "HumanReviewed"
    )
    partial = relationships["L3|7.1.4.1|L3-CES1-03|94"]
    assert partial.review_status == "HumanReviewed"
    assert partial.coverage == "partial"
    assert partial.blocks_standalone_pass is True


def test_generated_file_matches_validated_model() -> None:
    generated = json.loads(Path(OUTPUT_PATH).read_text(encoding="utf-8"))
    model = UnifiedFirewallCatalog.model_validate(generated)
    rebuilt = build_catalog()

    assert model == rebuilt
