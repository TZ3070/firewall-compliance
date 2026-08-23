import json
from pathlib import Path

from app.models.cross_standard import CrossStandardCatalog
from scripts.build_cross_standard_mappings import OUTPUT_PATH, build_catalog


def test_cross_standard_catalog_applies_approved_mapping_decisions() -> None:
    catalog = build_catalog()

    assert catalog.review_status == "Draft"
    assert catalog.statistics.mapping_count == 102
    assert catalog.statistics.by_relationship == {
        "equivalent": 23,
        "partial": 13,
        "refines": 17,
        "supports": 49,
    }
    assert catalog.statistics.pending_question_count == 0
    assert catalog.statistics.human_reviewed_mapping_count == 29
    assert all(not item.standalone_pass_allowed for item in catalog.mappings)


def test_mapping_ids_and_control_pairs_are_unique() -> None:
    catalog = build_catalog()
    mapping_ids = [item.mapping_id for item in catalog.mappings]
    pairs = [
        (item.source.control_id, item.target.control_id)
        for item in catalog.mappings
    ]

    assert len(mapping_ids) == len(set(mapping_ids))
    assert len(pairs) == len(set(pairs))


def test_approved_questions_are_auditable_and_no_longer_pending() -> None:
    catalog = build_catalog()

    assert catalog.pending_questions == ()
    assert {item.question_id for item in catalog.review_decisions} == {
        "Q-MAP-001",
        "Q-MAP-002",
        "Q-MAP-003",
        "Q-MAP-004",
        "Q-MAP-005",
    }
    assert all(
        item.review_decision_id
        for item in catalog.mappings
        if item.review_status == "HumanReviewed"
    )


def test_partial_and_product_relationships_cannot_pass_standalone() -> None:
    catalog = build_catalog()

    assert all(
        not item.standalone_pass_allowed
        for item in catalog.mappings
        if item.relationship in {"partial", "supports"}
    )
    lab_mapping = next(
        item
        for item in catalog.mappings
        if item.source.control_id == "GB20281-FW-046"
    )
    assert lab_mapping.evidence_scope == "product-laboratory-test"
    assert lab_mapping.coverage == "partial"


def test_every_product_mapping_is_limited_to_network_firewalls() -> None:
    catalog = build_catalog()
    product_mappings = [
        item
        for item in catalog.mappings
        if item.source.standard_code == "GB/T 20281—2020"
    ]

    assert product_mappings
    assert all(item.conditional for item in product_mappings)
    assert all(
        "product_type == network-based-firewall" in item.applicability_conditions
        for item in product_mappings
    )
    assert "GB20281-FW-021" in catalog.unmapped_control_ids["GB/T 20281—2020"]
    assert all(
        item.source.control_id != "GB20281-FW-021" for item in product_mappings
    )


def test_generated_cross_standard_file_matches_validated_model() -> None:
    generated = json.loads(Path(OUTPUT_PATH).read_text(encoding="utf-8"))
    model = CrossStandardCatalog.model_validate(generated)

    assert model == build_catalog()
