from hashlib import sha256

import pytest

from scripts.publish_reviewed_verbatim import (
    EXCERPT_HEADERS,
    REVIEW_HEADERS,
    build_reviewed_catalog,
    validate_review_rows,
)


TEXT = "8.1.3.3   入侵防范\na) 应检测网络攻击行为。"
TEXT_HASH = sha256(TEXT.encode("utf-8")).hexdigest()


def _candidates() -> dict:
    return {
        "catalog_id": "candidate-v1",
        "catalog_version": "1.0.0",
        "source_unified_catalog": {"path": "unified.json", "sha256": "a" * 64},
        "sources": [],
        "records": [
            {
                "record_id": "control-1",
                "record_type": "requirement-control",
                "standard_code": "JR/T TEST—2026",
                "title": "入侵防范",
                "source_catalog_id": "source-1",
                "source_record_pointer": "/controls/0",
                "machine_extraction_status": "Extracted",
                "review_status": "PendingHumanReview",
                "citation_eligible": False,
                "text_kind": "verbatim-candidate",
                "issues": [],
                "excerpts": [
                    {
                        "reference_index": 0,
                        "relation": "requirement",
                        "clause_id": "8.1.3.3",
                        "requested_item_selector": "a",
                        "extracted_items": ["a"],
                        "classified_protection_level": 3,
                        "printed_pages": [30],
                        "pdf_page_indexes": [38],
                        "text": TEXT,
                        "content_sha256": TEXT_HASH,
                        "source_heading_occurrences": 1,
                    }
                ],
            }
        ],
    }


def _review_rows(decision: str = "Approved") -> tuple[tuple[str, ...], ...]:
    return (
        REVIEW_HEADERS,
        (
            "control-1",
            "JR/T TEST—2026",
            "requirement-control",
            "入侵防范",
            "Extracted",
            "1",
            "8.1.3.3 a",
            "",
            decision,
            "" if decision != "Rejected" else "原文不符",
            TEXT_HASH,
        ),
    )


def _excerpt_rows() -> tuple[tuple[str, ...], ...]:
    return (
        EXCERPT_HEADERS,
        (
            "control-1",
            "JR/T TEST—2026",
            "requirement-control",
            "1",
            "8.1.3.3 a",
            "3",
            "30",
            "38",
            TEXT,
            TEXT_HASH,
        ),
    )


def _unified() -> dict:
    return {
        "sources": [{"catalog_id": "source-1", "sha256": "b" * 64}],
        "controls": [
            {
                "record_id": "control-1",
                "topic": "intrusion-prevention",
                "context": "general",
                "search_text": "入侵防范 网络攻击",
            }
        ],
        "measurement_units": [],
    }


def test_approved_review_is_published_as_citable_verbatim() -> None:
    candidates = _candidates()
    decisions = validate_review_rows(candidates, _review_rows(), _excerpt_rows())

    published = build_reviewed_catalog(
        candidate_payload=candidates,
        unified_payload=_unified(),
        decisions=decisions,
        review_file_name="review.xlsx",
        review_sha256="c" * 64,
        reviewed_on="2026-08-23",
    )

    assert published["record_count"] == 1
    assert published["excerpt_count"] == 1
    record = published["records"][0]
    assert record["review_status"] == "HumanReviewed"
    assert record["citation_eligible"] is True
    assert record["text_kind"] == "verbatim"
    assert record["review_decision"]["review_artifact_sha256"] == "c" * 64


def test_pending_review_fails_closed() -> None:
    with pytest.raises(ValueError, match="尚未完成审核"):
        validate_review_rows(_candidates(), _review_rows("Pending"), _excerpt_rows())


def test_rejected_review_is_not_published() -> None:
    candidates = _candidates()
    decisions = validate_review_rows(
        candidates,
        _review_rows("Rejected"),
        _excerpt_rows(),
    )
    published = build_reviewed_catalog(
        candidate_payload=candidates,
        unified_payload=_unified(),
        decisions=decisions,
        review_file_name="review.xlsx",
        review_sha256="c" * 64,
        reviewed_on="2026-08-23",
    )

    assert published["records"] == []
    assert published["rejected_records"] == [
        {"record_id": "control-1", "notes": "原文不符"}
    ]
