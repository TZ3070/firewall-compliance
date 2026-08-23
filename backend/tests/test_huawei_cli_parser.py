import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parsers.huawei_cli import HuaweiCliParser


ATOMIC_CONFIG_DIR = (
    Path(__file__).resolve().parents[1] / "data" / "huawei-atomic-configs"
)
DEFAULT_CLI_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "mock" / "default-firewall.cfg"
)
REVIEWED_CATALOG_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "catalog"
    / "reviewed-verbatim-catalog-v1.json"
)


def assert_contains(actual: Any, expected: Any) -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        for key, value in expected.items():
            assert key in actual
            assert_contains(actual[key], value)
        return
    if isinstance(expected, list):
        assert actual == expected
        return
    assert actual == expected


@pytest.mark.parametrize("cfg_path", sorted(ATOMIC_CONFIG_DIR.glob("*.cfg")))
def test_twenty_atomic_huawei_configs_match_expected_json(cfg_path: Path) -> None:
    expected_path = cfg_path.with_suffix(".json")
    standard_case = json.loads(expected_path.read_text(encoding="utf-8"))
    expected = standard_case["expected_parsed_patch"]

    actual = HuaweiCliParser().parse_patch(cfg_path.read_text(encoding="utf-8"))

    assert_contains(actual, expected)
    assert standard_case["expected_result"] in {
        "Passed",
        "Failed",
        "NeedsReview",
        "NotApplicable",
    }
    assert standard_case["primary_standard"]["review_status"] == "HumanReviewed"
    assert standard_case["primary_standard"]["citation_eligible"] is True


def test_parse_api_returns_structured_huawei_patch() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/v1/config/parse",
        json={
            "vendor": "Huawei",
            "cli_content": "profile type ips name IPS-TEST\n action block\n",
        },
    )

    assert response.status_code == 200
    assert response.json()["parser_version"] == "huawei-vrp-cli/1.0.0"
    assert response.json()["structured_patch"] == {
        "threat_prevention": {"ips_enabled": True}
    }


def test_parse_api_rejects_unrecognized_text() -> None:
    response = TestClient(app).post(
        "/api/v1/config/parse",
        json={"vendor": "Huawei", "cli_content": "this is not Huawei CLI"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "HUAWEI_CLI_PARSE_FAILED"


def test_complete_default_cli_can_enter_existing_json_pipeline() -> None:
    parsed = HuaweiCliParser().parse_complete(
        DEFAULT_CLI_PATH.read_text(encoding="utf-8")
    )

    assert parsed["target"]["hostname"] == "FW-MOCK-01"
    assert parsed["access_control"]["default_action"] == "deny"
    assert parsed["management"]["allowed_source_cidrs"] == ["192.0.2.32/27"]
    assert parsed["threat_prevention"]["ips_enabled"] is True
    assert parsed["logging"]["remote_logging"]["servers"][0]["reachable"] is None


def test_all_scenario_standard_references_are_exact_reviewed_catalog_content() -> None:
    catalog = json.loads(REVIEWED_CATALOG_PATH.read_text(encoding="utf-8"))
    records = {record["record_id"]: record for record in catalog["records"]}

    for standard_path in sorted(ATOMIC_CONFIG_DIR.glob("*.json")):
        standard_case = json.loads(standard_path.read_text(encoding="utf-8"))
        references = [
            standard_case["primary_standard"],
            *standard_case["related_standards"],
        ]
        for reference in references:
            record = records[reference["record_id"]]
            exact_excerpts = [
                excerpt
                for excerpt in record["excerpts"]
                if excerpt["text"] == reference["verbatim_text"]
                and excerpt["content_sha256"] == reference["content_sha256"]
            ]
            assert exact_excerpts
            assert record["review_status"] == "HumanReviewed"
            assert record["citation_eligible"] is True
