import asyncio
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.models.contracts import ParseWarningCode, VerificationStatus
from app.api.routes.configuration import get_configuration_service
from app.providers.mock_config import (
    MockConfigProvider,
    build_snapshot,
    canonicalize_json,
)
from app.parsers.huawei_cli import HuaweiCliParser
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.services.config_parser import FirewallConfigParser, resolve_json_pointer
from app.services.configuration import ConfigurationService


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "mock" / "default-firewall.json"
)


def load_fixture() -> dict[str, Any]:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def test_provider_creates_unique_immutable_snapshots_with_stable_hash() -> None:
    provider = MockConfigProvider()
    first = asyncio.run(provider.get_current_snapshot())
    second = asyncio.run(provider.get_current_snapshot())
    cli_path = FIXTURE_PATH.with_suffix(".cfg")
    raw_content = HuaweiCliParser().parse_complete(
        cli_path.read_text(encoding="utf-8")
    )
    expected_canonical = canonicalize_json(raw_content)
    expected_hash = hashlib.sha256(expected_canonical.encode("utf-8")).hexdigest()

    assert first.snapshot_id != second.snapshot_id
    assert first.content_sha256 == second.content_sha256 == expected_hash
    assert first.raw_content == second.raw_content == expected_canonical

    with pytest.raises(ValidationError):
        first.target_id = "changed-target"  # type: ignore[misc]


def test_every_configuration_evidence_pointer_resolves_to_snapshot_value() -> None:
    snapshot = build_snapshot(load_fixture(), snapshot_id="snp-evidence-test")
    parsed = FirewallConfigParser().parse(snapshot)
    raw_content = json.loads(snapshot.raw_content)

    assert parsed.evidence
    for evidence in parsed.evidence:
        assert evidence.snapshot_id == snapshot.snapshot_id
        assert resolve_json_pointer(raw_content, evidence.source_pointer) == evidence.value


def test_null_and_missing_values_never_become_configuration_verified() -> None:
    parser = FirewallConfigParser()
    default_snapshot = build_snapshot(load_fixture(), snapshot_id="snp-null-test")
    default_parsed = parser.parse(default_snapshot)

    dos_evidence = next(
        evidence
        for evidence in default_parsed.evidence
        if evidence.source_pointer == "/threat_prevention/dos_protection_enabled"
    )
    assert dos_evidence.verification_status is VerificationStatus.INSUFFICIENT_EVIDENCE
    assert any(
        warning.code is ParseWarningCode.NULL_VALUE
        and warning.source_pointer == "/threat_prevention/dos_protection_enabled"
        for warning in default_parsed.warnings
    )

    expiry_evidence = next(
        evidence
        for evidence in default_parsed.evidence
        if evidence.source_pointer == "/access_control/policies/1/expires_at"
    )
    assert expiry_evidence.value is None
    assert expiry_evidence.verification_status is VerificationStatus.CONFIGURATION_VERIFIED

    missing_content = load_fixture()
    del missing_content["threat_prevention"]["dos_protection_enabled"]
    missing_snapshot = build_snapshot(missing_content, snapshot_id="snp-missing-test")
    missing_parsed = parser.parse(missing_snapshot)

    assert any(
        warning.code is ParseWarningCode.MISSING_FIELD
        and warning.source_pointer == "/threat_prevention/dos_protection_enabled"
        for warning in missing_parsed.warnings
    )
    assert all(
        evidence.source_pointer != "/threat_prevention/dos_protection_enabled"
        for evidence in missing_parsed.evidence
    )
    assert missing_parsed.normalized_config.threat_prevention.dos_protection_enabled is None
    assert missing_parsed.completeness == default_parsed.completeness


def test_policy_id_changes_content_hash_but_not_policy_semantic_facts() -> None:
    original_content = load_fixture()
    renamed_content = copy.deepcopy(original_content)
    renamed_content["access_control"]["policies"][0]["policy_id"] = "renamed-policy"

    original_snapshot = build_snapshot(original_content, snapshot_id="snp-policy-original")
    renamed_snapshot = build_snapshot(renamed_content, snapshot_id="snp-policy-renamed")
    parser = FirewallConfigParser()
    original = parser.parse(original_snapshot).normalized_config
    renamed = parser.parse(renamed_snapshot).normalized_config

    def semantic_policy_facts(configuration: Any) -> tuple[dict[str, Any], ...]:
        return tuple(
            policy.model_dump(exclude={"policy_id", "name"})
            for policy in configuration.access_control.policies
        )

    assert original_snapshot.content_sha256 != renamed_snapshot.content_sha256
    assert semantic_policy_facts(original) == semantic_policy_facts(renamed)


def test_current_config_api_returns_vendor_cli_instead_of_structured_json(
    tmp_path: Path,
) -> None:
    repository = SQLiteSnapshotRepository(tmp_path / "api-snapshots.db")
    service = ConfigurationService(repository=repository)
    app.dependency_overrides[get_configuration_service] = lambda: service
    client = TestClient(app)
    try:
        first_response = client.get("/api/v1/config/current")
        second_response = client.get("/api/v1/config/current")
    finally:
        app.dependency_overrides.clear()

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    first = first_response.json()
    second = second_response.json()

    assert first["snapshot_id"] != second["snapshot_id"]
    assert first["content_sha256"] == second["content_sha256"]
    assert first["target_id"] == "default-firewall-mock"
    assert first["configuration"]["management"]["protocols"]["telnet"]["enabled"] is False
    assert first["configuration"]["access_control"]["default_action"] == "deny"
    assert first["warnings"]
    assert first["evidence"]
    assert "raw_content" not in first
    assert first["original_config_format"] == "vendor_cli_mock"
    assert "sysname FW-MOCK-01" in first["original_config_content"]
    assert "security-policy" in first["original_config_content"]
    assert first["original_config_content"].lstrip().startswith("! MOCK DATA")
    assert first["original_config_sha256"] == hashlib.sha256(
        first["original_config_content"].encode("utf-8")
    ).hexdigest()
    assert repository.get(first["snapshot_id"]) is not None
    assert repository.get(second["snapshot_id"]) is not None
