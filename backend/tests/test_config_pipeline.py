import asyncio
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.api.routes.configuration import get_configuration_service
from app.models.contracts import (
    RawConfigurationSnapshot,
)
from app.providers.mock_config import MockConfigProvider
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.services.configuration import ConfigurationService


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "mock" / "default-firewall.cfg"
)


class InlineHuaweiProvider:
    def __init__(self, cli_content: str) -> None:
        self.cli_content = cli_content

    async def fetch_raw_configuration(self) -> RawConfigurationSnapshot:
        return RawConfigurationSnapshot(
            acquisition_id=f"acq-{uuid4().hex}",
            target_id="inline-huawei",
            provider_version="inline-test/2.0.0",
            collected_at=datetime.now(timezone.utc),
            content=self.cli_content,
            content_sha256=hashlib.sha256(self.cli_content.encode()).hexdigest(),
            vendor_hint="Huawei",
        )


def test_provider_creates_unique_immutable_acquisitions_with_stable_hash() -> None:
    provider = MockConfigProvider()
    first = asyncio.run(provider.fetch_raw_configuration())
    second = asyncio.run(provider.fetch_raw_configuration())
    expected_content = FIXTURE_PATH.read_text(encoding="utf-8")
    expected_hash = hashlib.sha256(expected_content.encode("utf-8")).hexdigest()

    assert first.acquisition_id != second.acquisition_id
    assert first.content_sha256 == second.content_sha256 == expected_hash
    assert first.content == second.content == expected_content

    with pytest.raises(ValidationError):
        first.target_id = "changed-target"  # type: ignore[misc]

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


def test_current_pipeline_exposes_only_explicit_cli_facts(
    tmp_path: Path,
) -> None:
    service = ConfigurationService(
        provider=InlineHuaweiProvider("sysname INLINE-HUAWEI\ntelnet server enable\n"),
        repository=SQLiteSnapshotRepository(tmp_path / "observed-facts.db"),
    )

    configuration = asyncio.run(service.get_current_config())
    facts = {item.field: item.value for item in configuration.observed_facts}

    assert facts == {
        "target.hostname": "INLINE-HUAWEI",
        "management.protocols.telnet.enabled": True,
    }
    assert configuration.vendor_detection is not None
    assert configuration.vendor_detection.vendor == "Huawei"
