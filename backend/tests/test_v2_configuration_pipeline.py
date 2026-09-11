import asyncio
from pathlib import Path

import pytest

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import RawConfigurationSnapshot, VerificationStatus
from app.parsers.registry import ParserRegistry, VendorDetector
from app.providers.mock_config import MockConfigProvider
from app.repositories.sqlite_acquisition import SQLiteAcquisitionRepository
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.services.configuration import ConfigurationService


def test_vendor_detection_precedes_parser_selection() -> None:
    raw = asyncio.run(MockConfigProvider().fetch_raw_configuration())
    detection = VendorDetector().detect(raw)

    assert detection.vendor == "Huawei"
    assert detection.confidence >= 0.5
    assert len(detection.matched_signatures) >= 2
    assert ParserRegistry().resolve(detection.vendor).version.startswith("huawei-vrp-cli/")


def test_unknown_vendor_is_never_sent_to_huawei_parser() -> None:
    raw = RawConfigurationSnapshot(
        acquisition_id="acq-unknown",
        target_id="unknown-device",
        provider_version="test/1",
        collected_at="2026-09-02T00:00:00Z",
        content="hostname unknown\ninterface ethernet 1\n",
        content_sha256="acb4887b3c001f1728064c17c03a10ce4a7407ec291ff7fe3f3b913d4d3c84a3",
    )
    # Make the fixture hash exact without weakening model validation.
    import hashlib

    raw = raw.model_copy(
        update={"content_sha256": hashlib.sha256(raw.content.encode()).hexdigest()}
    )
    with pytest.raises(ConfigurationPipelineError) as error:
        VendorDetector().detect(raw)
    assert error.value.code is ConfigurationErrorCode.UNSUPPORTED_VENDOR


def test_explicit_three_phase_pipeline_persists_original_cli(tmp_path: Path) -> None:
    database = tmp_path / "pipeline.db"
    service = ConfigurationService(
        repository=SQLiteSnapshotRepository(database),
        acquisition_repository=SQLiteAcquisitionRepository(database),
    )

    raw = asyncio.run(service.acquire_raw_configuration())
    detection = asyncio.run(service.detect_vendor(raw.acquisition_id))
    current = asyncio.run(service.parse_acquisition(raw.acquisition_id))

    assert detection.vendor == "Huawei"
    assert current.acquisition_id == raw.acquisition_id
    assert current.vendor_detection == detection
    assert current.parser_version.startswith("huawei-vrp-cli/")
    assert current.original_config_sha256 == raw.content_sha256
    assert current.configuration.target.vendor == "Huawei"
    assert any(
        item.raw_config_sha256 == raw.content_sha256
        and item.raw_line_start is not None
        for item in current.evidence
        if item.verification_status is VerificationStatus.CONFIGURATION_VERIFIED
    )
