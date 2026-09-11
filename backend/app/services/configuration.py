import asyncio
import hashlib
import json
from uuid import uuid4

from app.core.config import get_settings
from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import (
    CurrentConfigResponse,
    FirewallSnapshot,
    RawConfigurationSnapshot,
)
from app.parsers.registry import ParserRegistry, VendorDetector
from app.providers.interfaces import ConfigProvider
from app.providers.mock_config import MockConfigProvider
from app.repositories.interfaces import AcquisitionRepository, SnapshotRepository
from app.repositories.sqlite_acquisition import SQLiteAcquisitionRepository
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository


class ConfigurationService:
    def __init__(
        self,
        provider: ConfigProvider | None = None,
        repository: SnapshotRepository | None = None,
        vendor_detector: VendorDetector | None = None,
        parser_registry: ParserRegistry | None = None,
        acquisition_repository: AcquisitionRepository | None = None,
    ) -> None:
        self._provider = provider or MockConfigProvider()
        self._vendor_detector = vendor_detector or VendorDetector()
        self._parser_registry = parser_registry or ParserRegistry()
        self._repository = repository or SQLiteSnapshotRepository(
            get_settings().resolved_database_path
        )
        repository_path = getattr(
            self._repository,
            "database_path",
            get_settings().resolved_database_path,
        )
        self._acquisition_repository = (
            acquisition_repository or SQLiteAcquisitionRepository(repository_path)
        )

    async def acquire_raw_configuration(self) -> RawConfigurationSnapshot:
        raw = await self._provider.fetch_raw_configuration()
        await asyncio.to_thread(self._acquisition_repository.save, raw)
        return raw

    async def detect_vendor(self, acquisition_id: str):
        raw = await asyncio.to_thread(
            self._acquisition_repository.get,
            acquisition_id,
        )
        if raw is None:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_FETCH_FAILED,
                f"原始配置采集 {acquisition_id} 不存在",
            )
        return self._vendor_detector.detect(raw)

    async def parse_acquisition(self, acquisition_id: str) -> CurrentConfigResponse:
        raw = await asyncio.to_thread(
            self._acquisition_repository.get,
            acquisition_id,
        )
        if raw is None:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_FETCH_FAILED,
                f"原始配置采集 {acquisition_id} 不存在",
            )

        vendor_detection = self._vendor_detector.detect(raw)
        vendor_parser = self._parser_registry.resolve(vendor_detection.vendor)
        snapshot_id = f"snp-{uuid4().hex}"
        parsed, observed_facts = vendor_parser.parse_configuration(
            raw.content,
            snapshot_id=snapshot_id,
            target_id=raw.target_id,
            raw_config_sha256=raw.content_sha256,
        )
        normalized_content = json.dumps(
            parsed.normalized_config.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        snapshot = FirewallSnapshot(
            snapshot_id=snapshot_id,
            target_id=raw.target_id,
            provider_version=raw.provider_version,
            collected_at=raw.collected_at,
            raw_content=normalized_content,
            content_sha256=hashlib.sha256(normalized_content.encode("utf-8")).hexdigest(),
            original_format="vendor_cli_mock",
            original_content=raw.content,
            original_content_sha256=raw.content_sha256,
            detected_vendor=vendor_detection.vendor,
            vendor_detection_confidence=vendor_detection.confidence,
        )
        await asyncio.to_thread(self._repository.save, snapshot, parsed)
        return CurrentConfigResponse(
            snapshot_id=snapshot.snapshot_id,
            target_id=snapshot.target_id,
            source_type=snapshot.source_type,
            provider_version=snapshot.provider_version,
            parser_version=parsed.parser_version,
            collected_at=snapshot.collected_at,
            content_sha256=snapshot.content_sha256,
            original_config_content=raw.content,
            original_config_sha256=raw.content_sha256,
            completeness=parsed.completeness,
            warnings=parsed.warnings,
            configuration=parsed.normalized_config,
            evidence=parsed.evidence,
            observed_facts=observed_facts,
            acquisition_id=raw.acquisition_id,
            vendor_detection=vendor_detection,
        )

    async def get_current_config(self) -> CurrentConfigResponse:
        raw = await self.acquire_raw_configuration()
        await self.detect_vendor(raw.acquisition_id)
        return await self.parse_acquisition(raw.acquisition_id)

    async def get_snapshot_configuration(
        self,
        snapshot_id: str,
    ) -> CurrentConfigResponse:
        stored = await asyncio.to_thread(self._repository.get, snapshot_id)
        if stored is None:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_FETCH_FAILED,
                f"配置快照 {snapshot_id} 不存在",
            )
        snapshot = stored.snapshot
        original = snapshot.original_content
        if original is None or snapshot.original_content_sha256 is None:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_INTEGRITY_FAILED,
                f"配置快照 {snapshot_id} 未绑定原始厂商配置",
            )
        raw = RawConfigurationSnapshot(
            acquisition_id=f"snapshot:{snapshot_id}",
            target_id=snapshot.target_id,
            provider_version=snapshot.provider_version,
            collected_at=snapshot.collected_at,
            content=original,
            content_sha256=snapshot.original_content_sha256,
            vendor_hint=snapshot.detected_vendor,
        )
        detection = self._vendor_detector.detect(raw)
        vendor_parser = self._parser_registry.resolve(detection.vendor)
        _, observed = vendor_parser.parse_configuration(
            original,
            snapshot_id=snapshot.snapshot_id,
            target_id=snapshot.target_id,
            raw_config_sha256=snapshot.original_content_sha256,
        )
        parsed = stored.parsed_configuration
        return CurrentConfigResponse(
            snapshot_id=snapshot.snapshot_id,
            target_id=snapshot.target_id,
            source_type=snapshot.source_type,
            provider_version=snapshot.provider_version,
            parser_version=parsed.parser_version,
            collected_at=snapshot.collected_at,
            content_sha256=snapshot.content_sha256,
            original_config_content=original,
            original_config_sha256=snapshot.original_content_sha256,
            completeness=parsed.completeness,
            warnings=parsed.warnings,
            configuration=parsed.normalized_config,
            evidence=parsed.evidence,
            observed_facts=observed,
            vendor_detection=detection,
        )
