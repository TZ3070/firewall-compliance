import asyncio
import hashlib

from app.core.config import get_settings
from app.models.contracts import CurrentConfigResponse
from app.providers.interfaces import ConfigProvider
from app.providers.mock_config import MockConfigProvider
from app.repositories.interfaces import SnapshotRepository
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.services.config_parser import FirewallConfigParser


class ConfigurationService:
    def __init__(
        self,
        provider: ConfigProvider | None = None,
        parser: FirewallConfigParser | None = None,
        repository: SnapshotRepository | None = None,
    ) -> None:
        self._provider = provider or MockConfigProvider()
        self._parser = parser or FirewallConfigParser()
        self._repository = repository or SQLiteSnapshotRepository(
            get_settings().resolved_database_path
        )

    async def get_original_config(self) -> str:
        """Read the bundled CLI text without parsing or persisting a snapshot."""
        return await self._provider.get_original_config()

    async def get_current_config(self) -> CurrentConfigResponse:
        snapshot = await self._provider.get_current_snapshot()
        original_config = await self._provider.get_original_config()
        parsed = self._parser.parse(snapshot)
        await asyncio.to_thread(self._repository.save, snapshot, parsed)
        return CurrentConfigResponse(
            snapshot_id=snapshot.snapshot_id,
            target_id=snapshot.target_id,
            source_type=snapshot.source_type,
            provider_version=snapshot.provider_version,
            parser_version=parsed.parser_version,
            collected_at=snapshot.collected_at,
            content_sha256=snapshot.content_sha256,
            original_config_content=original_config,
            original_config_sha256=hashlib.sha256(
                original_config.encode("utf-8")
            ).hexdigest(),
            completeness=parsed.completeness,
            warnings=parsed.warnings,
            configuration=parsed.normalized_config,
            evidence=parsed.evidence,
        )
