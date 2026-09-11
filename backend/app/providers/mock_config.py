import hashlib
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import RawConfigurationSnapshot


BACKEND_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MOCK_ORIGINAL_PATH = BACKEND_ROOT / "data" / "mock" / "default-firewall.cfg"
PROVIDER_VERSION = "mock-configuration-api/2.0.0"

class MockConfigProvider:
    """Mock implementation of the future customer configuration API."""

    async def fetch_raw_configuration(self) -> RawConfigurationSnapshot:
        cli_content = self._read_original_config()
        return RawConfigurationSnapshot(
            acquisition_id=f"acq-{uuid4().hex}",
            target_id="default-firewall-mock",
            provider_version=PROVIDER_VERSION,
            collected_at=datetime.now(timezone.utc),
            content=cli_content,
            content_sha256=hashlib.sha256(cli_content.encode("utf-8")).hexdigest(),
            vendor_hint="Huawei",
        )

    @staticmethod
    def _read_original_config() -> str:
        try:
            return DEFAULT_MOCK_ORIGINAL_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_FETCH_FAILED,
                "无法读取内置默认 Mock 原始配置",
            ) from exc
