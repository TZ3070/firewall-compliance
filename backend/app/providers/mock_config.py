import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import DefaultFirewallConfig, FirewallSnapshot
from app.parsers.huawei_cli import HuaweiCliParser


BACKEND_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MOCK_ORIGINAL_PATH = BACKEND_ROOT / "data" / "mock" / "default-firewall.cfg"
PROVIDER_VERSION = "mock-json-provider/1.0.0"


def canonicalize_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def build_snapshot(
    raw_content: dict[str, Any],
    *,
    collected_at: datetime | None = None,
    snapshot_id: str | None = None,
) -> FirewallSnapshot:
    try:
        validated = DefaultFirewallConfig.model_validate(raw_content)
        canonical_content = canonicalize_json(raw_content)
    except (TypeError, ValueError, ValidationError) as exc:
        raise ConfigurationPipelineError(
            ConfigurationErrorCode.CONFIG_PARSE_FAILED,
            "默认 Mock 配置不符合固定 Schema",
        ) from exc

    content_sha256 = hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()
    return FirewallSnapshot(
        snapshot_id=snapshot_id or f"snp-{uuid4().hex}",
        target_id=validated.target.target_id,
        provider_version=PROVIDER_VERSION,
        collected_at=collected_at or datetime.now(timezone.utc),
        raw_content=canonical_content,
        content_sha256=content_sha256,
    )


class MockConfigProvider:
    async def get_original_config(self) -> str:
        try:
            return DEFAULT_MOCK_ORIGINAL_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_FETCH_FAILED,
                "无法读取内置默认 Mock 原始配置",
            ) from exc

    async def get_current_snapshot(self) -> FirewallSnapshot:
        try:
            cli_content = DEFAULT_MOCK_ORIGINAL_PATH.read_text(encoding="utf-8")
            raw_content = HuaweiCliParser().parse_complete(cli_content)
        except (OSError, TypeError, ValueError) as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_FETCH_FAILED,
                "无法读取或解析内置默认 Mock CLI 配置",
            ) from exc

        if not isinstance(raw_content, dict):
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_PARSE_FAILED,
                "默认 Mock 配置根节点必须是 JSON object",
            )

        return build_snapshot(raw_content)
