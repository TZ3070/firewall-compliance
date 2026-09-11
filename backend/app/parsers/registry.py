from __future__ import annotations

import re
from typing import Protocol

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import RawConfigurationSnapshot, VendorDetectionResult
from app.parsers.huawei_cli import HuaweiCliParser


class VendorParser(Protocol):
    version: str

    def parse_configuration(
        self,
        cli_content: str,
        *,
        snapshot_id: str,
        target_id: str,
        raw_config_sha256: str,
    ): ...


class VendorDetector:
    """Deterministic multi-signature detector; model inference is not evidence."""

    _HUAWEI_SIGNATURES = (
        ("sysname", re.compile(r"(?im)^\s*sysname\s+\S+")),
        ("stelnet", re.compile(r"(?im)^\s*(?:undo\s+)?stelnet server enable")),
        ("telnet", re.compile(r"(?im)^\s*(?:undo\s+)?telnet server enable")),
        ("firewall-zone", re.compile(r"(?im)^\s*firewall zone\s+\S+")),
        ("security-policy", re.compile(r"(?im)^\s*security-policy\s*$")),
        ("hrp", re.compile(r"(?im)^\s*(?:undo\s+)?hrp enable\s*$")),
        ("info-center", re.compile(r"(?im)^\s*(?:undo\s+)?info-center\b")),
    )

    def detect(self, raw: RawConfigurationSnapshot) -> VendorDetectionResult:
        matched = tuple(
            name
            for name, pattern in self._HUAWEI_SIGNATURES
            if pattern.search(raw.content)
        )
        hint_is_huawei = (raw.vendor_hint or "").casefold() == "huawei"
        if len(matched) >= 2 or (hint_is_huawei and matched):
            signature_score = min(len(matched) / 4, 1.0)
            confidence = min(signature_score + (0.15 if hint_is_huawei else 0.0), 1.0)
            return VendorDetectionResult(
                vendor="Huawei",
                confidence=round(confidence, 4),
                matched_signatures=matched,
                used_vendor_hint=hint_is_huawei,
            )
        raise ConfigurationPipelineError(
            ConfigurationErrorCode.UNSUPPORTED_VENDOR,
            "无法从配置特征识别受支持的防火墙厂商；当前仅支持 Huawei。",
        )


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: dict[str, VendorParser] = {
            "huawei": HuaweiCliParser(),
        }

    @property
    def supported_vendors(self) -> tuple[str, ...]:
        return tuple(sorted(self._parsers))

    def resolve(self, vendor: str) -> VendorParser:
        parser = self._parsers.get(vendor.casefold())
        if parser is None:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.PARSER_NOT_FOUND,
                f"未找到厂商 {vendor} 对应的配置 Parser。",
            )
        return parser
