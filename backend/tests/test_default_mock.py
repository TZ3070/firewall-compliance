import hashlib
import ipaddress
from pathlib import Path
from typing import Any

from app.parsers.huawei_cli import HuaweiCliParser
from app.providers.mock_config import MockConfigProvider


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "mock" / "default-firewall.cfg"
)
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
FORBIDDEN_TOKENS = ("password", "private-key", "secret", "community", "token")


def _walk(value: Any):
    if isinstance(value, dict):
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)
    else:
        yield value


def _parse_ip(value: str):
    candidate = value.split("/", maxsplit=1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def test_default_mock_is_raw_huawei_cli_and_parses_deterministically() -> None:
    content = FIXTURE_PATH.read_text(encoding="utf-8")
    parsed = HuaweiCliParser().parse_complete(content)

    assert content.lstrip().startswith("! MOCK DATA")
    assert "sysname FW-MOCK-01" in content
    assert parsed["target"]["hostname"] == "FW-MOCK-01"
    assert parsed["target"]["vendor"] == "Huawei"
    assert parsed["access_control"]["default_action"] == "deny"
    assert parsed["management"]["protocols"]["telnet"]["enabled"] is False


def test_default_mock_contains_no_credential_material() -> None:
    content = FIXTURE_PATH.read_text(encoding="utf-8").casefold()

    assert all(token not in content for token in FORBIDDEN_TOKENS)


def test_default_mock_uses_only_documentation_ip_ranges() -> None:
    parsed = HuaweiCliParser().parse_complete(FIXTURE_PATH.read_text(encoding="utf-8"))
    addresses = {
        address
        for value in _walk(parsed)
        if isinstance(value, str)
        if (address := _parse_ip(value)) is not None
    }

    assert addresses
    assert all(
        any(address in network for network in DOCUMENTATION_NETWORKS)
        for address in addresses
    )


def test_mock_provider_hashes_the_raw_cli() -> None:
    content = FIXTURE_PATH.read_text(encoding="utf-8")
    assert hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert MockConfigProvider._read_original_config() == content
