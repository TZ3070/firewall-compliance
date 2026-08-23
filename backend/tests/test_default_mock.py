import ipaddress
import json
from pathlib import Path
from typing import Any


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "mock" / "default-firewall.json"
)

DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

FORBIDDEN_KEY_FRAGMENTS = {
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
    "community",
}


def load_fixture() -> dict[str, Any]:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def walk(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for nested_value in value.values():
            values.extend(walk(nested_value))
    elif isinstance(value, list):
        for nested_value in value:
            values.extend(walk(nested_value))
    return values


def walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, nested_value in value.items():
            keys.append(key)
            keys.extend(walk_keys(nested_value))
    elif isinstance(value, list):
        for nested_value in value:
            keys.extend(walk_keys(nested_value))
    return keys


def parse_ip_value(
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = value.split("/", maxsplit=1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def resolve_pointer(document: Any, pointer: str) -> Any:
    current = document
    for raw_token in pointer.lstrip("/").split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current


def test_default_mock_is_pure_configuration_fixture() -> None:
    fixture = load_fixture()

    assert fixture["_mock_metadata"]["is_mock"] is True
    assert fixture["_mock_metadata"]["contains_real_customer_data"] is False
    assert fixture["target"]["target_id"] == "default-firewall-mock"
    assert "snapshot_id" not in fixture
    assert "content_sha256" not in fixture
    assert "mock_findings" not in fixture


def test_default_mock_contains_no_credential_fields() -> None:
    keys = {key.lower() for key in walk_keys(load_fixture())}

    for key in keys:
        assert not any(fragment in key for fragment in FORBIDDEN_KEY_FRAGMENTS)


def test_default_mock_uses_only_documentation_ip_ranges() -> None:
    fixture = load_fixture()
    ip_values = {
        parsed
        for value in walk(fixture)
        if isinstance(value, str)
        if (parsed := parse_ip_value(value)) is not None
    }

    assert ip_values
    for address in ip_values:
        assert any(address in network for network in DOCUMENTATION_NETWORKS)


def test_default_mock_has_stable_future_evidence_pointers() -> None:
    fixture = load_fixture()

    assert resolve_pointer(fixture, "/management/protocols/telnet/enabled") is False
    assert resolve_pointer(fixture, "/access_control/default_action") == "deny"
    assert resolve_pointer(fixture, "/threat_prevention/dos_protection_enabled") is None
