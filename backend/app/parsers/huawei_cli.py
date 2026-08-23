from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any


PARSER_VERSION = "huawei-vrp-cli/1.0.0"


def _deep_merge(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def _cidr(address: str, mask: str) -> str:
    return str(ipaddress.ip_network((address, mask), strict=False))


def _neutral_huawei_mock() -> dict[str, Any]:
    return {
        "_mock_metadata": {
            "is_mock": True,
            "contains_real_customer_data": False,
            "source_profile": "Huawei HiSecEngine/USG VRP-style",
            "fixture_version": "cli-derived-1.0.0",
            "notice": "人工构造的公开演示配置；JSON 由确定性 Huawei CLI 解析器生成。",
        },
        "target": {
            "target_id": "default-firewall-mock",
            "display_name": "Default Firewall Mock",
            "vendor": "Huawei",
            "product_family": "HiSecEngine/USG",
            "model": "USG-MOCK",
            "software_version": "VRP-MOCK-1.0",
            "hostname": "UNKNOWN",
        },
        "management": {
            "protocols": {
                "ssh": {"enabled": False, "port": 22},
                "https": {"enabled": False, "port": 443},
                "telnet": {"enabled": False, "port": 23},
                "http": {"enabled": False, "port": 80},
            },
            "source_interface": "",
            "allowed_source_cidrs": [],
            "mfa_enabled": None,
            "accounts": [],
        },
        "interfaces": [],
        "access_control": {"default_action": None, "policies": []},
        "logging": {
            "policy_log_enabled": None,
            "threat_log_enabled": None,
            "audit_log_enabled": None,
            "local_retention_days": None,
            "remote_logging": {"enabled": False, "servers": []},
        },
        "time_sync": {"enabled": None, "servers": []},
        "network_stack": {
            "ipv4_enabled": None,
            "ipv6_enabled": None,
            "ipv4_default_route_configured": None,
            "ipv6_default_route_configured": None,
        },
        "threat_prevention": {
            "ips_enabled": None,
            "antivirus_enabled": None,
            "dos_protection_enabled": None,
        },
        "high_availability": {
            "enabled": None,
            "protocol": None,
            "state": None,
            "configuration_synchronized": None,
        },
        "vpn": {"enabled": None},
    }


class HuaweiCliParser:
    """Parse a controlled Huawei VRP-style export without model inference."""

    version = PARSER_VERSION

    def parse_patch(self, cli_content: str) -> dict[str, Any]:
        patch: dict[str, Any] = {}
        management: dict[str, Any] = {}
        protocols: dict[str, Any] = {}
        logging: dict[str, Any] = {}
        time_sync: dict[str, Any] = {}
        threat: dict[str, Any] = {}
        ha: dict[str, Any] = {}
        network: dict[str, Any] = {}
        vpn: dict[str, Any] = {}
        target: dict[str, Any] = {}
        interfaces: list[dict[str, Any]] = []
        zones: dict[str, str] = {}
        policies: list[dict[str, Any]] = []
        accounts: dict[str, dict[str, Any]] = {}
        allowed_sources: list[str] = []
        remote_servers: list[dict[str, Any]] = []
        ntp_servers: list[str] = []

        section: str | None = None
        current_interface: dict[str, Any] | None = None
        current_zone: str | None = None
        current_policy: dict[str, Any] | None = None
        current_account: str | None = None

        def flush_interface() -> None:
            nonlocal current_interface
            if current_interface is not None:
                interfaces.append(current_interface)
                current_interface = None

        def flush_policy() -> None:
            nonlocal current_policy
            if current_policy is not None:
                policies.append(current_policy)
                current_policy = None

        for raw_line in cli_content.splitlines():
            stripped = raw_line.strip()
            lowered = stripped.lower()
            if not stripped:
                continue
            if lowered.startswith("! mock operational output:"):
                state_match = re.search(r"state=([\w-]+)", lowered)
                sync_match = re.search(r"configuration-synchronized=(true|false)", lowered)
                if state_match:
                    ha["state"] = state_match.group(1)
                if sync_match:
                    ha["configuration_synchronized"] = sync_match.group(1) == "true"
                continue
            if stripped.startswith("!"):
                continue
            if stripped == "#":
                flush_interface()
                flush_policy()
                section = None
                current_zone = None
                continue

            if lowered.startswith("sysname "):
                target["hostname"] = stripped.split(maxsplit=1)[1]
                continue
            if lowered.startswith("interface "):
                flush_interface()
                section = "interface"
                current_interface = {
                    "name": stripped.split(maxsplit=1)[1],
                    "description": "",
                    "zone": "",
                    "ipv4_cidrs": [],
                    "ipv6_cidrs": [],
                    "enabled": True,
                    "management_services": [],
                }
                continue
            if lowered.startswith("firewall zone "):
                flush_interface()
                section = "zone"
                current_zone = stripped.split(maxsplit=2)[2]
                continue
            if lowered == "security-policy":
                flush_interface()
                section = "policy"
                continue
            if lowered == "aaa":
                section = "aaa"
                continue

            if section == "interface" and current_interface is not None:
                if lowered.startswith("description "):
                    current_interface["description"] = stripped.split(maxsplit=1)[1]
                elif lowered.startswith("ip address "):
                    parts = stripped.split()
                    current_interface["ipv4_cidrs"].append(_cidr(parts[2], parts[3]))
                    network["ipv4_enabled"] = True
                elif lowered == "ipv6 enable":
                    network["ipv6_enabled"] = True
                elif lowered.startswith("ipv6 address "):
                    current_interface["ipv6_cidrs"].append(stripped.split(maxsplit=2)[2].lower())
                    network["ipv6_enabled"] = True
                elif lowered == "shutdown":
                    current_interface["enabled"] = False
                elif lowered.startswith("service-manage ") and lowered.endswith(" permit"):
                    current_interface["management_services"].append(stripped.split()[1])
                continue

            if section == "zone" and current_zone and lowered.startswith("add interface "):
                zones[stripped.split(maxsplit=2)[2]] = current_zone
                continue

            if section == "policy":
                if lowered.startswith("rule name "):
                    flush_policy()
                    name = stripped.split(maxsplit=2)[2]
                    current_policy = {
                        "policy_id": name.lower(),
                        "name": name,
                        "source_zones": [],
                        "destination_zones": [],
                        "source_cidrs": [],
                        "destination_cidrs": [],
                        "services": [],
                        "action": "deny",
                        "logging_enabled": False,
                        "enabled": True,
                        "expires_at": None,
                    }
                    continue
                if current_policy is not None:
                    if lowered.startswith("source-zone "):
                        current_policy["source_zones"].append(stripped.split(maxsplit=1)[1])
                    elif lowered.startswith("destination-zone "):
                        current_policy["destination_zones"].append(stripped.split(maxsplit=1)[1])
                    elif lowered.startswith("source-address "):
                        parts = stripped.split()
                        current_policy["source_cidrs"].append(
                            "any" if parts[1].lower() == "any" else _cidr(parts[1], parts[3])
                        )
                    elif lowered.startswith("destination-address "):
                        parts = stripped.split()
                        current_policy["destination_cidrs"].append(
                            "any" if parts[1].lower() == "any" else _cidr(parts[1], parts[3])
                        )
                    elif lowered == "service any":
                        current_policy["services"].append("any")
                    elif lowered.startswith("service protocol "):
                        parts = stripped.split()
                        current_policy["services"].append(f"{parts[2]}/{parts[-1]}")
                    elif lowered.startswith("action "):
                        current_policy["action"] = stripped.split(maxsplit=1)[1].lower()
                    elif lowered == "log enable":
                        current_policy["logging_enabled"] = True
                continue

            if section == "aaa":
                account_match = re.match(r"local-user\s+(\S+)\s+", stripped, re.IGNORECASE)
                if account_match:
                    current_account = account_match.group(1)
                    account = accounts.setdefault(
                        current_account,
                        {
                            "account_id": current_account,
                            "role": "operator",
                            "enabled": True,
                            "mfa_bound": None,
                        },
                    )
                    level_match = re.search(r"\blevel\s+(\d+)", lowered)
                    if level_match:
                        account["role"] = "security_admin" if int(level_match.group(1)) >= 15 else "auditor"
                if lowered == "administrator multi-factor-authentication enable":
                    management["mfa_enabled"] = True
                elif lowered == "undo administrator multi-factor-authentication enable":
                    management["mfa_enabled"] = False
                continue

            if lowered == "stelnet server enable":
                protocols["ssh"] = {"enabled": True}
            elif lowered == "undo stelnet server enable":
                protocols["ssh"] = {"enabled": False}
            elif lowered == "telnet server enable":
                protocols["telnet"] = {"enabled": True}
            elif lowered == "undo telnet server enable":
                protocols["telnet"] = {"enabled": False}
            elif lowered == "http secure-server enable":
                protocols["https"] = {"enabled": True}
            elif lowered == "undo http secure-server enable":
                protocols["https"] = {"enabled": False}
            elif lowered == "http server enable":
                protocols["http"] = {"enabled": True}
            elif lowered == "undo http server enable":
                protocols["http"] = {"enabled": False}
            elif lowered.startswith("ssh server-source -i "):
                management["source_interface"] = stripped.split()[-1]
            elif lowered.startswith("rule ") and " permit source " in lowered:
                parts = stripped.split()
                source_index = [item.lower() for item in parts].index("source")
                address = parts[source_index + 1]
                if address.lower() == "any":
                    allowed_sources.append("any")
                else:
                    wildcard = parts[source_index + 2]
                    netmask = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(wildcard)) ^ 0xFFFFFFFF))
                    allowed_sources.append(_cidr(address, netmask))
            elif lowered == "log type policy enable":
                logging["policy_log_enabled"] = True
            elif lowered == "log type threat enable":
                logging["threat_log_enabled"] = True
            elif lowered == "info-center enable":
                logging["audit_log_enabled"] = True
            elif lowered == "undo info-center enable":
                logging["audit_log_enabled"] = False
            elif lowered.startswith("info-center source "):
                logging["audit_log_enabled"] = True
            elif lowered.startswith("info-center logfile retention-days "):
                logging["local_retention_days"] = int(stripped.split()[-1])
            elif lowered.startswith("info-center loghost "):
                parts = stripped.split()
                server = {
                    "address": parts[2],
                    "port": int(parts[parts.index("port") + 1]),
                    "transport": parts[parts.index("transport") + 1].lower(),
                    "reachable": None,
                }
                remote_servers.append(server)
            elif lowered == "ntp-service enable":
                time_sync["enabled"] = True
            elif lowered == "undo ntp-service enable":
                time_sync["enabled"] = False
            elif lowered.startswith("ntp-service unicast-server "):
                ntp_servers.append(stripped.split()[2])
            elif lowered.startswith("profile type ips "):
                threat["ips_enabled"] = True
            elif lowered.startswith("undo profile type ips "):
                threat["ips_enabled"] = False
            elif lowered.startswith("profile type av "):
                threat["antivirus_enabled"] = True
            elif lowered.startswith("undo profile type av "):
                threat["antivirus_enabled"] = False
            elif lowered == "anti-ddos baseline enable":
                threat["dos_protection_enabled"] = True
            elif lowered == "undo anti-ddos baseline enable":
                threat["dos_protection_enabled"] = False
            elif lowered == "hrp enable":
                ha["enabled"] = True
            elif lowered == "undo hrp enable":
                ha["enabled"] = False
            elif lowered.startswith("hrp protocol "):
                ha["protocol"] = stripped.split(maxsplit=2)[2]
            elif lowered == "ipsec enable":
                vpn["enabled"] = True
            elif lowered == "undo ipsec enable":
                vpn["enabled"] = False
            elif lowered.startswith("ip route-static 0.0.0.0 0.0.0.0 "):
                network["ipv4_default_route_configured"] = True
            elif lowered.startswith("ipv6 route-static :: 0 "):
                network["ipv6_default_route_configured"] = True

        flush_interface()
        flush_policy()
        for interface in interfaces:
            interface["zone"] = zones.get(interface["name"], interface["zone"])
        if policies:
            default_candidates = [
                item for item in policies
                if item["source_zones"] == ["any"] and item["destination_zones"] == ["any"]
            ]
            access: dict[str, Any] = {"policies": policies}
            if default_candidates:
                access["default_action"] = default_candidates[-1]["action"]
            patch["access_control"] = access
        if protocols:
            management["protocols"] = protocols
        if allowed_sources:
            management["allowed_source_cidrs"] = allowed_sources
        if accounts:
            management["accounts"] = list(accounts.values())
        if management:
            patch["management"] = management
        if target:
            patch["target"] = target
        if interfaces:
            patch["interfaces"] = interfaces
        if remote_servers:
            logging["remote_logging"] = {"enabled": True, "servers": remote_servers}
        if logging:
            patch["logging"] = logging
        if ntp_servers:
            time_sync["servers"] = ntp_servers
        if time_sync:
            patch["time_sync"] = time_sync
        if threat:
            patch["threat_prevention"] = threat
        if ha:
            patch["high_availability"] = ha
        if network:
            patch["network_stack"] = network
        if vpn:
            patch["vpn"] = vpn
        if not patch:
            raise ValueError("no supported Huawei VRP configuration was recognized")
        return patch

    def parse_complete(self, cli_content: str) -> dict[str, Any]:
        configuration = _neutral_huawei_mock()
        _deep_merge(configuration, self.parse_patch(cli_content))
        return configuration
