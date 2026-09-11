from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any

from pydantic import ValidationError

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import (
    ConfigurationEvidence,
    ConfigurationParseWarning,
    NormalizedFirewallConfig,
    ObservedConfigurationFact,
    ParsedFirewallConfiguration,
    ParseWarningCode,
    VerificationStatus,
)


PARSER_VERSION = "huawei-vrp-cli/1.0.0"


def _deep_merge(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def _flatten_explicit_values(
    value: Any,
    *,
    prefix: str = "",
) -> tuple[tuple[str, Any], ...]:
    facts: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            field = f"{prefix}.{key}" if prefix else key
            facts.extend(_flatten_explicit_values(child, prefix=field))
    elif prefix:
        # Lists are kept as one semantic fact. Expanding list indexes would expose
        # unstable policy/server identifiers to retrieval planning.
        facts.append((prefix, copy.deepcopy(value)))
    return tuple(facts)


def _cidr(address: str, mask: str) -> str:
    return str(ipaddress.ip_network((address, mask), strict=False))


def _neutral_huawei_mock() -> dict[str, Any]:
    return {
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

    def parse_observed_fields(self, cli_content: str) -> tuple[tuple[str, Any], ...]:
        """Return only values explicitly recognized from the CLI, never defaults."""

        return _flatten_explicit_values(self.parse_patch(cli_content))

    def parse_configuration(
        self,
        cli_content: str,
        *,
        snapshot_id: str,
        target_id: str,
        raw_config_sha256: str,
    ) -> tuple[ParsedFirewallConfiguration, tuple[ObservedConfigurationFact, ...]]:
        """Produce the normalized configuration and evidence directly from Huawei CLI."""

        complete = self.parse_complete(cli_content)
        complete["target"]["target_id"] = target_id
        try:
            normalized = NormalizedFirewallConfig.model_validate(complete)
        except ValidationError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_PARSE_FAILED,
                "Huawei CLI 解析结果不符合规范化配置契约",
            ) from exc

        observed = tuple(
            ObservedConfigurationFact(field=field, value=value)
            for field, value in self.parse_observed_fields(cli_content)
        )
        evidence, warnings, completeness = _build_cli_evidence(
            normalized=normalized,
            observed=observed,
            cli_content=cli_content,
            snapshot_id=snapshot_id,
            raw_config_sha256=raw_config_sha256,
            parser_version=self.version,
        )
        return (
            ParsedFirewallConfiguration(
                parser_version=self.version,
                normalized_config=normalized,
                completeness=completeness,
                warnings=warnings,
                evidence=evidence,
            ),
            observed,
        )


_CLI_LINE_PATTERNS = {
    "target.hostname": r"^\s*sysname\s+",
    "management.protocols.ssh": r"^\s*(?:undo\s+)?stelnet server enable",
    "management.protocols.telnet": r"^\s*(?:undo\s+)?telnet server enable",
    "management.protocols.https": r"^\s*(?:undo\s+)?http secure-server enable",
    "management.protocols.http": r"^\s*(?:undo\s+)?http server enable",
    "management.source_interface": r"^\s*ssh server-source\s+",
    "management.allowed_source_cidrs": r"^\s*rule\s+.+\spermit source\s+",
    "management.mfa_enabled": r"^\s*(?:undo\s+)?administrator multi-factor-authentication enable",
    "management.accounts": r"^\s*local-user\s+",
    "access_control.default_action": r"^\s*action\s+(?:deny|permit)\s*$",
    "access_control.policies": r"^\s*(?:rule name|action|log enable)\b",
    "logging.policy_log_enabled": r"^\s*log type policy enable",
    "logging.threat_log_enabled": r"^\s*log type threat enable",
    "logging.audit_log_enabled": r"^\s*(?:undo\s+)?info-center (?:enable|source)\b",
    "logging.local_retention_days": r"^\s*info-center logfile retention-days\s+",
    "logging.remote_logging": r"^\s*info-center loghost\s+",
    "time_sync.enabled": r"^\s*(?:undo\s+)?ntp-service enable",
    "time_sync.servers": r"^\s*ntp-service unicast-server\s+",
    "threat_prevention.ips_enabled": r"^\s*(?:undo\s+)?profile type ips\s+",
    "threat_prevention.antivirus_enabled": r"^\s*(?:undo\s+)?profile type av\s+",
    "threat_prevention.dos_protection_enabled": r"^\s*(?:undo\s+)?anti-ddos baseline enable",
    "high_availability": r"^\s*(?:(?:undo\s+)?hrp\b|! MOCK operational output:)",
    "network_stack.ipv4": r"^\s*(?:ip address|ip route-static)\s+",
    "network_stack.ipv6": r"^\s*(?:ipv6 enable|ipv6 address|ipv6 route-static)\b",
    "vpn.enabled": r"^\s*(?:undo\s+)?ipsec enable",
    "interfaces": r"^\s*(?:interface|ip address|ipv6 address|service-manage)\b",
}


def _evidence_values(
    value: Any,
    *,
    field: str = "",
    pointer: str = "",
):
    if isinstance(value, dict):
        for key, child in value.items():
            child_field = f"{field}.{key}" if field else key
            escaped = key.replace("~", "~0").replace("/", "~1")
            yield from _evidence_values(
                child,
                field=child_field,
                pointer=f"{pointer}/{escaped}",
            )
        return
    if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
        for index, child in enumerate(value):
            identity = (
                child.get("account_id")
                or child.get("policy_id")
                or child.get("name")
                or str(index)
            )
            yield from _evidence_values(
                child,
                field=f"{field}[{identity}]",
                pointer=f"{pointer}/{index}",
            )
        return
    yield field, pointer, value


def _matching_cli_line(
    field: str,
    lines: list[str],
) -> tuple[int, str] | None:
    candidates = [
        (prefix, pattern)
        for prefix, pattern in _CLI_LINE_PATTERNS.items()
        if field.startswith(prefix)
    ]
    if not candidates:
        return None
    _, pattern = max(candidates, key=lambda item: len(item[0]))
    matches = [
        (index, line)
        for index, line in enumerate(lines, start=1)
        if re.search(pattern, line, flags=re.IGNORECASE)
    ]
    if not matches:
        return None
    return matches[-1] if field == "access_control.default_action" else matches[0]


def _build_cli_evidence(
    *,
    normalized: NormalizedFirewallConfig,
    observed: tuple[ObservedConfigurationFact, ...],
    cli_content: str,
    snapshot_id: str,
    raw_config_sha256: str,
    parser_version: str,
) -> tuple[
    tuple[ConfigurationEvidence, ...],
    tuple[ConfigurationParseWarning, ...],
    float,
]:
    explicit_fields = {item.field for item in observed}
    grouped_fields = {
        "access_control.policies",
        "management.accounts",
        "interfaces",
        "logging.remote_logging.servers",
    }
    lines = cli_content.splitlines()
    evidence: list[ConfigurationEvidence] = []
    warnings: list[ConfigurationParseWarning] = []
    verified = 0
    values = list(_evidence_values(normalized.model_dump(mode="json")))

    for field, pointer, value in values:
        explicit = field in explicit_fields or any(
            group in explicit_fields and field.startswith(f"{group}[")
            for group in grouped_fields
        )
        match = _matching_cli_line(field, lines) if explicit else None
        status = (
            VerificationStatus.CONFIGURATION_VERIFIED
            if value is not None and match is not None
            else VerificationStatus.INSUFFICIENT_EVIDENCE
        )
        if status is VerificationStatus.CONFIGURATION_VERIFIED:
            verified += 1
        elif value is None:
            warnings.append(
                ConfigurationParseWarning(
                    code=ParseWarningCode.NULL_VALUE,
                    field=field,
                    source_pointer=pointer,
                    message="配置字段值未知，需要人工复核",
                )
            )

        binding = {}
        if match is not None:
            line_number, excerpt = match
            binding = {
                "raw_config_excerpt": excerpt.strip(),
                "raw_line_start": line_number,
                "raw_line_end": line_number,
                "raw_config_sha256": raw_config_sha256,
            }
        evidence.append(
            ConfigurationEvidence(
                snapshot_id=snapshot_id,
                field=field,
                value=value,
                source_pointer=pointer,
                parser_version=parser_version,
                verification_status=status,
                **binding,
            )
        )

    completeness = round(verified / len(values), 4) if values else 0.0
    return tuple(evidence), tuple(warnings), completeness
