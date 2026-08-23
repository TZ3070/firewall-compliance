import json
from typing import Any

from pydantic import ValidationError

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import (
    ConfigurationEvidence,
    ConfigurationParseWarning,
    DefaultFirewallConfig,
    FirewallSnapshot,
    NormalizedFirewallConfig,
    ParsedFirewallConfiguration,
    ParseWarningCode,
    VerificationStatus,
)


PARSER_VERSION = "mock-json-parser/1.0.0"
_MISSING = object()


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document

    current = document
    for raw_token in pointer.lstrip("/").split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise KeyError(pointer)
    return current


def _get_pointer_or_missing(document: Any, pointer: str) -> Any:
    try:
        return resolve_json_pointer(document, pointer)
    except (IndexError, KeyError, TypeError, ValueError):
        return _MISSING


class FirewallConfigParser:
    def parse(self, snapshot: FirewallSnapshot) -> ParsedFirewallConfiguration:
        try:
            raw_content = json.loads(snapshot.raw_content)
            validated = DefaultFirewallConfig.model_validate(raw_content)
        except (json.JSONDecodeError, TypeError, ValidationError) as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.CONFIG_PARSE_FAILED,
                "Snapshot 中的 Mock 配置无法解析",
            ) from exc

        normalized = NormalizedFirewallConfig(
            target=validated.target,
            management=validated.management,
            interfaces=validated.interfaces,
            access_control=validated.access_control,
            logging=validated.logging,
            time_sync=validated.time_sync,
            network_stack=validated.network_stack,
            threat_prevention=validated.threat_prevention,
            high_availability=validated.high_availability,
            vpn=validated.vpn,
        )

        evidence: list[ConfigurationEvidence] = []
        warnings: list[ConfigurationParseWarning] = []
        expected_evidence_count = 0
        verified_evidence_count = 0

        def record(
            field: str,
            pointer: str,
            *,
            null_is_verified: bool = False,
        ) -> None:
            nonlocal expected_evidence_count, verified_evidence_count
            expected_evidence_count += 1
            value = _get_pointer_or_missing(raw_content, pointer)

            if value is _MISSING:
                warnings.append(
                    ConfigurationParseWarning(
                        code=ParseWarningCode.MISSING_FIELD,
                        field=field,
                        source_pointer=pointer,
                        message="配置字段缺失，不能生成已验证证据",
                    )
                )
                return

            if value is None and not null_is_verified:
                warnings.append(
                    ConfigurationParseWarning(
                        code=ParseWarningCode.NULL_VALUE,
                        field=field,
                        source_pointer=pointer,
                        message="配置字段值未知，需要人工复核",
                    )
                )
                evidence.append(
                    ConfigurationEvidence(
                        snapshot_id=snapshot.snapshot_id,
                        field=field,
                        value=None,
                        source_pointer=pointer,
                        parser_version=PARSER_VERSION,
                        verification_status=VerificationStatus.INSUFFICIENT_EVIDENCE,
                    )
                )
                return

            verified_evidence_count += 1
            evidence.append(
                ConfigurationEvidence(
                    snapshot_id=snapshot.snapshot_id,
                    field=field,
                    value=value,
                    source_pointer=pointer,
                    parser_version=PARSER_VERSION,
                    verification_status=VerificationStatus.CONFIGURATION_VERIFIED,
                )
            )

        record("target.vendor", "/target/vendor")
        record("target.product_family", "/target/product_family")
        record("target.model", "/target/model")
        record("target.software_version", "/target/software_version")
        record("target.hostname", "/target/hostname")

        for protocol_name in ("ssh", "https", "telnet", "http"):
            record(
                f"management.protocols.{protocol_name}.enabled",
                f"/management/protocols/{protocol_name}/enabled",
            )
            record(
                f"management.protocols.{protocol_name}.port",
                f"/management/protocols/{protocol_name}/port",
            )

        record("management.source_interface", "/management/source_interface")
        record(
            "management.allowed_source_cidrs",
            "/management/allowed_source_cidrs",
        )
        record("management.mfa_enabled", "/management/mfa_enabled")

        for index, account in enumerate(validated.management.accounts):
            field_prefix = f"management.accounts[{account.account_id}]"
            pointer_prefix = f"/management/accounts/{index}"
            record(f"{field_prefix}.role", f"{pointer_prefix}/role")
            record(f"{field_prefix}.enabled", f"{pointer_prefix}/enabled")
            record(f"{field_prefix}.mfa_bound", f"{pointer_prefix}/mfa_bound")

        for index, interface in enumerate(validated.interfaces):
            field_prefix = f"interfaces[{interface.name}]"
            pointer_prefix = f"/interfaces/{index}"
            record(f"{field_prefix}.zone", f"{pointer_prefix}/zone")
            record(f"{field_prefix}.ipv4_cidrs", f"{pointer_prefix}/ipv4_cidrs")
            record(f"{field_prefix}.ipv6_cidrs", f"{pointer_prefix}/ipv6_cidrs")
            record(f"{field_prefix}.enabled", f"{pointer_prefix}/enabled")
            record(
                f"{field_prefix}.management_services",
                f"{pointer_prefix}/management_services",
            )

        record("access_control.default_action", "/access_control/default_action")
        for index, policy in enumerate(validated.access_control.policies):
            field_prefix = f"access_control.policies[{policy.policy_id}]"
            pointer_prefix = f"/access_control/policies/{index}"
            for field_name in (
                "source_zones",
                "destination_zones",
                "source_cidrs",
                "destination_cidrs",
                "services",
                "action",
                "logging_enabled",
                "enabled",
            ):
                record(
                    f"{field_prefix}.{field_name}",
                    f"{pointer_prefix}/{field_name}",
                )
            record(
                f"{field_prefix}.expires_at",
                f"{pointer_prefix}/expires_at",
                null_is_verified=True,
            )

        for field_name in (
            "policy_log_enabled",
            "threat_log_enabled",
            "audit_log_enabled",
            "local_retention_days",
        ):
            record(f"logging.{field_name}", f"/logging/{field_name}")
        record("logging.remote_logging.enabled", "/logging/remote_logging/enabled")
        for index, _server in enumerate(validated.logging.remote_logging.servers):
            field_prefix = f"logging.remote_logging.servers[{index}]"
            pointer_prefix = f"/logging/remote_logging/servers/{index}"
            for field_name in ("address", "port", "transport", "reachable"):
                record(
                    f"{field_prefix}.{field_name}",
                    f"{pointer_prefix}/{field_name}",
                )

        record("time_sync.enabled", "/time_sync/enabled")
        record("time_sync.servers", "/time_sync/servers")

        for field_name in (
            "ipv4_enabled",
            "ipv6_enabled",
            "ipv4_default_route_configured",
            "ipv6_default_route_configured",
        ):
            record(f"network_stack.{field_name}", f"/network_stack/{field_name}")

        for field_name in (
            "ips_enabled",
            "antivirus_enabled",
            "dos_protection_enabled",
        ):
            record(
                f"threat_prevention.{field_name}",
                f"/threat_prevention/{field_name}",
            )

        for field_name in (
            "enabled",
            "protocol",
            "state",
            "configuration_synchronized",
        ):
            record(
                f"high_availability.{field_name}",
                f"/high_availability/{field_name}",
            )

        record("vpn.enabled", "/vpn/enabled")

        completeness = (
            verified_evidence_count / expected_evidence_count
            if expected_evidence_count
            else 0.0
        )
        return ParsedFirewallConfiguration(
            parser_version=PARSER_VERSION,
            normalized_config=normalized,
            completeness=round(completeness, 4),
            warnings=tuple(warnings),
            evidence=tuple(evidence),
        )
