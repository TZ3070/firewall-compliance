from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FindingResult(StrEnum):
    PASSED = "Passed"
    FAILED = "Failed"
    NEEDS_REVIEW = "NeedsReview"
    NOT_APPLICABLE = "NotApplicable"


class VerificationStatus(StrEnum):
    CONFIGURATION_VERIFIED = "ConfigurationVerified"
    USER_CONFIRMED = "UserConfirmed"
    MODEL_INFERRED = "ModelInferred"
    INSUFFICIENT_EVIDENCE = "InsufficientEvidence"


class AssessmentStatus(StrEnum):
    COMPLETED = "Completed"
    INCOMPLETE = "Incomplete"
    FAILED = "Failed"


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str


class FirewallSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_id: str
    target_id: str
    source_type: Literal["mock"] = "mock"
    provider_version: str
    collected_at: datetime
    raw_content: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ConfigurationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_id: str
    field: str
    value: Any
    source_pointer: str
    parser_version: str
    verification_status: VerificationStatus
    raw_config_excerpt: str | None = None
    raw_line_start: int | None = Field(default=None, ge=1)
    raw_line_end: int | None = Field(default=None, ge=1)
    raw_config_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_raw_binding(self) -> "ConfigurationEvidence":
        binding = (
            self.raw_config_excerpt,
            self.raw_line_start,
            self.raw_line_end,
            self.raw_config_sha256,
        )
        if all(value is None for value in binding):
            return self
        if any(value is None for value in binding):
            raise ValueError("raw configuration binding must be complete")
        if self.raw_line_end < self.raw_line_start:  # type: ignore[operator]
            raise ValueError("raw configuration line range is invalid")
        return self


class FrozenConfigModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        populate_by_name=True,
    )


class ObservedConfigurationFact(FrozenConfigModel):
    """A value explicitly present in the vendor CLI, excluding schema defaults."""

    field: str = Field(min_length=1, max_length=256)
    value: Any
    source: Literal["vendor_cli_explicit"] = "vendor_cli_explicit"


class MockMetadata(FrozenConfigModel):
    is_mock: Literal[True]
    contains_real_customer_data: Literal[False]
    source_profile: str
    fixture_version: str
    notice: str


class TargetConfig(FrozenConfigModel):
    target_id: str
    display_name: str
    vendor: str
    product_family: str
    model: str
    software_version: str
    hostname: str


class ManagementProtocolConfig(FrozenConfigModel):
    enabled: bool
    port: int = Field(ge=1, le=65535)


class ManagementProtocols(FrozenConfigModel):
    ssh: ManagementProtocolConfig
    https: ManagementProtocolConfig
    telnet: ManagementProtocolConfig
    http: ManagementProtocolConfig


class AdministratorAccount(FrozenConfigModel):
    account_id: str
    role: str
    enabled: bool
    mfa_bound: bool | None = None


class ManagementConfig(FrozenConfigModel):
    protocols: ManagementProtocols
    source_interface: str
    allowed_source_cidrs: tuple[str, ...]
    mfa_enabled: bool | None = None
    accounts: tuple[AdministratorAccount, ...]


class InterfaceConfig(FrozenConfigModel):
    name: str
    description: str
    zone: str
    ipv4_cidrs: tuple[str, ...]
    ipv6_cidrs: tuple[str, ...]
    enabled: bool
    management_services: tuple[str, ...]


class AccessPolicyConfig(FrozenConfigModel):
    policy_id: str
    name: str
    source_zones: tuple[str, ...]
    destination_zones: tuple[str, ...]
    source_cidrs: tuple[str, ...]
    destination_cidrs: tuple[str, ...]
    services: tuple[str, ...]
    action: Literal["permit", "deny"]
    logging_enabled: bool
    enabled: bool
    expires_at: str | None = None


class AccessControlConfig(FrozenConfigModel):
    default_action: Literal["permit", "deny"] | None = None
    policies: tuple[AccessPolicyConfig, ...]


class RemoteLogServerConfig(FrozenConfigModel):
    address: str
    port: int = Field(ge=1, le=65535)
    transport: Literal["tls", "tcp", "udp"]
    reachable: bool | None = None


class RemoteLoggingConfig(FrozenConfigModel):
    enabled: bool
    servers: tuple[RemoteLogServerConfig, ...]


class LoggingConfig(FrozenConfigModel):
    policy_log_enabled: bool | None = None
    threat_log_enabled: bool | None = None
    audit_log_enabled: bool | None = None
    local_retention_days: int | None = Field(default=None, ge=0)
    remote_logging: RemoteLoggingConfig


class TimeSyncConfig(FrozenConfigModel):
    enabled: bool | None = None
    servers: tuple[str, ...]


class NetworkStackConfig(FrozenConfigModel):
    ipv4_enabled: bool | None = None
    ipv6_enabled: bool | None = None
    ipv4_default_route_configured: bool | None = None
    ipv6_default_route_configured: bool | None = None


class ThreatPreventionConfig(FrozenConfigModel):
    ips_enabled: bool | None = None
    antivirus_enabled: bool | None = None
    dos_protection_enabled: bool | None = None


class HighAvailabilityConfig(FrozenConfigModel):
    enabled: bool | None = None
    protocol: str | None = None
    state: str | None = None
    configuration_synchronized: bool | None = None


class VpnConfig(FrozenConfigModel):
    enabled: bool | None = None


class DefaultFirewallConfig(FrozenConfigModel):
    mock_metadata: MockMetadata = Field(alias="_mock_metadata")
    target: TargetConfig
    management: ManagementConfig
    interfaces: tuple[InterfaceConfig, ...]
    access_control: AccessControlConfig
    logging: LoggingConfig
    time_sync: TimeSyncConfig
    network_stack: NetworkStackConfig
    threat_prevention: ThreatPreventionConfig
    high_availability: HighAvailabilityConfig
    vpn: VpnConfig


class NormalizedFirewallConfig(FrozenConfigModel):
    target: TargetConfig
    management: ManagementConfig
    interfaces: tuple[InterfaceConfig, ...]
    access_control: AccessControlConfig
    logging: LoggingConfig
    time_sync: TimeSyncConfig
    network_stack: NetworkStackConfig
    threat_prevention: ThreatPreventionConfig
    high_availability: HighAvailabilityConfig
    vpn: VpnConfig


class HuaweiCliParseRequest(FrozenConfigModel):
    vendor: Literal["Huawei"] = "Huawei"
    cli_content: str = Field(min_length=1, max_length=100_000)


class HuaweiCliParseResponse(FrozenConfigModel):
    vendor: Literal["Huawei"] = "Huawei"
    parser_version: str
    structured_patch: dict[str, Any]


class ParseWarningCode(StrEnum):
    MISSING_FIELD = "MISSING_FIELD"
    NULL_VALUE = "NULL_VALUE"


class ConfigurationParseWarning(FrozenConfigModel):
    code: ParseWarningCode
    field: str
    source_pointer: str
    message: str


class ParsedFirewallConfiguration(FrozenConfigModel):
    parser_version: str
    normalized_config: NormalizedFirewallConfig
    completeness: float = Field(ge=0.0, le=1.0)
    warnings: tuple[ConfigurationParseWarning, ...]
    evidence: tuple[ConfigurationEvidence, ...]


class StoredSnapshot(FrozenConfigModel):
    snapshot: FirewallSnapshot
    parsed_configuration: ParsedFirewallConfiguration
    persisted_at: datetime


class CurrentConfigResponse(FrozenConfigModel):
    snapshot_id: str
    target_id: str
    source_type: Literal["mock"]
    provider_version: str
    parser_version: str
    collected_at: datetime
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_config_format: Literal["vendor_cli_mock"] = "vendor_cli_mock"
    original_config_content: str
    original_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completeness: float = Field(ge=0.0, le=1.0)
    warnings: tuple[ConfigurationParseWarning, ...]
    configuration: NormalizedFirewallConfig
    evidence: tuple[ConfigurationEvidence, ...]
    observed_facts: tuple[ObservedConfigurationFact, ...] = ()


class AssessmentClauseReference(FrozenConfigModel):
    record_id: str | None = None
    standard_code: str
    clause_id: str
    classified_protection_level: int = Field(ge=2, le=4)
    printed_pages: tuple[int, ...] = ()
    pdf_page_indexes: tuple[int, ...] = ()


class LevelAssessmentFinding(FrozenConfigModel):
    finding_id: str
    classified_protection_level: int = Field(ge=2, le=4)
    control_id: str
    control_title: str
    check_title: str
    rule_id: str
    result: FindingResult
    severity: str
    explanation: str
    standard_references: tuple[AssessmentClauseReference, ...] = ()
    configuration_evidence: tuple[ConfigurationEvidence, ...] = ()
    limitations: tuple[str, ...] = ()
    control_coverage: Literal["full", "partial"]
    control_conclusion_allowed: Literal[False] = False


class LevelAssessmentSummary(FrozenConfigModel):
    classified_protection_level: int = Field(ge=2, le=4)
    counts: dict[FindingResult, int]
    findings: tuple[LevelAssessmentFinding, ...]


class CurrentAssessmentResponse(FrozenConfigModel):
    assessment_id: str
    snapshot_id: str
    target_id: str
    status: AssessmentStatus
    rule_pack_version: str
    catalog_id: str
    catalog_version: str
    levels: tuple[LevelAssessmentSummary, ...]
    disclaimer: str
