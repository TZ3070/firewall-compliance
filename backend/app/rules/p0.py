from __future__ import annotations

import json
from hashlib import sha256
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from app.models.contracts import (
    AssessmentClauseReference,
    ConfigurationEvidence,
    CurrentAssessmentResponse,
    CurrentConfigResponse,
    FindingResult,
    LevelAssessmentFinding,
    LevelAssessmentSummary,
    NormalizedFirewallConfig,
)


RULE_PACK_VERSION = "p0-current-config/1.0.0"
CATALOG_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "catalog"
    / "jr-t-0071-2-2020-firewall-candidates.json"
)
RULE_PACK_SHA256 = sha256(Path(__file__).read_bytes()).hexdigest()


@dataclass(frozen=True)
class RuleEvaluation:
    result: FindingResult
    explanation: str
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class P0Rule:
    rule_id: str
    control_id: str
    severity: str
    evidence_selectors: tuple[str, ...]
    evaluator: Callable[[NormalizedFirewallConfig], RuleEvaluation]
    check_title: str
    control_coverage: Literal["full", "partial"] = "partial"


def _boolean_evaluation(
    value: bool | None,
    *,
    passed: str,
    failed: str,
) -> RuleEvaluation:
    if value is None:
        return RuleEvaluation(
            FindingResult.NEEDS_REVIEW,
            "当前配置字段为空，无法形成确定性结论。",
        )
    return RuleEvaluation(
        FindingResult.PASSED if value else FindingResult.FAILED,
        passed if value else failed,
    )


def _default_deny(config: NormalizedFirewallConfig) -> RuleEvaluation:
    value = config.access_control.default_action
    if value is None:
        return RuleEvaluation(
            FindingResult.NEEDS_REVIEW,
            "当前配置未提供访问控制默认动作。",
        )
    if value == "deny":
        return RuleEvaluation(FindingResult.PASSED, "访问控制默认动作为 deny。")
    return RuleEvaluation(FindingResult.FAILED, "访问控制默认动作不是 deny。")


def _plaintext_management_disabled(
    config: NormalizedFirewallConfig,
) -> RuleEvaluation:
    telnet = config.management.protocols.telnet.enabled
    http = config.management.protocols.http.enabled
    secure_enabled = (
        config.management.protocols.ssh.enabled
        or config.management.protocols.https.enabled
    )
    if telnet or http:
        return RuleEvaluation(
            FindingResult.FAILED,
            "Telnet 或 HTTP 明文管理协议仍处于启用状态。",
        )
    if not secure_enabled:
        return RuleEvaluation(
            FindingResult.FAILED,
            "明文管理协议已关闭，但 SSH 和 HTTPS 均未启用。",
        )
    return RuleEvaluation(
        FindingResult.PASSED,
        "Telnet 和 HTTP 已关闭，且至少启用 SSH 或 HTTPS。",
    )


def _management_source_restricted(
    config: NormalizedFirewallConfig,
) -> RuleEvaluation:
    cidrs = config.management.allowed_source_cidrs
    unrestricted = {"any", "0.0.0.0/0", "::/0"}
    if not config.management.source_interface or not cidrs:
        return RuleEvaluation(
            FindingResult.FAILED,
            "未配置管理来源接口或允许的管理来源地址范围。",
        )
    if any(item.lower() in unrestricted for item in cidrs):
        return RuleEvaluation(
            FindingResult.FAILED,
            "管理来源范围包含不受限制的地址。",
        )
    return RuleEvaluation(
        FindingResult.PASSED,
        "管理接口和管理来源地址范围均已限制。",
    )


def _mfa_enabled(config: NormalizedFirewallConfig) -> RuleEvaluation:
    return _boolean_evaluation(
        config.management.mfa_enabled,
        passed="管理用户 MFA 已启用。",
        failed="管理用户 MFA 未启用。",
    )


def _audit_logging_enabled(config: NormalizedFirewallConfig) -> RuleEvaluation:
    return _boolean_evaluation(
        config.logging.audit_log_enabled,
        passed="设备审计日志已启用。",
        failed="设备审计日志未启用。",
    )


def _retention_six_months(config: NormalizedFirewallConfig) -> RuleEvaluation:
    days = config.logging.local_retention_days
    if days is None:
        return RuleEvaluation(
            FindingResult.NEEDS_REVIEW,
            "当前配置未提供本地日志留存天数。",
        )
    if days >= 180:
        return RuleEvaluation(
            FindingResult.PASSED,
            f"本地日志留存 {days} 天，达到不少于 180 天的规则阈值。",
        )
    if config.logging.remote_logging.enabled:
        return RuleEvaluation(
            FindingResult.NEEDS_REVIEW,
            f"本地日志仅留存 {days} 天；远程日志已启用，但当前配置未提供远端留存期限。",
            ("需要远程日志平台的留存策略或查询证据。",),
        )
    return RuleEvaluation(
        FindingResult.FAILED,
        f"本地日志仅留存 {days} 天，且未启用远程日志，未达到 180 天。",
    )


def _remote_logging(config: NormalizedFirewallConfig) -> RuleEvaluation:
    remote = config.logging.remote_logging
    if not remote.enabled:
        return RuleEvaluation(FindingResult.FAILED, "远程日志发送未启用。")
    if not remote.servers:
        return RuleEvaluation(
            FindingResult.FAILED,
            "远程日志已启用，但未配置日志服务器。",
        )
    if any(server.reachable is True for server in remote.servers):
        unknown_count = sum(server.reachable is None for server in remote.servers)
        limitations = (
            (f"另有 {unknown_count} 台日志服务器连通性未知。",)
            if unknown_count
            else ()
        )
        return RuleEvaluation(
            FindingResult.PASSED,
            "远程日志已启用，且至少一台日志服务器连通。",
            limitations,
        )
    if any(server.reachable is None for server in remote.servers):
        return RuleEvaluation(
            FindingResult.NEEDS_REVIEW,
            "远程日志已启用，但没有已验证连通的日志服务器。",
        )
    return RuleEvaluation(
        FindingResult.FAILED,
        "已配置的远程日志服务器均不可达。",
    )


def _time_sync(config: NormalizedFirewallConfig) -> RuleEvaluation:
    if config.time_sync.enabled is None:
        return RuleEvaluation(
            FindingResult.NEEDS_REVIEW,
            "当前配置未提供时间同步启用状态。",
        )
    if not config.time_sync.enabled:
        return RuleEvaluation(FindingResult.FAILED, "时间同步未启用。")
    if not config.time_sync.servers:
        return RuleEvaluation(
            FindingResult.FAILED,
            "时间同步已启用，但未配置时间服务器。",
        )
    return RuleEvaluation(
        FindingResult.PASSED,
        "时间同步已启用并配置了时间服务器。",
    )


def _ips_enabled(config: NormalizedFirewallConfig) -> RuleEvaluation:
    return _boolean_evaluation(
        config.threat_prevention.ips_enabled,
        passed="IPS 功能已启用。",
        failed="IPS 功能未启用。",
    )


def _antivirus_enabled(config: NormalizedFirewallConfig) -> RuleEvaluation:
    return _boolean_evaluation(
        config.threat_prevention.antivirus_enabled,
        passed="恶意代码防护功能已启用。",
        failed="恶意代码防护功能未启用。",
    )


def _high_availability(config: NormalizedFirewallConfig) -> RuleEvaluation:
    ha = config.high_availability
    if ha.enabled is None or ha.configuration_synchronized is None or ha.state is None:
        return RuleEvaluation(
            FindingResult.NEEDS_REVIEW,
            "高可用启用状态、运行状态或配置同步状态存在缺失。",
        )
    if not ha.enabled:
        return RuleEvaluation(FindingResult.FAILED, "高可用未启用。")
    healthy_states = {"active", "standby", "healthy", "normal", "ready"}
    if ha.state.lower() not in healthy_states or not ha.configuration_synchronized:
        return RuleEvaluation(
            FindingResult.FAILED,
            f"高可用状态为 {ha.state}，配置同步状态为 {ha.configuration_synchronized}。",
        )
    return RuleEvaluation(
        FindingResult.PASSED,
        "高可用已启用、运行状态正常且配置已同步。",
    )


def _configuration_backup_unavailable(
    _config: NormalizedFirewallConfig,
) -> RuleEvaluation:
    return RuleEvaluation(
        FindingResult.NEEDS_REVIEW,
        "当前配置快照没有配置备份时间、周期和备份成功状态字段。",
        ("需要备份记录或配置管理平台证据。",),
    )


P0_RULES = (
    P0Rule(
        "P0-DEFAULT-DENY",
        "JR0071-2-FW-007",
        "critical",
        ("access_control.default_action",),
        _default_deny,
        "访问控制默认拒绝",
        "full",
    ),
    P0Rule(
        "P0-SECURE-MANAGEMENT-PROTOCOLS",
        "JR0071-2-FW-032",
        "high",
        ("management.protocols.*",),
        _plaintext_management_disabled,
        "禁用明文管理协议",
    ),
    P0Rule(
        "P0-MANAGEMENT-SOURCE",
        "JR0071-2-FW-031",
        "high",
        ("management.source_interface", "management.allowed_source_cidrs"),
        _management_source_restricted,
        "限制管理接口和来源地址",
        "full",
    ),
    P0Rule(
        "P0-MANAGEMENT-MFA",
        "JR0071-2-FW-027",
        "high",
        ("management.mfa_enabled", "management.accounts*"),
        _mfa_enabled,
        "管理用户多因素认证",
        "full",
    ),
    P0Rule(
        "P0-AUDIT-LOGGING",
        "JR0071-2-FW-036",
        "high",
        ("logging.audit_log_enabled",),
        _audit_logging_enabled,
        "启用设备审计日志",
    ),
    P0Rule(
        "P0-LOG-RETENTION",
        "JR0071-2-FW-037",
        "medium",
        ("logging.local_retention_days", "logging.remote_logging.enabled"),
        _retention_six_months,
        "验证日志六个月留存",
    ),
    P0Rule(
        "P0-REMOTE-LOGGING",
        "JR0071-2-FW-047",
        "medium",
        ("logging.remote_logging.*",),
        _remote_logging,
        "远程集中日志发送",
    ),
    P0Rule(
        "P0-TIME-SYNC",
        "JR0071-2-FW-023",
        "medium",
        ("time_sync.*",),
        _time_sync,
        "启用统一时间同步",
        "full",
    ),
    P0Rule(
        "P0-IPS",
        "JR0071-2-FW-014",
        "high",
        ("threat_prevention.ips_enabled",),
        _ips_enabled,
        "启用 IPS 功能",
    ),
    P0Rule(
        "P0-ANTIVIRUS",
        "JR0071-2-FW-017",
        "high",
        ("threat_prevention.antivirus_enabled",),
        _antivirus_enabled,
        "启用恶意代码防护",
    ),
    P0Rule(
        "P0-HIGH-AVAILABILITY",
        "JR0071-2-FW-002",
        "high",
        ("high_availability.*",),
        _high_availability,
        "高可用运行和配置同步",
    ),
    P0Rule(
        "P0-CONFIGURATION-BACKUP",
        "JR0071-2-FW-038",
        "medium",
        (),
        _configuration_backup_unavailable,
        "配置备份记录完整性",
        "full",
    ),
)


class P0CurrentConfigRuleEngine:
    def __init__(self, catalog_path: Path = CATALOG_PATH) -> None:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
        candidates = [
            *payload["control_candidates"],
            *payload["conditional_extension_candidates"],
        ]
        self._catalog_id = payload["catalog_id"]
        self._catalog_version = payload["catalog_version"]
        self._controls = {item["control_id"]: item for item in candidates}
        missing = {rule.control_id for rule in P0_RULES} - set(self._controls)
        if missing:
            raise ValueError(f"P0 规则引用不存在的控制项：{sorted(missing)}")

        self._catalog_sha256 = sha256(catalog_path.read_bytes()).hexdigest()

    @property
    def catalog_sha256(self) -> str:
        return self._catalog_sha256

    @staticmethod
    def _matches_selector(field: str, selector: str) -> bool:
        return (
            field.startswith(selector[:-1])
            if selector.endswith("*")
            else field == selector
        )

    def _select_evidence(
        self,
        evidence: tuple[ConfigurationEvidence, ...],
        selectors: tuple[str, ...],
    ) -> tuple[ConfigurationEvidence, ...]:
        return tuple(
            item
            for item in evidence
            if any(
                self._matches_selector(item.field, selector)
                for selector in selectors
            )
        )

    @staticmethod
    def _references_for_level(
        control: dict[str, object], level: int
    ) -> tuple[AssessmentClauseReference, ...]:
        refs = []
        for source_ref in control["source_refs"]:  # type: ignore[index]
            if source_ref["level"] != level:
                continue
            refs.append(
                AssessmentClauseReference(
                    record_id=str(control["control_id"]),
                    standard_code="JR/T 0071.2—2020",
                    clause_id=source_ref["clause_id"],
                    classified_protection_level=level,
                    printed_pages=tuple(source_ref["printed_pages"]),
                    pdf_page_indexes=tuple(source_ref["pdf_page_indexes"]),
                )
            )
        return tuple(refs)

    def evaluate(self, current: CurrentConfigResponse) -> CurrentAssessmentResponse:
        level_summaries: list[LevelAssessmentSummary] = []
        for level in (2, 3, 4):
            findings: list[LevelAssessmentFinding] = []
            for rule in P0_RULES:
                control = self._controls[rule.control_id]
                references = self._references_for_level(control, level)
                evidence = self._select_evidence(
                    current.evidence, rule.evidence_selectors
                )
                if not references:
                    evaluation = RuleEvaluation(
                        FindingResult.NOT_APPLICABLE,
                        f"该控制项未在 JR/T 0071.2—2020 第 {level} 级中出现。",
                    )
                    evidence = ()
                else:
                    evaluation = rule.evaluator(current.configuration)
                findings.append(
                    LevelAssessmentFinding(
                        finding_id=(
                            f"{current.snapshot_id}:{rule.control_id}:L{level}"
                        ),
                        classified_protection_level=level,
                        control_id=rule.control_id,
                        control_title=str(control["title"]),
                        check_title=rule.check_title,
                        rule_id=rule.rule_id,
                        result=evaluation.result,
                        severity=rule.severity,
                        explanation=evaluation.explanation,
                        standard_references=references,
                        configuration_evidence=evidence,
                        limitations=evaluation.limitations,
                        control_coverage=rule.control_coverage,
                    )
                )
            counts = Counter(item.result for item in findings)
            level_summaries.append(
                LevelAssessmentSummary(
                    classified_protection_level=level,
                    counts={result: counts[result] for result in FindingResult},
                    findings=tuple(findings),
                )
            )

        return CurrentAssessmentResponse(
            assessment_id=f"asm:{current.snapshot_id}:{RULE_PACK_VERSION}",
            snapshot_id=current.snapshot_id,
            target_id=current.target_id,
            status="Completed",
            rule_pack_version=RULE_PACK_VERSION,
            catalog_id=self._catalog_id,
            catalog_version=self._catalog_version,
            levels=tuple(level_summaries),
            disclaimer=(
                "结果仅表示当前防火墙配置对本规则集控制项的匹配状态，不是信息系统最终等级保护测评结论。"
            ),
        )
