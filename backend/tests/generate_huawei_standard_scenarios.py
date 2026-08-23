from __future__ import annotations

import json
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = BACKEND_ROOT / "data" / "catalog" / "reviewed-verbatim-catalog-v1.json"
OUTPUT_DIR = BACKEND_ROOT / "data" / "huawei-atomic-configs"


SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "name": "01-default-deny-compliant",
        "cfg": """security-policy
 rule name DEFAULT-DENY
  source-zone any
  destination-zone any
  source-address any
  destination-address any
  service any
  action deny
""",
        "patch": {"access_control": {"default_action": "deny"}},
        "judgment": "Passed",
        "primary": "JR0071-2-FW-007",
        "related": ["GB22239-FW-002", "GB20281-FW-009", "L3|7.1.3.2|L3-ABS1-05|88"],
        "reason": "配置明确存在 any-to-any 的最终 deny 规则，可证明缺省拒绝。",
    },
    {
        "name": "02-default-permit-noncompliant",
        "cfg": """security-policy
 rule name DEFAULT-PERMIT-UNSAFE
  source-zone any
  destination-zone any
  source-address any
  destination-address any
  service any
  action permit
""",
        "patch": {"access_control": {"default_action": "permit"}},
        "judgment": "Failed",
        "primary": "JR0071-2-FW-007",
        "related": ["GB22239-FW-002", "GB20281-FW-009", "L3|7.1.3.2|L3-ABS1-05|88"],
        "reason": "配置明确将缺省动作设为 permit，与默认拒绝要求相反。",
    },
    {
        "name": "03-telnet-enabled-noncompliant",
        "cfg": "telnet server enable\n",
        "patch": {"management": {"protocols": {"telnet": {"enabled": True}}}},
        "judgment": "Failed",
        "primary": "JR0071-2-FW-026",
        "related": ["GB22239-FW-019", "GB20281-FW-043", "JR0071-2-FW-032"],
        "reason": "Telnet 以明文方式承载远程管理，不能保护鉴别信息传输。",
    },
    {
        "name": "04-secure-management-compliant",
        "cfg": """undo telnet server enable
undo http server enable
stelnet server enable
http secure-server enable
""",
        "patch": {
            "management": {
                "protocols": {
                    "telnet": {"enabled": False},
                    "http": {"enabled": False},
                    "ssh": {"enabled": True},
                    "https": {"enabled": True},
                }
            }
        },
        "judgment": "Passed",
        "primary": "JR0071-2-FW-026",
        "related": ["GB22239-FW-019", "GB20281-FW-043", "JR0071-2-FW-032"],
        "reason": "明确关闭 Telnet/HTTP，并启用 SSH/HTTPS 加密管理通道。",
    },
    {
        "name": "05-management-source-any-noncompliant",
        "cfg": """ssh server-source -i GigabitEthernet0/0/0
acl number 2000
 rule 5 permit source any
ssh server acl 2000
""",
        "patch": {"management": {"source_interface": "GigabitEthernet0/0/0", "allowed_source_cidrs": ["any"]}},
        "judgment": "Failed",
        "primary": "JR0071-2-FW-031",
        "related": ["GB22239-FW-022", "GB20281-FW-043"],
        "reason": "虽限定管理接口，但管理源 ACL 允许 any，未限制终端来源。",
    },
    {
        "name": "06-management-source-restricted-compliant",
        "cfg": """ssh server-source -i GigabitEthernet0/0/0
acl number 2000
 rule 5 permit source 192.0.2.32 0.0.0.31
ssh server acl 2000
""",
        "patch": {"management": {"source_interface": "GigabitEthernet0/0/0", "allowed_source_cidrs": ["192.0.2.32/27"]}},
        "judgment": "Passed",
        "primary": "JR0071-2-FW-031",
        "related": ["GB22239-FW-022", "GB20281-FW-043"],
        "reason": "配置同时约束管理接口和可管理的源地址段。",
    },
    {
        "name": "07-mfa-disabled-noncompliant",
        "cfg": """aaa
 undo administrator multi-factor-authentication enable
""",
        "patch": {"management": {"mfa_enabled": False}},
        "judgment": "Failed",
        "primary": "JR0071-2-FW-027",
        "related": ["GB22239-FW-018", "GB20281-FW-039"],
        "reason": "配置明确关闭管理用户多因素鉴别。",
    },
    {
        "name": "08-mfa-enabled-compliant",
        "cfg": """aaa
 administrator multi-factor-authentication enable
""",
        "patch": {"management": {"mfa_enabled": True}},
        "judgment": "Passed",
        "primary": "JR0071-2-FW-027",
        "related": ["GB22239-FW-018", "GB20281-FW-039"],
        "reason": "配置明确启用管理用户多因素鉴别。",
    },
    {
        "name": "09-audit-disabled-noncompliant",
        "cfg": "undo info-center enable\n",
        "patch": {"logging": {"audit_log_enabled": False}},
        "judgment": "Failed",
        "primary": "JR0071-2-FW-036",
        "related": ["GB22239-FW-026", "GB20281-FW-031"],
        "reason": "配置明确关闭设备信息中心/审计日志功能。",
    },
    {
        "name": "10-audit-enabled-compliant",
        "cfg": """info-center enable
log type policy enable
log type threat enable
""",
        "patch": {"logging": {"audit_log_enabled": True, "policy_log_enabled": True, "threat_log_enabled": True}},
        "judgment": "Passed",
        "primary": "JR0071-2-FW-036",
        "related": ["GB22239-FW-026", "GB20281-FW-031"],
        "reason": "配置启用设备审计、策略日志和威胁日志。",
    },
    {
        "name": "11-short-local-retention-needs-review",
        "cfg": """info-center logfile retention-days 30
info-center loghost 192.0.2.200 port 6514 transport tls
""",
        "patch": {"logging": {"local_retention_days": 30, "remote_logging": {"enabled": True}}},
        "judgment": "NeedsReview",
        "primary": "JR0071-2-FW-037",
        "related": ["GB22239-FW-014", "GB20281-FW-033"],
        "reason": "本地仅留存30天；已配置远程日志，但 CLI 不能证明远端留存期。",
        "limitations": ["需要远程日志平台的留存策略和实际日志记录。"],
    },
    {
        "name": "12-retention-180-days-compliant",
        "cfg": "info-center logfile retention-days 180\n",
        "patch": {"logging": {"local_retention_days": 180}},
        "judgment": "Passed",
        "primary": "JR0071-2-FW-037",
        "related": ["GB22239-FW-014", "GB20281-FW-033"],
        "reason": "设备本地日志留存阈值设为180天，满足当前规则对六个月的量化口径。",
    },
    {
        "name": "13-remote-log-configured-needs-review",
        "cfg": "info-center loghost 192.0.2.200 port 6514 transport tls\n",
        "patch": {"logging": {"remote_logging": {"enabled": True}}},
        "judgment": "NeedsReview",
        "primary": "JR0071-2-FW-047",
        "related": ["GB22239-FW-032"],
        "reason": "CLI 可证明已配置 TLS 远程日志目标，但不能证明可达、已收集、已分析和实际留存期。",
        "limitations": ["需要日志平台连通性、收集记录和留存策略证据。"],
    },
    {
        "name": "14-ntp-enabled-compliant",
        "cfg": """ntp-service enable
ntp-service unicast-server 192.0.2.123
ntp-service unicast-server 192.0.2.124 preference
""",
        "patch": {"time_sync": {"enabled": True, "servers": ["192.0.2.123", "192.0.2.124"]}},
        "judgment": "Passed",
        "primary": "JR0071-2-FW-023",
        "related": ["L3|7.1.4.3|L3-CES1-19|99"],
        "reason": "配置启用 NTP 并指定两个时钟源。",
    },
    {
        "name": "15-ips-disabled-noncompliant",
        "cfg": "undo profile type ips name IPS-BANK-PROTECT\n",
        "patch": {"threat_prevention": {"ips_enabled": False}},
        "judgment": "Failed",
        "primary": "JR0071-2-FW-014",
        "related": ["GB22239-FW-009"],
        "reason": "配置明确删除/关闭 IPS 防护配置文件。",
    },
    {
        "name": "16-ips-enabled-compliant",
        "cfg": """profile type ips name IPS-BANK-PROTECT
 action block
""",
        "patch": {"threat_prevention": {"ips_enabled": True}},
        "judgment": "Passed",
        "primary": "JR0071-2-FW-014",
        "related": ["GB22239-FW-009"],
        "reason": "配置创建 IPS 防护配置文件并设置阻断动作。",
    },
    {
        "name": "17-antivirus-disabled-noncompliant",
        "cfg": "undo profile type av name AV-BANK-PROTECT\n",
        "patch": {"threat_prevention": {"antivirus_enabled": False}},
        "judgment": "Failed",
        "primary": "JR0071-2-FW-017",
        "related": ["GB22239-FW-011", "GB20281-FW-026"],
        "reason": "配置明确删除/关闭防恶意代码配置文件。",
    },
    {
        "name": "18-ha-enabled-needs-review",
        "cfg": """hrp enable
hrp protocol HRP
""",
        "patch": {"high_availability": {"enabled": True, "protocol": "HRP"}},
        "judgment": "NeedsReview",
        "primary": "JR0071-2-FW-002",
        "related": ["GB22239-FW-008", "GB20281-FW-005"],
        "reason": "CLI 只能证明已启用 HRP，不能单独证明硬件冗余、当前运行状态和配置同步成功。",
        "limitations": ["需要双机拓扑、运行状态和切换验证证据。"],
    },
    {
        "name": "19-backup-record-needs-review",
        "cfg": "sysname FW-BACKUP-REVIEW\n",
        "patch": {"target": {"hostname": "FW-BACKUP-REVIEW"}},
        "judgment": "NeedsReview",
        "primary": "JR0071-2-FW-038",
        "related": ["GB22239-FW-025", "L3|7.1.5.1|L3-SMC1-03|107"],
        "reason": "运行配置快照不包含每月及变更后的备份成功记录，无法仅凭 CLI 判定。",
        "limitations": ["需要配置管理平台、备份任务和备份文件记录。"],
    },
    {
        "name": "20-ipv6-route-needs-review",
        "cfg": "ipv6 route-static :: 0 2001:db8:100::1\n",
        "patch": {"network_stack": {"ipv6_default_route_configured": True}},
        "judgment": "NeedsReview",
        "primary": "GB20281-FW-008",
        "related": [],
        "reason": "CLI 可证明存在 IPv6 默认路由，但不能证明产品的 IPv6 协议一致性、健壮性和全部功能要求。",
        "limitations": ["需要 IPv6 协议一致性与健壮性测试证据。"],
    },
)


def _select_excerpt(record: dict[str, Any]) -> dict[str, Any]:
    requirement_excerpts = [
        item
        for item in record["excerpts"]
        if item.get("relation") == "requirement"
    ]
    candidates = requirement_excerpts or record["excerpts"]
    return next(
        (
            item
            for item in candidates
            if item.get("classified_protection_level") == 3
        ),
        candidates[0],
    )


def _standard_reference(record: dict[str, Any]) -> dict[str, Any]:
    excerpt = _select_excerpt(record)
    return {
        "record_id": record["record_id"],
        "standard_code": record["standard_code"],
        "title": record["title"],
        "clause_id": excerpt.get("clause_id", excerpt.get("guide_clause_id")),
        "classified_protection_level": excerpt["classified_protection_level"],
        "verbatim_text": excerpt["text"],
        "content_sha256": excerpt["content_sha256"],
        "review_status": record["review_status"],
        "citation_eligible": record["citation_eligible"],
        "source_record_pointer": record["source_record_pointer"],
    }


def main() -> None:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    records = {record["record_id"]: record for record in catalog["records"]}
    if catalog["record_count"] != 440:
        raise RuntimeError("reviewed catalog is not the expected 440-record catalog")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for scenario in SCENARIOS:
        record_ids = [scenario["primary"], *scenario["related"]]
        missing = set(record_ids) - set(records)
        if missing:
            raise RuntimeError(f"missing reviewed standard records: {sorted(missing)}")
        cfg_path = OUTPUT_DIR / f"{scenario['name']}.cfg"
        standard_path = OUTPUT_DIR / f"{scenario['name']}.json"
        cfg_path.write_text(
            "! MOCK Huawei VRP-style configuration; fictitious test data only.\n"
            + scenario["cfg"],
            encoding="utf-8",
        )
        payload = {
            "schema_version": "1.0.0",
            "scenario_id": scenario["name"],
            "vendor": "Huawei",
            "judgment_scope": "configuration-only preliminary assessment",
            "expected_result": scenario["judgment"],
            "expected_parsed_patch": scenario["patch"],
            "judgment_reason": scenario["reason"],
            "limitations": scenario.get("limitations", []),
            "primary_standard": _standard_reference(records[scenario["primary"]]),
            "related_standards": [
                _standard_reference(records[record_id])
                for record_id in scenario["related"]
            ],
            "catalog_provenance": {
                "catalog_id": catalog["catalog_id"],
                "catalog_version": catalog["catalog_version"],
                "catalog_record_count": catalog["record_count"],
                "review_artifact_sha256": catalog["review_artifact"]["sha256"],
            },
        }
        standard_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(f"generated {len(SCENARIOS)} CFG/standard JSON pairs in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
