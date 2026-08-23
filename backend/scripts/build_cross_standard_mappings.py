from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.models.catalog import UnifiedFirewallCatalog
from app.models.cross_standard import (
    ControlEndpoint,
    CrossStandardCatalog,
    CrossStandardMapping,
    CrossStandardStatistics,
    MappingReviewDecision,
    PendingMappingQuestion,
)


CATALOG_DIR = BACKEND_ROOT / "data" / "catalog"
UNIFIED_CATALOG_PATH = CATALOG_DIR / "unified-firewall-catalog-v1.json"
GB20281_CATALOG_PATH = CATALOG_DIR / "gb-t-20281-2020-firewall-candidates.json"
OUTPUT_PATH = CATALOG_DIR / "firewall-cross-standard-mappings-v1.json"
DECISION_PATH = CATALOG_DIR / "cross-standard-mapping-review-decisions.json"

# JR/T 0071.2 refines or corresponds to GB/T 22239. These entries are limited to
# relationships whose control objective is explicit in both normalized catalogs.
BASELINE_MAPPINGS = (
    ("JR0071-2-FW-001", "GB22239-FW-007", "equivalent", "full"),
    ("JR0071-2-FW-002", "GB22239-FW-008", "refines", "full"),
    ("JR0071-2-FW-004", "GB22239-FW-036", "refines", "full"),
    ("JR0071-2-FW-005", "GB22239-FW-001", "equivalent", "full"),
    ("JR0071-2-FW-007", "GB22239-FW-002", "equivalent", "full"),
    ("JR0071-2-FW-008", "GB22239-FW-003", "equivalent", "full"),
    ("JR0071-2-FW-009", "GB22239-FW-004", "equivalent", "full"),
    ("JR0071-2-FW-010", "GB22239-FW-005", "equivalent", "full"),
    ("JR0071-2-FW-011", "GB22239-FW-006", "equivalent", "full"),
    ("JR0071-2-FW-014", "GB22239-FW-009", "equivalent", "full"),
    ("JR0071-2-FW-016", "GB22239-FW-010", "equivalent", "full"),
    ("JR0071-2-FW-017", "GB22239-FW-011", "refines", "full"),
    ("JR0071-2-FW-018", "GB22239-FW-012", "equivalent", "full"),
    ("JR0071-2-FW-020", "GB22239-FW-013", "equivalent", "full"),
    ("JR0071-2-FW-021", "GB22239-FW-014", "refines", "full"),
    ("JR0071-2-FW-022", "GB22239-FW-015", "equivalent", "full"),
    ("JR0071-2-FW-024", "GB22239-FW-016", "refines", "full"),
    ("JR0071-2-FW-025", "GB22239-FW-017", "equivalent", "full"),
    ("JR0071-2-FW-026", "GB22239-FW-019", "refines", "full"),
    ("JR0071-2-FW-027", "GB22239-FW-018", "equivalent", "full"),
    ("JR0071-2-FW-028", "GB22239-FW-020", "partial", "partial"),
    ("JR0071-2-FW-029", "GB22239-FW-020", "partial", "partial"),
    ("JR0071-2-FW-030", "GB22239-FW-021", "refines", "full"),
    ("JR0071-2-FW-031", "GB22239-FW-022", "equivalent", "full"),
    ("JR0071-2-FW-032", "GB22239-FW-023", "equivalent", "full"),
    ("JR0071-2-FW-033", "GB22239-FW-024", "refines", "full"),
    ("JR0071-2-FW-036", "GB22239-FW-026", "partial", "partial"),
    ("JR0071-2-FW-037", "GB22239-FW-026", "partial", "partial"),
    ("JR0071-2-FW-039", "GB22239-FW-025", "refines", "full"),
    ("JR0071-2-FW-040", "GB22239-FW-027", "refines", "full"),
    ("JR0071-2-FW-043", "GB22239-FW-028", "refines", "full"),
    ("JR0071-2-FW-044", "GB22239-FW-029", "equivalent", "full"),
    ("JR0071-2-FW-045", "GB22239-FW-030", "equivalent", "full"),
    ("JR0071-2-FW-046", "GB22239-FW-031", "equivalent", "full"),
    ("JR0071-2-FW-047", "GB22239-FW-032", "refines", "full"),
    ("JR0071-2-FW-048", "GB22239-FW-033", "equivalent", "full"),
    ("JR0071-2-FW-049", "GB22239-FW-034", "refines", "full"),
    ("JR0071-2-FW-049", "GB22239-FW-035", "refines", "full"),
    ("JR0071-2-FW-CLOUD-001", "GB22239-FW-CLOUD-001", "refines", "full"),
    ("JR0071-2-FW-CLOUD-002", "GB22239-FW-CLOUD-002", "refines", "full"),
    ("JR0071-2-FW-CLOUD-004", "GB22239-FW-CLOUD-003", "refines", "full"),
    ("JR0071-2-FW-CLOUD-007", "GB22239-FW-CLOUD-004", "equivalent", "full"),
    ("JR0071-2-FW-MOBILE-002", "GB22239-FW-MOBILE-001", "equivalent", "full"),
    ("JR0071-2-FW-IOT-002", "GB22239-FW-IOT-001", "equivalent", "full"),
)

# Product controls are capability evidence only. A supports relationship never
# proves that the capability is enabled or correctly configured in the target.
PRODUCT_MAPPINGS = (
    ("GB20281-FW-005", "JR0071-2-FW-002", "partial"),
    ("GB20281-FW-009", "JR0071-2-FW-007", "full"),
    ("GB20281-FW-010", "JR0071-2-FW-009", "full"),
    ("GB20281-FW-012", "JR0071-2-FW-010", "full"),
    ("GB20281-FW-019", "JR0071-2-FW-011", "partial"),
    ("GB20281-FW-023", "JR0071-2-FW-014", "partial"),
    ("GB20281-FW-023", "JR0071-2-FW-CLOUD-005", "partial"),
    ("GB20281-FW-024", "JR0071-2-FW-014", "partial"),
    ("GB20281-FW-024", "JR0071-2-FW-CLOUD-006", "full"),
    ("GB20281-FW-026", "JR0071-2-FW-017", "partial"),
    ("GB20281-FW-032", "JR0071-2-FW-020", "full"),
    ("GB20281-FW-033", "JR0071-2-FW-021", "full"),
    ("GB20281-FW-036", "JR0071-2-FW-024", "partial"),
    ("GB20281-FW-037", "JR0071-2-FW-025", "full"),
    ("GB20281-FW-038", "JR0071-2-FW-024", "partial"),
    ("GB20281-FW-038", "JR0071-2-FW-028", "partial"),
    ("GB20281-FW-039", "JR0071-2-FW-027", "full"),
    ("GB20281-FW-043", "JR0071-2-FW-026", "partial"),
    ("GB20281-FW-043", "JR0071-2-FW-031", "full"),
    ("GB20281-FW-044", "JR0071-2-FW-045", "partial"),
    ("GB20281-FW-006", "JR0071-2-FW-002", "partial"),
    ("GB20281-FW-018", "JR0071-2-FW-007", "partial"),
    ("GB20281-FW-020", "JR0071-2-FW-011", "partial"),
    ("GB20281-FW-022", "JR0071-2-FW-011", "partial"),
    ("GB20281-FW-025", "JR0071-2-FW-014", "partial"),
    ("GB20281-FW-027", "JR0071-2-FW-014", "partial"),
    ("GB20281-FW-028", "JR0071-2-FW-015", "partial"),
    ("GB20281-FW-029", "JR0071-2-FW-015", "partial"),
    ("GB20281-FW-030", "JR0071-2-FW-015", "partial"),
)

APPROVED_BASELINE_PARTIAL_MAPPINGS = (
    ("JR0071-2-FW-023", "GB22239-FW-035"),
    ("JR0071-2-FW-038", "GB22239-FW-025"),
    ("JR0071-2-FW-041", "GB22239-FW-031"),
    ("JR0071-2-FW-042", "GB22239-FW-033"),
)

APPROVED_CONDITIONAL_MAPPINGS = (
    ("JR0071-2-FW-CLOUD-003", "GB22239-FW-CLOUD-002", "cloud"),
    ("JR0071-2-FW-CLOUD-005", "GB22239-FW-CLOUD-003", "cloud"),
    ("JR0071-2-FW-CLOUD-006", "GB22239-FW-CLOUD-003", "cloud"),
    ("JR0071-2-FW-MOBILE-001", "GB22239-FW-036", "mobile"),
    ("JR0071-2-FW-026", "GB22239-FW-CLOUD-005", "cloud"),
)

APPROVED_PRODUCT_PERFORMANCE_MAPPINGS = (
    ("GB20281-FW-015", "JR0071-2-FW-002", "product-capability", None),
    ("GB20281-FW-016", "JR0071-2-FW-002", "product-capability", None),
    ("GB20281-FW-016", "JR0071-2-FW-014", "product-capability", None),
    (
        "GB20281-FW-016",
        "JR0071-2-FW-CLOUD-005",
        "product-capability",
        "cloud",
    ),
    ("GB20281-FW-046", "JR0071-2-FW-002", "product-laboratory-test", None),
)

APPROVED_PRODUCT_MANAGEMENT_MAPPINGS = (
    ("GB20281-FW-031", "JR0071-2-FW-016"),
    ("GB20281-FW-031", "JR0071-2-FW-018"),
    ("GB20281-FW-034", "JR0071-2-FW-016"),
    ("GB20281-FW-034", "JR0071-2-FW-049"),
    ("GB20281-FW-040", "JR0071-2-FW-023"),
    ("GB20281-FW-040", "JR0071-2-FW-047"),
    ("GB20281-FW-041", "JR0071-2-FW-030"),
    ("GB20281-FW-041", "JR0071-2-FW-043"),
    ("GB20281-FW-041", "JR0071-2-FW-044"),
    ("GB20281-FW-042", "JR0071-2-FW-040"),
    ("GB20281-FW-042", "JR0071-2-FW-043"),
    ("GB20281-FW-042", "JR0071-2-FW-044"),
    ("GB20281-FW-042", "JR0071-2-FW-049"),
    ("GB20281-FW-045", "JR0071-2-FW-032"),
    ("GB20281-FW-045", "JR0071-2-FW-033"),
)

PENDING_QUESTIONS = (
    PendingMappingQuestion(
        question_id="Q-MAP-001",
        source_control_ids=(
            "JR0071-2-FW-023",
            "JR0071-2-FW-038",
            "JR0071-2-FW-041",
            "JR0071-2-FW-042",
        ),
        candidate_target_control_ids=(
            "GB22239-FW-035",
            "GB22239-FW-025",
            "GB22239-FW-031",
            "GB22239-FW-033",
        ),
        issue="金融标准分别要求审计时间、配置备份、每日监测和版本管理；等保控制更宽或强调集中管理，不能视为完全等价。",
        recommended_handling="建立 partial 关系，保留差异说明，不允许跨标准复用通过结论。",
    ),
    PendingMappingQuestion(
        question_id="Q-MAP-002",
        source_control_ids=(
            "JR0071-2-FW-CLOUD-003",
            "JR0071-2-FW-CLOUD-005",
            "JR0071-2-FW-CLOUD-006",
            "JR0071-2-FW-MOBILE-001",
            "JR0071-2-FW-026",
        ),
        candidate_target_control_ids=(
            "GB22239-FW-CLOUD-002",
            "GB22239-FW-CLOUD-003",
            "GB22239-FW-036",
            "GB22239-FW-CLOUD-005",
        ),
        issue="候选项控制目标相关，但存在通用、云和移动场景交叉，适用条件不完全相同。",
        recommended_handling="只建立 conditional partial 关系；检索可召回，但判定时必须同时满足来源和目标的场景条件。",
    ),
    PendingMappingQuestion(
        question_id="Q-MAP-003",
        source_control_ids=(
            "GB20281-FW-015",
            "GB20281-FW-016",
            "GB20281-FW-046",
        ),
        candidate_target_control_ids=(
            "JR0071-2-FW-002",
            "JR0071-2-FW-014",
            "JR0071-2-FW-CLOUD-005",
        ),
        issue="产品标准中的带宽、连接速率和实验室性能结果与现场容量、DoS 防护要求相关，但不能证明现场配置和实际承载能力。",
        recommended_handling="建立 supports/partial 关系，并把证据类型限定为产品能力或实验室测试，禁止直接形成现场合规结论。",
    ),
    PendingMappingQuestion(
        question_id="Q-MAP-004",
        source_control_ids=(
            "GB20281-FW-031",
            "GB20281-FW-034",
            "GB20281-FW-040",
            "GB20281-FW-041",
            "GB20281-FW-042",
            "GB20281-FW-045",
        ),
        candidate_target_control_ids=(
            "JR0071-2-FW-016",
            "JR0071-2-FW-018",
            "JR0071-2-FW-023",
            "JR0071-2-FW-030",
            "JR0071-2-FW-033",
            "JR0071-2-FW-040",
            "JR0071-2-FW-043",
            "JR0071-2-FW-044",
            "JR0071-2-FW-047",
            "JR0071-2-FW-049",
        ),
        issue="单个产品管理或审计能力可能支撑多个金融控制项，但每个金融控制项还包含角色、流程、集中管理或留存等额外要求。",
        recommended_handling="按具体子能力建立 supports/partial 一对多关系，所有关系禁止单独通过。",
    ),
)


def _load_unified_catalog() -> tuple[UnifiedFirewallCatalog, str]:
    raw = UNIFIED_CATALOG_PATH.read_bytes()
    catalog = UnifiedFirewallCatalog.model_validate_json(raw)
    return catalog, hashlib.sha256(raw).hexdigest()


def _load_review_decisions() -> dict[str, MappingReviewDecision]:
    payload = json.loads(DECISION_PATH.read_text(encoding="utf-8"))
    decisions = {
        item["question_id"]: MappingReviewDecision.model_validate(item)
        for item in payload["decisions"]
    }
    expected = {
        "Q-MAP-001",
        "Q-MAP-002",
        "Q-MAP-003",
        "Q-MAP-004",
        "Q-MAP-005",
    }
    if set(decisions) != expected:
        raise ValueError(
            f"跨标准人工确认集合异常：{sorted(set(decisions) ^ expected)}"
        )
    return decisions


def _load_network_product_levels() -> dict[str, tuple[str, ...]]:
    payload = json.loads(GB20281_CATALOG_PATH.read_text(encoding="utf-8"))
    levels_by_control: dict[str, tuple[str, ...]] = {}
    for control in payload["control_candidates"]:
        applicability = control["network_level_applicability"]
        levels_by_control[control["control_id"]] = tuple(
            level
            for level in ("basic", "enhanced")
            if applicability.get(level) not in (None, "not-applicable")
        )
    return levels_by_control


def _network_product_conditions(
    control_id: str, levels_by_control: dict[str, tuple[str, ...]]
) -> tuple[str, ...]:
    levels = levels_by_control[control_id]
    if not levels:
        raise ValueError(f"非网络型防火墙控制项不能进入当前映射：{control_id}")
    serialized_levels = ",".join(levels)
    return (
        "product_type == network-based-firewall",
        f"product_security_level in [{serialized_levels}]",
    )


def _mapping_basis(relationship: str, source_title: str, target_title: str) -> str:
    if relationship == "equivalent":
        return f"“{source_title}”与“{target_title}”在共同适用等级内控制目标一致。"
    if relationship == "refines":
        return f"“{source_title}”覆盖“{target_title}”的基线目标，并包含金融行业细化或增强要求。"
    if relationship == "partial":
        return f"“{source_title}”与“{target_title}”只在部分控制范围重合，必须结合其他控制项判断。"
    return f"产品能力“{source_title}”可支撑“{target_title}”，但不能证明现场已启用或正确配置。"


def build_catalog() -> CrossStandardCatalog:
    unified, unified_sha256 = _load_unified_catalog()
    decisions = _load_review_decisions()
    network_product_levels = _load_network_product_levels()
    controls = {item.record_id: item for item in unified.controls}
    mappings: list[CrossStandardMapping] = []

    for index, (source_id, target_id, relationship, coverage) in enumerate(
        BASELINE_MAPPINGS, start=1
    ):
        source = controls[source_id]
        target = controls[target_id]
        mappings.append(
            CrossStandardMapping(
                mapping_id=f"XMAP-BASE-{index:03d}",
                source=ControlEndpoint(
                    standard_code=source.standard_code,
                    control_id=source.record_id,
                    title=source.title,
                ),
                target=ControlEndpoint(
                    standard_code=target.standard_code,
                    control_id=target.record_id,
                    title=target.title,
                ),
                relationship=relationship,
                coverage=coverage,
                confidence=1.0 if relationship == "equivalent" else 0.95,
                review_status="DeterministicMatched",
                evidence_scope="requirement-alignment",
                mapping_basis=_mapping_basis(
                    relationship, source.title, target.title
                ),
            )
        )

    for index, (source_id, target_id, coverage) in enumerate(
        PRODUCT_MAPPINGS, start=1
    ):
        source = controls[source_id]
        target = controls[target_id]
        product_conditions = _network_product_conditions(
            source_id, network_product_levels
        )
        mappings.append(
            CrossStandardMapping(
                mapping_id=f"XMAP-PRODUCT-{index:03d}",
                source=ControlEndpoint(
                    standard_code=source.standard_code,
                    control_id=source.record_id,
                    title=source.title,
                ),
                target=ControlEndpoint(
                    standard_code=target.standard_code,
                    control_id=target.record_id,
                    title=target.title,
                ),
                relationship="supports",
                coverage=coverage,
                confidence=0.95 if coverage == "full" else 0.85,
                review_status="DeterministicMatched",
                conditional=True,
                applicability_conditions=product_conditions,
                evidence_scope="product-capability",
                mapping_basis=_mapping_basis("supports", source.title, target.title),
            )
        )

    decision = decisions["Q-MAP-001"]
    for index, (source_id, target_id) in enumerate(
        APPROVED_BASELINE_PARTIAL_MAPPINGS, start=1
    ):
        source = controls[source_id]
        target = controls[target_id]
        mappings.append(
            CrossStandardMapping(
                mapping_id=f"XMAP-REVIEW-BASE-{index:03d}",
                source=ControlEndpoint(
                    standard_code=source.standard_code,
                    control_id=source.record_id,
                    title=source.title,
                ),
                target=ControlEndpoint(
                    standard_code=target.standard_code,
                    control_id=target.record_id,
                    title=target.title,
                ),
                relationship="partial",
                coverage="partial",
                confidence=0.8,
                review_status="HumanReviewed",
                evidence_scope="requirement-alignment",
                review_decision_id=decision.decision_id,
                mapping_basis=_mapping_basis("partial", source.title, target.title),
            )
        )

    decision = decisions["Q-MAP-002"]
    for index, (source_id, target_id, context) in enumerate(
        APPROVED_CONDITIONAL_MAPPINGS, start=1
    ):
        source = controls[source_id]
        target = controls[target_id]
        mappings.append(
            CrossStandardMapping(
                mapping_id=f"XMAP-REVIEW-CONTEXT-{index:03d}",
                source=ControlEndpoint(
                    standard_code=source.standard_code,
                    control_id=source.record_id,
                    title=source.title,
                ),
                target=ControlEndpoint(
                    standard_code=target.standard_code,
                    control_id=target.record_id,
                    title=target.title,
                ),
                relationship="partial",
                coverage="partial",
                confidence=0.75,
                review_status="HumanReviewed",
                conditional=True,
                applicability_conditions=(f"deployment_context.{context} == true",),
                evidence_scope="requirement-alignment",
                review_decision_id=decision.decision_id,
                mapping_basis=(
                    _mapping_basis("partial", source.title, target.title)
                    + f" 仅在 {context} 场景适用。"
                ),
            )
        )

    decision = decisions["Q-MAP-003"]
    for index, (source_id, target_id, evidence_scope, context) in enumerate(
        APPROVED_PRODUCT_PERFORMANCE_MAPPINGS, start=1
    ):
        source = controls[source_id]
        target = controls[target_id]
        conditions = _network_product_conditions(source_id, network_product_levels)
        if context:
            conditions = (*conditions, f"deployment_context.{context} == true")
        mappings.append(
            CrossStandardMapping(
                mapping_id=f"XMAP-REVIEW-PERF-{index:03d}",
                source=ControlEndpoint(
                    standard_code=source.standard_code,
                    control_id=source.record_id,
                    title=source.title,
                ),
                target=ControlEndpoint(
                    standard_code=target.standard_code,
                    control_id=target.record_id,
                    title=target.title,
                ),
                relationship="supports",
                coverage="partial",
                confidence=0.75,
                review_status="HumanReviewed",
                conditional=True,
                applicability_conditions=conditions,
                evidence_scope=evidence_scope,
                review_decision_id=decision.decision_id,
                mapping_basis=(
                    _mapping_basis("supports", source.title, target.title)
                    + " 证据仅代表产品能力或实验室结果。"
                ),
            )
        )

    decision = decisions["Q-MAP-004"]
    for index, (source_id, target_id) in enumerate(
        APPROVED_PRODUCT_MANAGEMENT_MAPPINGS, start=1
    ):
        source = controls[source_id]
        target = controls[target_id]
        product_conditions = _network_product_conditions(
            source_id, network_product_levels
        )
        mappings.append(
            CrossStandardMapping(
                mapping_id=f"XMAP-REVIEW-MGMT-{index:03d}",
                source=ControlEndpoint(
                    standard_code=source.standard_code,
                    control_id=source.record_id,
                    title=source.title,
                ),
                target=ControlEndpoint(
                    standard_code=target.standard_code,
                    control_id=target.record_id,
                    title=target.title,
                ),
                relationship="supports",
                coverage="partial",
                confidence=0.8,
                review_status="HumanReviewed",
                conditional=True,
                applicability_conditions=product_conditions,
                evidence_scope="product-capability",
                review_decision_id=decision.decision_id,
                mapping_basis=_mapping_basis("supports", source.title, target.title),
            )
        )

    pairs = [
        (item.source.control_id, item.target.control_id) for item in mappings
    ]
    if len(pairs) != len(set(pairs)):
        raise ValueError("跨标准映射存在重复控制项对")
    for mapping in mappings:
        if mapping.source.control_id not in controls:
            raise ValueError(f"映射来源不存在：{mapping.source.control_id}")
        if mapping.target.control_id not in controls:
            raise ValueError(f"映射目标不存在：{mapping.target.control_id}")

    relationship_counts = Counter(item.relationship for item in mappings)
    source_standard_counts = Counter(item.source.standard_code for item in mappings)
    mapped_controls: dict[str, set[str]] = {}
    for mapping in mappings:
        mapped_controls.setdefault(mapping.source.standard_code, set()).add(
            mapping.source.control_id
        )
        mapped_controls.setdefault(mapping.target.standard_code, set()).add(
            mapping.target.control_id
        )
    controlled_standards = {
        "GB/T 22239—2019",
        "GB/T 20281—2020",
        "JR/T 0071.2—2020",
    }
    all_control_ids = {
        standard: {
            item.record_id
            for item in unified.controls
            if item.standard_code == standard
        }
        for standard in controlled_standards
    }
    unmapped_control_ids = {
        standard: tuple(sorted(ids - mapped_controls.get(standard, set())))
        for standard, ids in sorted(all_control_ids.items())
    }

    return CrossStandardCatalog(
        catalog_version="1.0.0",
        generated_on="2026-08-23",
        review_status="Draft",
        scope="连接 GB/T 22239、JR/T 0071.2 与 GB/T 20281 的防火墙控制项；JR/T 0072 的 measures 关系继续由统一目录承载。",
        unified_catalog_id=unified.catalog_id,
        unified_catalog_sha256=unified_sha256,
        mapping_policy=(
            "JR/T 0071.2 到 GB/T 22239 使用 equivalent、refines 或 partial。",
            "GB/T 20281 到 JR/T 0071.2 仅使用 supports，表示产品能力支撑。",
            "当前产品范围仅限 network-based-firewall，并按 basic/enhanced 适用表过滤。",
            "所有跨标准关系 standalone_pass_allowed 均为 false。",
            "待用户确认的问题不写成正式映射。",
        ),
        mappings=tuple(mappings),
        review_decisions=tuple(decisions[key] for key in sorted(decisions)),
        pending_questions=(),
        unmapped_control_ids=unmapped_control_ids,
        statistics=CrossStandardStatistics(
            mapping_count=len(mappings),
            by_relationship=dict(sorted(relationship_counts.items())),
            by_source_standard=dict(sorted(source_standard_counts.items())),
            mapped_control_count={
                key: len(value) for key, value in sorted(mapped_controls.items())
            },
            unmapped_control_count={
                key: len(value) for key, value in unmapped_control_ids.items()
            },
            pending_question_count=0,
            human_reviewed_mapping_count=sum(
                item.review_status == "HumanReviewed" for item in mappings
            ),
        ),
    )


def main() -> None:
    catalog = build_catalog()
    OUTPUT_PATH.write_text(
        json.dumps(catalog.model_dump(mode="json"), ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(
        f"generated {OUTPUT_PATH}: {catalog.statistics.mapping_count} confirmed "
        f"mappings, {catalog.statistics.pending_question_count} pending questions"
    )


if __name__ == "__main__":
    main()
