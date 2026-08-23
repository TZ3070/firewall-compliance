from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FrozenCrossStandardModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ControlEndpoint(FrozenCrossStandardModel):
    standard_code: str
    control_id: str
    title: str


class CrossStandardMapping(FrozenCrossStandardModel):
    mapping_id: str
    source: ControlEndpoint
    target: ControlEndpoint
    relationship: Literal["equivalent", "refines", "supports", "partial"]
    coverage: Literal["full", "partial"]
    confidence: float = Field(ge=0.0, le=1.0)
    review_status: Literal["DeterministicMatched", "HumanReviewed"]
    standalone_pass_allowed: Literal[False] = False
    conditional: bool = False
    applicability_conditions: tuple[str, ...] = ()
    evidence_scope: Literal[
        "requirement-alignment", "product-capability", "product-laboratory-test"
    ]
    review_decision_id: str | None = None
    mapping_basis: str

    @model_validator(mode="after")
    def validate_mapping_semantics(self) -> "CrossStandardMapping":
        if self.relationship == "partial" and self.coverage != "partial":
            raise ValueError("partial 关系必须使用 partial 覆盖范围")
        if self.relationship == "supports" and self.source.standard_code != "GB/T 20281—2020":
            raise ValueError("supports 关系的来源必须是 GB/T 20281—2020 产品控制项")
        if self.source.standard_code == self.target.standard_code:
            raise ValueError("跨标准映射的来源和目标不能属于同一标准")
        if self.conditional and not self.applicability_conditions:
            raise ValueError("conditional 关系必须提供适用条件")
        if self.review_status == "HumanReviewed" and not self.review_decision_id:
            raise ValueError("人工审核关系必须关联 review_decision_id")
        return self


class MappingReviewDecision(FrozenCrossStandardModel):
    decision_id: str
    question_id: str
    status: Literal["Approved"]
    action: str


class PendingMappingQuestion(FrozenCrossStandardModel):
    question_id: str
    source_control_ids: tuple[str, ...]
    candidate_target_control_ids: tuple[str, ...]
    issue: str
    recommended_handling: str
    status: Literal["AwaitingUserConfirmation"] = "AwaitingUserConfirmation"


class CrossStandardStatistics(FrozenCrossStandardModel):
    mapping_count: int
    by_relationship: dict[str, int]
    by_source_standard: dict[str, int]
    mapped_control_count: dict[str, int]
    unmapped_control_count: dict[str, int]
    pending_question_count: int
    human_reviewed_mapping_count: int


class CrossStandardCatalog(FrozenCrossStandardModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    catalog_id: Literal["firewall-cross-standard-mappings-v1"] = (
        "firewall-cross-standard-mappings-v1"
    )
    catalog_version: str
    generated_on: str
    review_status: Literal["Draft", "Reviewed"]
    scope: str
    unified_catalog_id: str
    unified_catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mapping_policy: tuple[str, ...]
    mappings: tuple[CrossStandardMapping, ...]
    review_decisions: tuple[MappingReviewDecision, ...]
    pending_questions: tuple[PendingMappingQuestion, ...]
    unmapped_control_ids: dict[str, tuple[str, ...]]
    statistics: CrossStandardStatistics
