from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FrozenCatalogModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CatalogSource(FrozenCatalogModel):
    catalog_id: str
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    standard_code: str
    title: str
    review_status: str
    record_count: int = Field(ge=0)


class ClauseReference(FrozenCatalogModel):
    relation: Literal["requirement", "test", "measurement"] = "requirement"
    clause_id: str
    item: str | None = None
    classified_protection_level: int | None = Field(default=None, ge=1, le=4)
    printed_pages: tuple[int, ...] = ()
    pdf_page_indexes: tuple[int, ...] = ()


class UnifiedControl(FrozenCatalogModel):
    record_id: str
    record_type: Literal["requirement-control", "product-control"]
    source_catalog_id: str
    source_record_pointer: str
    standard_code: str
    title: str
    topic: str
    context: str
    conditional: bool
    priority: str | None = None
    classified_protection_levels: tuple[int, ...] = ()
    assessment_modes: tuple[str, ...]
    summary: str
    source_references: tuple[ClauseReference, ...]
    evidence_selectors: tuple[str, ...] = ()
    applicability_condition: str | None = None
    review_status: str
    search_text: str


class UnifiedMeasurementUnit(FrozenCatalogModel):
    record_id: str
    record_type: Literal["measurement-unit"] = "measurement-unit"
    source_catalog_id: str
    source_record_pointer: str
    standard_code: str
    canonical_measurement_unit_id: str
    source_measurement_unit_id: str
    record_aliases: tuple[str, ...] = ()
    classified_protection_level: int = Field(ge=1, le=4)
    context: str
    conditional: bool
    guide_clause_id: str
    printed_pages: tuple[int, ...]
    pdf_page_indexes: tuple[int, ...]
    requirement_standard_code: str
    requirement_clause_id: str
    requirement_bullet: str | None = None
    requirement_control_ids: tuple[str, ...]
    measurement_indicator: str
    assessment_objects: str
    assessment_steps: tuple[str, ...]
    decision_rule: str
    assessment_methods: tuple[str, ...]
    mapping_confidence: float = Field(ge=0.0, le=1.0)
    mapping_review_status: str
    search_text: str


class CatalogRelationship(FrozenCatalogModel):
    relationship_id: str
    relationship_type: Literal["measures"]
    source_record_id: str
    target_record_id: str
    source_standard_code: str
    target_standard_code: str
    confidence: float = Field(ge=0.0, le=1.0)
    review_status: str
    coverage: Literal["full", "partial"] = "full"
    blocks_standalone_pass: bool = False


class CatalogAlias(FrozenCatalogModel):
    alias_id: str
    alias_type: Literal["source-record-id"]
    alias_record_id: str
    canonical_record_id: str
    decision_id: str


class ReviewDecision(FrozenCatalogModel):
    decision_id: str
    decision_type: Literal[
        "context-normalization",
        "mapping-wording-equivalence",
        "mapping-partial-coverage",
        "source-id-alias",
    ]
    status: Literal["Approved"]
    applies_to: tuple[str, ...]
    action: str
    rationale: str


class CatalogException(FrozenCatalogModel):
    exception_id: str
    exception_type: Literal["source-anomaly", "mapping-needs-review"]
    source_catalog_id: str
    record_id: str | None = None
    details: dict[str, Any]
    resolution_status: Literal["unresolved", "resolved"]
    resolution_decision_id: str | None = None
    blocks_final_determination: bool


class CatalogStatistics(FrozenCatalogModel):
    source_catalog_count: int
    control_count: int
    requirement_control_count: int
    product_control_count: int
    measurement_unit_count: int
    relationship_count: int
    exception_count: int
    unresolved_exception_count: int
    alias_count: int
    review_decision_count: int
    by_standard: dict[str, int]
    by_context: dict[str, int]


class ReviewGate(FrozenCatalogModel):
    final_determination_allowed: bool
    reason: str
    unresolved_exception_ids: tuple[str, ...]


class UnifiedFirewallCatalog(FrozenCatalogModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    catalog_id: Literal["unified-firewall-catalog-v1"] = (
        "unified-firewall-catalog-v1"
    )
    catalog_version: str
    generated_on: str
    scope: str
    sources: tuple[CatalogSource, ...]
    controls: tuple[UnifiedControl, ...]
    measurement_units: tuple[UnifiedMeasurementUnit, ...]
    relationships: tuple[CatalogRelationship, ...]
    aliases: tuple[CatalogAlias, ...]
    review_decisions: tuple[ReviewDecision, ...]
    exceptions: tuple[CatalogException, ...]
    statistics: CatalogStatistics
    review_gate: ReviewGate
