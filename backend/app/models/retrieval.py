from enum import StrEnum
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FrozenRetrievalModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class KnowledgeTextKind(StrEnum):
    SUMMARY = "summary"
    MEASUREMENT = "measurement"
    VERBATIM = "verbatim"


class RetrievalSource(StrEnum):
    EXACT = "exact"
    DENSE = "dense"
    SPARSE = "sparse"
    RRF = "rrf"
    RERANK = "rerank"


def knowledge_point_id(*, catalog_id: str, catalog_version: str, record_id: str) -> str:
    """Return a stable Qdrant-compatible UUID for a catalog record."""

    identity = f"{catalog_id}:{catalog_version}:{record_id}"
    return str(uuid5(NAMESPACE_URL, identity))


class KnowledgeChunk(FrozenRetrievalModel):
    point_id: str
    catalog_id: str
    catalog_version: str
    record_id: str
    record_type: Literal[
        "requirement-control",
        "product-control",
        "measurement-unit",
    ]
    source_catalog_id: str
    source_record_pointer: str
    source_catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    standard_code: str
    clause_ids: tuple[str, ...]
    title: str
    text: str
    search_text: str
    text_kind: KnowledgeTextKind
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    citation_eligible: bool = False
    review_status: str
    topic: str | None = None
    context: str | None = None
    classified_protection_levels: tuple[int, ...] = ()
    printed_pages: tuple[int, ...] = ()
    pdf_page_indexes: tuple[int, ...] = ()

    @model_validator(mode="after")
    def protect_citation_boundary(self) -> "KnowledgeChunk":
        if not self.citation_eligible:
            return self
        if self.text_kind is not KnowledgeTextKind.VERBATIM:
            raise ValueError("only verbatim standard text can be citation eligible")
        return self


class KnowledgeLookup(FrozenRetrievalModel):
    record_id: str | None = None
    standard_code: str | None = None
    clause_id: str | None = None
    citation_eligible: bool | None = None
    limit: int = Field(default=10, ge=1, le=100)

    @model_validator(mode="after")
    def require_stable_identity(self) -> "KnowledgeLookup":
        if self.record_id:
            return self
        if self.standard_code and self.clause_id:
            return self
        raise ValueError("provide record_id or both standard_code and clause_id")


class KnowledgeSearchFilters(FrozenRetrievalModel):
    standard_code: str | None = None
    record_type: Literal[
        "requirement-control",
        "product-control",
        "measurement-unit",
    ] | None = None
    review_status: str | None = None
    citation_eligible: bool | None = None
    context: str | None = None
    classified_protection_level: int | None = Field(default=None, ge=1, le=4)


class RetrievedKnowledge(FrozenRetrievalModel):
    chunk: KnowledgeChunk
    score: float = Field(ge=0.0)
    retrieval_sources: tuple[RetrievalSource, ...]
    degradation_notices: tuple[str, ...] = ()


class KnowledgeIndexManifest(FrozenRetrievalModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    index_version: str
    collection_name: str
    catalog_id: str
    catalog_version: str
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dense_model: str
    sparse_model: str
    point_count: int = Field(ge=0)
