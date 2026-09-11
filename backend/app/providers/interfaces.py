from typing import Protocol

from app.models.contracts import RawConfigurationSnapshot
from app.models.retrieval import (
    KnowledgeLookup,
    KnowledgeSearchFilters,
    RetrievedKnowledge,
)


class ConfigProvider(Protocol):
    async def fetch_raw_configuration(self) -> RawConfigurationSnapshot: ...


class KnowledgeRetriever(Protocol):
    async def retrieve_exact(
        self,
        *,
        lookup: KnowledgeLookup,
    ) -> tuple[RetrievedKnowledge, ...]: ...

    async def search(
        self,
        *,
        query: str,
        filters: KnowledgeSearchFilters | None = None,
        limit: int = 10,
    ) -> tuple[RetrievedKnowledge, ...]: ...
