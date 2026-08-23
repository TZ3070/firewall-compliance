from typing import Protocol

from app.models.contracts import FirewallSnapshot
from app.models.retrieval import (
    KnowledgeLookup,
    KnowledgeSearchFilters,
    RetrievedKnowledge,
)


class ConfigProvider(Protocol):
    async def get_current_snapshot(self) -> FirewallSnapshot: ...

    async def get_original_config(self) -> str: ...


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
