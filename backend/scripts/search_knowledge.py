from __future__ import annotations

import argparse
import asyncio

from app.core.config import get_settings
from app.models.retrieval import KnowledgeSearchFilters
from app.providers.qdrant_knowledge import QdrantKnowledgeStore
from app.providers.retrieval_factory import (
    create_knowledge_embedder,
    create_knowledge_reranker,
)


async def search(query: str, standard_code: str | None, limit: int) -> None:
    settings = get_settings()
    embedder = create_knowledge_embedder(settings)
    store = QdrantKnowledgeStore(
        path=settings.resolved_qdrant_path,
        collection_name=settings.qdrant_collection,
        embedder=embedder,
        reranker=create_knowledge_reranker(settings),
        prefetch_limit=settings.rag_prefetch_limit,
    )
    try:
        results = await store.search(
            query=query,
            filters=(
                KnowledgeSearchFilters(standard_code=standard_code)
                if standard_code
                else None
            ),
            limit=limit,
        )
    finally:
        store.close()

    for rank, result in enumerate(results, start=1):
        chunk = result.chunk
        print(
            f"{rank}. {chunk.record_id} | {chunk.standard_code} | "
            f"score={result.score:.6f} | citable={chunk.citation_eligible} | "
            f"sources={','.join(source.value for source in result.retrieval_sources)}"
        )
        print(f"   {chunk.title}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Test local Qdrant hybrid retrieval")
    parser.add_argument("query")
    parser.add_argument("--standard-code")
    parser.add_argument("--limit", type=int, default=5)
    args = parser.parse_args()
    asyncio.run(search(args.query, args.standard_code, args.limit))


if __name__ == "__main__":
    main()
