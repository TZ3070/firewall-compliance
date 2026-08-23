from __future__ import annotations

from app.core.config import get_settings
from app.providers.qdrant_knowledge import QdrantKnowledgeStore
from app.providers.retrieval_factory import create_knowledge_embedder
from app.services.knowledge_index import build_knowledge_chunks


def main() -> None:
    settings = get_settings()
    manifest, chunks = build_knowledge_chunks(
        collection_name=settings.qdrant_collection,
        dense_model=settings.effective_dense_model,
        sparse_model=settings.rag_sparse_model,
    )
    embedder = create_knowledge_embedder(settings)
    store = QdrantKnowledgeStore(
        path=settings.resolved_qdrant_path,
        collection_name=settings.qdrant_collection,
        embedder=embedder,
        prefetch_limit=settings.rag_prefetch_limit,
    )
    try:
        store.rebuild(manifest=manifest, chunks=chunks)
    finally:
        store.close()

    print(
        f"indexed {manifest.point_count} records into "
        f"{settings.resolved_qdrant_path}/{settings.qdrant_collection}"
    )
    print(f"catalog_sha256={manifest.catalog_sha256}")
    print(
        f"citation_eligible={sum(chunk.citation_eligible for chunk in chunks)}"
    )


if __name__ == "__main__":
    main()
