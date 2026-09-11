from functools import lru_cache

from app.core.config import get_settings
from app.providers.qdrant_knowledge import QdrantKnowledgeStore
from app.providers.retrieval_factory import (
    create_knowledge_embedder,
    create_knowledge_reranker,
)
from app.services.knowledge_index import build_knowledge_chunks


@lru_cache
def get_knowledge_store() -> QdrantKnowledgeStore:
    settings = get_settings()
    manifest, _ = build_knowledge_chunks(
        collection_name=settings.qdrant_collection,
        dense_model=settings.effective_dense_model,
        sparse_model=settings.rag_sparse_model,
    )
    return QdrantKnowledgeStore(
        path=settings.resolved_qdrant_path,
        collection_name=settings.qdrant_collection,
        embedder_factory=lambda: create_knowledge_embedder(settings),
        reranker=create_knowledge_reranker(settings),
        prefetch_limit=settings.rag_prefetch_limit,
        expected_manifest=manifest,
    )
