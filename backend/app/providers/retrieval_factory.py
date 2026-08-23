from __future__ import annotations

from app.core.config import Settings
from app.providers.embeddings import (
    FastEmbedKnowledgeEmbedder,
    KnowledgeEmbedder,
    BailianKnowledgeEmbedder,
)
from app.providers.reranking import BailianKnowledgeReranker, KnowledgeReranker


def create_knowledge_embedder(settings: Settings) -> KnowledgeEmbedder:
    if settings.bailian_embedding_enabled:
        return BailianKnowledgeEmbedder(
            api_key=settings.bailian_embedding_api_key,
            base_url=settings.bailian_embedding_base_url,
            dense_model=settings.bailian_embedding_model,
            dense_dimension=settings.bailian_embedding_dimension,
            sparse_model=settings.rag_sparse_model,
            cache_dir=settings.resolved_rag_model_cache_path,
            timeout_seconds=settings.bailian_embedding_timeout_seconds,
        )
    return FastEmbedKnowledgeEmbedder(
        dense_model=settings.rag_dense_model,
        sparse_model=settings.rag_sparse_model,
        cache_dir=settings.resolved_rag_model_cache_path,
    )


def create_knowledge_reranker(settings: Settings) -> KnowledgeReranker | None:
    if not settings.bailian_rerank_enabled:
        return None
    return BailianKnowledgeReranker(
        api_key=settings.bailian_rerank_api_key,
        base_url=settings.bailian_rerank_base_url,
        model=settings.bailian_rerank_model,
        instruct=settings.bailian_rerank_instruct,
        timeout_seconds=settings.bailian_rerank_timeout_seconds,
    )
