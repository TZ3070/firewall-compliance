from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from threading import Lock
from typing import Callable

from qdrant_client import QdrantClient, models

from app.models.retrieval import (
    KnowledgeChunk,
    KnowledgeIndexManifest,
    KnowledgeLookup,
    KnowledgeSearchFilters,
    RetrievedKnowledge,
    RetrievalSource,
)
from app.providers.embeddings import KnowledgeEmbedder, SparseEmbedding
from app.providers.reranking import KnowledgeReranker


DENSE_VECTOR_NAME = "dense"
SPARSE_VECTOR_NAME = "sparse"
logger = logging.getLogger(__name__)


def _match(key: str, value: str | bool | int) -> models.FieldCondition:
    return models.FieldCondition(key=key, match=models.MatchValue(value=value))


def _payload_filter(
    filters: KnowledgeSearchFilters | None = None,
    *,
    lookup: KnowledgeLookup | None = None,
) -> models.Filter | None:
    conditions: list[models.Condition] = []
    if lookup is not None:
        if lookup.record_id:
            conditions.append(_match("record_id", lookup.record_id))
        if lookup.standard_code:
            conditions.append(_match("standard_code", lookup.standard_code))
        if lookup.clause_id:
            conditions.append(_match("clause_ids", lookup.clause_id))
        if lookup.citation_eligible is not None:
            conditions.append(_match("citation_eligible", lookup.citation_eligible))
    if filters is not None:
        for key in (
            "standard_code",
            "record_type",
            "review_status",
            "citation_eligible",
            "context",
        ):
            value = getattr(filters, key)
            if value is not None:
                conditions.append(_match(key, value))
        if filters.classified_protection_level is not None:
            conditions.append(
                _match(
                    "classified_protection_levels",
                    filters.classified_protection_level,
                )
            )
    return models.Filter(must=conditions) if conditions else None


def _sparse_vector(vector: SparseEmbedding) -> models.SparseVector:
    return models.SparseVector(
        indices=list(vector.indices),
        values=list(vector.values),
    )


class QdrantKnowledgeStore:
    """Local Qdrant storage and fixed dense+sparse RRF retrieval."""

    def __init__(
        self,
        *,
        path: Path,
        collection_name: str,
        embedder: KnowledgeEmbedder | None = None,
        embedder_factory: Callable[[], KnowledgeEmbedder] | None = None,
        reranker: KnowledgeReranker | None = None,
        prefetch_limit: int = 20,
        expected_manifest: KnowledgeIndexManifest | None = None,
    ) -> None:
        path.mkdir(parents=True, exist_ok=True)
        self._client = QdrantClient(path=str(path))
        self._collection_name = collection_name
        self._embedder = embedder
        self._embedder_factory = embedder_factory
        self._reranker = reranker
        self._embedder_lock = Lock()
        self._prefetch_limit = prefetch_limit
        self._expected_manifest = expected_manifest

    def close(self) -> None:
        self._client.close()

    def set_embedder(self, embedder: KnowledgeEmbedder) -> None:
        if self._embedder is not None and (
            self._embedder.dense_model != embedder.dense_model
            or self._embedder.sparse_model != embedder.sparse_model
        ):
            raise ValueError("cannot replace the knowledge store with different models")
        self._embedder = embedder

    def _require_embedder(self) -> KnowledgeEmbedder:
        if self._embedder is not None:
            return self._embedder
        with self._embedder_lock:
            if self._embedder is None and self._embedder_factory is not None:
                self._embedder = self._embedder_factory()
        if self._embedder is None:
            raise RuntimeError("an embedder is required for this operation")
        return self._embedder

    def _assert_collection_compatible(self) -> None:
        if self._expected_manifest is None:
            return
        collection = self._client.get_collection(self._collection_name)
        metadata = collection.config.metadata or {}
        expected = self._expected_manifest.model_dump(mode="json")
        if metadata != expected or collection.points_count != expected["point_count"]:
            raise RuntimeError(
                "Qdrant collection manifest does not match the current catalog"
            )

    def rebuild(
        self,
        *,
        manifest: KnowledgeIndexManifest,
        chunks: Sequence[KnowledgeChunk],
        batch_size: int = 64,
    ) -> None:
        if manifest.collection_name != self._collection_name:
            raise ValueError("manifest collection does not match configured collection")
        if manifest.point_count != len(chunks):
            raise ValueError("manifest point count does not match chunks")
        embedder = self._require_embedder()
        if manifest.dense_model != embedder.dense_model:
            raise ValueError("manifest dense model does not match embedder")
        if manifest.sparse_model != embedder.sparse_model:
            raise ValueError("manifest sparse model does not match embedder")

        if self._client.collection_exists(self._collection_name):
            self._client.delete_collection(self._collection_name)
        self._client.create_collection(
            collection_name=self._collection_name,
            vectors_config={
                DENSE_VECTOR_NAME: models.VectorParams(
                    size=embedder.dense_dimension,
                    distance=models.Distance.COSINE,
                )
            },
            sparse_vectors_config={
                SPARSE_VECTOR_NAME: models.SparseVectorParams(
                    modifier=models.Modifier.IDF,
                )
            },
            metadata=manifest.model_dump(mode="json"),
        )

        for start in range(0, len(chunks), batch_size):
            batch = chunks[start : start + batch_size]
            texts = [chunk.search_text for chunk in batch]
            dense_vectors = embedder.embed_documents(texts)
            sparse_vectors = embedder.embed_sparse_documents(texts)
            if len(dense_vectors) != len(batch) or len(sparse_vectors) != len(batch):
                raise ValueError("embedder returned an unexpected vector count")
            points = [
                models.PointStruct(
                    id=chunk.point_id,
                    vector={
                        DENSE_VECTOR_NAME: list(dense),
                        SPARSE_VECTOR_NAME: _sparse_vector(sparse),
                    },
                    payload=chunk.model_dump(mode="json"),
                )
                for chunk, dense, sparse in zip(
                    batch,
                    dense_vectors,
                    sparse_vectors,
                    strict=True,
                )
            ]
            self._client.upsert(
                collection_name=self._collection_name,
                points=points,
                wait=True,
            )

        collection = self._client.get_collection(self._collection_name)
        if collection.points_count != len(chunks):
            raise RuntimeError("Qdrant point count does not match the manifest")

    async def retrieve_exact(
        self,
        *,
        lookup: KnowledgeLookup,
    ) -> tuple[RetrievedKnowledge, ...]:
        self._assert_collection_compatible()
        records, _ = self._client.scroll(
            collection_name=self._collection_name,
            scroll_filter=_payload_filter(lookup=lookup),
            limit=lookup.limit,
            with_payload=True,
            with_vectors=False,
        )
        return tuple(
            RetrievedKnowledge(
                chunk=KnowledgeChunk.model_validate(record.payload),
                score=1.0,
                retrieval_sources=(RetrievalSource.EXACT,),
            )
            for record in records
        )

    async def search(
        self,
        *,
        query: str,
        filters: KnowledgeSearchFilters | None = None,
        limit: int = 10,
    ) -> tuple[RetrievedKnowledge, ...]:
        self._assert_collection_compatible()
        if not query.strip():
            raise ValueError("query must not be empty")
        embedder = self._require_embedder()
        if limit < 1 or limit > 50:
            raise ValueError("limit must be between 1 and 50")
        payload_filter = _payload_filter(filters)
        sparse = embedder.embed_sparse_query(query)
        degradation_notices: tuple[str, ...] = ()
        try:
            dense = embedder.embed_query(query)
        except Exception:
            logger.warning(
                "dense embedding unavailable; falling back to sparse retrieval",
                exc_info=True,
            )
            dense = None
            degradation_notices = (
                "向量 API 暂时不可用，已使用本地关键词检索继续查询。",
            )
        prefetch_limit = max(self._prefetch_limit, limit)
        candidate_limit = max(prefetch_limit, limit) if self._reranker else limit
        if dense is None:
            response = self._client.query_points(
                collection_name=self._collection_name,
                query=_sparse_vector(sparse),
                using=SPARSE_VECTOR_NAME,
                query_filter=payload_filter,
                limit=candidate_limit,
                with_payload=True,
                with_vectors=False,
            )
            retrieval_sources = (RetrievalSource.SPARSE,)
        else:
            response = self._client.query_points(
                collection_name=self._collection_name,
                prefetch=[
                    models.Prefetch(
                        query=list(dense),
                        using=DENSE_VECTOR_NAME,
                        filter=payload_filter,
                        limit=prefetch_limit,
                    ),
                    models.Prefetch(
                        query=_sparse_vector(sparse),
                        using=SPARSE_VECTOR_NAME,
                        filter=payload_filter,
                        limit=prefetch_limit,
                    ),
                ],
                query=models.FusionQuery(fusion=models.Fusion.RRF),
                query_filter=payload_filter,
                limit=candidate_limit,
                with_payload=True,
                with_vectors=False,
            )
            retrieval_sources = (
                RetrievalSource.DENSE,
                RetrievalSource.SPARSE,
                RetrievalSource.RRF,
            )
        rrf_results = tuple(
            RetrievedKnowledge(
                chunk=KnowledgeChunk.model_validate(point.payload),
                score=max(float(point.score), 0.0),
                retrieval_sources=retrieval_sources,
                degradation_notices=degradation_notices,
            )
            for point in response.points
        )
        if self._reranker is None:
            return rrf_results[:limit]
        try:
            reranked = await self._reranker.rerank(
                query=query,
                documents=tuple(item.chunk.search_text for item in rrf_results),
                top_n=limit,
            )
            if not reranked:
                raise ValueError("reranker returned no results")
            return tuple(
                rrf_results[item.index].model_copy(
                    update={
                        "score": item.score,
                        "retrieval_sources": (
                            *rrf_results[item.index].retrieval_sources,
                            RetrievalSource.RERANK,
                        ),
                    }
                )
                for item in reranked
            )
        except Exception:
            logger.warning(
                "knowledge rerank failed; falling back to RRF order",
                exc_info=True,
            )
            rerank_notice = "重排 API 暂时不可用，已按本地检索排序返回结果。"
            return tuple(
                item.model_copy(
                    update={
                        "degradation_notices": tuple(
                            dict.fromkeys((*item.degradation_notices, rerank_notice))
                        )
                    }
                )
                for item in rrf_results[:limit]
            )
