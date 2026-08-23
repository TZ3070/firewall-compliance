from __future__ import annotations

import asyncio
from hashlib import sha256
from pathlib import Path

from app.models.retrieval import (
    KnowledgeChunk,
    KnowledgeIndexManifest,
    KnowledgeLookup,
    KnowledgeSearchFilters,
    KnowledgeTextKind,
    RetrievalSource,
    knowledge_point_id,
)
from app.providers.embeddings import SparseEmbedding, prepare_sparse_text
from app.providers.qdrant_knowledge import QdrantKnowledgeStore
from app.providers.reranking import RerankResult


class DeterministicEmbedder:
    dense_model = "test-dense"
    sparse_model = "test-sparse"
    dense_dimension = 3

    _terms = ("日志", "管理", "访问")

    def embed_documents(self, texts: list[str]) -> tuple[tuple[float, ...], ...]:
        return tuple(self.embed_query(text) for text in texts)

    def embed_sparse_documents(self, texts: list[str]) -> tuple[SparseEmbedding, ...]:
        return tuple(self.embed_sparse_query(text) for text in texts)

    def embed_query(self, text: str) -> tuple[float, ...]:
        return tuple(float(text.count(term) + 1) for term in self._terms)

    def embed_sparse_query(self, text: str) -> SparseEmbedding:
        matches = [index + 1 for index, term in enumerate(self._terms) if term in text]
        if not matches:
            matches = [99]
        return SparseEmbedding(
            indices=tuple(matches),
            values=tuple(1.0 for _ in matches),
        )


class ReverseReranker:
    async def rerank(
        self,
        *,
        query: str,
        documents: list[str] | tuple[str, ...],
        top_n: int,
    ) -> tuple[RerankResult, ...]:
        assert query
        return tuple(
            RerankResult(index=index, score=1.0 - rank / 10)
            for rank, index in enumerate(
                reversed(range(len(documents)))
            )
        )[:top_n]


class QueryFailingEmbedder(DeterministicEmbedder):
    def embed_documents(self, texts: list[str]) -> tuple[tuple[float, ...], ...]:
        working = DeterministicEmbedder()
        return tuple(working.embed_query(text) for text in texts)

    def embed_query(self, text: str) -> tuple[float, ...]:
        raise RuntimeError("向量 API 不可用")


class FailingReranker:
    async def rerank(self, **_: object) -> tuple[RerankResult, ...]:
        raise RuntimeError("重排 API 不可用")


def _chunk(record_id: str, text: str, standard_code: str) -> KnowledgeChunk:
    return KnowledgeChunk(
        point_id=knowledge_point_id(
            catalog_id="test-catalog",
            catalog_version="1.0.0",
            record_id=record_id,
        ),
        catalog_id="test-catalog",
        catalog_version="1.0.0",
        record_id=record_id,
        record_type="requirement-control",
        source_catalog_id="test-source",
        source_record_pointer=f"/controls/{record_id}",
        source_catalog_sha256="a" * 64,
        standard_code=standard_code,
        clause_ids=("8.1",),
        title=text,
        text=text,
        search_text=text,
        text_kind=KnowledgeTextKind.SUMMARY,
        content_sha256=sha256(text.encode()).hexdigest(),
        review_status="Candidate",
    )


def _manifest(collection: str, count: int) -> KnowledgeIndexManifest:
    return KnowledgeIndexManifest(
        index_version="test/1.0.0",
        collection_name=collection,
        catalog_id="test-catalog",
        catalog_version="1.0.0",
        catalog_sha256="b" * 64,
        dense_model="test-dense",
        sparse_model="test-sparse",
        point_count=count,
    )


def test_qdrant_exact_lookup_and_hybrid_filtering(tmp_path: Path) -> None:
    chunks = (
        _chunk("logging", "远程日志审计", "JR/T TEST—2026"),
        _chunk("management", "安全管理协议", "GB/T TEST—2026"),
        _chunk("access", "访问控制默认拒绝", "GB/T TEST—2026"),
    )
    store = QdrantKnowledgeStore(
        path=tmp_path / "qdrant",
        collection_name="knowledge",
        embedder=DeterministicEmbedder(),
        prefetch_limit=3,
    )
    try:
        store.rebuild(manifest=_manifest("knowledge", len(chunks)), chunks=chunks)

        exact = asyncio.run(
            store.retrieve_exact(lookup=KnowledgeLookup(record_id="logging"))
        )
        results = asyncio.run(
            store.search(
                query="管理协议",
                filters=KnowledgeSearchFilters(standard_code="GB/T TEST—2026"),
                limit=2,
            )
        )
    finally:
        store.close()

    assert [item.chunk.record_id for item in exact] == ["logging"]
    assert results
    assert all(item.chunk.standard_code == "GB/T TEST—2026" for item in results)
    assert results[0].chunk.record_id == "management"


def test_separate_qdrant_paths_do_not_leak_records(tmp_path: Path) -> None:
    first = QdrantKnowledgeStore(
        path=tmp_path / "first",
        collection_name="knowledge",
        embedder=DeterministicEmbedder(),
    )
    second = QdrantKnowledgeStore(
        path=tmp_path / "second",
        collection_name="knowledge",
        embedder=DeterministicEmbedder(),
    )
    try:
        first.rebuild(
            manifest=_manifest("knowledge", 1),
            chunks=(_chunk("first-only", "日志", "A"),),
        )
        second.rebuild(
            manifest=_manifest("knowledge", 1),
            chunks=(_chunk("second-only", "管理", "B"),),
        )
        leaked = asyncio.run(
            second.retrieve_exact(lookup=KnowledgeLookup(record_id="first-only"))
        )
    finally:
        first.close()
        second.close()

    assert leaked == ()


def test_hybrid_rrf_candidates_are_reranked_after_fusion(tmp_path: Path) -> None:
    chunks = (
        _chunk("logging", "远程日志审计", "A"),
        _chunk("management", "安全管理协议", "A"),
        _chunk("access", "访问控制默认拒绝", "A"),
    )
    store = QdrantKnowledgeStore(
        path=tmp_path / "qdrant-rerank",
        collection_name="knowledge",
        embedder=DeterministicEmbedder(),
        reranker=ReverseReranker(),
        prefetch_limit=3,
    )
    try:
        store.rebuild(manifest=_manifest("knowledge", len(chunks)), chunks=chunks)
        results = asyncio.run(store.search(query="日志", limit=2))
    finally:
        store.close()

    assert len(results) == 2
    assert all(RetrievalSource.RRF in item.retrieval_sources for item in results)
    assert all(RetrievalSource.RERANK in item.retrieval_sources for item in results)
    assert results[0].score == 1.0


def test_search_deduplicates_excerpts_before_control_top_k(tmp_path: Path) -> None:
    first_logging = _chunk("logging", "日志 日志 日志", "A")
    second_logging = first_logging.model_copy(
        update={
            "point_id": knowledge_point_id(
                catalog_id="test-catalog",
                catalog_version="1.0.0",
                record_id="logging:excerpt:2",
            ),
            "text": "日志的另一个原文分块",
            "search_text": "日志 日志的另一个原文分块",
            "content_sha256": sha256(
                "日志的另一个原文分块".encode()
            ).hexdigest(),
        }
    )
    chunks = (
        first_logging,
        second_logging,
        _chunk("management", "管理日志", "A"),
    )
    store = QdrantKnowledgeStore(
        path=tmp_path / "qdrant-control-dedup",
        collection_name="knowledge",
        embedder=DeterministicEmbedder(),
        prefetch_limit=3,
    )
    try:
        store.rebuild(manifest=_manifest("knowledge", len(chunks)), chunks=chunks)
        results = asyncio.run(store.search(query="日志", limit=2))
    finally:
        store.close()

    assert len(results) == 2
    assert len({item.chunk.record_id for item in results}) == 2
    assert {item.chunk.record_id for item in results} == {"logging", "management"}


def test_dense_api_failure_falls_back_to_sparse_with_notice(tmp_path: Path) -> None:
    chunks = (
        _chunk("logging", "远程日志审计", "A"),
        _chunk("management", "安全管理协议", "A"),
    )
    store = QdrantKnowledgeStore(
        path=tmp_path / "qdrant-sparse-fallback",
        collection_name="knowledge",
        embedder=QueryFailingEmbedder(),
        prefetch_limit=2,
    )
    try:
        store.rebuild(manifest=_manifest("knowledge", len(chunks)), chunks=chunks)
        results = asyncio.run(store.search(query="日志", limit=1))
    finally:
        store.close()

    assert results
    assert results[0].retrieval_sources == (RetrievalSource.SPARSE,)
    assert results[0].degradation_notices == (
        "向量 API 暂时不可用，已使用本地关键词检索继续查询。",
    )


def test_rerank_api_failure_returns_rrf_results_with_notice(tmp_path: Path) -> None:
    chunks = (
        _chunk("logging", "远程日志审计", "A"),
        _chunk("management", "安全管理协议", "A"),
    )
    store = QdrantKnowledgeStore(
        path=tmp_path / "qdrant-rerank-fallback",
        collection_name="knowledge",
        embedder=DeterministicEmbedder(),
        reranker=FailingReranker(),
        prefetch_limit=2,
    )
    try:
        store.rebuild(manifest=_manifest("knowledge", len(chunks)), chunks=chunks)
        results = asyncio.run(store.search(query="日志", limit=1))
    finally:
        store.close()

    assert results
    assert RetrievalSource.RRF in results[0].retrieval_sources
    assert RetrievalSource.RERANK not in results[0].retrieval_sources
    assert results[0].degradation_notices == (
        "重排 API 暂时不可用，已按本地检索排序返回结果。",
    )


def test_sparse_preprocessing_preserves_identifiers_and_segments_chinese() -> None:
    prepared = prepare_sparse_text("GB/T 22239—2019 8.1.3 禁用明文管理")

    assert "gb_t" in prepared
    assert "22239_2019" in prepared
    assert "8_1_3" in prepared
    assert "管理" in prepared


def test_search_rejects_a_collection_built_from_another_manifest(tmp_path: Path) -> None:
    manifest = _manifest("knowledge", 1)
    mismatched = manifest.model_copy(update={"catalog_sha256": "c" * 64})
    store = QdrantKnowledgeStore(
        path=tmp_path / "qdrant",
        collection_name="knowledge",
        embedder=DeterministicEmbedder(),
        expected_manifest=mismatched,
    )
    try:
        store.rebuild(
            manifest=manifest,
            chunks=(_chunk("logging", "远程日志", "A"),),
        )
        try:
            asyncio.run(store.search(query="日志"))
        except RuntimeError as exc:
            assert "manifest" in str(exc)
        else:
            raise AssertionError("stale collection manifest was accepted")
    finally:
        store.close()
