from __future__ import annotations

import asyncio
import json

import httpx

from app.providers.embeddings import BailianKnowledgeEmbedder
from app.providers.reranking import BailianKnowledgeReranker


def test_bailian_embedding_uses_compatible_api_and_preserves_input_order(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/compatible-mode/v1/embeddings"
        assert request.headers["Authorization"] == "Bearer embedding-key"
        body = json.loads(request.content)
        assert body["model"] == "text-embedding-v4"
        assert body["dimensions"] == 3
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0, 0.0]},
                    {"index": 0, "embedding": [1.0, 0.0, 0.0]},
                ]
            },
        )

    embedder = BailianKnowledgeEmbedder(
        api_key="embedding-key",
        base_url="https://example.test/compatible-mode/v1",
        dense_model="text-embedding-v4",
        dense_dimension=3,
        sparse_model="Qdrant/bm25",
        cache_dir=tmp_path / "cache",
        transport=httpx.MockTransport(handler),
    )

    assert embedder.embed_documents(("第一条", "第二条")) == (
        (1.0, 0.0, 0.0),
        (0.0, 1.0, 0.0),
    )


def test_bailian_rerank_uses_rrf_candidates_and_returns_scores() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/compatible-api/v1/reranks"
        assert request.headers["Authorization"] == "Bearer rerank-key"
        body = json.loads(request.content)
        assert body["model"] == "qwen3-rerank"
        assert body["top_n"] == 2
        return httpx.Response(
            200,
            json={
                "results": [
                    {"index": 1, "relevance_score": 0.93},
                    {"index": 0, "relevance_score": 0.51},
                ]
            },
        )

    reranker = BailianKnowledgeReranker(
        api_key="rerank-key",
        base_url="https://example.test/compatible-api/v1",
        model="qwen3-rerank",
        instruct="Retrieve relevant compliance passages.",
        transport=httpx.MockTransport(handler),
    )
    results = asyncio.run(
        reranker.rerank(
            query="远程日志要求",
            documents=("日志留存", "远程日志审计"),
            top_n=2,
        )
    )

    assert [item.index for item in results] == [1, 0]
    assert [item.score for item in results] == [0.93, 0.51]
