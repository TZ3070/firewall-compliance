from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence

import httpx


@dataclass(frozen=True)
class RerankResult:
    index: int
    score: float


class KnowledgeReranker(Protocol):
    async def rerank(
        self,
        *,
        query: str,
        documents: Sequence[str],
        top_n: int,
    ) -> tuple[RerankResult, ...]: ...


class BailianKnowledgeReranker:
    """Adapter for Model Studio's qwen3-rerank compatible endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str = "qwen3-rerank",
        instruct: str,
        timeout_seconds: float = 20.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key.strip() or not base_url.strip():
            raise ValueError("Bailian rerank API key and base URL are required")
        self._api_key = api_key.strip()
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._instruct = instruct
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def rerank(
        self,
        *,
        query: str,
        documents: Sequence[str],
        top_n: int,
    ) -> tuple[RerankResult, ...]:
        if not documents:
            return ()
        body: dict[str, Any] = {
            "model": self._model,
            "query": query,
            "documents": list(documents),
            "top_n": min(top_n, len(documents)),
            "instruct": self._instruct,
        }
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._api_key}"},
            timeout=self._timeout_seconds,
            transport=self._transport,
        ) as client:
            response = await client.post("/reranks", json=body)
            response.raise_for_status()
            payload = response.json()
        results = tuple(
            RerankResult(
                index=int(item["index"]),
                score=max(float(item["relevance_score"]), 0.0),
            )
            for item in payload["results"]
        )
        if len({item.index for item in results}) != len(results):
            raise ValueError("Bailian rerank returned duplicate indexes")
        if any(item.index < 0 or item.index >= len(documents) for item in results):
            raise ValueError("Bailian rerank returned an invalid document index")
        return results
