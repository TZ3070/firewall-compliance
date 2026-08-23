from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Protocol, Sequence

import httpx


_HAN_RUN = re.compile(r"[\u3400-\u9fff]+")
_IDENTIFIER = re.compile(r"[A-Za-z0-9]+(?:[./_—-][A-Za-z0-9]+)+")


@dataclass(frozen=True)
class SparseEmbedding:
    indices: tuple[int, ...]
    values: tuple[float, ...]


class KnowledgeEmbedder(Protocol):
    dense_model: str
    sparse_model: str
    dense_dimension: int

    def embed_documents(
        self,
        texts: Sequence[str],
    ) -> tuple[tuple[float, ...], ...]: ...

    def embed_sparse_documents(
        self,
        texts: Sequence[str],
    ) -> tuple[SparseEmbedding, ...]: ...

    def embed_query(self, text: str) -> tuple[float, ...]: ...

    def embed_sparse_query(self, text: str) -> SparseEmbedding: ...


def prepare_sparse_text(text: str) -> str:
    """Add Chinese character n-grams and intact identifiers for BM25 matching."""

    terms: list[str] = []
    for identifier in _IDENTIFIER.findall(text):
        terms.append(re.sub(r"[./_—-]", "_", identifier.lower()))
    for run in _HAN_RUN.findall(text):
        characters = list(run)
        terms.extend(characters)
        terms.extend(
            "".join(characters[index : index + 2])
            for index in range(len(characters) - 1)
        )
    return f"{text} {' '.join(terms)}".strip()


class FastEmbedKnowledgeEmbedder:
    def __init__(
        self,
        *,
        dense_model: str,
        sparse_model: str,
        cache_dir: Path,
    ) -> None:
        from fastembed import SparseTextEmbedding, TextEmbedding

        cache_dir.mkdir(parents=True, exist_ok=True)
        descriptions = {
            item["model"]: item for item in TextEmbedding.list_supported_models()
        }
        if dense_model not in descriptions:
            raise ValueError(f"unsupported FastEmbed dense model: {dense_model}")

        self.dense_model = dense_model
        self.sparse_model = sparse_model
        self.dense_dimension = int(descriptions[dense_model]["dim"])
        self._dense = TextEmbedding(
            model_name=dense_model,
            cache_dir=str(cache_dir),
            lazy_load=True,
        )
        self._sparse = SparseTextEmbedding(
            model_name=sparse_model,
            cache_dir=str(cache_dir),
            disable_stemmer=True,
            lazy_load=True,
        )

    def embed_documents(
        self,
        texts: Sequence[str],
    ) -> tuple[tuple[float, ...], ...]:
        return tuple(tuple(float(value) for value in vector) for vector in self._dense.embed(texts))

    def embed_sparse_documents(
        self,
        texts: Sequence[str],
    ) -> tuple[SparseEmbedding, ...]:
        prepared = [prepare_sparse_text(text) for text in texts]
        return tuple(self._to_sparse(vector) for vector in self._sparse.embed(prepared))

    def embed_query(self, text: str) -> tuple[float, ...]:
        return next(iter(self.embed_documents((text,))))

    def embed_sparse_query(self, text: str) -> SparseEmbedding:
        prepared = prepare_sparse_text(text)
        vector = next(iter(self._sparse.query_embed(prepared)))
        return self._to_sparse(vector)

    @staticmethod
    def _to_sparse(vector: object) -> SparseEmbedding:
        indices = getattr(vector, "indices")
        values = getattr(vector, "values")
        return SparseEmbedding(
            indices=tuple(int(value) for value in indices),
            values=tuple(float(value) for value in values),
        )


class BailianKnowledgeEmbedder:
    """Alibaba Cloud Model Studio dense embeddings plus local BM25."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        dense_model: str,
        dense_dimension: int,
        sparse_model: str,
        cache_dir: Path,
        timeout_seconds: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key.strip() or not base_url.strip():
            raise ValueError("Bailian embedding API key and base URL are required")
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.dense_model = dense_model
        self.sparse_model = sparse_model
        self.dense_dimension = dense_dimension
        self._api_key = api_key.strip()
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._cache_dir = cache_dir
        self._sparse: object | None = None
        self._sparse_lock = Lock()

    def _require_sparse(self) -> object:
        if self._sparse is not None:
            return self._sparse
        with self._sparse_lock:
            if self._sparse is None:
                from fastembed import SparseTextEmbedding

                self._sparse = SparseTextEmbedding(
                    model_name=self.sparse_model,
                    cache_dir=str(self._cache_dir),
                    disable_stemmer=True,
                    lazy_load=True,
                )
        return self._sparse

    def embed_documents(
        self,
        texts: Sequence[str],
    ) -> tuple[tuple[float, ...], ...]:
        if not texts:
            return ()
        vectors: list[tuple[float, ...]] = []
        for start in range(0, len(texts), 10):
            vectors.extend(self._embed_batch(texts[start : start + 10]))
        return tuple(vectors)

    def _embed_batch(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        body: dict[str, Any] = {
            "model": self.dense_model,
            "input": list(texts),
            "dimensions": self.dense_dimension,
            "encoding_format": "float",
        }
        with httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._api_key}"},
            timeout=self._timeout_seconds,
            transport=self._transport,
        ) as client:
            response = client.post("/embeddings", json=body)
            response.raise_for_status()
            payload = response.json()
        records = sorted(payload["data"], key=lambda item: int(item["index"]))
        if len(records) != len(texts):
            raise ValueError("Bailian embedding response count does not match input")
        vectors = tuple(
            tuple(float(value) for value in record["embedding"])
            for record in records
        )
        if any(len(vector) != self.dense_dimension for vector in vectors):
            raise ValueError("Bailian embedding response dimension mismatch")
        return vectors

    def embed_sparse_documents(
        self,
        texts: Sequence[str],
    ) -> tuple[SparseEmbedding, ...]:
        prepared = [prepare_sparse_text(text) for text in texts]
        sparse = self._require_sparse()
        return tuple(
            self._to_sparse(vector)
            for vector in getattr(sparse, "embed")(prepared)
        )

    def embed_query(self, text: str) -> tuple[float, ...]:
        return self.embed_documents((text,))[0]

    def embed_sparse_query(self, text: str) -> SparseEmbedding:
        sparse = self._require_sparse()
        vector = next(
            iter(getattr(sparse, "query_embed")(prepare_sparse_text(text)))
        )
        return self._to_sparse(vector)

    @staticmethod
    def _to_sparse(vector: object) -> SparseEmbedding:
        indices = getattr(vector, "indices")
        values = getattr(vector, "values")
        return SparseEmbedding(
            indices=tuple(int(value) for value in indices),
            values=tuple(float(value) for value in values),
        )
