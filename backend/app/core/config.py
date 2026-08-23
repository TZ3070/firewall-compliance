from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = PROJECT_ROOT / "backend"


class Settings(BaseSettings):
    app_env: str = "development"
    app_name: str = "bank-firewall-compliance-chatbot"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"
    database_path: str = "./data/app-v2.db"
    demo_fixture_mode: bool = True

    rag_backend: Literal["qdrant_local"] = "qdrant_local"
    qdrant_path: str = "./data/qdrant"
    qdrant_collection: str = "firewall-standard-knowledge-v1"
    rag_model_cache_path: str = "./data/model-cache"
    rag_dense_model: str = "BAAI/bge-small-zh-v1.5"
    rag_sparse_model: str = "Qdrant/bm25"
    rag_top_k: int = Field(default=8, ge=1, le=50)
    rag_prefetch_limit: int = Field(default=20, ge=1, le=100)
    rag_enforce_review_status: bool = True

    bailian_embedding_base_url: str = ""
    bailian_embedding_api_key: str = ""
    bailian_embedding_model: str = "text-embedding-v4"
    bailian_embedding_dimension: int = Field(default=1024, ge=64, le=4096)
    bailian_embedding_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    bailian_rerank_base_url: str = ""
    bailian_rerank_api_key: str = ""
    bailian_rerank_model: str = "qwen3-rerank"
    bailian_rerank_timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)
    bailian_rerank_instruct: str = (
        "Given a compliance search query, retrieve relevant standard passages."
    )

    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-v4-pro"
    deepseek_timeout_seconds: float = Field(default=45.0, ge=1.0, le=60.0)

    @property
    def resolved_database_path(self) -> Path:
        configured_path = Path(self.database_path)
        if configured_path.is_absolute():
            return configured_path
        return (BACKEND_ROOT / configured_path).resolve()

    @property
    def resolved_qdrant_path(self) -> Path:
        configured_path = Path(self.qdrant_path)
        if configured_path.is_absolute():
            return configured_path
        return (BACKEND_ROOT / configured_path).resolve()

    @property
    def resolved_rag_model_cache_path(self) -> Path:
        configured_path = Path(self.rag_model_cache_path)
        if configured_path.is_absolute():
            return configured_path
        return (BACKEND_ROOT / configured_path).resolve()

    @property
    def bailian_embedding_enabled(self) -> bool:
        return bool(
            self.bailian_embedding_api_key.strip()
            and self.bailian_embedding_base_url.strip()
        )

    @property
    def bailian_rerank_enabled(self) -> bool:
        return bool(
            self.bailian_rerank_api_key.strip()
            and self.bailian_rerank_base_url.strip()
        )

    @property
    def effective_dense_model(self) -> str:
        return (
            self.bailian_embedding_model
            if self.bailian_embedding_enabled
            else self.rag_dense_model
        )

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
