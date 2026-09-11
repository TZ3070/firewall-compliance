from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import get_settings
from app.models.contracts import RawConfigurationSnapshot
from app.models.retrieval import KnowledgeSearchFilters
from app.parsers.huawei_cli import HuaweiCliParser
from app.providers.qdrant_knowledge import QdrantKnowledgeStore
from app.providers.retrieval_factory import (
    create_knowledge_embedder,
    create_knowledge_reranker,
)
from app.repositories.sqlite_acquisition import SQLiteAcquisitionRepository
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.configuration import ConfigurationService
from app.services.knowledge_index import build_knowledge_chunks


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
SCENARIO_DIR = BACKEND_ROOT / "data" / "huawei-atomic-configs"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "outputs" / "huawei-pipeline-evaluation"


def _json_dump(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _contains(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return actual == expected
    return actual == expected


@dataclass(frozen=True)
class ScenarioConfigProvider:
    cfg_path: Path

    async def fetch_raw_configuration(self) -> RawConfigurationSnapshot:
        content = self.cfg_path.read_text(encoding="utf-8")
        if not any(
            line.strip().casefold().startswith("sysname ")
            for line in content.splitlines()
        ):
            content = f"sysname HuaweiAtomicFixture\n{content}"
        return RawConfigurationSnapshot(
            acquisition_id=f"acq-eval-{uuid4().hex}",
            target_id=self.cfg_path.stem,
            provider_version="huawei-scenario-evaluator/2.0.0",
            collected_at=datetime.now(timezone.utc),
            content=content,
            content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            vendor_hint="Huawei",
        )


def _build_knowledge_store() -> QdrantKnowledgeStore:
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


async def _evaluate_scenario(
    *,
    cfg_path: Path,
    expected: dict[str, Any],
    knowledge_store: QdrantKnowledgeStore,
    database_path: Path,
) -> dict[str, Any]:
    provider = ScenarioConfigProvider(cfg_path)
    service = ConfigurationService(
        provider=provider,
        repository=SQLiteSnapshotRepository(database_path),
        acquisition_repository=SQLiteAcquisitionRepository(database_path),
    )
    current = await service.get_current_config()
    draft = P0CurrentConfigRuleEngine().evaluate_controls(current)

    raw_patch = HuaweiCliParser().parse_patch(
        cfg_path.read_text(encoding="utf-8")
    )
    parser_matches = _contains(raw_patch, expected["expected_parsed_patch"])
    primary = expected["primary_standard"]
    query = " ".join(
        (
            str(primary["standard_code"]),
            str(primary["title"]),
            str(expected["judgment_reason"]),
        )
    )
    retrieved = await knowledge_store.search(
        query=query,
        filters=KnowledgeSearchFilters(
            review_status="HumanReviewed",
            citation_eligible=True,
        ),
        limit=8,
    )
    retrieved_ids = [item.chunk.record_id for item in retrieved]
    target_id = str(primary["record_id"])
    target_rank = (
        retrieved_ids.index(target_id) + 1 if target_id in retrieved_ids else None
    )
    matching_finding = next(
        (item for item in draft.findings if item.control_key == target_id),
        None,
    )
    degradation_notices = tuple(
        dict.fromkeys(
            notice
            for item in retrieved
            for notice in item.degradation_notices
        )
    )

    return {
        "scenario_id": expected["scenario_id"],
        "config_file": cfg_path.name,
        "vendor": current.vendor_detection.vendor if current.vendor_detection else None,
        "parser_version": current.parser_version,
        "parser_matches_expected_patch": parser_matches,
        "rule_finding_count": len(draft.findings),
        "target": {
            "record_id": target_id,
            "standard_code": primary["standard_code"],
            "clause_id": primary["clause_id"],
            "expected_result": expected["expected_result"],
            "retrieval_rank": target_rank,
            "rule_result": (
                matching_finding.result.value if matching_finding is not None else None
            ),
            "rule_result_matches": (
                matching_finding.result.value == expected["expected_result"]
                if matching_finding is not None
                else None
            ),
        },
        "retrieval": {
            "query": query,
            "record_ids": retrieved_ids,
            "sources": [
                [source.value for source in item.retrieval_sources]
                for item in retrieved
            ],
            "degradation_notices": degradation_notices,
        },
    }


def _summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    recalled = sum(item["target"]["retrieval_rank"] is not None for item in results)
    rule_covered = [item for item in results if item["target"]["rule_result"] is not None]
    rule_correct = sum(item["target"]["rule_result_matches"] is True for item in rule_covered)
    return {
        "scenario_count": total,
        "parser_match_count": sum(
            item["parser_matches_expected_patch"] for item in results
        ),
        "target_recall_at_8_count": recalled,
        "target_recall_at_8": round(recalled / total, 4) if total else None,
        "current_rule_target_coverage_count": len(rule_covered),
        "current_rule_target_correct_count": rule_correct,
        "runs_with_degradation_notices": sum(
            bool(item["retrieval"]["degradation_notices"])
            for item in results
        ),
    }


def _markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    rows = []
    for item in payload["results"]:
        target = item["target"]
        rows.append(
            "| {scenario} | {parser} | {rank} | {rule} | {expected} |".format(
                scenario=item["scenario_id"],
                parser="通过" if item["parser_matches_expected_patch"] else "失败",
                rank=target["retrieval_rank"] or "未召回",
                rule=target["rule_result"] or "当前规则集未直接覆盖",
                expected=target["expected_result"],
            )
        )
    return "\n".join(
        [
            "# Huawei 配置管道与 RAG 回归评测",
            "",
            "> 本脚本验证当前 v2 配置、Parser、规则和检索能力，不伪造 Agent-Compose Run。",
            "",
            f"- 场景数：{summary['scenario_count']}",
            f"- Parser 通过：{summary['parser_match_count']}/{summary['scenario_count']}",
            f"- 目标 Recall@8：{summary['target_recall_at_8_count']}/{summary['scenario_count']}",
            f"- 当前规则直接覆盖：{summary['current_rule_target_coverage_count']}/{summary['scenario_count']}",
            "",
            "| 场景 | Parser | RAG Rank | 当前规则结果 | 预期结果 |",
            "|---|---:|---:|---|---|",
            *rows,
            "",
        ]
    )


async def run_evaluation(
    *,
    output_dir: Path,
    limit: int | None,
) -> dict[str, Any]:
    cfg_paths = sorted(SCENARIO_DIR.glob("*.cfg"))
    if limit is not None:
        cfg_paths = cfg_paths[:limit]
    if not cfg_paths:
        raise RuntimeError("没有找到待评测 CFG")

    output_dir.mkdir(parents=True, exist_ok=True)
    database_path = output_dir / "evaluation.db"
    knowledge_store = _build_knowledge_store()
    results = []
    try:
        for index, cfg_path in enumerate(cfg_paths, start=1):
            expected = json.loads(
                cfg_path.with_suffix(".json").read_text(encoding="utf-8")
            )
            print(f"[{index}/{len(cfg_paths)}] {expected['scenario_id']}", flush=True)
            results.append(
                await _evaluate_scenario(
                    cfg_path=cfg_path,
                    expected=expected,
                    knowledge_store=knowledge_store,
                    database_path=database_path,
                )
            )
    finally:
        knowledge_store.close()

    settings = get_settings()
    payload = {
        "schema_version": "2.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": "configuration-parser-rules-rag",
        "agent_compose_run": False,
        "models": {
            "dense": settings.effective_dense_model,
            "sparse": settings.rag_sparse_model,
            "reranker": (
                settings.bailian_rerank_model
                if settings.bailian_rerank_enabled
                else None
            ),
        },
        "summary": _summary(results),
        "results": results,
    }
    (output_dir / "evaluation-results.json").write_text(
        _json_dump(payload) + "\n",
        encoding="utf-8",
    )
    (output_dir / "evaluation-summary.md").write_text(
        _markdown(payload),
        encoding="utf-8",
    )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="运行当前 v2 Huawei 配置管道、规则与 RAG 回归评测。"
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit 必须大于 0")

    payload = asyncio.run(
        run_evaluation(
            output_dir=args.output_dir.resolve(),
            limit=args.limit,
        )
    )
    print(_json_dump(payload["summary"]))
    print(f"output={args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
