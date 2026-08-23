from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.agent.react_agent import BoundedComplianceReActAgent
from app.core.config import get_settings
from app.models.agent import ModelCandidateAssessment, ReActAction, ReActObservation, ReActTool
from app.models.contracts import CurrentConfigResponse, FirewallSnapshot
from app.models.retrieval import KnowledgeLookup, KnowledgeSearchFilters, RetrievedKnowledge
from app.parsers.huawei_cli import HuaweiCliParser
from app.providers.deepseek import DeepSeekAgent
from app.providers.interfaces import KnowledgeRetriever
from app.providers.mock_config import build_snapshot
from app.providers.qdrant_knowledge import QdrantKnowledgeStore
from app.providers.retrieval_factory import (
    create_knowledge_embedder,
    create_knowledge_reranker,
)
from app.repositories.sqlite_report import SQLiteReportRepository
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.citations import CitationValidator
from app.services.configuration import ConfigurationService
from app.services.knowledge_index import build_knowledge_chunks
from app.services.reports import ReportService


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
SCENARIO_DIR = BACKEND_ROOT / "data" / "huawei-atomic-configs"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "outputs" / "huawei-agent-evaluation"
DEFAULT_REQUEST = "开始检测当前防火墙配置"


def _json_dump(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json_dump(value) + "\n", encoding="utf-8")


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


@dataclass(frozen=True)
class ScenarioConfigProvider:
    cfg_path: Path

    async def get_original_config(self) -> str:
        return self.cfg_path.read_text(encoding="utf-8")

    async def get_current_snapshot(self) -> FirewallSnapshot:
        cli_content = await self.get_original_config()
        raw_content = HuaweiCliParser().parse_complete(cli_content)
        return build_snapshot(raw_content)


class RecordingKnowledgeRetriever:
    def __init__(self, delegate: KnowledgeRetriever) -> None:
        self._delegate = delegate
        self.search_calls: list[dict[str, Any]] = []

    async def retrieve_exact(
        self,
        *,
        lookup: KnowledgeLookup,
    ) -> tuple[RetrievedKnowledge, ...]:
        return await self._delegate.retrieve_exact(lookup=lookup)

    async def search(
        self,
        *,
        query: str,
        filters: KnowledgeSearchFilters | None = None,
        limit: int = 10,
    ) -> tuple[RetrievedKnowledge, ...]:
        results = await self._delegate.search(
            query=query,
            filters=filters,
            limit=limit,
        )
        self.search_calls.append(
            {
                "query": query,
                "limit": limit,
                "results": [item.model_dump(mode="json") for item in results],
            }
        )
        return results


class RecordingDeepSeekAgent:
    def __init__(self, delegate: DeepSeekAgent) -> None:
        self._delegate = delegate
        self.evaluation_calls: list[dict[str, Any]] = []

    async def decide_react_action(
        self,
        *,
        user_request: str,
        allowed_tools: tuple[ReActTool, ...],
        observations: tuple[ReActObservation, ...],
    ) -> ReActAction | None:
        return await self._delegate.decide_react_action(
            user_request=user_request,
            allowed_tools=allowed_tools,
            observations=observations,
        )

    async def evaluate_compliance_candidates(
        self,
        *,
        configuration: CurrentConfigResponse,
        knowledge: tuple[RetrievedKnowledge, ...],
    ) -> tuple[ModelCandidateAssessment, ...]:
        # DeepSeekAgent deliberately sends only knowledge[:8]. Persist exactly that
        # boundary so retrieval misses and model misses are measured separately.
        sent = knowledge[:8]
        assessments = await self._delegate.evaluate_compliance_candidates(
            configuration=configuration,
            knowledge=knowledge,
        )
        self.evaluation_calls.append(
            {
                "sent_record_ids": [item.chunk.record_id for item in sent],
                "assessments": [item.model_dump(mode="json") for item in assessments],
            }
        )
        return assessments

    def consume_notices(self) -> tuple[str, ...]:
        return self._delegate.consume_notices()


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


def _target_report_findings(report: dict[str, Any], target_record_id: str) -> list[dict[str, Any]]:
    return [
        finding
        for level in report["levels"]
        for finding in level["findings"]
        if finding["control_id"] == target_record_id
    ]


def _target_rank(search_calls: list[dict[str, Any]], target_record_id: str) -> int | None:
    ranks = [
        index
        for call in search_calls
        for index, item in enumerate(call["results"], start=1)
        if item["chunk"]["record_id"] == target_record_id
    ]
    return min(ranks) if ranks else None


async def _evaluate_scenario(
    *,
    cfg_path: Path,
    expected: dict[str, Any],
    knowledge_store: QdrantKnowledgeStore,
    deepseek: DeepSeekAgent,
    database_path: Path,
    user_request: str,
) -> dict[str, Any]:
    recording_retriever = RecordingKnowledgeRetriever(knowledge_store)
    recording_deepseek = RecordingDeepSeekAgent(deepseek)
    snapshot_repository = SQLiteSnapshotRepository(database_path)
    report_repository = SQLiteReportRepository(database_path)
    configuration_service = ConfigurationService(
        provider=ScenarioConfigProvider(cfg_path),
        repository=snapshot_repository,
    )
    report_service = ReportService(
        rule_engine=P0CurrentConfigRuleEngine(),
        citation_validator=CitationValidator(
            knowledge_store,
            enforce_review_status=get_settings().rag_enforce_review_status,
        ),
        repository=report_repository,
    )
    agent = BoundedComplianceReActAgent(
        configuration_service=configuration_service,
        report_service=report_service,
        knowledge_retriever=recording_retriever,
        deepseek_agent=recording_deepseek,  # type: ignore[arg-type]
    )

    started_at = datetime.now(timezone.utc)
    run = await agent.run(user_request)
    finished_at = datetime.now(timezone.utc)
    report = run.report.model_dump(mode="json")

    primary = expected["primary_standard"]
    primary_id = primary["record_id"]
    expected_ids = _unique(
        [primary_id]
        + [item["record_id"] for item in expected.get("related_standards", [])]
    )
    retrieved_ids = _unique(
        [
            item["chunk"]["record_id"]
            for call in recording_retriever.search_calls
            for item in call["results"]
        ]
    )
    sent_to_model_ids = _unique(
        [
            record_id
            for call in recording_deepseek.evaluation_calls
            for record_id in call["sent_record_ids"]
        ]
    )
    model_assessments = [
        assessment
        for call in recording_deepseek.evaluation_calls
        for assessment in call["assessments"]
    ]
    primary_model_items = [
        item for item in model_assessments if item["record_id"] == primary_id
    ]
    primary_model_result = (
        primary_model_items[0]["suggested_result"] if primary_model_items else None
    )
    target_findings = _target_report_findings(report, primary_id)
    expected_level = primary.get("classified_protection_level")
    level_target_findings = [
        finding
        for finding in target_findings
        if finding["classified_protection_level"] == expected_level
    ]
    selected_findings = level_target_findings or target_findings
    final_results = _unique([finding["result"] for finding in selected_findings])
    expected_result = expected["expected_result"]

    return {
        "schema_version": "1.0.0",
        "scenario_id": expected["scenario_id"],
        "config_file": cfg_path.name,
        "expected_file": cfg_path.with_suffix(".json").name,
        "user_request": user_request,
        "started_at": started_at.isoformat(timespec="seconds"),
        "finished_at": finished_at.isoformat(timespec="seconds"),
        "expected": {
            "result": expected_result,
            "primary_record_id": primary_id,
            "primary_standard_code": primary["standard_code"],
            "primary_clause_id": primary["clause_id"],
            "accepted_record_ids": expected_ids,
            "reason": expected["judgment_reason"],
            "limitations": expected["limitations"],
        },
        "metrics": {
            "primary_recalled": primary_id in retrieved_ids,
            "primary_recall_rank": _target_rank(
                recording_retriever.search_calls, primary_id
            ),
            "any_expected_record_recalled": bool(set(expected_ids) & set(retrieved_ids)),
            "primary_sent_to_model": primary_id in sent_to_model_ids,
            "primary_answered_by_model": primary_model_result is not None,
            "primary_model_result": primary_model_result,
            "primary_model_judgment_correct": (
                primary_model_result == expected_result
                if primary_model_result is not None
                else None
            ),
            "end_to_end_model_success": (
                primary_id in retrieved_ids
                and primary_id in sent_to_model_ids
                and primary_model_result == expected_result
            ),
            "target_present_in_final_report": bool(selected_findings),
            "final_report_results": final_results,
            "final_report_target_correct": (
                expected_result in final_results if final_results else None
            ),
        },
        "retrieval": {
            "calls": recording_retriever.search_calls,
            "retrieved_record_ids": retrieved_ids,
        },
        "model": {
            "calls": recording_deepseek.evaluation_calls,
            "sent_record_ids": sent_to_model_ids,
            "assessments": model_assessments,
            "gated_candidates": [
                item.model_dump(mode="json") for item in run.candidates
            ],
        },
        "agent": {
            "trace": run.trace.model_dump(mode="json"),
            "notices": list(run.notices),
        },
        "configuration": run.configuration.model_dump(mode="json"),
        "report": report,
    }


def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    recalled = sum(item["metrics"]["primary_recalled"] for item in results)
    any_recalled = sum(
        item["metrics"]["any_expected_record_recalled"] for item in results
    )
    sent = sum(item["metrics"]["primary_sent_to_model"] for item in results)
    answered = [
        item
        for item in results
        if item["metrics"]["primary_answered_by_model"]
    ]
    correct_answered = sum(
        item["metrics"]["primary_model_judgment_correct"] for item in answered
    )
    end_to_end = sum(
        item["metrics"]["end_to_end_model_success"] for item in results
    )
    final_present = [
        item
        for item in results
        if item["metrics"]["target_present_in_final_report"]
    ]
    final_correct = sum(
        bool(item["metrics"]["final_report_target_correct"])
        for item in final_present
    )
    degraded = sum(bool(item["agent"]["notices"]) for item in results)

    def rate(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    return {
        "scenario_count": total,
        "primary_recalled_count": recalled,
        "primary_recall_at_agent_k": rate(recalled, total),
        "any_expected_record_recalled_count": any_recalled,
        "any_expected_record_recall_at_agent_k": rate(any_recalled, total),
        "primary_sent_to_model_count": sent,
        "primary_sent_to_model_rate": rate(sent, total),
        "primary_answered_by_model_count": len(answered),
        "model_correct_when_answered_count": correct_answered,
        "model_accuracy_when_answered": rate(correct_answered, len(answered)),
        "end_to_end_model_success_count": end_to_end,
        "end_to_end_model_success_rate": rate(end_to_end, total),
        "target_present_in_final_report_count": len(final_present),
        "final_report_target_correct_count": final_correct,
        "final_report_accuracy_when_present": rate(final_correct, len(final_present)),
        "runs_with_degradation_notices": degraded,
    }


def _format_assessments(assessments: list[dict[str, Any]]) -> str:
    if not assessments:
        return "无"
    return "、".join(
        f"{item['record_id']}={item['suggested_result']}"
        for item in assessments
    ).replace("|", "&#124;")


def _build_markdown(
    *,
    generated_at: str,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
) -> str:
    rows: list[str] = []
    for item in results:
        expected = item["expected"]
        metrics = item["metrics"]
        actual = (
            f"RAG目标召回：{'✅' if metrics['primary_recalled'] else '❌'}"
            f"（rank={metrics['primary_recall_rank'] or '-'}）<br>"
            f"送入模型：{'✅' if metrics['primary_sent_to_model'] else '❌'}<br>"
            f"模型目标结论：{metrics['primary_model_result'] or '未判断'} "
            f"{'✅' if metrics['primary_model_judgment_correct'] else '❌' if metrics['primary_model_judgment_correct'] is False else '—'}<br>"
            f"模型实际判断：{_format_assessments(item['model']['assessments'])}<br>"
            f"正式报告目标结果：{', '.join(metrics['final_report_results']) or '未进入报告'}"
        )
        expected_cell = (
            f"**{expected['result']}**<br>"
            f"{expected['primary_record_id']}<br>"
            f"{expected['primary_standard_code']} · {expected['primary_clause_id']}"
        )
        config_link = (
            "../../backend/data/huawei-atomic-configs/" + item["config_file"]
        )
        rows.append(
            f"| [{item['config_file']}]({config_link}) | {expected_cell} | {actual} |"
        )

    return "\n".join(
        [
            "# 华为原子配置 Agent/RAG/大模型评测",
            "",
            f"- 生成时间（UTC）：`{generated_at}`",
            f"- 场景数：{summary['scenario_count']}",
            f"- 主目标条款召回：{summary['primary_recalled_count']}/{summary['scenario_count']}（{summary['primary_recall_at_agent_k']}）",
            f"- 主目标送入模型：{summary['primary_sent_to_model_count']}/{summary['scenario_count']}（{summary['primary_sent_to_model_rate']}）",
            f"- 模型条件准确率：{summary['model_correct_when_answered_count']}/{summary['primary_answered_by_model_count']}（{summary['model_accuracy_when_answered']}）",
            f"- 端到端模型成功率：{summary['end_to_end_model_success_count']}/{summary['scenario_count']}（{summary['end_to_end_model_success_rate']}）",
            "- 统计口径：只考察每个金标文件声明的目标标准，不因返回其他标准而扣分。‘条件准确率’只计算模型实际回答了目标条款的场景；‘端到端成功’要求目标被召回、送入模型且结论正确。",
            "",
            "| 配置文件 | 预期结果 | Agent 实际检测结果 |",
            "|---|---|---|",
            *rows,
            "",
        ]
    )


async def run_evaluation(
    *,
    output_dir: Path,
    user_request: str,
    limit: int | None,
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.deepseek_api_key.strip():
        raise RuntimeError("DEEPSEEK_API_KEY 未配置，不能运行真实大模型评测")
    if not settings.bailian_embedding_enabled:
        raise RuntimeError("百炼 Embedding 未配置，不能运行真实混合检索评测")

    cfg_paths = sorted(SCENARIO_DIR.glob("*.cfg"))
    if limit is not None:
        cfg_paths = cfg_paths[:limit]
    if not cfg_paths:
        raise RuntimeError("没有找到待评测 CFG")

    output_dir.mkdir(parents=True, exist_ok=True)
    detail_dir = output_dir / "details"
    detail_dir.mkdir(parents=True, exist_ok=True)
    database_path = output_dir / "evaluation.db"
    knowledge_store = _build_knowledge_store()
    deepseek = DeepSeekAgent(
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        model=settings.deepseek_model,
        timeout_seconds=settings.deepseek_timeout_seconds,
    )
    results: list[dict[str, Any]] = []
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        for index, cfg_path in enumerate(cfg_paths, start=1):
            expected = json.loads(
                cfg_path.with_suffix(".json").read_text(encoding="utf-8")
            )
            print(f"[{index}/{len(cfg_paths)}] {expected['scenario_id']}", flush=True)
            try:
                result = await _evaluate_scenario(
                    cfg_path=cfg_path,
                    expected=expected,
                    knowledge_store=knowledge_store,
                    deepseek=deepseek,
                    database_path=database_path,
                    user_request=user_request,
                )
            except Exception as exc:
                result = {
                    "schema_version": "1.0.0",
                    "scenario_id": expected["scenario_id"],
                    "config_file": cfg_path.name,
                    "expected_file": cfg_path.with_suffix(".json").name,
                    "expected": {
                        "result": expected["expected_result"],
                        "primary_record_id": expected["primary_standard"]["record_id"],
                        "primary_standard_code": expected["primary_standard"]["standard_code"],
                        "primary_clause_id": expected["primary_standard"]["clause_id"],
                    },
                    "error": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                }
                print(f"  ERROR {type(exc).__name__}: {exc}", flush=True)
                _write_json(detail_dir / f"{expected['scenario_id']}.json", result)
                raise
            results.append(result)
            _write_json(detail_dir / f"{expected['scenario_id']}.json", result)
            _write_json(output_dir / "results.partial.json", results)
            metrics = result["metrics"]
            print(
                "  "
                f"recall={metrics['primary_recalled']} "
                f"sent={metrics['primary_sent_to_model']} "
                f"model={metrics['primary_model_result']} "
                f"correct={metrics['primary_model_judgment_correct']}",
                flush=True,
            )
    finally:
        knowledge_store.close()

    summary = _aggregate(results)
    payload = {
        "schema_version": "1.0.0",
        "generated_at": generated_at,
        "evaluation_scope": {
            "input_count": len(results),
            "user_request": user_request,
            "primary_target_only": True,
            "penalize_extra_retrievals": False,
            "deepseek_model": settings.deepseek_model,
            "dense_model": settings.effective_dense_model,
            "sparse_model": settings.rag_sparse_model,
            "reranker_model": (
                settings.bailian_rerank_model
                if settings.bailian_rerank_enabled
                else None
            ),
        },
        "summary": summary,
        "results": results,
    }
    _write_json(output_dir / "agent-evaluation-results.json", payload)
    markdown = _build_markdown(
        generated_at=generated_at,
        summary=summary,
        results=results,
    )
    (output_dir / "agent-evaluation-comparison.md").write_text(
        markdown,
        encoding="utf-8",
    )
    partial = output_dir / "results.partial.json"
    if partial.exists():
        partial.unlink()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="运行 20 组华为 CFG 的真实 ReAct/RAG/DeepSeek 端到端评测。"
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--request", default=DEFAULT_REQUEST)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit 必须大于 0")

    payload = asyncio.run(
        run_evaluation(
            output_dir=args.output_dir.resolve(),
            user_request=args.request,
            limit=args.limit,
        )
    )
    print(_json_dump(payload["summary"]))
    print(f"output={args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
