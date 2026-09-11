from __future__ import annotations

from app.models.retrieval import KnowledgeSearchFilters
from app.providers.interfaces import KnowledgeRetriever
from app.repositories.sqlite_assessment_session import (
    SQLiteAssessmentSessionRepository,
)
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.configuration import ConfigurationService


class AgentToolSequenceError(RuntimeError):
    pass


class ComplianceAgentToolService:
    """Server-side deterministic tools invoked by the Agent-Compose agent."""

    def __init__(
        self,
        *,
        configuration_service: ConfigurationService,
        rule_engine: P0CurrentConfigRuleEngine,
        knowledge_retriever: KnowledgeRetriever,
        sessions: SQLiteAssessmentSessionRepository,
    ) -> None:
        self._configuration = configuration_service
        self._rules = rule_engine
        self._knowledge = knowledge_retriever
        self._sessions = sessions

    def _session(self, assessment_id: str):
        session = self._sessions.get(assessment_id)
        if session is None:
            raise AgentToolSequenceError(f"assessment {assessment_id} 不存在")
        return session

    async def fetch_configuration(self, assessment_id: str) -> dict[str, object]:
        self._session(assessment_id)
        raw = await self._configuration.acquire_raw_configuration()
        self._sessions.update(assessment_id, acquisition_id=raw.acquisition_id)
        self._sessions.append_step(assessment_id, "configuration.fetch")
        return {
            "assessmentId": assessment_id,
            "acquisitionId": raw.acquisition_id,
            "targetId": raw.target_id,
            "sourceType": raw.source_type,
            "contentFormat": raw.content_format,
            "contentSha256": raw.content_sha256,
            "contentLength": len(raw.content),
            "vendorHint": raw.vendor_hint,
        }

    async def detect_vendor(self, assessment_id: str) -> dict[str, object]:
        session = self._session(assessment_id)
        if not session.acquisition_id:
            raise AgentToolSequenceError("必须先调用 configuration.fetch")
        detection = await self._configuration.detect_vendor(session.acquisition_id)
        self._sessions.append_step(assessment_id, "vendor.detect")
        return {
            "vendor": detection.vendor,
            "confidence": detection.confidence,
            "matchedSignatures": detection.matched_signatures,
            "usedVendorHint": detection.used_vendor_hint,
        }

    async def parse_configuration(self, assessment_id: str) -> dict[str, object]:
        session = self._session(assessment_id)
        if "vendor.detect" not in session.steps or not session.acquisition_id:
            raise AgentToolSequenceError("必须先调用 vendor.detect")
        current = await self._configuration.parse_acquisition(session.acquisition_id)
        self._sessions.update(assessment_id, snapshot_id=current.snapshot_id)
        self._sessions.append_step(assessment_id, "configuration.parse")
        return {
            "snapshotId": current.snapshot_id,
            "targetId": current.target_id,
            "vendor": current.configuration.target.vendor,
            "productFamily": current.configuration.target.product_family,
            "model": current.configuration.target.model,
            "parserVersion": current.parser_version,
            "completeness": current.completeness,
            "observedFactCount": len(current.observed_facts),
            "warningCount": len(current.warnings),
            "originalConfigSha256": current.original_config_sha256,
        }

    async def evaluate_rules(self, assessment_id: str) -> dict[str, object]:
        session = self._session(assessment_id)
        if "configuration.parse" not in session.steps or not session.snapshot_id:
            raise AgentToolSequenceError("必须先调用 configuration.parse")
        current = await self._configuration.get_snapshot_configuration(
            session.snapshot_id
        )
        draft = self._rules.evaluate_controls(current)
        self._sessions.update(assessment_id, draft_json=draft)
        self._sessions.append_step(assessment_id, "rules.evaluate")
        return {
            "assessmentId": draft.assessment_id,
            "snapshotId": draft.snapshot_id,
            "findingCount": len(draft.findings),
            "findings": [
                {
                    "controlKey": item.control_key,
                    "title": item.check_title,
                    "result": item.result.value,
                    "severity": item.severity,
                    "explanation": item.explanation,
                    "evidenceFields": [
                        evidence.field for evidence in item.configuration_evidence
                    ],
                }
                for item in draft.findings
            ],
        }

    async def search_standards(
        self,
        assessment_id: str,
        query: str,
    ) -> dict[str, object]:
        session = self._session(assessment_id)
        if "configuration.parse" not in session.steps:
            raise AgentToolSequenceError("必须先调用 configuration.parse")
        results = await self._knowledge.search(
            query=query,
            filters=KnowledgeSearchFilters(
                review_status="HumanReviewed",
                citation_eligible=True,
            ),
            limit=8,
        )
        self._sessions.append_step(assessment_id, "standards.search")
        return {
            "query": query,
            "count": len(results),
            "results": [
                {
                    "recordId": item.chunk.record_id,
                    "standardCode": item.chunk.standard_code,
                    "clauseIds": item.chunk.clause_ids,
                    "title": item.chunk.title,
                    "text": item.chunk.text,
                    "score": item.score,
                }
                for item in results
            ],
            "degradationNotices": tuple(
                dict.fromkeys(
                    notice
                    for item in results
                    for notice in item.degradation_notices
                )
            ),
        }

    async def prepare_report(self, assessment_id: str) -> dict[str, object]:
        session = self._session(assessment_id)
        required = {"rules.evaluate", "standards.search"}
        missing = required - set(session.steps)
        if missing or session.draft is None:
            raise AgentToolSequenceError(
                f"报告准备缺少步骤：{', '.join(sorted(missing))}"
            )
        self._sessions.update(assessment_id, prepared=True)
        self._sessions.append_step(assessment_id, "report.prepare")
        return {
            "assessmentId": assessment_id,
            "prepared": True,
            "findingCount": len(session.draft.findings),
            "message": "报告草稿已准备；最终报告将在 Agent Run 成功后由后端校验并固化。",
        }
