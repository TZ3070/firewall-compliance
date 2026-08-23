from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from app.models.agent import AgentCandidateFinding
from app.models.contracts import (
    AssessmentClauseReference,
    AssessmentStatus,
    CurrentConfigResponse,
    FindingResult,
    VerificationStatus,
)
from app.models.reports import (
    AuditFinding,
    AuditLevelSummary,
    AuditReport,
    CitationValidationStatus,
    ReportFilter,
    StandardSourceFile,
    calculate_report_sha256,
)
from app.models.retrieval import RetrievedKnowledge
from app.repositories.interfaces import ReportRepository
from app.rules.p0 import P0CurrentConfigRuleEngine, RULE_PACK_SHA256
from app.services.citations import CitationValidator
from app.services.knowledge_index import build_knowledge_chunks


STANDARD_PDF_MANIFEST_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "catalog"
    / "standard-pdf-manifest-v1.json"
)
HYBRID_RULE_PACK_VERSION = "hybrid-react-rag/1.0.0"
HYBRID_RULE_PACK_SHA256 = sha256(
    Path(__file__).read_bytes() + RULE_PACK_SHA256.encode("ascii")
).hexdigest()


def load_standard_sources(
    manifest_path: Path = STANDARD_PDF_MANIFEST_PATH,
) -> tuple[StandardSourceFile, ...]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    return tuple(
        StandardSourceFile.model_validate(item) for item in payload["sources"]
    )


class ReportService:
    def __init__(
        self,
        *,
        rule_engine: P0CurrentConfigRuleEngine,
        citation_validator: CitationValidator,
        repository: ReportRepository,
    ) -> None:
        self._rule_engine = rule_engine
        self._citation_validator = citation_validator
        self._repository = repository
        self._manifest, _ = build_knowledge_chunks()
        self._standard_sources = load_standard_sources()

    async def create_from_configuration(
        self,
        current: CurrentConfigResponse,
        *,
        model_candidates: tuple[AgentCandidateFinding, ...] = (),
        retrieved_knowledge: tuple[RetrievedKnowledge, ...] = (),
    ) -> AuditReport:
        """Create one immutable report from the exact snapshot already observed by an agent."""
        return await self._create_from_configuration(
            current,
            model_candidates=model_candidates,
            retrieved_knowledge=retrieved_knowledge,
        )

    async def _create_from_configuration(
        self,
        current: CurrentConfigResponse,
        *,
        model_candidates: tuple[AgentCandidateFinding, ...] = (),
        retrieved_knowledge: tuple[RetrievedKnowledge, ...] = (),
    ) -> AuditReport:
        assessment = self._rule_engine.evaluate(current)
        report_levels: list[AuditLevelSummary] = []
        citations_complete = True

        for level in assessment.levels:
            report_findings: list[AuditFinding] = []
            for finding in level.findings:
                references = tuple(
                    [
                        await self._citation_validator.validate(reference)
                        for reference in finding.standard_references
                    ]
                )
                if finding.result is not FindingResult.NOT_APPLICABLE and (
                    not references
                    or any(
                        reference.validation_status
                        is not CitationValidationStatus.VALID
                        for reference in references
                    )
                ):
                    citations_complete = False
                limitations = finding.limitations
                if finding.result is not FindingResult.NOT_APPLICABLE and not references:
                    limitations = (
                        *limitations,
                        "未找到适用标准引用，本条仅为配置规则的初步结果。",
                    )
                elif references and any(
                    reference.validation_status
                    is not CitationValidationStatus.VALID
                    for reference in references
                ):
                    limitations = (
                        *limitations,
                        "标准依据尚未通过可引用原文校验，本条仅为配置规则的初步结果。",
                    )
                report_findings.append(
                    AuditFinding(
                        finding_id=finding.finding_id,
                        classified_protection_level=finding.classified_protection_level,
                        control_id=finding.control_id,
                        control_title=finding.control_title,
                        check_title=finding.check_title,
                        rule_id=finding.rule_id,
                        result=finding.result,
                        severity=finding.severity,
                        explanation=finding.explanation,
                        standard_references=references,
                        configuration_evidence=finding.configuration_evidence,
                        limitations=limitations,
                        control_coverage=finding.control_coverage,
                    )
                )
            report_levels.append(
                AuditLevelSummary(
                    classified_protection_level=level.classified_protection_level,
                    counts=level.counts,
                    findings=tuple(report_findings),
                )
            )

        deterministic_control_ids = {
            finding.control_id
            for level in report_levels
            for finding in level.findings
        }
        dynamic_by_level = await self._build_model_assisted_findings(
            current=current,
            candidates=model_candidates,
            retrieved_knowledge=retrieved_knowledge,
            deterministic_control_ids=deterministic_control_ids,
        )
        dynamic_count = sum(len(items) for items in dynamic_by_level.values())
        if dynamic_count:
            merged_levels: list[AuditLevelSummary] = []
            for level in report_levels:
                findings = (
                    *level.findings,
                    *dynamic_by_level.get(level.classified_protection_level, ()),
                )
                counts = Counter(item.result for item in findings)
                merged_levels.append(
                    AuditLevelSummary(
                        classified_protection_level=level.classified_protection_level,
                        counts={result: counts[result] for result in FindingResult},
                        findings=findings,
                    )
                )
            report_levels = merged_levels

        draft = AuditReport(
            report_id=f"rpt:{assessment.assessment_id}",
            assessment_id=assessment.assessment_id,
            snapshot_id=assessment.snapshot_id,
            snapshot_sha256=current.content_sha256,
            target_id=assessment.target_id,
            status=(
                AssessmentStatus.COMPLETED
                if citations_complete
                else AssessmentStatus.INCOMPLETE
            ),
            created_at=datetime.now(timezone.utc),
            rule_pack_version=(
                f"{assessment.rule_pack_version}+{HYBRID_RULE_PACK_VERSION}"
                if model_candidates
                else assessment.rule_pack_version
            ),
            rule_pack_sha256=(
                HYBRID_RULE_PACK_SHA256 if model_candidates else RULE_PACK_SHA256
            ),
            control_catalog_id=assessment.catalog_id,
            control_catalog_version=assessment.catalog_version,
            control_catalog_sha256=self._rule_engine.catalog_sha256,
            knowledge_catalog_id=self._manifest.catalog_id,
            knowledge_catalog_version=self._manifest.catalog_version,
            knowledge_catalog_sha256=self._manifest.catalog_sha256,
            standard_sources=self._standard_sources,
            levels=tuple(report_levels),
            disclaimer=(
                assessment.disclaimer
                + (
                    f" 本次另有 {dynamic_count} 条 Finding 由 RAG 真实标准原文和"
                    "大模型判断生成，已执行配置证据门控，不属于高置信度确定性规则结论。"
                    if dynamic_count
                    else ""
                )
            ),
            report_sha256="0" * 64,
        )
        report = draft.model_copy(
            update={"report_sha256": calculate_report_sha256(draft)}
        )
        self._repository.save(report)
        return report

    async def _build_model_assisted_findings(
        self,
        *,
        current: CurrentConfigResponse,
        candidates: tuple[AgentCandidateFinding, ...],
        retrieved_knowledge: tuple[RetrievedKnowledge, ...],
        deterministic_control_ids: set[str],
    ) -> dict[int, tuple[AuditFinding, ...]]:
        chunks_by_record = {
            item.chunk.record_id: item.chunk for item in retrieved_knowledge
        }
        evidence_by_field = {item.field: item for item in current.evidence}
        findings_by_level: dict[int, list[AuditFinding]] = {2: [], 3: [], 4: []}
        seen: set[tuple[str, int]] = set()

        for candidate in candidates:
            if candidate.record_id in deterministic_control_ids:
                continue
            chunk = chunks_by_record.get(candidate.record_id)
            if chunk is None or not chunk.citation_eligible:
                continue
            applicable_levels = tuple(
                level for level in chunk.classified_protection_levels if level in (2, 3, 4)
            )
            if not applicable_levels:
                continue

            bound_evidence = tuple(
                evidence_by_field[field]
                for field in candidate.configuration_fields
                if field in evidence_by_field
            )
            verified = bool(bound_evidence) and (
                len(bound_evidence) == len(candidate.configuration_fields)
                and all(
                    item.verification_status
                    is VerificationStatus.CONFIGURATION_VERIFIED
                    for item in bound_evidence
                )
            )
            result = candidate.gated_result
            if result in (FindingResult.PASSED, FindingResult.FAILED) and not verified:
                result = FindingResult.NEEDS_REVIEW

            for level in applicable_levels:
                identity = (candidate.record_id, level)
                if identity in seen:
                    continue
                references = tuple(
                    [
                        await self._citation_validator.validate(
                            AssessmentClauseReference(
                                record_id=candidate.record_id,
                                standard_code=chunk.standard_code,
                                clause_id=clause_id,
                                classified_protection_level=level,
                                printed_pages=chunk.printed_pages,
                                pdf_page_indexes=chunk.pdf_page_indexes,
                            )
                        )
                        for clause_id in chunk.clause_ids
                    ]
                )
                valid_references = tuple(
                    reference
                    for reference in references
                    if reference.validation_status is CitationValidationStatus.VALID
                    and reference.record_id == candidate.record_id
                )
                if not valid_references:
                    continue
                seen.add(identity)
                findings_by_level[level].append(
                    AuditFinding(
                        finding_id=(
                            f"{current.snapshot_id}:MODEL:{candidate.record_id}:L{level}"
                        ),
                        classified_protection_level=level,
                        control_id=candidate.record_id,
                        control_title=candidate.title,
                        check_title=candidate.title,
                        rule_id="MODEL-ASSISTED-RAG",
                        result=result,
                        severity=(
                            "high"
                            if result is FindingResult.FAILED
                            else "medium"
                            if result is FindingResult.NEEDS_REVIEW
                            else "info"
                        ),
                        explanation=candidate.explanation,
                        standard_references=valid_references,
                        configuration_evidence=bound_evidence,
                        limitations=(
                            "本条由大模型基于 RAG 原文与结构化配置辅助判断，不属于高置信度确定性规则结论。",
                            *(
                                (
                                    "配置证据不足以证明标准要求，需要人工复核。",
                                )
                                if result is FindingResult.NEEDS_REVIEW
                                else ()
                            ),
                        ),
                        control_coverage="partial",
                    )
                )

        return {
            level: tuple(findings) for level, findings in findings_by_level.items()
        }

    def get(self, report_id: str) -> AuditReport | None:
        return self._repository.get(report_id)

    def query(self, report_filter: ReportFilter) -> tuple[AuditReport, ...]:
        return self._repository.query(report_filter)
