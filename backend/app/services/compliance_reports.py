from collections import Counter
from datetime import datetime, timezone

from app.models.compliance import (
    CitationValidationStatus,
    ComplianceFinding,
    ComplianceReport,
    ControlAssessmentDraft,
    StandardSourceFile,
    calculate_compliance_report_sha256,
)
from app.models.contracts import AssessmentStatus, FindingResult
from app.repositories.sqlite_compliance_report import (
    SQLiteComplianceReportRepository,
)
from app.services.citations import CitationValidator
from app.services.standard_sources import load_standard_sources


class ComplianceReportService:
    """Validate an Agent draft and persist the final immutable v2 report."""

    def __init__(
        self,
        *,
        citation_validator: CitationValidator,
        repository: SQLiteComplianceReportRepository,
        standard_sources: tuple[StandardSourceFile, ...] | None = None,
    ) -> None:
        self._citation_validator = citation_validator
        self._repository = repository
        self._standard_sources = standard_sources or load_standard_sources()

    async def create(
        self,
        draft: ControlAssessmentDraft,
        *,
        agent_run_id: str,
    ) -> ComplianceReport:
        findings: list[ComplianceFinding] = []
        citations_complete = True
        for finding in draft.findings:
            references = tuple(
                [
                    await self._citation_validator.validate(reference)
                    for reference in finding.standard_references
                ]
            )
            valid = bool(references) and all(
                reference.validation_status is CitationValidationStatus.VALID
                for reference in references
            )
            if finding.result is not FindingResult.NOT_APPLICABLE and not valid:
                citations_complete = False
            limitations = finding.limitations
            if not valid:
                limitations = (
                    *limitations,
                    "标准引用未全部通过原文、版本和哈希校验，结论标记为不完整。",
                )
            findings.append(
                ComplianceFinding(
                    finding_id=finding.finding_id,
                    control_key=finding.control_key,
                    control_title=finding.control_title,
                    check_title=finding.check_title,
                    rule_id=finding.rule_id,
                    result=finding.result,
                    severity=finding.severity,
                    explanation=finding.explanation,
                    applicable_protection_levels=finding.applicable_protection_levels,
                    standard_references=references,
                    configuration_evidence=finding.configuration_evidence,
                    limitations=limitations,
                    coverage=finding.coverage,
                    origin=finding.origin,
                )
            )

        counts = Counter(item.result for item in findings)
        report = ComplianceReport(
            report_id=f"rpt2:{draft.assessment_id}",
            assessment_id=draft.assessment_id,
            snapshot_id=draft.snapshot_id,
            snapshot_sha256=draft.snapshot_sha256,
            original_config_sha256=draft.original_config_sha256,
            target_id=draft.target_id,
            vendor=draft.vendor,
            status=(
                AssessmentStatus.COMPLETED
                if citations_complete
                else AssessmentStatus.INCOMPLETE
            ),
            created_at=datetime.now(timezone.utc),
            agent_run_id=agent_run_id,
            parser_version=draft.parser_version,
            rule_pack_version=draft.rule_pack_version,
            counts={result: counts[result] for result in FindingResult},
            findings=tuple(findings),
            standard_sources=self._standard_sources,
            disclaimer=draft.disclaimer,
            report_sha256="0" * 64,
        )
        report = report.model_copy(
            update={"report_sha256": calculate_compliance_report_sha256(report)}
        )
        self._repository.save(report)
        return report

    def get(self, report_id: str) -> ComplianceReport | None:
        return self._repository.get(report_id)

    def list(self) -> tuple[ComplianceReport, ...]:
        return self._repository.list()

    def latest(self) -> ComplianceReport | None:
        return self._repository.latest()
