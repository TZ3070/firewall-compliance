import asyncio
from pathlib import Path

from collections import Counter

from app.models.contracts import FindingResult
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.configuration import ConfigurationService


def build_configuration_service(database_path: Path) -> ConfigurationService:
    return ConfigurationService(
        repository=SQLiteSnapshotRepository(database_path)
    )


def test_current_config_is_evaluated_once_without_level_input(tmp_path: Path) -> None:
    configuration_service = build_configuration_service(tmp_path / "engine.db")
    current = asyncio.run(configuration_service.get_current_config())
    assessment = P0CurrentConfigRuleEngine().evaluate_controls(current)
    counts = Counter(item.result for item in assessment.findings)

    assert len(assessment.findings) == 12
    assert counts == {
        FindingResult.PASSED: 7,
        FindingResult.FAILED: 2,
        FindingResult.NEEDS_REVIEW: 3,
    }


def test_level_applicability_is_metadata_not_a_scan_dimension(
    tmp_path: Path,
) -> None:
    configuration_service = build_configuration_service(tmp_path / "results.db")
    current = asyncio.run(configuration_service.get_current_config())
    assessment = P0CurrentConfigRuleEngine().evaluate_controls(current)
    findings = {item.control_key: item for item in assessment.findings}

    mfa = findings["JR0071-2-FW-027"]
    assert mfa.result is FindingResult.FAILED
    assert mfa.applicable_protection_levels == (3, 4)
    backup = findings["JR0071-2-FW-038"]
    assert backup.result is FindingResult.NEEDS_REVIEW
    assert backup.applicable_protection_levels == (2, 3, 4)
    assert backup.limitations


def test_passed_finding_contains_snapshot_evidence_and_standard_reference(
    tmp_path: Path,
) -> None:
    configuration_service = build_configuration_service(tmp_path / "evidence.db")
    current = asyncio.run(configuration_service.get_current_config())
    assessment = P0CurrentConfigRuleEngine().evaluate_controls(current)
    finding = next(
        item
        for item in assessment.findings
        if item.control_key == "JR0071-2-FW-007"
    )

    assert finding.result is FindingResult.PASSED
    assert finding.configuration_evidence[0].snapshot_id == assessment.snapshot_id
    assert finding.configuration_evidence[0].source_pointer == (
        "/access_control/default_action"
    )
    level_three_reference = next(
        reference
        for reference in finding.standard_references
        if reference.classified_protection_level == 3
    )
    assert level_three_reference.clause_id == "8.1.3.2 a"
    assert level_three_reference.pdf_page_indexes == (38,)
