import asyncio
from pathlib import Path

from app.models.contracts import FindingResult
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.configuration import ConfigurationService


def build_configuration_service(database_path: Path) -> ConfigurationService:
    return ConfigurationService(
        repository=SQLiteSnapshotRepository(database_path)
    )


def test_current_config_is_evaluated_across_all_three_levels(tmp_path: Path) -> None:
    configuration_service = build_configuration_service(tmp_path / "engine.db")
    current = asyncio.run(configuration_service.get_current_config())
    assessment = P0CurrentConfigRuleEngine().evaluate(current)
    levels = {
        item.classified_protection_level: item for item in assessment.levels
    }

    assert set(levels) == {2, 3, 4}
    assert levels[2].counts == {
        FindingResult.PASSED: 6,
        FindingResult.FAILED: 0,
        FindingResult.NEEDS_REVIEW: 2,
        FindingResult.NOT_APPLICABLE: 4,
    }
    for level in (3, 4):
        assert levels[level].counts == {
            FindingResult.PASSED: 7,
            FindingResult.FAILED: 2,
            FindingResult.NEEDS_REVIEW: 3,
            FindingResult.NOT_APPLICABLE: 0,
        }


def test_level_applicability_and_evidence_results_are_not_conflated(
    tmp_path: Path,
) -> None:
    configuration_service = build_configuration_service(tmp_path / "results.db")
    current = asyncio.run(configuration_service.get_current_config())
    assessment = P0CurrentConfigRuleEngine().evaluate(current)
    findings = {
        (item.classified_protection_level, finding.control_id): finding
        for item in assessment.levels
        for finding in item.findings
    }

    assert findings[(2, "JR0071-2-FW-027")].result is FindingResult.NOT_APPLICABLE
    assert findings[(3, "JR0071-2-FW-027")].result is FindingResult.FAILED
    assert findings[(4, "JR0071-2-FW-027")].result is FindingResult.FAILED
    for level in (2, 3, 4):
        backup = findings[(level, "JR0071-2-FW-038")]
        assert backup.result is FindingResult.NEEDS_REVIEW
        assert backup.limitations


def test_passed_finding_contains_snapshot_evidence_and_standard_reference(
    tmp_path: Path,
) -> None:
    configuration_service = build_configuration_service(tmp_path / "evidence.db")
    current = asyncio.run(configuration_service.get_current_config())
    assessment = P0CurrentConfigRuleEngine().evaluate(current)
    level_three = next(
        item for item in assessment.levels if item.classified_protection_level == 3
    )
    finding = next(
        item for item in level_three.findings if item.control_id == "JR0071-2-FW-007"
    )

    assert finding.result is FindingResult.PASSED
    assert finding.configuration_evidence[0].snapshot_id == assessment.snapshot_id
    assert finding.configuration_evidence[0].source_pointer == (
        "/access_control/default_action"
    )
    assert finding.standard_references[0].clause_id == "8.1.3.2 a"
    assert finding.standard_references[0].pdf_page_indexes == (38,)
