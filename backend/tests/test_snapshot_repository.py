import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import FirewallSnapshot
from app.parsers.huawei_cli import HuaweiCliParser
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "mock" / "default-firewall.cfg"
)


def build_record(
    snapshot_id: str,
    cli_content: str | None = None,
    *,
    target_id: str = "default-firewall-mock",
):
    original = cli_content or FIXTURE_PATH.read_text(encoding="utf-8")
    original_sha256 = hashlib.sha256(original.encode("utf-8")).hexdigest()
    parsed, _ = HuaweiCliParser().parse_configuration(
        original,
        snapshot_id=snapshot_id,
        target_id=target_id,
        raw_config_sha256=original_sha256,
    )
    normalized_content = json.dumps(
        parsed.normalized_config.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    snapshot = FirewallSnapshot(
        snapshot_id=snapshot_id,
        target_id=target_id,
        provider_version="snapshot-test/2.0.0",
        collected_at=datetime.now(timezone.utc),
        raw_content=normalized_content,
        content_sha256=hashlib.sha256(normalized_content.encode("utf-8")).hexdigest(),
        original_format="vendor_cli_mock",
        original_content=original,
        original_content_sha256=original_sha256,
        detected_vendor="Huawei",
        vendor_detection_confidence=1.0,
    )
    return snapshot, parsed


def test_snapshot_round_trip_uses_a_temporary_database(tmp_path: Path) -> None:
    repository = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    snapshot, parsed = build_record("snp-round-trip")

    stored = repository.save(snapshot, parsed)
    loaded = repository.get(snapshot.snapshot_id)

    assert loaded is not None
    assert loaded.snapshot == snapshot
    assert loaded.parsed_configuration == parsed
    assert loaded.persisted_at == stored.persisted_at


def test_same_content_can_be_saved_under_different_snapshot_ids(tmp_path: Path) -> None:
    database_path = tmp_path / "snapshots.db"
    repository = SQLiteSnapshotRepository(database_path)
    first_snapshot, first_parsed = build_record("snp-repeat-1")
    second_snapshot, second_parsed = build_record("snp-repeat-2")

    repository.save(first_snapshot, first_parsed)
    repository.save(second_snapshot, second_parsed)

    assert first_snapshot.content_sha256 == second_snapshot.content_sha256
    with sqlite3.connect(database_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    assert count == 2


def test_duplicate_snapshot_id_is_rejected_without_overwrite(tmp_path: Path) -> None:
    repository = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    original_snapshot, original_parsed = build_record("snp-duplicate")
    repository.save(original_snapshot, original_parsed)

    changed_content = FIXTURE_PATH.read_text(encoding="utf-8").replace(
        "sysname FW-MOCK-01",
        "sysname CHANGED-MOCK-HOST",
    )
    changed_snapshot, changed_parsed = build_record("snp-duplicate", changed_content)

    with pytest.raises(ConfigurationPipelineError) as error:
        repository.save(changed_snapshot, changed_parsed)

    assert error.value.code is ConfigurationErrorCode.SNAPSHOT_ALREADY_EXISTS
    loaded = repository.get("snp-duplicate")
    assert loaded is not None
    assert loaded.snapshot.content_sha256 == original_snapshot.content_sha256


def test_sqlite_triggers_reject_update_and_delete(tmp_path: Path) -> None:
    database_path = tmp_path / "snapshots.db"
    repository = SQLiteSnapshotRepository(database_path)
    snapshot, parsed = build_record("snp-immutable")
    repository.save(snapshot, parsed)

    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="snapshots are immutable"):
            connection.execute(
                "UPDATE snapshots SET target_id = ? WHERE snapshot_id = ?",
                ("changed", snapshot.snapshot_id),
            )

    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="snapshots are immutable"):
            connection.execute(
                "DELETE FROM snapshots WHERE snapshot_id = ?",
                (snapshot.snapshot_id,),
            )

    assert repository.get(snapshot.snapshot_id) is not None


def test_read_detects_persisted_content_corruption(tmp_path: Path) -> None:
    database_path = tmp_path / "snapshots.db"
    repository = SQLiteSnapshotRepository(database_path)
    snapshot, parsed = build_record("snp-corrupt")
    repository.save(snapshot, parsed)

    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER snapshots_reject_update")
        connection.execute(
            "UPDATE snapshots SET raw_content_json = ? WHERE snapshot_id = ?",
            ("{}", snapshot.snapshot_id),
        )
        connection.commit()

    with pytest.raises(ConfigurationPipelineError) as error:
        repository.get(snapshot.snapshot_id)
    assert error.value.code is ConfigurationErrorCode.SNAPSHOT_INTEGRITY_FAILED


def test_parameterized_insert_handles_sql_metacharacters(tmp_path: Path) -> None:
    repository = SQLiteSnapshotRepository(tmp_path / "snapshots.db")
    target_id = "mock'; DROP TABLE snapshots;--"
    snapshot, parsed = build_record("snp-sql-characters", target_id=target_id)

    repository.save(snapshot, parsed)
    loaded = repository.get(snapshot.snapshot_id)

    assert loaded is not None
    assert loaded.snapshot.target_id == target_id
