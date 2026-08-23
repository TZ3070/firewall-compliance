import copy
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.providers.mock_config import build_snapshot
from app.repositories.sqlite_snapshot import SQLiteSnapshotRepository
from app.services.config_parser import FirewallConfigParser


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "mock" / "default-firewall.json"
)


def load_fixture() -> dict[str, Any]:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def build_record(snapshot_id: str, raw_content: dict[str, Any] | None = None):
    snapshot = build_snapshot(raw_content or load_fixture(), snapshot_id=snapshot_id)
    parsed = FirewallConfigParser().parse(snapshot)
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

    changed_content = copy.deepcopy(load_fixture())
    changed_content["target"]["hostname"] = "CHANGED-MOCK-HOST"
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
    raw_content = load_fixture()
    target_id = "mock'; DROP TABLE snapshots;--"
    raw_content["target"]["target_id"] = target_id
    snapshot, parsed = build_record("snp-sql-characters", raw_content)

    repository.save(snapshot, parsed)
    loaded = repository.get(snapshot.snapshot_id)

    assert loaded is not None
    assert loaded.snapshot.target_id == target_id
