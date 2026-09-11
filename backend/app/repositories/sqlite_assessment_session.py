from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from app.models.compliance import ControlAssessmentDraft
from app.models.runtime import AssessmentSession, AgentRunStatus


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS assessment_sessions (
    assessment_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    system_id TEXT NOT NULL,
    configuration_source_id TEXT NOT NULL,
    status TEXT NOT NULL,
    acquisition_id TEXT,
    snapshot_id TEXT,
    draft_json TEXT,
    prepared INTEGER NOT NULL DEFAULT 0,
    report_id TEXT,
    steps_json TEXT NOT NULL DEFAULT '[]',
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assessment_sessions_run_id
ON assessment_sessions(run_id);
"""


class SQLiteAssessmentSessionRepository:
    _UPDATABLE = {
        "status",
        "acquisition_id",
        "snapshot_id",
        "draft_json",
        "prepared",
        "report_id",
        "steps_json",
        "error",
        "run_id",
    }

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._lock = Lock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            self._database_path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.executescript(SCHEMA_SQL)
                connection.commit()
            self._initialized = True

    def create(
        self,
        *,
        assessment_id: str,
        run_id: str,
        system_id: str,
        configuration_source_id: str,
        status: AgentRunStatus,
    ) -> AssessmentSession:
        self._initialize()
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO assessment_sessions (
                        assessment_id, run_id, system_id, configuration_source_id,
                        status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assessment_id,
                        run_id,
                        system_id,
                        configuration_source_id,
                        status,
                        now,
                        now,
                    ),
                )
        session = self.get(assessment_id)
        assert session is not None
        return session

    def update(self, assessment_id: str, **values: object) -> AssessmentSession:
        self._initialize()
        unknown = set(values) - self._UPDATABLE
        if unknown:
            raise ValueError(f"unsupported assessment fields: {sorted(unknown)}")
        encoded = dict(values)
        if isinstance(encoded.get("status"), AgentRunStatus):
            encoded["status"] = encoded["status"].value
        if isinstance(encoded.get("draft_json"), ControlAssessmentDraft):
            encoded["draft_json"] = encoded["draft_json"].model_dump_json()
        if "prepared" in encoded:
            encoded["prepared"] = int(bool(encoded["prepared"]))
        encoded["updated_at"] = datetime.now(timezone.utc).isoformat()
        assignments = ", ".join(f"{name} = ?" for name in encoded)
        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    f"UPDATE assessment_sessions SET {assignments} WHERE assessment_id = ?",
                    (*encoded.values(), assessment_id),
                )
        if cursor.rowcount != 1:
            raise KeyError(assessment_id)
        session = self.get(assessment_id)
        assert session is not None
        return session

    def append_step(self, assessment_id: str, step: str) -> AssessmentSession:
        session = self.get(assessment_id)
        if session is None:
            raise KeyError(assessment_id)
        steps = tuple(dict.fromkeys((*session.steps, step)))
        return self.update(
            assessment_id,
            steps_json=json.dumps(steps, ensure_ascii=False),
        )

    def get(self, assessment_id: str) -> AssessmentSession | None:
        self._initialize()
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM assessment_sessions WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()
        return self._decode(row) if row is not None else None

    def get_by_run(self, run_id: str) -> AssessmentSession | None:
        self._initialize()
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM assessment_sessions WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return self._decode(row) if row is not None else None

    @staticmethod
    def _decode(row: sqlite3.Row) -> AssessmentSession:
        return AssessmentSession(
            assessment_id=row["assessment_id"],
            run_id=row["run_id"],
            system_id=row["system_id"],
            configuration_source_id=row["configuration_source_id"],
            status=row["status"],
            acquisition_id=row["acquisition_id"],
            snapshot_id=row["snapshot_id"],
            draft=(
                ControlAssessmentDraft.model_validate_json(row["draft_json"])
                if row["draft_json"]
                else None
            ),
            prepared=bool(row["prepared"]),
            report_id=row["report_id"],
            steps=tuple(json.loads(row["steps_json"])),
            error=row["error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
