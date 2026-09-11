from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from threading import Lock

from pydantic import ValidationError

from app.models.compliance import (
    ComplianceReport,
    verify_compliance_report_integrity,
)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS compliance_reports_v2 (
    report_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL,
    agent_run_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    report_sha256 TEXT NOT NULL CHECK (length(report_sha256) = 64),
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_compliance_reports_v2_created_at
ON compliance_reports_v2(created_at DESC);

CREATE TRIGGER IF NOT EXISTS compliance_reports_v2_reject_update
BEFORE UPDATE ON compliance_reports_v2
BEGIN
    SELECT RAISE(ABORT, 'compliance reports are immutable');
END;

CREATE TRIGGER IF NOT EXISTS compliance_reports_v2_reject_delete
BEFORE DELETE ON compliance_reports_v2
BEGIN
    SELECT RAISE(ABORT, 'compliance reports are immutable');
END;
"""


class SQLiteComplianceReportRepository:
    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialization_lock = Lock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        if self._initialized:
            return
        with self._initialization_lock:
            if self._initialized:
                return
            self._database_path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.executescript(SCHEMA_SQL)
                connection.commit()
            self._initialized = True

    def save(self, report: ComplianceReport) -> None:
        verify_compliance_report_integrity(report)
        self._initialize()
        payload = report.model_dump_json()
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO compliance_reports_v2 (
                            report_id, assessment_id, snapshot_id, target_id,
                            status, agent_run_id, created_at, report_sha256,
                            payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            report.report_id,
                            report.assessment_id,
                            report.snapshot_id,
                            report.target_id,
                            report.status,
                            report.agent_run_id,
                            report.created_at.isoformat(),
                            report.report_sha256,
                            payload,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"compliance report {report.report_id} already exists"
            ) from exc

    def get(self, report_id: str) -> ComplianceReport | None:
        self._initialize()
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload_json FROM compliance_reports_v2 WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            report = ComplianceReport.model_validate_json(row["payload_json"])
            verify_compliance_report_integrity(report)
            return report
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"stored compliance report {report_id} failed integrity validation"
            ) from exc

    def list(self) -> tuple[ComplianceReport, ...]:
        self._initialize()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT payload_json FROM compliance_reports_v2 ORDER BY created_at DESC"
            ).fetchall()
        reports = tuple(
            ComplianceReport.model_validate_json(row["payload_json"])
            for row in rows
        )
        for report in reports:
            verify_compliance_report_integrity(report)
        return reports

    def latest(self) -> ComplianceReport | None:
        reports = self.list()
        return reports[0] if reports else None
