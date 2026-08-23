from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path
from threading import Lock

from pydantic import ValidationError

from app.models.reports import AuditReport, ReportFilter, verify_report_integrity


logger = logging.getLogger(__name__)


REPORT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    report_sha256 TEXT NOT NULL CHECK (length(report_sha256) = 64),
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at
ON reports(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reports_snapshot_id
ON reports(snapshot_id);

CREATE TRIGGER IF NOT EXISTS reports_reject_update
BEFORE UPDATE ON reports
BEGIN
    SELECT RAISE(ABORT, 'reports are immutable');
END;

CREATE TRIGGER IF NOT EXISTS reports_reject_delete
BEFORE DELETE ON reports
BEGIN
    SELECT RAISE(ABORT, 'reports are immutable');
END;
"""


class SQLiteReportRepository:
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
                connection.executescript(REPORT_SCHEMA_SQL)
                connection.commit()
            self._initialized = True

    def save(self, report: AuditReport) -> None:
        verify_report_integrity(report)
        self._initialize()
        payload = json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO reports (
                            report_id,
                            assessment_id,
                            snapshot_id,
                            target_id,
                            status,
                            created_at,
                            report_sha256,
                            payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            report.report_id,
                            report.assessment_id,
                            report.snapshot_id,
                            report.target_id,
                            report.status,
                            report.created_at.isoformat(),
                            report.report_sha256,
                            payload,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"report {report.report_id} already exists; overwrite rejected"
            ) from exc

    def get(self, report_id: str) -> AuditReport | None:
        self._initialize()
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload_json FROM reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            report = AuditReport.model_validate_json(row["payload_json"])
            verify_report_integrity(report)
            return report
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"stored report {report_id} failed integrity validation") from exc

    def query(self, report_filter: ReportFilter) -> tuple[AuditReport, ...]:
        self._initialize()
        if report_filter.report_id:
            report = self.get(report_filter.report_id)
            candidates = () if report is None else (report,)
        else:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT payload_json FROM reports ORDER BY created_at DESC"
                ).fetchall()
            verified_reports: list[AuditReport] = []
            for row in rows:
                try:
                    report = AuditReport.model_validate_json(row["payload_json"])
                    verify_report_integrity(report)
                except (ValidationError, ValueError, json.JSONDecodeError):
                    logger.warning(
                        "skipping stored report that is incompatible or failed integrity validation"
                    )
                    continue
                verified_reports.append(report)
            candidates = tuple(verified_reports)

        if report_filter.report_id:
            for report in candidates:
                verify_report_integrity(report)

        return tuple(
            report
            for report in candidates
            if self._matches(report, report_filter)
        )

    @staticmethod
    def _matches(report: AuditReport, report_filter: ReportFilter) -> bool:
        findings = tuple(
            finding for level in report.levels for finding in level.findings
        )
        if report_filter.result is not None and not any(
            finding.result is report_filter.result for finding in findings
        ):
            return False
        if report_filter.severity is not None and not any(
            finding.severity == report_filter.severity for finding in findings
        ):
            return False
        if report_filter.finding_id is not None and not any(
            finding.finding_id == report_filter.finding_id for finding in findings
        ):
            return False
        if report_filter.standard_code is not None and not any(
            reference.standard_code == report_filter.standard_code
            for finding in findings
            for reference in finding.standard_references
        ):
            return False
        return True
