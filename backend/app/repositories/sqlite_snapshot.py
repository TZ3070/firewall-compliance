import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from pydantic import ValidationError

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import (
    ConfigurationEvidence,
    ConfigurationParseWarning,
    FirewallSnapshot,
    NormalizedFirewallConfig,
    ParsedFirewallConfiguration,
    StoredSnapshot,
)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type = 'mock'),
    provider_version TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    raw_content_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    normalized_config_json TEXT NOT NULL,
    completeness REAL NOT NULL CHECK (completeness >= 0.0 AND completeness <= 1.0),
    warnings_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    persisted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_content_sha256
ON snapshots(content_sha256);

CREATE TRIGGER IF NOT EXISTS snapshots_reject_update
BEFORE UPDATE ON snapshots
BEGIN
    SELECT RAISE(ABORT, 'snapshots are immutable');
END;

CREATE TRIGGER IF NOT EXISTS snapshots_reject_delete
BEFORE DELETE ON snapshots
BEGIN
    SELECT RAISE(ABORT, 'snapshots are immutable');
END;
"""


def _canonicalize_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _calculate_sha256(raw_content: str) -> str:
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()


class SQLiteSnapshotRepository:
    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialization_lock = Lock()
        self._initialized = False

    @property
    def database_path(self) -> Path:
        return self._database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        if self._initialized:
            return

        with self._initialization_lock:
            if self._initialized:
                return
            self._database_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with closing(self._connect()) as connection:
                    connection.executescript(SCHEMA_SQL)
                    connection.commit()
            except sqlite3.DatabaseError as exc:
                raise ConfigurationPipelineError(
                    ConfigurationErrorCode.SNAPSHOT_PERSIST_FAILED,
                    "无法初始化本地 Snapshot 数据库",
                ) from exc
            self._initialized = True

    @staticmethod
    def _validate_integrity(
        snapshot: FirewallSnapshot,
        parsed_configuration: ParsedFirewallConfiguration,
    ) -> None:
        if _calculate_sha256(snapshot.raw_content) != snapshot.content_sha256:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_INTEGRITY_FAILED,
                "Snapshot 原始内容与 SHA-256 不一致",
            )
        if parsed_configuration.normalized_config.target.target_id != snapshot.target_id:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_INTEGRITY_FAILED,
                "Snapshot target_id 与标准化配置不一致",
            )
        if any(
            item.snapshot_id != snapshot.snapshot_id
            for item in parsed_configuration.evidence
        ):
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_INTEGRITY_FAILED,
                "配置证据引用了其他 Snapshot",
            )

    def save(
        self,
        snapshot: FirewallSnapshot,
        parsed_configuration: ParsedFirewallConfiguration,
    ) -> StoredSnapshot:
        self._validate_integrity(snapshot, parsed_configuration)
        self._initialize()
        persisted_at = datetime.now(timezone.utc)
        parameters = (
            snapshot.snapshot_id,
            snapshot.target_id,
            snapshot.source_type,
            snapshot.provider_version,
            parsed_configuration.parser_version,
            snapshot.collected_at.isoformat(),
            snapshot.raw_content,
            snapshot.content_sha256,
            _canonicalize_json(
                parsed_configuration.normalized_config.model_dump(mode="json")
            ),
            parsed_configuration.completeness,
            _canonicalize_json(
                [warning.model_dump(mode="json") for warning in parsed_configuration.warnings]
            ),
            _canonicalize_json(
                [evidence.model_dump(mode="json") for evidence in parsed_configuration.evidence]
            ),
            persisted_at.isoformat(),
        )

        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO snapshots (
                            snapshot_id,
                            target_id,
                            source_type,
                            provider_version,
                            parser_version,
                            collected_at,
                            raw_content_json,
                            content_sha256,
                            normalized_config_json,
                            completeness,
                            warnings_json,
                            evidence_json,
                            persisted_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        parameters,
                    )
        except sqlite3.IntegrityError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_ALREADY_EXISTS,
                f"Snapshot {snapshot.snapshot_id} 已存在，拒绝覆盖",
            ) from exc
        except sqlite3.DatabaseError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_PERSIST_FAILED,
                "保存 Snapshot 失败",
            ) from exc

        return StoredSnapshot(
            snapshot=snapshot,
            parsed_configuration=parsed_configuration,
            persisted_at=persisted_at,
        )

    def get(self, snapshot_id: str) -> StoredSnapshot | None:
        self._initialize()
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT
                        snapshot_id,
                        target_id,
                        source_type,
                        provider_version,
                        parser_version,
                        collected_at,
                        raw_content_json,
                        content_sha256,
                        normalized_config_json,
                        completeness,
                        warnings_json,
                        evidence_json,
                        persisted_at
                    FROM snapshots
                    WHERE snapshot_id = ?
                    """,
                    (snapshot_id,),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_PERSIST_FAILED,
                "读取 Snapshot 失败",
            ) from exc

        if row is None:
            return None

        try:
            snapshot = FirewallSnapshot(
                snapshot_id=row["snapshot_id"],
                target_id=row["target_id"],
                source_type=row["source_type"],
                provider_version=row["provider_version"],
                collected_at=row["collected_at"],
                raw_content=row["raw_content_json"],
                content_sha256=row["content_sha256"],
            )
            parsed_configuration = ParsedFirewallConfiguration(
                parser_version=row["parser_version"],
                normalized_config=NormalizedFirewallConfig.model_validate(
                    json.loads(row["normalized_config_json"])
                ),
                completeness=row["completeness"],
                warnings=tuple(
                    ConfigurationParseWarning.model_validate(item)
                    for item in json.loads(row["warnings_json"])
                ),
                evidence=tuple(
                    ConfigurationEvidence.model_validate(item)
                    for item in json.loads(row["evidence_json"])
                ),
            )
            stored = StoredSnapshot(
                snapshot=snapshot,
                parsed_configuration=parsed_configuration,
                persisted_at=row["persisted_at"],
            )
            self._validate_integrity(snapshot, parsed_configuration)
            return stored
        except (
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValidationError,
        ) as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_INTEGRITY_FAILED,
                f"Snapshot {snapshot_id} 的持久化内容损坏",
            ) from exc
