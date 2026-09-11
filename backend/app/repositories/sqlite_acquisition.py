import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path
from threading import Lock

from app.core.errors import ConfigurationErrorCode, ConfigurationPipelineError
from app.models.contracts import RawConfigurationSnapshot


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS raw_configuration_acquisitions (
    acquisition_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    provider_version TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    content_format TEXT NOT NULL,
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    vendor_hint TEXT
);

CREATE INDEX IF NOT EXISTS idx_acquisitions_content_sha256
ON raw_configuration_acquisitions(content_sha256);

CREATE TRIGGER IF NOT EXISTS acquisitions_reject_update
BEFORE UPDATE ON raw_configuration_acquisitions
BEGIN
    SELECT RAISE(ABORT, 'configuration acquisitions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS acquisitions_reject_delete
BEFORE DELETE ON raw_configuration_acquisitions
BEGIN
    SELECT RAISE(ABORT, 'configuration acquisitions are immutable');
END;
"""


class SQLiteAcquisitionRepository:
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
            try:
                with closing(self._connect()) as connection:
                    connection.executescript(SCHEMA_SQL)
                    connection.commit()
            except sqlite3.DatabaseError as exc:
                raise ConfigurationPipelineError(
                    ConfigurationErrorCode.SNAPSHOT_PERSIST_FAILED,
                    "无法初始化原始配置采集数据库",
                ) from exc
            self._initialized = True

    @staticmethod
    def _verify(acquisition: RawConfigurationSnapshot) -> None:
        actual = hashlib.sha256(acquisition.content.encode("utf-8")).hexdigest()
        if actual != acquisition.content_sha256:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_INTEGRITY_FAILED,
                "原始配置采集内容与 SHA-256 不一致",
            )

    def save(self, acquisition: RawConfigurationSnapshot) -> None:
        self._verify(acquisition)
        self._initialize()
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO raw_configuration_acquisitions (
                            acquisition_id, target_id, source_type, provider_version,
                            collected_at, content_format, content, content_sha256,
                            vendor_hint
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            acquisition.acquisition_id,
                            acquisition.target_id,
                            acquisition.source_type,
                            acquisition.provider_version,
                            acquisition.collected_at.isoformat(),
                            acquisition.content_format,
                            acquisition.content,
                            acquisition.content_sha256,
                            acquisition.vendor_hint,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_ALREADY_EXISTS,
                f"原始配置采集 {acquisition.acquisition_id} 已存在",
            ) from exc
        except sqlite3.DatabaseError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_PERSIST_FAILED,
                "保存原始配置采集失败",
            ) from exc

    def get(self, acquisition_id: str) -> RawConfigurationSnapshot | None:
        self._initialize()
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM raw_configuration_acquisitions WHERE acquisition_id = ?",
                    (acquisition_id,),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise ConfigurationPipelineError(
                ConfigurationErrorCode.SNAPSHOT_PERSIST_FAILED,
                "读取原始配置采集失败",
            ) from exc
        if row is None:
            return None
        acquisition = RawConfigurationSnapshot(
            acquisition_id=row["acquisition_id"],
            target_id=row["target_id"],
            source_type=row["source_type"],
            provider_version=row["provider_version"],
            collected_at=row["collected_at"],
            content_format=row["content_format"],
            content=row["content"],
            content_sha256=row["content_sha256"],
            vendor_hint=row["vendor_hint"],
        )
        self._verify(acquisition)
        return acquisition
