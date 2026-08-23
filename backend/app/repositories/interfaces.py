from typing import Protocol

from app.models.contracts import (
    FirewallSnapshot,
    ParsedFirewallConfiguration,
    StoredSnapshot,
)
from app.models.reports import AuditReport, ReportFilter


class SnapshotRepository(Protocol):
    def save(
        self,
        snapshot: FirewallSnapshot,
        parsed_configuration: ParsedFirewallConfiguration,
    ) -> StoredSnapshot: ...

    def get(self, snapshot_id: str) -> StoredSnapshot | None: ...


class ReportRepository(Protocol):
    def save(self, report: AuditReport) -> None: ...

    def get(self, report_id: str) -> AuditReport | None: ...

    def query(self, report_filter: ReportFilter) -> tuple[AuditReport, ...]: ...
