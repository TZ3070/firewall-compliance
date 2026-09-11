from typing import Protocol

from app.models.contracts import (
    FirewallSnapshot,
    ParsedFirewallConfiguration,
    RawConfigurationSnapshot,
    StoredSnapshot,
)


class SnapshotRepository(Protocol):
    def save(
        self,
        snapshot: FirewallSnapshot,
        parsed_configuration: ParsedFirewallConfiguration,
    ) -> StoredSnapshot: ...

    def get(self, snapshot_id: str) -> StoredSnapshot | None: ...


class AcquisitionRepository(Protocol):
    def save(self, acquisition: RawConfigurationSnapshot) -> None: ...

    def get(self, acquisition_id: str) -> RawConfigurationSnapshot | None: ...
