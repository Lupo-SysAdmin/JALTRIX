from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Capability:
    available: bool
    reason: str
    provider: str | None = None


@dataclass(frozen=True)
class ManagedEndpoint:
    endpoint_id: str
    provider: str
    managed: bool
    critical: bool
    last_seen: str


class EDRProvider(Protocol):
    def discover_capabilities(self) -> dict[str, Capability]: ...
    def list_endpoints(self) -> list[ManagedEndpoint]: ...
    def get_isolation_status(self, endpoint_id: str) -> str: ...
    def isolate(self, endpoint_id: str, action_id: str) -> str: ...
    def restore(self, endpoint_id: str, action_id: str) -> str: ...
    def verify(self, endpoint_id: str, action_id: str) -> bool: ...


class UnconfiguredEDR:
    """Fail closed even when called directly, without the GUI."""

    def discover_capabilities(self):
        return {
            action: Capability(False, "provider_not_configured")
            for action in ("isolate", "restore")
        }

    def list_endpoints(self):
        return []

    def get_isolation_status(self, endpoint_id):
        return "UNAVAILABLE"

    def isolate(self, endpoint_id, action_id):
        raise PermissionError("EDR provider not configured")

    restore = isolate

    def verify(self, endpoint_id, action_id):
        return False
