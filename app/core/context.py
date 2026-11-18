"""Per-request context passed from the API layer into services."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RequestMeta:
    """Traceability data for one HTTP request."""

    correlation_id: str
    source_ip: str | None = None


@dataclass(frozen=True, slots=True)
class Actor:
    """Who performed an audited action."""

    subject: str
    role: str
