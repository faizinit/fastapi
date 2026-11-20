"""Prometheus metrics held in a per-application registry."""

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


class Metrics:
    """Request, security and provider metrics for availability, latency and anomaly monitoring."""

    content_type = CONTENT_TYPE_LATEST

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "http_requests_total",
            "HTTP requests by method, route template and status.",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency.",
            ["method", "route"],
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.security_events = Counter(
            "security_events_total",
            "Security events by type.",
            ["event_type"],
            registry=self.registry,
        )
        self.llm_requests = Counter(
            "llm_requests_total",
            "Processed LLM requests by task and outcome.",
            ["task", "outcome"],
            registry=self.registry,
        )
        self.provider_duration = Histogram(
            "provider_call_duration_seconds",
            "Provider call latency.",
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)
