"""Domain enumerations shared by models, schemas and services."""

from enum import StrEnum


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class IdentityStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"


class PolicyKind(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    REQUEST_RULE = "request_rule"
    RESPONSE_SCHEMA = "response_schema"
    CONTENT_SECURITY = "content_security"


class QuotaScope(StrEnum):
    CALLER = "caller"
    TEAM = "team"
    PROJECT = "project"
    TASK = "task"


class QuotaKind(StrEnum):
    RATE = "rate"
    QUOTA = "quota"


class LLMRequestStatus(StrEnum):
    RECEIVED = "received"
    REJECTED = "rejected"
    SUCCEEDED = "succeeded"
    PROVIDER_ERROR = "provider_error"
    TIMEOUT = "timeout"
    RESPONSE_INVALID = "response_invalid"


class SecurityEventType(StrEnum):
    AUTH_FAILED = "auth_failed"
    ACCESS_DENIED = "access_denied"
    INVALID_REQUEST = "invalid_request"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    PROMPT_INJECTION = "prompt_injection"
    IDENTITY_OVERRIDE = "identity_override"
    DUPLICATE_REQUEST = "duplicate_request"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXCEEDED = "quota_exceeded"
    RESPONSE_INVALID = "response_invalid"
    PROVIDER_FAILURE = "provider_failure"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
