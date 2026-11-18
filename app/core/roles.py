from enum import StrEnum


class Role(StrEnum):
    """Authorization roles. Admin and auditor roles come from the token; `service` from the DB."""

    SERVICE = "service"
    GOVERNANCE_ADMIN = "governance_admin"
    AUDIT_REVIEWER = "audit_reviewer"
