import uuid
from datetime import datetime

from pydantic import Field

from app.models.enums import SecurityEventType, Severity
from app.models.types import JSONObject
from app.schemas.common import ApiModel


class AuditLogRead(ApiModel):
    id: uuid.UUID
    seq: int
    actor_sub: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str | None
    request_id: str | None
    correlation_id: str | None
    outcome: str
    metadata: JSONObject = Field(validation_alias="event_metadata")
    prev_hash: str
    row_hash: str
    occurred_at: datetime


class AuditVerifyRead(ApiModel):
    valid: bool
    checked: int = Field(description="Entries verified, starting at `fromSeq`.")
    first_broken_seq: int | None = Field(
        description="Sequence number of the first entry that fails verification, if any."
    )


class SecurityEventRead(ApiModel):
    id: uuid.UUID
    event_type: SecurityEventType
    severity: Severity
    request_id: str | None
    correlation_id: str | None
    llm_request_id: uuid.UUID | None
    project_id: uuid.UUID | None
    service_identity_id: uuid.UUID | None
    caller_sub: str | None
    source_ip: str | None
    details: JSONObject
    occurred_at: datetime
