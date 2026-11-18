from pydantic import Field, field_validator

from app.schemas.common import ApiModel
from app.schemas.llm_model import MODEL_NAME_PATTERN
from app.schemas.task import TASK_NAME_PATTERN

REQUEST_ID_PATTERN = r"^[A-Za-z0-9._:-]+$"


class LLMParameters(ApiModel):
    """Sampling parameters the caller may set; projects can restrict them with request rules."""

    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int | None = Field(default=None, ge=1, le=32_768)


class LLMProcessRequest(ApiModel):
    request_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=REQUEST_ID_PATTERN,
        description="Unique per agentic step within the project.",
        examples=["workflow-42-step-3"],
    )
    task: str = Field(pattern=TASK_NAME_PATTERN, examples=["summarize_document"])
    model: str = Field(pattern=MODEL_NAME_PATTERN, examples=["gpt-4o"])
    input: str = Field(min_length=1, description="The text to process.")
    parameters: LLMParameters | None = None
    project_id: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Informational only. Authorization comes from the verified token; a value that "
            "differs from the caller's registered project is rejected with 403."
        ),
    )
    team: str | None = Field(
        default=None,
        max_length=100,
        description="Informational only; a team that differs from the registered one is rejected.",
    )

    @field_validator("input")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("input must contain non-whitespace text")
        return value


class LLMUsage(ApiModel):
    input_bytes: int
    output_bytes: int
    provider_attempts: int


class LLMProcessResponse(ApiModel):
    request_id: str
    task: str
    model: str
    output: str
    usage: LLMUsage
