"""Policy schemas, including the typed definition for each policy kind."""

import re
import uuid
from typing import Annotated, Literal, Self

import jsonschema
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from app.models.enums import PolicyKind
from app.models.types import JSONObject
from app.schemas.common import ApiModel, Timestamped, UpdateModel

MAX_PATTERN_LENGTH = 500
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*{]")


def validate_pattern(pattern: str) -> str:
    """Accept patterns that compile and lack an obvious catastrophic-backtracking shape."""
    if _NESTED_QUANTIFIER.search(pattern):
        raise ValueError(
            "pattern contains a nested quantifier, which risks catastrophic backtracking"
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"pattern is not a valid regular expression: {exc}") from exc
    return pattern


class RegexRule(ApiModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    pattern: str = Field(min_length=1, max_length=MAX_PATTERN_LENGTH)
    description: str = Field(default="", max_length=300)

    _pattern = field_validator("pattern")(validate_pattern)


class PromptInjectionDefinition(ApiModel):
    """Extra patterns checked against normalised input, in addition to the built-in rules."""

    rules: list[RegexRule] = Field(min_length=1, max_length=200)


class RequestRuleDefinition(ApiModel):
    """Constraints on the request's input length and parameters."""

    min_input_length: int | None = Field(default=None, ge=0)
    max_input_length: int | None = Field(default=None, ge=1)
    max_tokens_limit: int | None = Field(default=None, ge=1)
    allowed_parameters: list[Literal["temperature", "max_tokens"]] | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one rule must be set")
        low, high = self.min_input_length, self.max_input_length
        if low is not None and high is not None and low > high:
            raise ValueError("minInputLength cannot exceed maxInputLength")
        return self


class ResponseSchemaDefinition(ApiModel):
    """A JSON Schema the provider's output must satisfy."""

    json_schema: JSONObject = Field(alias="schema")

    @field_validator("json_schema")
    @classmethod
    def _valid_schema(cls, value: JSONObject) -> JSONObject:
        try:
            jsonschema.Draft202012Validator.check_schema(value)
        except jsonschema.SchemaError as exc:
            raise ValueError(f"not a valid JSON Schema: {exc.message}") from exc
        return value


class ContentSecurityDefinition(ApiModel):
    """Patterns that must not appear in output, and an output size cap."""

    deny_patterns: list[RegexRule] = Field(default_factory=list, max_length=200)
    max_output_chars: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _check(self) -> Self:
        if not self.deny_patterns and self.max_output_chars is None:
            raise ValueError("define denyPatterns or maxOutputChars")
        return self


DEFINITION_MODELS: dict[PolicyKind, type[BaseModel]] = {
    PolicyKind.PROMPT_INJECTION: PromptInjectionDefinition,
    PolicyKind.REQUEST_RULE: RequestRuleDefinition,
    PolicyKind.RESPONSE_SCHEMA: ResponseSchemaDefinition,
    PolicyKind.CONTENT_SECURITY: ContentSecurityDefinition,
}


def normalize_definition(kind: PolicyKind, raw: JSONObject) -> JSONObject:
    """Validate `raw` for `kind` and return its canonical stored form.

    Raises `ValueError` with a readable message when the definition is invalid.
    """
    try:
        parsed = DEFINITION_MODELS[kind].model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'definition'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ValueError(f"invalid {kind.value} definition: {problems}") from exc
    dumped: JSONObject = parsed.model_dump(mode="json", by_alias=True, exclude_none=True)
    return dumped


PolicyName = Annotated[str, Field(min_length=1, max_length=200)]


class PolicyCreate(ApiModel):
    name: PolicyName
    kind: PolicyKind
    scope_task_id: uuid.UUID | None = Field(
        default=None, description="Restrict the policy to one task; omit for a global policy."
    )
    definition: JSONObject
    enabled: bool = True

    @model_validator(mode="after")
    def _normalize(self) -> Self:
        self.definition = normalize_definition(self.kind, self.definition)
        return self


class PolicyUpdate(UpdateModel):
    name: PolicyName | None = None
    definition: JSONObject | None = None
    enabled: bool | None = None


class PolicyRead(Timestamped):
    id: uuid.UUID
    name: str
    kind: PolicyKind
    scope_task_id: uuid.UUID | None
    definition: JSONObject
    version: int
    enabled: bool
