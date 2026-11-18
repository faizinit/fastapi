"""Application errors and RFC 9457 problem-detail rendering."""

from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any, cast

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_MEDIA_TYPE = "application/problem+json"
PROBLEM_TYPE_PREFIX = "urn:central-security:problem:"

logger = structlog.get_logger(__name__)


class FieldError(BaseModel):
    """A single field-level validation failure."""

    field: str = Field(description="Dotted path of the offending field.")
    message: str
    code: str


class ProblemDetail(BaseModel):
    """RFC 9457 problem details, extended with a request id and field errors."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    type: str = Field(examples=["urn:central-security:problem:forbidden"])
    title: str
    status: int
    detail: str
    instance: str
    request_id: str | None = None
    errors: list[FieldError] | None = None


class AppError(Exception):
    """Base class for errors that map to a standard problem response."""

    status_code: int = 500
    slug: str = "internal-error"
    title: str = "Internal Server Error"

    def __init__(
        self,
        detail: str | None = None,
        *,
        errors: Sequence[FieldError] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.detail = detail or self.title
        self.errors = list(errors) if errors else None
        self.headers = dict(headers) if headers else {}
        super().__init__(self.detail)


class BadRequestError(AppError):
    status_code = 400
    slug = "bad-request"
    title = "Bad Request"


class UnauthorizedError(AppError):
    status_code = 401
    slug = "unauthorized"
    title = "Unauthorized"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(
            detail or "Authentication is required.", headers={"WWW-Authenticate": "Bearer"}
        )


class ForbiddenError(AppError):
    status_code = 403
    slug = "forbidden"
    title = "Forbidden"


class NotFoundError(AppError):
    status_code = 404
    slug = "not-found"
    title = "Not Found"


class ConflictError(AppError):
    status_code = 409
    slug = "conflict"
    title = "Conflict"


class PolicyViolationError(AppError):
    status_code = 400
    slug = "policy-violation"
    title = "Request Rejected by Policy"


class PayloadTooLargeError(AppError):
    status_code = 413
    slug = "payload-too-large"
    title = "Payload Too Large"


class RateLimitedError(AppError):
    status_code = 429
    slug = "rate-limit-exceeded"
    title = "Too Many Requests"

    def __init__(self, detail: str | None = None, *, retry_after_seconds: int = 1) -> None:
        super().__init__(
            detail or "Rate limit or quota exceeded.",
            headers={"Retry-After": str(max(1, retry_after_seconds))},
        )


class ResponseValidationError(AppError):
    status_code = 502
    slug = "response-validation-failed"
    title = "Bad Gateway"


class DependencyUnavailableError(AppError):
    status_code = 503
    slug = "dependency-unavailable"
    title = "Service Unavailable"


class UpstreamTimeoutError(AppError):
    status_code = 504
    slug = "upstream-timeout"
    title = "Gateway Timeout"


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else None


def problem_response(
    request: Request,
    *,
    status_code: int,
    slug: str,
    title: str,
    detail: str,
    errors: Sequence[FieldError] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = ProblemDetail(
        type=f"{PROBLEM_TYPE_PREFIX}{slug}",
        title=title,
        status=status_code,
        detail=detail,
        instance=request.url.path,
        request_id=_request_id(request),
        errors=list(errors) if errors else None,
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json", exclude_none=True, by_alias=True),
        media_type=PROBLEM_MEDIA_TYPE,
        headers=dict(headers) if headers else None,
    )


def _field_errors(exc: RequestValidationError) -> list[FieldError]:
    return [
        FieldError(
            field=".".join(str(part) for part in err["loc"] if part != "body") or "body",
            message=str(err["msg"]),
            code=str(err["type"]),
        )
        for err in exc.errors()
    ]


def _handle_app_error(request: Request, exc: Exception) -> JSONResponse:
    error = cast(AppError, exc)
    return problem_response(
        request,
        status_code=error.status_code,
        slug=error.slug,
        title=error.title,
        detail=error.detail,
        errors=error.errors,
        headers=error.headers,
    )


def _handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
    error = cast(RequestValidationError, exc)
    return problem_response(
        request,
        status_code=400,
        slug="validation-failed",
        title="Bad Request",
        detail="The request failed schema validation.",
        errors=_field_errors(error),
    )


def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    error = cast(StarletteHTTPException, exc)
    phrase = HTTPStatus(error.status_code).phrase
    slug = phrase.lower().replace(" ", "-")
    return problem_response(
        request,
        status_code=error.status_code,
        slug=slug,
        title=phrase,
        detail=phrase if error.status_code >= 500 else str(error.detail),
        headers=error.headers,
    )


def _handle_database_unavailable(request: Request, exc: Exception) -> JSONResponse:
    logger.error("database_unavailable", error_type=type(exc).__name__)
    return problem_response(
        request,
        status_code=503,
        slug=DependencyUnavailableError.slug,
        title=DependencyUnavailableError.title,
        detail="A required dependency is unavailable.",
        headers={"Retry-After": "5"},
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(OperationalError, _handle_database_unavailable)


ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ProblemDetail, "description": "Malformed request or schema failure."},
    401: {"model": ProblemDetail, "description": "Missing, invalid or expired credentials."},
    403: {"model": ProblemDetail, "description": "Caller is not authorized."},
    404: {"model": ProblemDetail, "description": "Resource not found."},
    409: {"model": ProblemDetail, "description": "Conflict with current state."},
    413: {"model": ProblemDetail, "description": "Payload too large."},
    429: {"model": ProblemDetail, "description": "Rate limit or quota exceeded."},
    502: {"model": ProblemDetail, "description": "Response failed validation."},
    503: {"model": ProblemDetail, "description": "A required dependency is unavailable."},
    504: {"model": ProblemDetail, "description": "Upstream provider timed out."},
}


ADMIN_ERROR_CODES = (401, 403, 429, 503)


def error_responses(*codes: int) -> dict[int | str, dict[str, Any]]:
    """Select documented error responses for a route's `responses=` argument."""
    return {code: ERROR_RESPONSES[code] for code in codes}
