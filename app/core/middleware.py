"""Pure ASGI middleware: request context, security headers and body-size limiting."""

import re
import time
import uuid
from collections.abc import MutableMapping

import structlog
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.exceptions import PayloadTooLargeError, problem_response
from app.core.metrics import Metrics

REQUEST_ID_HEADER = "X-Request-ID"
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")

logger = structlog.get_logger("app.request")


def _state(scope: Scope) -> MutableMapping[str, object]:
    state: MutableMapping[str, object] = scope.setdefault("state", {})
    return state


def _incoming_request_id(scope: Scope) -> str:
    for name, value in scope["headers"]:
        if name == b"x-request-id":
            candidate: str = value.decode("latin-1")
            if _VALID_REQUEST_ID.fullmatch(candidate):
                return candidate
    return str(uuid.uuid4())


def _route_label(scope: Scope) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else "unmatched"


class RequestContextMiddleware:
    """Assigns a request id, logs every request, records metrics, and renders unhandled errors."""

    def __init__(self, app: ASGIApp, metrics: Metrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _incoming_request_id(scope)
        state = _state(scope)
        state["request_id"] = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        started = time.perf_counter()
        status_code = 500
        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_started = True
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            logger.exception("unhandled_exception", path=scope["path"])
            if response_started:
                raise
            response = problem_response(
                Request(scope),
                status_code=500,
                slug="internal-error",
                title="Internal Server Error",
                detail="An unexpected error occurred.",
            )
            await response(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - started
            route = _route_label(scope)
            method = scope["method"]
            self.metrics.http_requests.labels(method, route, str(status_code)).inc()
            self.metrics.http_duration.labels(method, route).observe(duration)
            logger.info(
                "request_completed",
                method=method,
                path=scope["path"],
                status=status_code,
                duration_ms=round(duration * 1000, 2),
                user_id=state.get("principal_id"),
            )
            structlog.contextvars.clear_contextvars()


class SecurityHeadersMiddleware:
    """Adds baseline security headers to every response."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_doc = scope["path"].startswith(_DOC_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("Cache-Control", "no-store")
                headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                if not is_doc:
                    headers.setdefault(
                        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
                    )
                if self.hsts:
                    headers.setdefault(
                        "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
                    )
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """Rejects request bodies larger than the configured limit with 413."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = self._declared_length(scope)
        if declared is not None and declared > self.max_bytes:
            await self._too_large(scope)(scope, receive, send)
            return

        received = 0
        exceeded = False
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise PayloadTooLargeError(self._detail())
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if exceeded:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not exceeded or response_started:
                raise
        if exceeded and not response_started:
            await self._too_large(scope)(scope, receive, send)

    def _detail(self) -> str:
        return f"Request body exceeds the {self.max_bytes}-byte limit."

    def _too_large(self, scope: Scope) -> Response:
        return problem_response(
            Request(scope),
            status_code=413,
            slug=PayloadTooLargeError.slug,
            title=PayloadTooLargeError.title,
            detail=self._detail(),
        )

    @staticmethod
    def _declared_length(scope: Scope) -> int | None:
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None
