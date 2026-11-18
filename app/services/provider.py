"""LLM provider boundary: a protocol, a local deterministic provider and a protective gateway."""

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

import structlog

from app.core.config import Settings
from app.core.exceptions import AppError, DependencyUnavailableError, UpstreamTimeoutError

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    model: str
    task: str
    text: str
    temperature: float | None = None
    max_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    output: str


class ProviderError(Exception):
    """A non-retryable provider failure."""


class ProviderUnavailableError(ProviderError):
    """A transient provider failure that is safe to retry."""


class LLMProvider(Protocol):
    async def complete(self, request: ProviderRequest) -> ProviderResponse: ...


class LocalProvider:
    """Deterministic provider that makes no external call; it returns the input as JSON."""

    async def complete(self, request: ProviderRequest) -> ProviderResponse:
        payload = {"model": request.model, "task": request.task, "echo": request.text}
        return ProviderResponse(output=json.dumps(payload, ensure_ascii=False))


@dataclass(frozen=True, slots=True)
class GatewayResult:
    output: str
    attempts: int


class GatewayError(Exception):
    """A failed provider call, carrying the error to return and how many attempts were made."""

    def __init__(self, error: AppError, attempts: int) -> None:
        super().__init__(error.detail)
        self.error = error
        self.attempts = attempts


class ProviderGateway:
    """Bounds provider calls: a total time budget, controlled retries and a concurrency cap.

    - The whole call, including waiting for a slot and retry backoff, fits in one time budget.
    - Only `ProviderUnavailableError` is retried, with exponential backoff.
    - Running out of budget is a 504; provider failure or saturation is a 503.
    """

    def __init__(
        self,
        provider: LLMProvider,
        settings: Settings,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._provider = provider
        self._timeout = settings.provider_timeout_seconds
        self._max_retries = settings.provider_max_retries
        self._backoff = settings.provider_backoff_base_seconds
        self._slots = asyncio.Semaphore(settings.provider_max_concurrency)
        self._sleep = sleep
        self._clock = clock

    async def complete(self, request: ProviderRequest) -> GatewayResult:
        deadline = self._clock() + self._timeout
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=self._timeout)
        except TimeoutError:
            raise GatewayError(
                DependencyUnavailableError("The provider is saturated; retry later."), 0
            ) from None
        try:
            return await self._call_with_retries(request, deadline)
        finally:
            self._slots.release()

    async def _call_with_retries(self, request: ProviderRequest, deadline: float) -> GatewayResult:
        attempts = 0
        while True:
            attempts += 1
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise GatewayError(
                    UpstreamTimeoutError("The upstream provider timed out."), attempts
                )
            try:
                async with asyncio.timeout(remaining):
                    response = await self._provider.complete(request)
                return GatewayResult(output=response.output, attempts=attempts)
            except TimeoutError:
                raise GatewayError(
                    UpstreamTimeoutError("The upstream provider timed out."), attempts
                ) from None
            except ProviderUnavailableError:
                logger.warning("provider_unavailable", attempt=attempts)
                delay = self._backoff * 2 ** (attempts - 1)
                if attempts > self._max_retries:
                    raise GatewayError(
                        DependencyUnavailableError("The provider is unavailable."), attempts
                    ) from None
                if self._clock() + delay >= deadline:
                    raise GatewayError(
                        UpstreamTimeoutError("The upstream provider timed out."), attempts
                    ) from None
                await self._sleep(delay)
            except ProviderError:
                logger.error("provider_failed", attempt=attempts)
                raise GatewayError(
                    DependencyUnavailableError("The provider could not complete the request."),
                    attempts,
                ) from None
