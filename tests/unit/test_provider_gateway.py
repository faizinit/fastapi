import asyncio
import json

import pytest

from app.core.config import Settings
from app.core.exceptions import DependencyUnavailableError, UpstreamTimeoutError
from app.services.provider import (
    GatewayError,
    LocalProvider,
    ProviderError,
    ProviderGateway,
    ProviderRequest,
    ProviderResponse,
    ProviderUnavailableError,
)

REQUEST = ProviderRequest(model="m", task="t", text="hello")


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "provider_timeout_seconds": 1.0,
        "provider_max_retries": 2,
        "provider_backoff_base_seconds": 0.1,
        "provider_max_concurrency": 4,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


class ScriptedProvider:
    """Plays back a list of outcomes: exceptions are raised, strings returned, floats slept."""

    def __init__(self, *script: object) -> None:
        self.script = list(script)
        self.calls = 0
        self.active = 0
        self.peak = 0

    async def complete(self, request: ProviderRequest) -> ProviderResponse:
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            step = self.script.pop(0) if self.script else "ok"
            if isinstance(step, BaseException):
                raise step
            if isinstance(step, float):
                await asyncio.sleep(step)
                return ProviderResponse("slept")
            return ProviderResponse(str(step))
        finally:
            self.active -= 1


class Sleeper:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


async def test_local_provider_echoes_deterministically() -> None:
    first = await LocalProvider().complete(REQUEST)
    second = await LocalProvider().complete(REQUEST)
    assert first == second
    assert json.loads(first.output) == {"model": "m", "task": "t", "echo": "hello"}


async def test_success_on_first_attempt() -> None:
    gateway = ProviderGateway(ScriptedProvider("result"), settings())
    result = await gateway.complete(REQUEST)
    assert (result.output, result.attempts) == ("result", 1)


async def test_transient_failures_are_retried_with_exponential_backoff() -> None:
    sleeper = Sleeper()
    provider = ScriptedProvider(ProviderUnavailableError(), ProviderUnavailableError(), "finally")
    gateway = ProviderGateway(provider, settings(), sleep=sleeper)
    result = await gateway.complete(REQUEST)
    assert (result.output, result.attempts, provider.calls) == ("finally", 3, 3)
    assert sleeper.delays == [0.1, 0.2]


async def test_retries_are_bounded_and_end_in_503() -> None:
    sleeper = Sleeper()
    provider = ScriptedProvider(*[ProviderUnavailableError()] * 10)
    gateway = ProviderGateway(provider, settings(provider_max_retries=2), sleep=sleeper)
    with pytest.raises(GatewayError) as caught:
        await gateway.complete(REQUEST)
    assert isinstance(caught.value.error, DependencyUnavailableError)
    assert caught.value.attempts == 3
    assert provider.calls == 3


async def test_zero_retries_means_a_single_attempt() -> None:
    provider = ScriptedProvider(ProviderUnavailableError(), "never reached")
    gateway = ProviderGateway(provider, settings(provider_max_retries=0), sleep=Sleeper())
    with pytest.raises(GatewayError) as caught:
        await gateway.complete(REQUEST)
    assert caught.value.attempts == 1


async def test_non_retryable_failure_is_not_retried() -> None:
    provider = ScriptedProvider(ProviderError("bad request"), "never reached")
    gateway = ProviderGateway(provider, settings(), sleep=Sleeper())
    with pytest.raises(GatewayError) as caught:
        await gateway.complete(REQUEST)
    assert isinstance(caught.value.error, DependencyUnavailableError)
    assert (caught.value.attempts, provider.calls) == (1, 1)
    assert "bad request" not in caught.value.error.detail


async def test_slow_provider_times_out_with_504() -> None:
    provider = ScriptedProvider(5.0)
    gateway = ProviderGateway(provider, settings(provider_timeout_seconds=0.05))
    with pytest.raises(GatewayError) as caught:
        await gateway.complete(REQUEST)
    assert isinstance(caught.value.error, UpstreamTimeoutError)
    assert caught.value.attempts == 1


async def test_provider_raising_timeout_is_a_504() -> None:
    gateway = ProviderGateway(ScriptedProvider(TimeoutError()), settings())
    with pytest.raises(GatewayError) as caught:
        await gateway.complete(REQUEST)
    assert isinstance(caught.value.error, UpstreamTimeoutError)


async def test_backoff_that_would_exceed_the_budget_is_a_504() -> None:
    provider = ScriptedProvider(ProviderUnavailableError(), "never reached")
    gateway = ProviderGateway(
        provider,
        settings(provider_timeout_seconds=1.0, provider_backoff_base_seconds=5.0),
        sleep=Sleeper(),
    )
    with pytest.raises(GatewayError) as caught:
        await gateway.complete(REQUEST)
    assert isinstance(caught.value.error, UpstreamTimeoutError)
    assert provider.calls == 1


async def test_exhausted_budget_before_an_attempt_is_a_504() -> None:
    ticks = iter([0.0, 2.0, 2.0, 2.0])
    gateway = ProviderGateway(
        ScriptedProvider("never reached"), settings(), clock=lambda: next(ticks)
    )
    with pytest.raises(GatewayError) as caught:
        await gateway.complete(REQUEST)
    assert isinstance(caught.value.error, UpstreamTimeoutError)


async def test_concurrency_is_capped() -> None:
    provider = ScriptedProvider(*[0.02] * 10)
    gateway = ProviderGateway(provider, settings(provider_max_concurrency=2))
    results = await asyncio.gather(*(gateway.complete(REQUEST) for _ in range(10)))
    assert len(results) == 10
    assert provider.peak == 2


async def test_saturated_gateway_rejects_queued_calls_with_503() -> None:
    provider = ScriptedProvider(5.0, 5.0, 5.0)
    gateway = ProviderGateway(
        provider, settings(provider_max_concurrency=1, provider_timeout_seconds=0.1)
    )
    outcomes = await asyncio.gather(
        *(gateway.complete(REQUEST) for _ in range(3)), return_exceptions=True
    )
    failures = [o for o in outcomes if isinstance(o, GatewayError)]
    saturated = [f for f in failures if f.attempts == 0]
    assert saturated
    assert all(isinstance(f.error, DependencyUnavailableError) for f in saturated)
    assert provider.calls < 3


async def test_slots_are_released_after_failures() -> None:
    provider = ScriptedProvider(ProviderError("x"), ProviderError("x"), "ok")
    gateway = ProviderGateway(provider, settings(provider_max_concurrency=1), sleep=Sleeper())
    for _ in range(2):
        with pytest.raises(GatewayError):
            await gateway.complete(REQUEST)
    assert (await gateway.complete(REQUEST)).output == "ok"
