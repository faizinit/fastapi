import asyncio
import json
from pathlib import Path

import httpx
import jwt
import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.exceptions import DependencyUnavailableError, UnauthorizedError
from app.core.roles import Role
from app.core.security import (
    JWKSKeyProvider,
    NoKeyProvider,
    Principal,
    StaticKeyProvider,
    TokenVerifier,
    build_key_provider,
    parse_roles,
)
from tests.tokens import KeyPair


def make_settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


@pytest.fixture
def verifier(keys: KeyPair) -> TokenVerifier:
    return TokenVerifier(make_settings(), StaticKeyProvider(keys.public_pem))


async def test_valid_token_yields_principal(verifier: TokenVerifier, keys: KeyPair) -> None:
    token = keys.mint(client_id="app-7", roles=["governance_admin", "bogus"])
    principal = await verifier.verify(token)
    assert principal.client_id == "app-7"
    assert principal.subject == "sub-app-7"
    assert principal.roles == {Role.GOVERNANCE_ADMIN}
    assert principal.token_id is not None
    assert principal.has_any_role(Role.GOVERNANCE_ADMIN, Role.SERVICE)
    assert not principal.has_any_role(Role.AUDIT_REVIEWER)


async def test_token_without_jti_is_accepted(verifier: TokenVerifier, keys: KeyPair) -> None:
    principal = await verifier.verify(keys.mint(drop=("jti",)))
    assert principal.token_id is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"expires_in": -600},
        {"issuer": "https://evil.example"},
        {"audience": "someone-else"},
        {"drop": ("exp",)},
        {"drop": ("iss",)},
        {"drop": ("aud",)},
        {"drop": ("sub",)},
        {"drop": ("client_id",)},
        {"subject": ""},
        {"extra": {"client_id": ""}},
        {"extra": {"client_id": 12}},
        {"extra": {"nbf": 4_000_000_000}},
    ],
)
async def test_invalid_claims_are_rejected(
    verifier: TokenVerifier, keys: KeyPair, overrides: dict[str, object]
) -> None:
    with pytest.raises(UnauthorizedError):
        await verifier.verify(keys.mint(**overrides))  # type: ignore[arg-type]


async def test_expired_token_message(verifier: TokenVerifier, keys: KeyPair) -> None:
    with pytest.raises(UnauthorizedError, match="expired"):
        await verifier.verify(keys.mint(expires_in=-600))


async def test_expiry_within_leeway_is_accepted(keys: KeyPair) -> None:
    verifier = TokenVerifier(
        make_settings(jwt_leeway_seconds=60), StaticKeyProvider(keys.public_pem)
    )
    assert await verifier.verify(keys.mint(expires_in=-30))


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "Bearer x"])
async def test_malformed_tokens_are_rejected(verifier: TokenVerifier, token: str) -> None:
    with pytest.raises(UnauthorizedError, match="malformed"):
        await verifier.verify(token)


async def test_tampered_signature_is_rejected(verifier: TokenVerifier, keys: KeyPair) -> None:
    head, body, signature = keys.mint().split(".")
    forged = ".".join(
        [head, body, signature[:-4] + ("AAAA" if signature[-4:] != "AAAA" else "BBBB")]
    )
    with pytest.raises(UnauthorizedError):
        await verifier.verify(forged)


async def test_token_signed_by_other_key_is_rejected(verifier: TokenVerifier) -> None:
    attacker = KeyPair(kid="attacker")
    with pytest.raises(UnauthorizedError, match="invalid"):
        await verifier.verify(attacker.mint())


async def test_algorithm_confusion_with_public_key_as_hmac_secret_is_rejected(
    verifier: TokenVerifier, keys: KeyPair
) -> None:
    forged = jwt.encode(
        {
            "iss": "https://idp.example.internal",
            "aud": "central-security",
            "sub": "x",
            "client_id": "x",
            "exp": 4_000_000_000,
        },
        "secret-that-is-long-enough-for-hs256-signing!!",
        algorithm="HS256",
    )
    with pytest.raises(UnauthorizedError, match="algorithm"):
        await verifier.verify(forged)


async def test_alg_none_is_rejected(verifier: TokenVerifier) -> None:
    unsigned = jwt.encode({"sub": "x", "exp": 4_000_000_000}, key="", algorithm="none")
    with pytest.raises(UnauthorizedError, match="algorithm"):
        await verifier.verify(unsigned)


def test_parse_roles_variants() -> None:
    assert parse_roles(["service", "audit_reviewer"]) == {Role.SERVICE, Role.AUDIT_REVIEWER}
    assert parse_roles("service governance_admin") == {Role.SERVICE, Role.GOVERNANCE_ADMIN}
    assert parse_roles(["nope", 5, None]) == frozenset()
    assert parse_roles(None) == frozenset()
    assert parse_roles(42) == frozenset()


def test_principal_is_immutable() -> None:
    principal = Principal("s", "c", frozenset())
    with pytest.raises(AttributeError):
        principal.subject = "other"  # type: ignore[misc]


async def test_verifier_check_and_close_delegate() -> None:
    verifier = TokenVerifier(make_settings(), NoKeyProvider())
    with pytest.raises(DependencyUnavailableError):
        await verifier.check_keys()
    await verifier.aclose()


async def test_no_key_provider_fails_closed(keys: KeyPair) -> None:
    verifier = TokenVerifier(make_settings(), NoKeyProvider())
    with pytest.raises(DependencyUnavailableError):
        await verifier.verify(keys.mint())


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class JwksServer:
    """An in-process JWKS endpoint whose behaviour tests can change."""

    def __init__(self, keys: KeyPair) -> None:
        self.keys = keys
        self.calls = 0
        self.status = 200
        self.body: str | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.status != 200:
            return httpx.Response(self.status)
        return httpx.Response(200, text=self.body or json.dumps(self.keys.jwks()))

    def provider(
        self, clock: FakeClock, *, ttl: int = 300, min_refresh: int = 30
    ) -> JWKSKeyProvider:
        client = httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
        return JWKSKeyProvider(
            "https://idp.example.internal/jwks",
            ttl_seconds=ttl,
            timeout_seconds=1,
            min_refresh_interval_seconds=min_refresh,
            client=client,
            clock=clock,
        )


@pytest.fixture
def jwks(keys: KeyPair) -> JwksServer:
    return JwksServer(keys)


async def test_jwks_key_is_fetched_once_and_cached(jwks: JwksServer, keys: KeyPair) -> None:
    clock = FakeClock()
    verifier = TokenVerifier(make_settings(), jwks.provider(clock))
    for _ in range(3):
        assert await verifier.verify(keys.mint())
    assert jwks.calls == 1


async def test_jwks_cache_refreshes_after_ttl(jwks: JwksServer, keys: KeyPair) -> None:
    clock = FakeClock()
    provider = jwks.provider(clock, ttl=60)
    verifier = TokenVerifier(make_settings(), provider)
    await verifier.verify(keys.mint())
    clock.now += 61
    await verifier.verify(keys.mint())
    assert jwks.calls == 2


async def test_expired_cache_with_failed_refresh_fails_closed(
    jwks: JwksServer, keys: KeyPair
) -> None:
    clock = FakeClock()
    verifier = TokenVerifier(make_settings(), jwks.provider(clock, ttl=60))
    await verifier.verify(keys.mint())
    jwks.status = 500
    clock.now += 61
    with pytest.raises(DependencyUnavailableError):
        await verifier.verify(keys.mint())


@pytest.mark.parametrize("body", ["not json", "{}", '{"keys": "nope"}'])
async def test_malformed_jwks_is_dependency_failure(
    jwks: JwksServer, keys: KeyPair, body: str
) -> None:
    jwks.body = body
    verifier = TokenVerifier(make_settings(), jwks.provider(FakeClock()))
    with pytest.raises(DependencyUnavailableError):
        await verifier.verify(keys.mint())


async def test_unreachable_jwks_is_dependency_failure(jwks: JwksServer, keys: KeyPair) -> None:
    jwks.status = 503
    verifier = TokenVerifier(make_settings(), jwks.provider(FakeClock()))
    with pytest.raises(DependencyUnavailableError):
        await verifier.verify(keys.mint())


async def test_unknown_kid_triggers_one_throttled_refresh(jwks: JwksServer, keys: KeyPair) -> None:
    clock = FakeClock()
    verifier = TokenVerifier(make_settings(), jwks.provider(clock, min_refresh=30))
    await verifier.verify(keys.mint())
    assert jwks.calls == 1
    for _ in range(5):
        with pytest.raises(UnauthorizedError, match="unknown key"):
            await verifier.verify(keys.mint(kid="rotated-away"))
    assert jwks.calls == 1
    clock.now += 31
    with pytest.raises(UnauthorizedError, match="unknown key"):
        await verifier.verify(keys.mint(kid="rotated-away"))
    assert jwks.calls == 2


async def test_token_without_kid_uses_single_key(jwks: JwksServer, keys: KeyPair) -> None:
    verifier = TokenVerifier(make_settings(), jwks.provider(FakeClock()))
    assert await verifier.verify(keys.mint(kid=None))


async def test_token_without_kid_rejected_when_multiple_keys(keys: KeyPair) -> None:
    other = KeyPair(kid="second")
    server = JwksServer(keys)
    server.body = json.dumps({"keys": keys.jwks()["keys"] + other.jwks()["keys"]})
    verifier = TokenVerifier(make_settings(), server.provider(FakeClock()))
    with pytest.raises(UnauthorizedError, match="unknown key"):
        await verifier.verify(keys.mint(kid=None))


async def test_concurrent_verifications_share_one_fetch(jwks: JwksServer, keys: KeyPair) -> None:
    verifier = TokenVerifier(make_settings(), jwks.provider(FakeClock()))
    await asyncio.gather(*(verifier.verify(keys.mint()) for _ in range(10)))
    assert jwks.calls == 1


async def test_jwks_check_and_close(jwks: JwksServer) -> None:
    provider = jwks.provider(FakeClock())
    await provider.check()
    await provider.check()
    assert jwks.calls == 1
    await provider.aclose()


async def test_jwks_provider_closes_client_it_created() -> None:
    provider = JWKSKeyProvider(
        "https://idp.example.internal/jwks",
        ttl_seconds=1,
        timeout_seconds=1,
        min_refresh_interval_seconds=1,
    )
    await provider.aclose()


async def test_static_provider_check_and_close(keys: KeyPair) -> None:
    provider = StaticKeyProvider(keys.public_pem)
    await provider.check()
    assert await provider.get_key(None) == keys.public_pem
    await provider.aclose()


async def test_no_key_provider_close() -> None:
    await NoKeyProvider().aclose()


def test_build_key_provider_variants(tmp_path: Path, keys: KeyPair) -> None:
    assert isinstance(
        build_key_provider(make_settings(jwt_jwks_url="https://idp/jwks")), JWKSKeyProvider
    )
    assert isinstance(
        build_key_provider(make_settings(jwt_public_key=SecretStr(keys.public_pem))),
        StaticKeyProvider,
    )
    key_file = tmp_path / "jwt.pub"
    key_file.write_text(keys.public_pem, encoding="utf-8")
    from_file = build_key_provider(make_settings(jwt_public_key_path=key_file))
    assert isinstance(from_file, StaticKeyProvider)
    assert isinstance(build_key_provider(make_settings()), NoKeyProvider)
