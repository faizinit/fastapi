"""JWT validation against externally issued tokens. Fails closed when keys are unavailable."""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import httpx
import jwt
import structlog
from jwt import PyJWK, PyJWKSet

from app.core.config import Settings
from app.core.exceptions import DependencyUnavailableError, UnauthorizedError
from app.core.roles import Role

logger = structlog.get_logger(__name__)

SigningKey = PyJWK | str
REQUIRED_CLAIMS = ["exp", "iss", "aud", "sub"]


@dataclass(frozen=True, slots=True)
class Principal:
    """The verified identity behind a request. Authorization derives only from this."""

    subject: str
    client_id: str
    roles: frozenset[Role]
    token_id: str | None = None

    def has_any_role(self, *roles: Role) -> bool:
        return not self.roles.isdisjoint(roles)


class KeyProvider(Protocol):
    async def get_key(self, kid: str | None) -> SigningKey: ...

    async def check(self) -> None:
        """Raise `DependencyUnavailableError` if signing keys cannot be obtained."""

    async def aclose(self) -> None: ...


class StaticKeyProvider:
    """A single PEM public key supplied through the secret vault."""

    def __init__(self, pem: str) -> None:
        self._pem = pem

    async def get_key(self, kid: str | None) -> SigningKey:
        return self._pem

    async def check(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


class JWKSKeyProvider:
    """Fetches and caches the identity provider's JWKS.

    A fresh cache is used as-is. Once it expires, a failed refresh raises
    `DependencyUnavailableError`, so stale keys are never trusted (fail closed).
    """

    def __init__(
        self,
        url: str,
        *,
        ttl_seconds: int,
        timeout_seconds: float,
        min_refresh_interval_seconds: int,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._ttl = ttl_seconds
        self._min_refresh_interval = min_refresh_interval_seconds
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None
        self._clock = clock
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str | None) -> SigningKey:
        if self._is_expired():
            await self._refresh()
        key = self._lookup(kid)
        if key is None and self._can_refresh_for_unknown_key():
            await self._refresh()
            key = self._lookup(kid)
        if key is None:
            raise UnauthorizedError("The token was signed with an unknown key.")
        return key

    async def check(self) -> None:
        if self._is_expired():
            await self._refresh()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _is_expired(self) -> bool:
        return self._fetched_at is None or self._clock() - self._fetched_at >= self._ttl

    def _can_refresh_for_unknown_key(self) -> bool:
        return (
            self._fetched_at is None
            or self._clock() - self._fetched_at >= self._min_refresh_interval
        )

    def _lookup(self, kid: str | None) -> PyJWK | None:
        if kid is None:
            return next(iter(self._keys.values())) if len(self._keys) == 1 else None
        return self._keys.get(kid)

    async def _refresh(self) -> None:
        observed = self._fetched_at
        async with self._lock:
            if self._fetched_at != observed:
                return
            try:
                response = await self._client.get(self._url)
                response.raise_for_status()
                key_set = PyJWKSet.from_dict(response.json())
            except (httpx.HTTPError, ValueError, jwt.PyJWTError) as exc:
                logger.error("jwks_refresh_failed", error_type=type(exc).__name__)
                raise DependencyUnavailableError(
                    "Signing keys are unavailable; authentication cannot proceed."
                ) from exc
            self._keys = {key.key_id: key for key in key_set.keys if key.key_id is not None}
            self._fetched_at = self._clock()


class TokenVerifier:
    """Validates bearer tokens and builds the `Principal`."""

    def __init__(self, settings: Settings, keys: KeyProvider) -> None:
        self._settings = settings
        self._keys = keys

    async def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("The token is malformed.") from exc
        if header.get("alg") not in self._settings.jwt_algorithms:
            raise UnauthorizedError("The token algorithm is not accepted.")

        key = await self._keys.get_key(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=self._settings.jwt_algorithms,
                audience=self._settings.jwt_audience,
                issuer=self._settings.jwt_issuer,
                leeway=self._settings.jwt_leeway_seconds,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.ExpiredSignatureError as exc:
            raise UnauthorizedError("The token has expired.") from exc
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("The token is invalid.") from exc
        return self._principal(claims)

    def _principal(self, claims: dict[str, object]) -> Principal:
        subject = claims.get("sub")
        client_id = claims.get(self._settings.jwt_client_id_claim)
        if not isinstance(subject, str) or not subject:
            raise UnauthorizedError("The token has no subject.")
        if not isinstance(client_id, str) or not client_id:
            raise UnauthorizedError("The token has no client identifier.")
        jti = claims.get("jti")
        return Principal(
            subject=subject,
            client_id=client_id,
            roles=parse_roles(claims.get(self._settings.jwt_roles_claim)),
            token_id=jti if isinstance(jti, str) else None,
        )

    async def check_keys(self) -> None:
        await self._keys.check()

    async def aclose(self) -> None:
        await self._keys.aclose()


def parse_roles(value: object) -> frozenset[Role]:
    """Parse a roles claim (list or space-separated string), ignoring unknown roles."""
    if isinstance(value, str):
        candidates: list[object] = list(value.split())
    elif isinstance(value, list):
        candidates = list(value)
    else:
        return frozenset()
    known = {role.value: role for role in Role}
    return frozenset(known[c] for c in candidates if isinstance(c, str) and c in known)


class NoKeyProvider:
    """Used when no signing key is configured: every token is refused (fail closed)."""

    async def get_key(self, kid: str | None) -> SigningKey:
        raise DependencyUnavailableError(
            "No signing key is configured; authentication is disabled."
        )

    async def check(self) -> None:
        raise DependencyUnavailableError("No signing key is configured.")

    async def aclose(self) -> None:
        return None


def build_key_provider(settings: Settings) -> KeyProvider:
    if settings.jwt_jwks_url:
        return JWKSKeyProvider(
            settings.jwt_jwks_url,
            ttl_seconds=settings.jwks_cache_ttl_seconds,
            timeout_seconds=settings.jwks_timeout_seconds,
            min_refresh_interval_seconds=settings.jwks_min_refresh_interval_seconds,
        )
    if settings.jwt_public_key is not None:
        return StaticKeyProvider(settings.jwt_public_key.get_secret_value())
    if settings.jwt_public_key_path is not None:
        return StaticKeyProvider(settings.jwt_public_key_path.read_text(encoding="utf-8"))
    return NoKeyProvider()
