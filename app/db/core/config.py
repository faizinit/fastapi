from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application configuration, read from `CS_`-prefixed environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="CS_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )

    environment: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    docs_enabled: bool = True
    app_title: str = "Central Security API"
    app_version: str = "1.0.0"

    database_url: str = "sqlite+aiosqlite:///./data/central_security.db"
    db_pool_size: int = Field(default=5, ge=1)
    db_max_overflow: int = Field(default=5, ge=0)
    db_pool_timeout_seconds: float = Field(default=30.0, gt=0)
    db_busy_timeout_ms: int = Field(default=5000, ge=0)

    jwt_issuer: str = "https://idp.example.internal"
    jwt_audience: str = "central-security"
    jwt_algorithms: list[str] = ["RS256"]
    jwt_jwks_url: str | None = None
    jwt_public_key: SecretStr | None = None
    jwt_public_key_path: Path | None = None
    jwt_client_id_claim: str = "client_id"
    jwt_roles_claim: str = "roles"
    jwt_leeway_seconds: int = Field(default=10, ge=0, le=300)
    jwks_cache_ttl_seconds: int = Field(default=300, ge=1)
    jwks_timeout_seconds: float = Field(default=3.0, gt=0)
    jwks_min_refresh_interval_seconds: int = Field(default=30, ge=0)

    cors_origins: list[str] = []
    max_request_body_bytes: int = Field(default=1_048_576, ge=1)

    auth_failure_limit_per_minute: int = Field(default=20, ge=1)
    default_caller_rate_limit_per_minute: int = Field(default=60, ge=1)

    provider_timeout_seconds: float = Field(default=30.0, gt=0)
    provider_max_retries: int = Field(default=2, ge=0, le=5)
    provider_backoff_base_seconds: float = Field(default=0.2, ge=0)
    provider_max_concurrency: int = Field(default=16, ge=1)
    max_response_bytes: int = Field(default=262_144, ge=1)

    metrics_enabled: bool = True
    metrics_token: SecretStr | None = None

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def log_json(self) -> bool:
        return self.environment is not Environment.DEVELOPMENT

    @property
    def has_signing_key_source(self) -> bool:
        return (
            bool(self.jwt_jwks_url)
            or self.jwt_public_key is not None
            or (self.jwt_public_key_path is not None)
        )

    @model_validator(mode="after")
    def _validate_security_posture(self) -> Self:
        if self.jwt_jwks_url and (self.jwt_public_key or self.jwt_public_key_path):
            raise ValueError("configure either a JWKS URL or a static public key, not both")
        if not self.jwt_algorithms or "none" in {a.lower() for a in self.jwt_algorithms}:
            raise ValueError("jwt_algorithms must be non-empty and must not allow 'none'")
        if any(a.upper().startswith("HS") for a in self.jwt_algorithms):
            raise ValueError("symmetric JWT algorithms are not allowed; use asymmetric keys")
        if self.is_production:
            if "*" in self.cors_origins:
                raise ValueError("wildcard CORS origin is not allowed in production")
            if self.docs_enabled:
                raise ValueError("docs_enabled must be false in production")
            if not self.has_signing_key_source:
                raise ValueError(
                    "production requires jwt_jwks_url, jwt_public_key or jwt_public_key_path"
                )
            if self.jwt_jwks_url and not self.jwt_jwks_url.startswith("https://"):
                raise ValueError("jwt_jwks_url must use https in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
