from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Environment, Settings, get_settings


def make(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def production(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": Environment.PRODUCTION,
        "docs_enabled": False,
        "jwt_jwks_url": "https://idp.example.internal/jwks",
    }
    base.update(overrides)
    return make(**base)


def test_defaults_are_development() -> None:
    settings = make()
    assert settings.environment is Environment.DEVELOPMENT
    assert not settings.is_production
    assert not settings.log_json


def test_json_logs_outside_development() -> None:
    assert make(environment=Environment.TEST).log_json


def test_environment_variables_are_prefixed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CS_LOG_LEVEL", "DEBUG")
    assert make().log_level == "DEBUG"


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()


@pytest.mark.parametrize("algorithms", [[], ["none"], ["HS256"]])
def test_unsafe_jwt_algorithms_are_rejected(algorithms: list[str]) -> None:
    with pytest.raises(ValidationError):
        make(jwt_algorithms=algorithms)


def test_valid_production_settings() -> None:
    assert production().is_production


def test_production_rejects_wildcard_cors() -> None:
    with pytest.raises(ValidationError, match="wildcard"):
        production(cors_origins=["*"])


def test_production_rejects_docs() -> None:
    with pytest.raises(ValidationError, match="docs_enabled"):
        production(docs_enabled=True)


def test_production_requires_signing_key_source() -> None:
    with pytest.raises(ValidationError, match="requires jwt_jwks_url"):
        production(jwt_jwks_url=None)


def test_production_requires_https_jwks() -> None:
    with pytest.raises(ValidationError, match="https"):
        production(jwt_jwks_url="http://idp.example.internal/jwks")


def test_jwks_and_static_key_are_mutually_exclusive() -> None:
    with pytest.raises(ValidationError, match="not both"):
        make(jwt_jwks_url="https://idp/jwks", jwt_public_key="pem")


def test_key_path_counts_as_signing_key_source() -> None:
    settings = production(jwt_jwks_url=None, jwt_public_key_path=Path("/run/secrets/jwt.pub"))
    assert settings.has_signing_key_source
