"""Guards against configuration and documentation drift."""

from pathlib import Path

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]


def env_names() -> list[str]:
    return [f"CS_{name.upper()}" for name in Settings.model_fields]


def test_every_setting_is_documented_in_the_readme() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    missing = [name for name in env_names() if f"`{name}`" not in readme]
    assert missing == []


def test_env_example_only_uses_real_settings_and_parses() -> None:
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    declared = [line.split("=", 1)[0] for line in lines if line and not line.startswith("#")]
    assert set(declared) <= set(env_names())
    settings = Settings(_env_file=ROOT / ".env.example")
    assert settings.jwt_jwks_url is None
    assert settings.jwt_public_key_path is None


def test_dockerfile_runs_as_a_non_root_user() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER app" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert dockerfile.count("FROM ") == 2


def test_makefile_declares_the_required_targets() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("test:", "lint:", "typecheck:", "migrate:", "seed:", "run:"):
        assert f"\n{target}" in makefile
