import json
import logging

import pytest
import structlog

from app.core.logging import MASK, configure_logging, mask_sensitive, mask_value


def test_sensitive_keys_are_masked() -> None:
    event = {
        "event": "login",
        "password": "hunter2",
        "Authorization": "Bearer abc",
        "access_token": "t",
        "input": "secret prompt",
        "user": "u1",
    }
    masked = mask_sensitive(None, "info", event)
    assert masked["event"] == "login"
    assert masked["user"] == "u1"
    for key in ("password", "Authorization", "access_token", "input"):
        assert masked[key] == MASK


def test_nested_values_are_masked() -> None:
    value = {"outer": [{"api_key": "k", "ok": 1}], "tuple": ({"secret": "s"},)}
    assert mask_value(value) == {
        "outer": [{"api_key": MASK, "ok": 1}],
        "tuple": [{"secret": MASK}],
    }


def test_non_container_values_pass_through() -> None:
    assert mask_value(5) == 5


def test_json_output_masks_and_includes_context(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", json_logs=True)
    structlog.contextvars.bind_contextvars(request_id="rid-1")
    try:
        structlog.get_logger("t").info("hello", password="x", count=2)
        logging.getLogger("uvicorn.error").info("from stdlib")
    finally:
        structlog.contextvars.clear_contextvars()
    lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line]
    assert lines[0]["request_id"] == "rid-1"
    assert lines[0]["password"] == MASK
    assert lines[0]["count"] == 2
    assert lines[0]["level"] == "info"
    assert lines[1]["event"] == "from stdlib"


def test_console_renderer_is_used_in_development(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", json_logs=False)
    structlog.get_logger("t").info("readable")
    assert "readable" in capsys.readouterr().err
