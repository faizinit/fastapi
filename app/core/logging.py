"""structlog configuration with sensitive-value masking."""

import logging
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog
from structlog.typing import EventDict, Processor

MASK = "***"
SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "credential",
    "private_key",
)
SENSITIVE_EXACT_KEYS = frozenset({"input", "output", "prompt", "completion", "messages"})


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_EXACT_KEYS or any(part in lowered for part in SENSITIVE_KEY_PARTS)


def mask_value(value: object) -> object:
    """Recursively mask values stored under sensitive keys."""
    if isinstance(value, Mapping):
        return {
            k: MASK if isinstance(k, str) and _is_sensitive(k) else mask_value(v)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [mask_value(item) for item in value]
    return value


def mask_sensitive(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> EventDict:
    """structlog processor that masks sensitive keys in every log event."""
    masked: EventDict = {}
    for key, value in event_dict.items():
        masked[key] = MASK if _is_sensitive(key) and key != "event" else mask_value(value)
    return masked


def configure_logging(*, level: str, json_logs: bool) -> None:
    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        mask_sensitive,
    ]
    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            renderer,
        ],
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True
