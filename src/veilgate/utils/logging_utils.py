import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class StderrJsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON written strictly to stderr."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload, default=str, ensure_ascii=False)


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Configures and returns a structured logger bound strictly to stderr.

    Asserts that stdout is NEVER used by any handler to maintain MCP JSON-RPC
    stdio transport purity.
    """
    logger = logging.getLogger(name)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers if setup_logger is called repeatedly
    if not logger.handlers:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(StderrJsonFormatter())
        logger.addHandler(stderr_handler)

    # Invariant assertion: stdout must never receive application logs
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and handler.stream is sys.stdout:
            raise RuntimeError(
                f"Logger '{name}' contains a handler directing logs to sys.stdout. "
                "This violates MCP stdio protocol integrity."
            )

    logger.propagate = False
    return logger
