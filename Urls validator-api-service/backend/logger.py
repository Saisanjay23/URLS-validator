"""
Logger — Enterprise URL Validation Engine.

Supports two modes:
  1. Standard logging (existing behavior, always available)
  2. Structured logging (JSON-like format with timing data, evidence summary)

Mode is controlled by ENABLE_STRUCTURED_LOGGING feature flag.
"""

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Any

from backend.config import ENABLE_STRUCTURED_LOGGING

# Create a custom logger
logger = logging.getLogger("SocialURLValidation")
logger.setLevel(logging.DEBUG)  # Capture everything

# Create handlers
# 1. Console handler for standard output
c_handler = logging.StreamHandler()
c_handler.setLevel(logging.INFO)

# 2. File handler with log rotation (5 MB per file, max 3 backups)
log_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "validation.log")
f_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
f_handler.setLevel(logging.DEBUG)

# Create formatters and add it to handlers
c_format = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
f_format = logging.Formatter('%(asctime)s - [%(levelname)s] - %(module)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)

# Add handlers to the logger (prevent duplicate logs if module is re-imported)
if not logger.handlers:
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)


def get_logger():
    return logger


def log_structured(level: str, message: str, **kwargs: Any) -> None:
    """
    Log a message with optional structured data.

    When ENABLE_STRUCTURED_LOGGING is ON, appends key=value pairs
    to the log message for easy parsing.

    When OFF, logs the plain message only (existing behavior).

    Args:
        level: Log level ("info", "warning", "error", "debug").
        message: Human-readable log message.
        **kwargs: Structured data fields (url, platform, status,
                  dns_ms, connect_ms, ttfb_ms, total_ms, confidence, etc.)
    """
    log_fn = getattr(logger, level.lower(), logger.info)

    if not ENABLE_STRUCTURED_LOGGING or not kwargs:
        log_fn(message)
        return

    # Build structured suffix
    parts = []
    for key, value in kwargs.items():
        if value is not None:
            if isinstance(value, float):
                parts.append(f"{key}={value:.1f}")
            elif isinstance(value, dict):
                parts.append(f"{key}={json.dumps(value, default=str)}")
            else:
                parts.append(f"{key}={value}")

    structured = " | ".join(parts)
    log_fn(f"{message} | {structured}")


def log_check_result(platform: str, url: str, status: str, reason: str,
                     evidence_data: dict[str, Any] | None = None) -> None:
    """
    Log a URL check result with optional evidence data.

    This replaces the manual logger.info() calls in _check_single,
    adding structured timing and evidence information when available.
    """
    base_msg = f"[{platform.upper()}] status={status.upper()} | reason={reason} | url={url}"

    if ENABLE_STRUCTURED_LOGGING and evidence_data:
        log_structured("info", base_msg, **evidence_data)
    else:
        logger.info(base_msg)
