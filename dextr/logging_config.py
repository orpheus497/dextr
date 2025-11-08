"""
dextr/logging_config.py

Logging configuration and utilities for the dextr application.
Provides structured logging for debugging, auditing, and security monitoring.
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Module-level logger cache
_loggers: Dict[str, logging.Logger] = {}
_configured = False


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """
    Configure logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (None for no file logging)
        verbose: If True, use DEBUG level
        quiet: If True, use ERROR level
    """
    global _configured

    # Determine effective log level
    if verbose:
        effective_level = logging.DEBUG
    elif quiet:
        effective_level = logging.ERROR
    else:
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        effective_level = level_map.get(log_level.upper(), logging.INFO)

    # Create root logger
    root_logger = logging.getLogger("dextr")
    root_logger.setLevel(logging.DEBUG)  # Capture everything, handlers filter

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(effective_level)

    # Console format (simpler for user-facing output)
    console_format = logging.Formatter(fmt="[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)  # Log everything to file

            # File format (more detailed)
            file_format = logging.Formatter(
                fmt=(
                    "%(asctime)s - %(name)s - %(levelname)s - "
                    "%(funcName)s:%(lineno)d - %(message)s"
                ),
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_format)
            root_logger.addHandler(file_handler)

        except (OSError, IOError) as e:
            # Log to console if file logging fails
            root_logger.warning(f"Failed to set up file logging: {e}")

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    # Ensure logging is configured
    if not _configured:
        setup_logging()

    # Return cached logger or create new one
    if name not in _loggers:
        _loggers[name] = logging.getLogger(f"dextr.{name}")

    return _loggers[name]


def log_security_event(event_type: str, details: Dict[str, Any], level: str = "INFO") -> None:
    """
    Log a security-relevant event.

    Args:
        event_type: Type of security event
        details: Event details
        level: Log level (INFO, WARNING, ERROR)
    """
    logger = get_logger("security")

    # Format message
    message = f"SECURITY EVENT: {event_type}"
    for key, value in details.items():
        message += f" | {key}={value}"

    # Log at appropriate level
    level_map = {
        "DEBUG": logger.debug,
        "INFO": logger.info,
        "WARNING": logger.warning,
        "ERROR": logger.error,
        "CRITICAL": logger.critical,
    }
    log_func = level_map.get(level.upper(), logger.info)
    log_func(message)


def log_operation_start(operation: str, **kwargs: Any) -> None:
    """
    Log the start of a major operation.

    Args:
        operation: Operation name
        **kwargs: Operation parameters
    """
    logger = get_logger("operations")
    params = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info(f"Starting {operation}: {params}")


def log_operation_complete(operation: str, **kwargs: Any) -> None:
    """
    Log the completion of a major operation.

    Args:
        operation: Operation name
        **kwargs: Operation results
    """
    logger = get_logger("operations")
    params = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info(f"Completed {operation}: {params}")


def log_operation_error(operation: str, error: Exception, **kwargs: Any) -> None:
    """
    Log an operation error.

    Args:
        operation: Operation name
        error: Exception that occurred
        **kwargs: Error context
    """
    logger = get_logger("operations")
    params = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.error(f"Failed {operation}: {error} | {params}", exc_info=True)


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable string.

    Args:
        size: Size in bytes

    Returns:
        Human-readable size string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            if unit == "B":
                return f"{size} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def get_timestamp() -> str:
    """
    Get current UTC timestamp in ISO format.

    Returns:
        ISO format timestamp string
    """
    return datetime.now(timezone.utc).isoformat()
