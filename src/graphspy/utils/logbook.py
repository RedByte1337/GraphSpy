# graphspy/utils/logbook.py

"""Logbook module for logging capabilities using Loguru.

Is this message about...

├─ Internal framework/library mechanics?
│  └─ Use TRACE
│
├─ Something the user might need to debug their usage?
│  └─ Use DEBUG
│
├─ Normal operational information?
│  └─ Use INFO
│
└─ Something went wrong or needs attention?
   └─ Use WARNING/ERROR
"""

# Built-in imports
import logging
import os
import sys
from pathlib import Path

# Third party library imports
from loguru import logger


class _InterceptHandler(logging.Handler):
    """Route stdlib logging records to loguru so Flask/Werkzeug respect our format."""

    def emit(self, record: logging.LogRecord) -> None:
        # Map stdlib level to loguru level
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where the log call originated
        frame, depth = logging.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def _format_message(record):
    """Custom formatter with compact symbols and colors."""
    level_name = record["level"].name

    # Modern color palette (hex colors for better terminal support)
    trace_brown = "#8b7355"
    debug_blue = "#6c9bd1"
    info_white = "#ecf0f1"
    success_green = "#52c88a"
    warning_orange = "#f39c12"
    error_red = "#e74c3c"
    critical_magenta = "#c71585"
    time_gray = "#a5a5a5"

    # Map levels to symbols and colors
    symbols = {
        "TRACE": (f"<fg {trace_brown}>[*]</fg {trace_brown}>", trace_brown),
        "DEBUG": (f"<fg {debug_blue}>[•]</fg {debug_blue}>", debug_blue),
        "INFO": (f"<fg {info_white}>[i]</fg {info_white}>", info_white),
        "SUCCESS": (f"<fg {success_green}>[✓]</fg {success_green}>", success_green),
        "WARNING": (f"<fg {warning_orange}>[!]</fg {warning_orange}>", warning_orange),
        "ERROR": (f"<fg {error_red}>[✗]</fg {error_red}>", error_red),
        "CRITICAL": (
            f"<fg {critical_magenta}><bold>[⚠]</bold></fg {critical_magenta}>",
            critical_magenta,
        ),
    }

    symbol, color = symbols.get(level_name, ("[?]", "white"))

    # Professional format: full UTC timestamp + symbol + message
    # Note: We must return a string template, not format it yet
    return (
        f"<fg {time_gray}>{{time:YYYY-MM-DD HH:mm:ss.SSS!UTC}} (UTC)</fg {time_gray}> "
        f"{symbol} "
        f"<fg {color}>{{message}}</fg {color}>"
        "\n{exception}"
    )


def _xdg_state_dir(app_name: str = "graphspy") -> Path:
    """Get platform-appropriate log directory following XDG standards."""
    # Highest priority: explicit override
    override = os.getenv("GRAPHSPY_LOG_DIR")
    if override:
        return Path(override).expanduser().resolve()

    if os.name == "nt":
        base = Path(os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return (base / app_name / "logs").resolve()

    # POSIX: follow XDG
    base = os.getenv("XDG_STATE_HOME")
    if base:
        return Path(base).expanduser().resolve() / app_name / "logs"

    return Path.home() / ".local" / "state" / app_name / "logs"


def setup_logging(level: str = "INFO"):
    """
    Setup logging with compact, visually intuitive output.

    Args:
        level: Log level (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
    """
    level = level.upper()

    # Validate log level
    valid_levels = ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
    if level not in valid_levels:
        level = "INFO"

    # Remove all Loguru handlers to avoid duplicates
    logger.remove()

    # Add custom formatted handler
    # enqueue=False for synchronous output to maintain ordering when using print()
    logger.add(
        sys.stderr,
        enqueue=False,
        backtrace=True,
        diagnose=True,
        level=level,
        format=_format_message,
        colorize=True,
    )

    # --- File handler (rotating, UTC timestamps)
    log_dir = _xdg_state_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "graphspy.log"

    # Configurable rotation & retention
    max_bytes = os.getenv("GRAPHSPY_LOG_MAX_BYTES", "10 MB")
    retention_days = int(os.getenv("GRAPHSPY_LOG_RETENTION_DAYS", "14"))

    # File format without colors
    file_format = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS!UTC} (UTC) "
        "[{level:7}] {message}\n"
        "{exception}"
    )

    logger.add(
        log_file,
        format=file_format,
        level=level,
        rotation=max_bytes,
        retention=f"{retention_days} days",
        compression="zip",
        encoding="utf-8",
        enqueue=True,  # Thread-safe
    )

    logger.trace(f"Logger initialized at level {level}")
    logger.trace(
        f"Log file: {log_file} (rotation {max_bytes}, retention {retention_days} days)"
    )

    # Intercept stdlib logging (Flask, Werkzeug, etc.) → route through loguru
    intercept = _InterceptHandler()
    logging.basicConfig(handlers=[intercept], level=0, force=True)
    for name in ("werkzeug", "flask", "flask.app"):
        stdlib_logger = logging.getLogger(name)
        stdlib_logger.handlers = [intercept]
        stdlib_logger.propagate = False