"""Logging setup and log-string sanitation.

Default is stdout only (journald). Nothing is written to disk by default,
to avoid SD wear. The config can switch the output to a file or to syslog.

The private key, the full JWT, and the password are never logged. Only
non-sensitive status is.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys

from .config import ConfigError, DebugConfig, LoggingConfig

_LOGGER = logging.getLogger("meshfan")


def sanitize(value: object, limit: int = 200) -> str:
    """Make an untrusted string safe for a log line.

    Drops control characters (including CR/LF, so a topic or a broker
    reason string cannot forge a log line) and caps the length.
    """
    text = "".join(ch for ch in str(value) if ch.isprintable())
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def file_handler(cfg: LoggingConfig) -> logging.Handler:
    """A rotating file handler whose file is created with mode 0600."""
    if not cfg.file_path:
        raise ConfigError("logging: file output requires file_path")
    parent = os.path.dirname(os.path.abspath(cfg.file_path))
    if not os.path.isdir(parent):
        raise OSError(f"log directory does not exist: {parent}")
    # Create with 0600 first so the file is never briefly world-readable.
    fd = os.open(cfg.file_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.close(fd)
    try:
        os.chmod(cfg.file_path, 0o600)
    except OSError:
        pass
    return logging.handlers.RotatingFileHandler(
        cfg.file_path,
        maxBytes=cfg.max_bytes,
        backupCount=cfg.backup_count,
        encoding="utf-8",
    )


def validate_file_path(cfg: LoggingConfig) -> None:
    """Open the log file (append, no truncate) to prove it is writable."""
    if not cfg.file_path:
        raise ConfigError("logging: file output requires file_path")
    fd = os.open(cfg.file_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.close(fd)
    try:
        os.chmod(cfg.file_path, 0o600)
    except OSError:
        pass


def setup_logging(cfg: LoggingConfig, debug: DebugConfig) -> None:
    """Configure the 'meshfan' logger and mirror it to paho.

    Only handlers this function created are removed on a later call;
    handlers an embedding application installed are left alone.
    """
    if not hasattr(logging, cfg.level):
        raise ConfigError(
            f"logging.level must be a real logging level (got {cfg.level!r})"
        )
    level = getattr(logging, cfg.level)
    root = logging.getLogger("meshfan")
    root.setLevel(level)
    paho = logging.getLogger("paho")
    for logger in (root, paho):
        for old in list(logger.handlers):
            if getattr(old, "_meshfan_owned", False):
                logger.removeHandler(old)
                # The handler is shared by both loggers; close it only
                # once it is out of the last one.
                if not any(old in lg.handlers for lg in (root, paho)):
                    old._meshfan_owned = False
                    try:
                        old.close()
                    except Exception:
                        pass

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    if cfg.output == "stdout":
        handler: logging.Handler = logging.StreamHandler(sys.stdout)
    elif cfg.output == "file":
        handler = file_handler(cfg)
    else:  # syslog
        handler = logging.handlers.SysLogHandler(address="/dev/log")

    handler.setFormatter(fmt)
    handler._meshfan_owned = True
    root.addHandler(handler)

    # paho has its own logger. Give it the same handler/formatter and do not
    # let records propagate to the root logger (which has no handler), so
    # paho output looks exactly like ours. DEBUG is an explicit opt-in.
    paho.addHandler(handler)
    paho.propagate = False
    paho.setLevel(logging.DEBUG if debug.paho else logging.WARNING)


def warn(message: str) -> None:
    """Log a startup warning through the meshfan logger."""
    _LOGGER.warning("%s", sanitize(message, 500))
