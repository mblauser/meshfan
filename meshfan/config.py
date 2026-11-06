"""Load and validate the meshfan config.

One YAML file defines everything: the source, the key, an enumerated list
of target brokers, token lifetime, reconnect policy, and logging. Secrets
(the private key) are referenced by env-var name or file path, never
inlined.

Validation is strict on purpose:

- every section has a key whitelist, so a typo cannot be silently ignored;
- security switches (tls.*, debug.*) must be real booleans, so a quoted
  "false" cannot turn into True;
- disabling TLS requires a second, explicit opt-in (tls.plaintext: true);
- numbers are range-checked and bad conversions are ConfigError;
- hostnames are syntax-checked only (DNS is resolved at connect time).
"""
from __future__ import annotations

import dataclasses
import os
import re
import socket
import stat
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when the config is missing or invalid."""


# Defaults that both the daemon and the `key encrypt` helper share.
DEFAULT_AGE_COMMAND = "age-sctl"
DEFAULT_PASSPHRASE_ENV = "MESHFAN_AGE_PASSPHRASE"
DEFAULT_AGE_TIMEOUT = 30.0


# --- small parsers ---------------------------------------------------------


def _unknown(mapping: dict[str, Any], allowed: set[str], section: str) -> None:
    """Raise on the first key that the section does not define."""
    for key in sorted(mapping, key=str):
        if key not in allowed:
            raise ConfigError(f"{section}: unknown key '{key}'")


def _req(mapping: dict[str, Any], key: str, section: str) -> object:
    if key not in mapping or mapping[key] is None:
        raise ConfigError(f"{section}: missing required key '{key}'")
    return mapping[key]


def _bool(mapping: dict[str, Any], key: str, section: str, default: bool) -> bool:
    """A security switch must be a real YAML/JSON boolean, never a string."""
    if key not in mapping or mapping[key] is None:
        return default
    value = mapping[key]
    if not isinstance(value, bool):
        raise ConfigError(
            f"{section}: '{key}' must be a boolean (true/false), "
            f"not {type(value).__name__}"
        )
    return value


def _int(
    mapping: dict[str, Any], key: str, section: str, default: int
) -> int:
    if key not in mapping or mapping[key] is None:
        return default
    value = mapping[key]
    if isinstance(value, bool):
        raise ConfigError(f"{section}: '{key}' must be an integer")
    if isinstance(value, float) and not value.is_integer():
        raise ConfigError(f"{section}: '{key}' must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as e:
        raise ConfigError(f"{section}: '{key}' must be an integer") from e


def _float(
    mapping: dict[str, Any], key: str, section: str, default: float
) -> float:
    if key not in mapping or mapping[key] is None:
        return default
    value = mapping[key]
    if isinstance(value, bool):
        raise ConfigError(f"{section}: '{key}' must be a number")
    try:
        return float(value)
    except (TypeError, ValueError) as e:
        raise ConfigError(f"{section}: '{key}' must be a number") from e


def _str(
    mapping: dict[str, Any],
    key: str,
    section: str,
    default: str | None = None,
    *,
    required: bool = False,
) -> str | None:
    if key not in mapping or mapping[key] is None:
        if required:
            raise ConfigError(f"{section}: missing required key '{key}'")
        return default
    value = mapping[key]
    if not isinstance(value, str):
        raise ConfigError(f"{section}: '{key}' must be a string")
    return value


def _port(mapping: dict[str, Any], key: str, section: str, default: int | None = None) -> int:
    value = _int(mapping, key, section, 0 if default is None else default)
    if not 1 <= value <= 65535:
        raise ConfigError(f"{section}: '{key}' must be between 1 and 65535")
    return value


# --- untrusted-string discipline -------------------------------------------

# WebSocket path: leading slash, printable ASCII only, no spaces, <= 255.
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,254}$")
_AUDIENCE_RE = re.compile(r"^[A-Za-z0-9._~:/@+-]{1,255}$")
_CLIENT_RE = re.compile(r"^[A-Za-z0-9._~:-]{1,128}$")
_HOST_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _path(value: str, section: str) -> str:
    if not _PATH_RE.match(value):
        raise ConfigError(
            f"{section}: path must start with '/' and contain only printable "
            "ASCII without spaces (<= 255 chars)"
        )
    return value


def _audience(value: str, section: str) -> str:
    if not _AUDIENCE_RE.match(value):
        raise ConfigError(
            f"{section}: audience must be 1-255 printable characters without spaces"
        )
    return value


def _client(value: str, section: str) -> str:
    if not _CLIENT_RE.match(value):
        raise ConfigError(
            f"{section}: client must be 1-128 characters from "
            "A-Z a-z 0-9 . _ ~ : -"
        )
    return value


def _topic(value: str, section: str) -> str:
    if not value or len(value) > 512 or any(
        not (0x20 <= ord(ch) <= 0x7E) for ch in value
    ):
        raise ConfigError(
            f"{section}: topic must be 1-512 printable ASCII characters"
        )
    return value


def _host(value: str, section: str) -> str:
    """Hostname *syntax* only. DNS is resolved on the connect path."""
    if not value or len(value) > 253:
        raise ConfigError(f"{section}: host must be 1-253 characters")
    if any(ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in value):
        raise ConfigError(f"{section}: host contains whitespace or control characters")
    # IPv6 (bare, no brackets or zone id)
    if ":" in value:
        try:
            socket.inet_pton(socket.AF_INET6, value)
        except OSError as e:
            raise ConfigError(f"{section}: invalid IPv6 address '{value}'") from e
        return value
    name = value[:-1] if value.endswith(".") else value
    if not name:
        raise ConfigError(f"{section}: invalid host '{value}'")
    for label in name.split("."):
        if not _HOST_LABEL_RE.match(label):
            raise ConfigError(f"{section}: invalid hostname '{value}'")
    return value


def _default_client_id() -> str:
    """A unique-ish source client id, so two relays cannot kick each other."""
    host = re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname())[:40]
    return f"meshfan-{host}-{os.getpid()}"


# --- config objects --------------------------------------------------------


@dataclasses.dataclass
class TlsConfig:
    enabled: bool = True
    insecure: bool = False
    plaintext: bool = False
    ca_file: str | None = None


@dataclasses.dataclass
class SourceConfig:
    host: str
    port: int
    topic: str
    username: str | None = None
    # The resolved password (filled in by __main__ from *_env / *_file).
    password: str | None = None
    password_env: str | None = None
    password_file: str | None = None
    client_id: str = dataclasses.field(default_factory=_default_client_id)
    keepalive: int = 30
    qos: int = 0
    tls: TlsConfig = dataclasses.field(default_factory=TlsConfig)


@dataclasses.dataclass
class BrokerConfig:
    name: str
    host: str
    port: int
    path: str
    audience: str
    client: str
    keepalive: int = 30
    tls: TlsConfig = dataclasses.field(default_factory=TlsConfig)


@dataclasses.dataclass
class KeyConfig:
    public_key: str
    private_key_env: str | None = None
    private_key_file: str | None = None
    # none | age (age-encrypted private_key_file)
    encryption: str = "none"
    passphrase_env: str | None = None
    age_command: str = DEFAULT_AGE_COMMAND
    age_timeout_seconds: float = DEFAULT_AGE_TIMEOUT


@dataclasses.dataclass
class TokenConfig:
    ttl_seconds: int = 3600
    renew_before_seconds: int = 360


@dataclasses.dataclass
class ReconnectConfig:
    base_delay: float = 1.0
    max_delay: float = 60.0
    multiplier: float = 2.0
    jitter: float = 0.5


@dataclasses.dataclass
class RuntimeConfig:
    max_queued_messages: int = 1000
    shutdown_timeout: float = 5.0
    username_prefix: str = "v1_"
    # How often a live sink re-checks token expiry, disconnects, and summary.
    token_check_seconds: float = 30.0
    # Time allowed for TCP connect + CONNACK before a retry.
    connect_timeout_seconds: float = 10.0
    # 0 disables the per-sink published/dropped summary.
    summary_interval_seconds: float = 300.0


@dataclasses.dataclass
class LoggingConfig:
    level: str = "INFO"
    output: str = "stdout"  # stdout | file | syslog
    file_path: str | None = None
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5


@dataclasses.dataclass
class DebugConfig:
    messages: bool = False
    tokens: bool = False
    paho: bool = False


@dataclasses.dataclass
class Config:
    source: SourceConfig
    key: KeyConfig
    brokers: list[BrokerConfig]
    token: TokenConfig
    reconnect: ReconnectConfig
    runtime: RuntimeConfig
    logging: LoggingConfig
    debug: DebugConfig
    warnings: list[str] = dataclasses.field(default_factory=list)


# --- section builders ------------------------------------------------------


def _tls(raw: object, section: str, role: str) -> TlsConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{section} must be a mapping")
    _unknown(raw, {"enabled", "insecure", "plaintext", "ca_file"}, section)
    enabled = _bool(raw, "enabled", section, True)
    insecure = _bool(raw, "insecure", section, False)
    plaintext = _bool(raw, "plaintext", section, False)
    ca_file = _str(raw, "ca_file", section)

    if enabled and plaintext:
        raise ConfigError(
            f"{section}: tls.plaintext=true is contradictory with tls.enabled=true"
        )
    if enabled and insecure:
        # Allowed, but the warning is emitted at startup.
        pass
    if not enabled:
        if insecure:
            raise ConfigError(
                f"{section}: tls.insecure has no effect when TLS is disabled; "
                "use tls.plaintext to acknowledge plaintext"
            )
        if not plaintext:
            if role == "sink":
                raise ConfigError(
                    f"{section}: tls.enabled=false sends the signed JWT in the "
                    "clear; add tls.plaintext=true to opt in explicitly"
                )
            raise ConfigError(
                f"{section}: tls.enabled=false sends traffic (and any "
                "credentials) in the clear; add tls.plaintext=true to opt in "
                "explicitly"
            )
    return TlsConfig(
        enabled=enabled,
        insecure=insecure,
        plaintext=plaintext,
        ca_file=ca_file or None,
    )


def _build_source(raw: object) -> SourceConfig:
    if not isinstance(raw, dict):
        raise ConfigError("source must be a mapping")
    _unknown(
        raw,
        {
            "host",
            "port",
            "topic",
            "username",
            "password",
            "password_env",
            "password_file",
            "client_id",
            "keepalive",
            "qos",
            "tls",
        },
        "source",
    )
    username = _str(raw, "username", "source")
    password = _str(raw, "password", "source")
    password_env = _str(raw, "password_env", "source") or None
    password_file = _str(raw, "password_file", "source") or None
    if password and (password_env or password_file):
        raise ConfigError(
            "source: use only one of password, password_env, password_file"
        )
    if password_env and password_file:
        raise ConfigError("source: use only one of password_env, password_file")

    client_id = _str(raw, "client_id", "source")
    if client_id is None:
        client_id = _default_client_id()
    keepalive = _int(raw, "keepalive", "source", 30)
    if keepalive < 1:
        raise ConfigError("source: keepalive must be >= 1")
    qos = _int(raw, "qos", "source", 0)
    if qos not in (0, 1, 2):
        raise ConfigError("source: qos must be 0, 1, or 2")

    return SourceConfig(
        host=_host(str(_req(raw, "host", "source")), "source"),
        port=_port(raw, "port", "source"),
        topic=_topic(str(_req(raw, "topic", "source")), "source"),
        username=username or None,
        password=password or None,
        password_env=password_env,
        password_file=password_file,
        client_id=_client(client_id, "source.client_id"),
        keepalive=keepalive,
        qos=qos,
        tls=_tls(raw.get("tls"), "source.tls", "source"),
    )


def _build_key(raw: object, warnings: list[str]) -> KeyConfig:
    if not isinstance(raw, dict):
        raise ConfigError("key must be a mapping")
    _unknown(
        raw,
        {
            "private_key_env",
            "private_key_file",
            "public_key",
            "encryption",
            "passphrase_env",
            "age_command",
            "age_timeout_seconds",
        },
        "key",
    )
    pk_env = _str(raw, "private_key_env", "key") or None
    pk_file = _str(raw, "private_key_file", "key") or None
    encryption = (_str(raw, "encryption", "key", "none") or "none").lower()
    if encryption not in ("none", "age"):
        raise ConfigError("key.encryption must be 'none' or 'age'")
    passphrase_env = _str(raw, "passphrase_env", "key") or None
    age_command = _str(raw, "age_command", "key", "age-sctl") or "age-sctl"
    age_timeout = _float(raw, "age_timeout_seconds", "key", 30.0)
    if age_timeout <= 0:
        raise ConfigError("key.age_timeout_seconds must be > 0")

    if encryption == "age":
        if not pk_file:
            raise ConfigError(
                "key.encryption=age requires key.private_key_file (the "
                "age-encrypted key file)"
            )
        if pk_env:
            raise ConfigError(
                "key.encryption=age cannot be combined with private_key_env; "
                "the age path decrypts private_key_file"
            )
        if not passphrase_env:
            raise ConfigError(
                "key.encryption=age requires key.passphrase_env (the env var "
                "holding the age passphrase)"
            )
    else:
        if not pk_env and not pk_file:
            raise ConfigError("key: set private_key_env or private_key_file")
        if pk_env and pk_file:
            warnings.append(
                "key: both private_key_env and private_key_file are set; "
                "the environment variable wins"
            )
        if passphrase_env:
            warnings.append(
                "key.passphrase_env is ignored because key.encryption is none"
            )

    public_key = _req(raw, "public_key", "key")
    if not isinstance(public_key, str):
        raise ConfigError("key.public_key must be a string")

    return KeyConfig(
        public_key=public_key,
        private_key_env=pk_env,
        private_key_file=pk_file,
        encryption=encryption,
        passphrase_env=passphrase_env,
        age_command=age_command,
        age_timeout_seconds=age_timeout,
    )


def _build_brokers(raw: object) -> list[BrokerConfig]:
    if not isinstance(raw, list) or not raw:
        raise ConfigError("brokers must be a non-empty list")
    brokers: list[BrokerConfig] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        section = f"brokers[{i}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{section} must be a mapping")
        _unknown(
            item,
            {"name", "host", "port", "path", "audience", "client", "keepalive", "tls"},
            section,
        )
        name = _str(item, "name", section, required=True) or ""
        if not name:
            raise ConfigError(f"{section}: name must not be empty")
        if name in seen:
            raise ConfigError(f"{section}: duplicate name '{name}'")
        seen.add(name)
        keepalive = _int(item, "keepalive", section, 30)
        if keepalive < 1:
            raise ConfigError(f"{section}: keepalive must be >= 1")
        brokers.append(
            BrokerConfig(
                name=name,
                host=_host(str(_req(item, "host", section)), section),
                port=_port(item, "port", section),
                path=_path(str(_req(item, "path", section)), section),
                audience=_audience(str(_req(item, "audience", section)), section),
                client=_client(str(_req(item, "client", section)), section),
                keepalive=keepalive,
                tls=_tls(item.get("tls"), f"{section}.tls", "sink"),
            )
        )
    return brokers


def _build_token(raw: object) -> TokenConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("token must be a mapping")
    _unknown(raw, {"ttl_seconds", "renew_before_seconds"}, "token")
    token = TokenConfig(
        ttl_seconds=_int(raw, "ttl_seconds", "token", 3600),
        renew_before_seconds=_int(raw, "renew_before_seconds", "token", 360),
    )
    if not 0 < token.ttl_seconds <= 86400:
        raise ConfigError("token: ttl_seconds must be in 1..86400")
    if not 0 <= token.renew_before_seconds < token.ttl_seconds:
        raise ConfigError("token: require 0 <= renew_before_seconds < ttl_seconds")
    return token


def _build_reconnect(raw: object) -> ReconnectConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("reconnect must be a mapping")
    _unknown(raw, {"base_delay", "max_delay", "multiplier", "jitter"}, "reconnect")
    reconnect = ReconnectConfig(
        base_delay=_float(raw, "base_delay", "reconnect", 1.0),
        max_delay=_float(raw, "max_delay", "reconnect", 60.0),
        multiplier=_float(raw, "multiplier", "reconnect", 2.0),
        jitter=_float(raw, "jitter", "reconnect", 0.5),
    )
    if not (0 < reconnect.base_delay <= reconnect.max_delay):
        raise ConfigError("reconnect: require 0 < base_delay <= max_delay")
    if reconnect.multiplier < 1.0:
        raise ConfigError("reconnect: multiplier must be >= 1.0")
    if not (0.0 <= reconnect.jitter < 1.0):
        raise ConfigError("reconnect: jitter must satisfy 0.0 <= jitter < 1.0")
    return reconnect


def _build_runtime(raw: object) -> RuntimeConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("runtime must be a mapping")
    _unknown(
        raw,
        {
            "max_queued_messages",
            "shutdown_timeout",
            "username_prefix",
            "token_check_seconds",
            "connect_timeout_seconds",
            "summary_interval_seconds",
        },
        "runtime",
    )
    runtime = RuntimeConfig(
        max_queued_messages=_int(raw, "max_queued_messages", "runtime", 1000),
        shutdown_timeout=_float(raw, "shutdown_timeout", "runtime", 5.0),
        username_prefix=_str(raw, "username_prefix", "runtime", "v1_") or "v1_",
        token_check_seconds=_float(raw, "token_check_seconds", "runtime", 30.0),
        connect_timeout_seconds=_float(
            raw, "connect_timeout_seconds", "runtime", 10.0
        ),
        summary_interval_seconds=_float(
            raw, "summary_interval_seconds", "runtime", 300.0
        ),
    )
    if runtime.max_queued_messages < 0:
        raise ConfigError("runtime: max_queued_messages must be >= 0")
    if runtime.shutdown_timeout <= 0:
        raise ConfigError("runtime: shutdown_timeout must be > 0")
    if runtime.token_check_seconds <= 0:
        raise ConfigError("runtime: token_check_seconds must be > 0")
    if runtime.connect_timeout_seconds <= 0:
        raise ConfigError("runtime: connect_timeout_seconds must be > 0")
    if runtime.summary_interval_seconds < 0:
        raise ConfigError("runtime: summary_interval_seconds must be >= 0")
    if not runtime.username_prefix or any(
        ord(ch) < 0x21 or ord(ch) > 0x7E for ch in runtime.username_prefix
    ):
        raise ConfigError("runtime: username_prefix must be printable ASCII")
    return runtime


def _build_logging(raw: object) -> LoggingConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("logging must be a mapping")
    _unknown(
        raw,
        {"level", "output", "file_path", "max_bytes", "backup_count"},
        "logging",
    )
    output = (_str(raw, "output", "logging", "stdout") or "stdout").lower()
    if output not in ("stdout", "file", "syslog"):
        raise ConfigError("logging.output must be stdout, file, or syslog")
    level = (_str(raw, "level", "logging", "INFO") or "INFO").upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ConfigError("logging.level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
    logging_cfg = LoggingConfig(
        level=level,
        output=output,
        file_path=_str(raw, "file_path", "logging") or None,
        max_bytes=_int(raw, "max_bytes", "logging", 10 * 1024 * 1024),
        backup_count=_int(raw, "backup_count", "logging", 5),
    )
    if output == "file" and not logging_cfg.file_path:
        raise ConfigError("logging: file output requires file_path")
    if logging_cfg.max_bytes < 0:
        raise ConfigError("logging: max_bytes must be >= 0")
    if logging_cfg.backup_count < 0:
        raise ConfigError("logging: backup_count must be >= 0")
    return logging_cfg


def _build_debug(raw: object) -> DebugConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("debug must be a mapping")
    _unknown(raw, {"messages", "tokens", "paho"}, "debug")
    return DebugConfig(
        messages=_bool(raw, "messages", "debug", False),
        tokens=_bool(raw, "tokens", "debug", False),
        paho=_bool(raw, "paho", "debug", False),
    )


def _build(raw: dict[str, Any], warnings: list[str]) -> Config:
    _unknown(
        raw,
        {"source", "key", "brokers", "token", "reconnect", "runtime", "logging", "debug"},
        "config",
    )
    return Config(
        source=_build_source(_req(raw, "source", "config")),
        key=_build_key(_req(raw, "key", "config"), warnings),
        brokers=_build_brokers(_req(raw, "brokers", "config")),
        token=_build_token(raw.get("token")),
        reconnect=_build_reconnect(raw.get("reconnect")),
        runtime=_build_runtime(raw.get("runtime")),
        logging=_build_logging(raw.get("logging")),
        debug=_build_debug(raw.get("debug")),
        warnings=warnings,
    )


def _yaml_error_message(exc: yaml.YAMLError) -> str:
    """Only the parser's problem/context, never str(exc) (may echo content)."""
    problem = getattr(exc, "problem", None)
    context = getattr(exc, "context", None)
    mark = getattr(exc, "problem_mark", None)
    where = ""
    if mark is not None:
        where = f" at line {mark.line + 1}, column {mark.column + 1}"
    parts = [p for p in (context, problem) if p]
    return ("invalid YAML: " + ": ".join(parts) + where) if parts else (
        "invalid YAML: could not parse the file"
    )


def load(path: str) -> Config:
    """Load and validate the config file at `path`."""
    warnings: list[str] = []

    try:
        st = os.stat(path)
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {path}") from e
    except OSError as e:
        raise ConfigError(f"cannot stat config file {path}: {e.strerror or e}") from e

    if stat.S_ISREG(st.st_mode) and (st.st_mode & 0o077):
        warnings.append(
            f"config file {path} has mode {oct(st.st_mode & 0o777)}; "
            "it may contain hostnames and credentials, so chmod 600/640 is advised"
        )

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {path}") from e
    except PermissionError as e:
        raise ConfigError(f"config file is not readable: {path}") from e
    except yaml.YAMLError as e:
        raise ConfigError(_yaml_error_message(e)) from e
    except UnicodeDecodeError as e:
        raise ConfigError(f"config file is not valid UTF-8: {path}") from e
    except OSError as e:
        raise ConfigError(f"cannot read config file {path}: {e.strerror or e}") from e

    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    return _build(raw, warnings)
