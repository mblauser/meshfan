"""Load and validate the Ed25519 key material.

The private key is a secret. It is loaded from an environment variable
(preferred) or a chmod-600 regular file, validated, and held in memory
only. The raw string is dropped after conversion to bytes.

The file may be age-encrypted (key.encryption: age). In that case the
passphrase comes from the environment variable named by
key.passphrase_env, is handed to `age-sctl` through a short-lived 0600
passphrase file (never on the command line), and is never logged.

The public key is not a secret. It is a 64-hex string in the config.

The pure hex validation/decoding lives in meshfan.jwt
(parse_private_key / parse_public_key), which has no I/O and no YAML
dependency; this module keeps the I/O wrappers.

Loading is idempotent by default for library callers: pass
``consume=False`` (and, for a retry-safe env, your own mapping) to keep
the variable set. The daemon (meshfan.cli) passes the defaults, which
pop the variable from os.environ after reading it.
"""
from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import tempfile
from collections.abc import Mapping

from ed25519_orlp import ed25519_sign, ed25519_verify

from .config import KeyConfig
from .errors import MeshfanError
from .jwt import parse_private_key, parse_public_key
from .log import sanitize

#: Fixed probe signed to prove the configured public key matches the private.
KEYPAIR_PROBE = b"meshfan keypair probe v1"


class KeyLoadError(MeshfanError):
    """Raised when key material is missing or malformed."""


def _read_env(
    name: str, what: str, env: Mapping[str, str], consume: bool
) -> str:
    """Read a secret from `env`.

    With consume=True the variable is removed from the environment after
    reading (only for mappings that support pop, i.e. os.environ or a
    dict), so a later crash dump, /proc/<pid>/environ read, or child
    process cannot pick the secret up. Prefer a systemd EnvironmentFile
    (mode 0600) over `Environment=` in the unit file.
    """
    value = env.get(name)
    if value is None:
        raise KeyLoadError(f"environment variable {name} is not set ({what})")
    if value == "":
        raise KeyLoadError(f"environment variable {name} is empty ({what})")
    if consume:
        pop = getattr(env, "pop", None)
        if pop is not None:
            pop(name, None)
    return value


def _check_file_security(path: str, st: os.stat_result) -> None:
    mode = oct(stat.S_IMODE(st.st_mode))
    if stat.S_ISLNK(st.st_mode):
        raise KeyLoadError(
            f"key file {path} is a symlink; refusing to follow it (mode {mode})"
        )
    if not stat.S_ISREG(st.st_mode):
        raise KeyLoadError(
            f"key file {path} is not a regular file (mode {mode})"
        )
    euid = os.geteuid()
    if st.st_uid not in (euid, 0):
        raise KeyLoadError(
            f"key file {path} is owned by uid {st.st_uid}; "
            f"expected {euid} or 0 (mode {mode})"
        )
    if st.st_mode & 0o077:
        raise KeyLoadError(
            f"key file {path} has unsafe mode {mode}; "
            "require 0600 or stricter (chmod 600)"
        )


def _check_secure_path(path: str) -> None:
    """Permission/owner/type check for a secret file (no symlink follow)."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError as e:
        raise KeyLoadError(
            f"cannot stat key file {path}: {e.strerror or e}"
        ) from e
    _check_file_security(path, st)


def _read_file_secure(path: str) -> str:
    """Read a secret file after checking owner/type/mode (no symlinks)."""
    _check_secure_path(path)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise KeyLoadError(
            f"cannot open key file {path}: {e.strerror or e}"
        ) from e
    try:
        # Re-check the opened descriptor: closes the stat/open race.
        _check_file_security(path, os.fstat(fd))
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = -1
            return f.read()
    except OSError as e:
        raise KeyLoadError(
            f"cannot read key file {path}: {e.strerror or e}"
        ) from e
    finally:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)


@contextlib.contextmanager
def _passphrase_file(passphrase: str):
    """Yield a path to a 0600 file holding the passphrase; remove afterwards."""
    directory = tempfile.mkdtemp(prefix="meshfan-age-")
    os.chmod(directory, 0o700)
    path = os.path.join(directory, "passphrase")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(passphrase)
        yield path
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)
        with contextlib.suppress(OSError):
            os.rmdir(directory)


def _run_age(args: list[str], timeout: float, secret: str | None = None) -> bytes:
    """Run age-sctl with stdin closed and no passphrase in argv.

    Any occurrence of `secret` in the tool's stderr is redacted before the
    message can reach a log or the terminal.
    """
    try:
        proc = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise KeyLoadError(
            f"age command not found: {args[0]}; install it or set "
            "key.age_command"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise KeyLoadError(f"age command timed out after {timeout:g}s") from e
    except OSError as e:
        raise KeyLoadError(f"cannot run age command {args[0]}: {e}") from e

    if proc.returncode != 0:
        detail = sanitize(
            proc.stderr.decode("utf-8", "replace").strip(), 200
        ) or f"exit status {proc.returncode}"
        if secret:
            detail = detail.replace(secret, "***")
        raise KeyLoadError(f"age command failed: {detail}")
    return proc.stdout


def _age_argv(age_command: str, mode: str, pass_file: str, in_path: str) -> list[str]:
    """Build the age-sctl argv.

    Contract: `age-sctl <encrypt|decrypt> --passphrase-file <path> <file>`,
    with the plaintext/ciphertext on stdout. The passphrase is only ever in
    the 0600 file, never in argv. If the installed age-sctl uses different
    flags, this is the single place to adapt (and key.age_command selects
    the binary).
    """
    return [age_command, mode, "--passphrase-file", pass_file, in_path]


def _age_decrypt(cfg: KeyConfig, passphrase: str) -> str:
    """Decrypt key.private_key_file and return its plaintext hex."""
    assert cfg.private_key_file is not None
    _check_secure_path(cfg.private_key_file)
    with _passphrase_file(passphrase) as pass_file:
        out = _run_age(
            _age_argv(
                cfg.age_command, "decrypt", pass_file, cfg.private_key_file
            ),
            cfg.age_timeout_seconds,
            secret=passphrase,
        )
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as e:
        raise KeyLoadError("age decrypted data is not text") from e


def load_private_key(
    cfg: KeyConfig,
    *,
    env: Mapping[str, str] = os.environ,
    consume: bool = True,
) -> bytes:
    """Load the 64-byte private key (128 hex chars, MeshCore expanded form).

    With key.encryption=age the file is decrypted first. Only the bytes are
    returned; the plaintext string is dropped.

    Args:
        cfg: the key section of the config.
        env: the mapping to read env-var secrets from (default: os.environ).
        consume: remove the read variable from `env` afterwards (default:
            True, the daemon behavior). Pass consume=False for idempotent
            library use (reload, retry, two relays in one process).
    """
    if cfg.encryption == "age":
        if not cfg.private_key_file:
            raise KeyLoadError("key.encryption=age requires private_key_file")
        if not cfg.passphrase_env:
            raise KeyLoadError("key.encryption=age requires passphrase_env")
        passphrase = _read_env(cfg.passphrase_env, "age passphrase", env, consume)
        raw = _age_decrypt(cfg, passphrase)
    elif cfg.private_key_env:
        raw = _read_env(cfg.private_key_env, "private key", env, consume)
    elif cfg.private_key_file:
        raw = _read_file_secure(cfg.private_key_file)
    else:
        raise KeyLoadError("no key source: set an env var name or a file path")

    try:
        return parse_private_key(raw)
    except ValueError as e:
        raise KeyLoadError(str(e)) from e


def load_public_key(hex_str: str) -> bytes:
    """Load and validate the 32-byte public key (64 hex chars)."""
    try:
        return parse_public_key(hex_str)
    except ValueError as e:
        raise KeyLoadError(str(e)) from e


def load_secret(
    env_name: str | None,
    file_path: str | None,
    inline: str | None,
    what: str,
    *,
    env: Mapping[str, str] = os.environ,
    consume: bool = True,
) -> str | None:
    """Resolve an optional secret from env (preferred), file, or inline.

    With consume=True the env var is removed from the environment after
    reading. Inline is accepted for compatibility but the caller should
    warn that it is deprecated.
    """
    if env_name:
        return _read_env(env_name, what, env, consume)
    if file_path:
        return _clean_secret(_read_file_secure(file_path))
    if inline is not None:
        return inline
    return None


def _clean_secret(value: str) -> str:
    return value.strip("\r\n")


def verify_keypair(public_key: bytes, private_key: bytes) -> None:
    """Sign a fixed probe and verify it with the configured public key."""
    try:
        signature = ed25519_sign(KEYPAIR_PROBE, public_key, private_key)
        ok = ed25519_verify(signature, KEYPAIR_PROBE, public_key)
    except Exception as e:  # the C extension raises ValueError on bad input
        raise KeyLoadError(f"keypair verification failed: {e}") from e
    if not ok:
        raise KeyLoadError(
            "key.public_key does not match the private key "
            "(the probe signature did not verify)"
        )


def encrypt_key_file(
    in_path: str,
    out_path: str,
    passphrase: str,
    age_command: str,
    timeout: float,
    *,
    force: bool = False,
) -> None:
    """Encrypt a plaintext 128-hex key file into an age passphrase file.

    The ciphertext is captured from age's stdout and written by us with mode
    0600, so the secret never lands in a default-umask file.
    """
    if os.path.exists(out_path) and not force:
        raise KeyLoadError(
            f"output file already exists: {out_path} (use --force to replace)"
        )

    raw = _read_file_secure(in_path)
    try:
        parse_private_key(raw)
    except ValueError as e:
        raise KeyLoadError(f"{in_path}: {e}") from e

    with _passphrase_file(passphrase) as pass_file:
        ciphertext = _run_age(
            _age_argv(age_command, "encrypt", pass_file, in_path),
            timeout,
            secret=passphrase,
        )
    if not ciphertext:
        raise KeyLoadError("age produced no ciphertext")

    out_dir = os.path.dirname(os.path.abspath(out_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".meshfan-age-", dir=out_dir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(ciphertext)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, out_path)
    except OSError as e:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise KeyLoadError(f"cannot write {out_path}: {e.strerror or e}") from e
