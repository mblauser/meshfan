"""Build and validate the SSL contexts once, before any connection.

Doing this at startup (and in --check) turns a missing or malformed CA file
into a clear exit 2 instead of an endless transient reconnect loop.
"""
from __future__ import annotations

import os
import ssl

from .config import ConfigError, TlsConfig


def build_ssl_context(tls: TlsConfig, label: str) -> ssl.SSLContext | None:
    """Return a context for a TLS endpoint, or None for plaintext.

    Raises ConfigError when the CA file is missing, is not a regular file,
    or cannot be loaded.
    """
    if not tls.enabled:
        return None

    ctx = ssl.create_default_context()
    if tls.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if tls.ca_file:
        if not os.path.isfile(tls.ca_file):
            raise ConfigError(f"{label}: ca_file not found: {tls.ca_file}")
        try:
            ctx.load_verify_locations(cafile=tls.ca_file)
        except (ssl.SSLError, OSError) as e:
            raise ConfigError(
                f"{label}: cannot load ca_file {tls.ca_file}: {e}"
            ) from e

    return ctx
