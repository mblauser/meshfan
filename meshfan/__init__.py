"""meshfan: an MQTT fan-out relay that signs Ed25519 device JWTs.

Subscribes to one MQTT source and republishes every message to a list of
MQTT-over-WebSocket (WSS) brokers. Each target is authenticated with a
short-lived Ed25519 device JWT (MeshCore "device signing") that meshfan
signs with the node's private key. No broker can sign that JWT itself,
which is the gap meshfan fills.

The supported public surface:

- signing:  sign_jwt, verify, Token
- config:   load_config (a YAML file), loads (a YAML string),
            from_dict (a parsed mapping), Config, ConfigError
- keys:     KeyLoadError
- errors:   MeshfanError (the base class for all of the above)

The token is NOT a standard RFC 7519 JWT and is not PyJWT-compatible
(see docs/JWT.md). The daemon (meshfan.app / meshfan.cli) needs the
[daemon] extra (paho-mqtt); parsing YAML configs needs the [config]
extra (PyYAML); the pure signer needs only ed25519-orlp.
"""
from __future__ import annotations

from .config import (
    Config,
    ConfigError,
    from_dict,
    load_config,
    loads,
)
from .errors import MeshfanError
from .jwt import Token, sign_jwt, verify
from .key import KeyLoadError

__version__ = "0.1.0"

__all__ = [
    "Config",
    "ConfigError",
    "KeyLoadError",
    "MeshfanError",
    "Token",
    "from_dict",
    "load_config",
    "loads",
    "sign_jwt",
    "verify",
    "__version__",
]
