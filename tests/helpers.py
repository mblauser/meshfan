"""Shared test helpers: a valid config mapping (placeholders only)."""
from __future__ import annotations


def valid_config_dict(pub_hex: str) -> dict:
    """A minimal valid config mapping; `pub_hex` is the 64-hex public key."""
    return {
        "source": {
            "host": "127.0.0.1",
            "port": 1883,
            "topic": "meshcore/#",
            "tls": {"enabled": False, "plaintext": True},
        },
        "key": {
            "private_key_env": "MESHFAN_TEST_KEY",
            "public_key": pub_hex,
        },
        "brokers": [
            {
                "name": "testbroker",
                "host": "broker.example.net",
                "port": 443,
                "path": "/mqtt",
                "audience": "map.example.net",
            }
        ],
    }


def write_yaml(path, mapping) -> str:
    import yaml

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(mapping, f)
    return str(path)
