"""The meshfan exception hierarchy.

Every error meshfan raises derives from MeshfanError, so a caller can
catch one base class:

    try:
        cfg = meshfan.load_config(path)
        secrets = meshfan.app.prepare(cfg)
    except meshfan.MeshfanError as e:
        ...

ConfigError: the config file or mapping is missing or invalid.
KeyLoadError: key material is missing, malformed, or fails verification.
"""
from __future__ import annotations


class MeshfanError(Exception):
    """Base class for every error meshfan raises."""
