"""Shared fixtures."""
from __future__ import annotations

import pytest
from ed25519_orlp import ed25519_create_keypair


@pytest.fixture()
def keypair():
    """A real MeshCore keypair: (public_key, private_key, seed)."""
    pub, priv, seed = ed25519_create_keypair()
    return pub, priv, seed
