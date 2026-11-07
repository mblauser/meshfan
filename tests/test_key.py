"""Key loading: env/file/empty/malformed/owner + idempotency."""
from __future__ import annotations

import os

import pytest
from ed25519_orlp import ed25519_create_keypair

from meshfan import KeyLoadError
from meshfan.config import KeyConfig
from meshfan.key import (
    load_private_key,
    load_public_key,
    load_secret,
    verify_keypair,
)


def _write_600(path: str, data: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def test_load_private_key_from_env(keypair):
    _pub, priv, _ = keypair
    env = {"MESHFAN_TEST_KEY": priv.hex()}
    cfg = KeyConfig(public_key="00" * 32, private_key_env="MESHFAN_TEST_KEY")
    assert load_private_key(cfg, env=env) == priv
    # consume=True (default) pops the variable
    assert "MESHFAN_TEST_KEY" not in env


def test_load_private_key_idempotent_with_consume_false(keypair):
    _pub, priv, _ = keypair
    env = {"MESHFAN_TEST_KEY": priv.hex()}
    cfg = KeyConfig(public_key="00" * 32, private_key_env="MESHFAN_TEST_KEY")
    assert load_private_key(cfg, env=env, consume=False) == priv
    # second call in the same process: still works
    assert load_private_key(cfg, env=env, consume=False) == priv
    assert "MESHFAN_TEST_KEY" in env


def test_load_private_key_env_not_set():
    cfg = KeyConfig(public_key="00" * 32, private_key_env="NOPE")
    with pytest.raises(KeyLoadError, match="not set"):
        load_private_key(cfg, env={})


def test_load_private_key_env_empty():
    cfg = KeyConfig(public_key="00" * 32, private_key_env="NOPE")
    with pytest.raises(KeyLoadError, match="empty"):
        load_private_key(cfg, env={"NOPE": ""})


def test_load_private_key_from_file(tmp_path, keypair):
    _pub, priv, _ = keypair
    p = tmp_path / "key"
    _write_600(str(p), priv.hex())
    cfg = KeyConfig(public_key="00" * 32, private_key_file=str(p))
    assert load_private_key(cfg) == priv


def test_load_private_key_file_bad_mode(tmp_path, keypair):
    _pub, priv, _ = keypair
    p = tmp_path / "key"
    _write_600(str(p), priv.hex())
    os.chmod(p, 0o644)
    cfg = KeyConfig(public_key="00" * 32, private_key_file=str(p))
    with pytest.raises(KeyLoadError, match="unsafe mode"):
        load_private_key(cfg)


def test_load_private_key_file_symlink(tmp_path, keypair):
    _pub, priv, _ = keypair
    real = tmp_path / "real"
    _write_600(str(real), priv.hex())
    link = tmp_path / "link"
    os.symlink(str(real), str(link))
    cfg = KeyConfig(public_key="00" * 32, private_key_file=str(link))
    with pytest.raises(KeyLoadError, match="symlink"):
        load_private_key(cfg)


def test_load_private_key_file_wrong_owner(tmp_path, keypair, monkeypatch):
    _pub, priv, _ = keypair
    p = tmp_path / "key"
    _write_600(str(p), priv.hex())
    monkeypatch.setattr(os, "geteuid", lambda: 999999)
    cfg = KeyConfig(public_key="00" * 32, private_key_file=str(p))
    with pytest.raises(KeyLoadError, match="owned by uid"):
        load_private_key(cfg)


def test_load_private_key_malformed(tmp_path, keypair):
    _pub, priv, _ = keypair
    p = tmp_path / "key"
    _write_600(str(p), priv.hex()[:127])  # 127 hex chars
    cfg = KeyConfig(public_key="00" * 32, private_key_file=str(p))
    with pytest.raises(KeyLoadError, match="128 hex characters"):
        load_private_key(cfg)


def test_load_private_key_malformed_non_hex(tmp_path):
    p = tmp_path / "key"
    _write_600(str(p), "g" * 128)
    cfg = KeyConfig(public_key="00" * 32, private_key_file=str(p))
    with pytest.raises(KeyLoadError, match="128 hex characters"):
        load_private_key(cfg)


def test_load_private_key_no_source():
    cfg = KeyConfig(public_key="00" * 32)
    with pytest.raises(KeyLoadError, match="no key source"):
        load_private_key(cfg)


def test_load_public_key_valid(keypair):
    pub, _priv, _ = keypair
    assert load_public_key(pub.hex()) == pub
    # whitespace is stripped
    spaced = " ".join(pub.hex()[i:i + 8] for i in range(0, 64, 8))
    assert load_public_key(spaced) == pub


def test_load_public_key_malformed():
    with pytest.raises(KeyLoadError, match="64 hex characters"):
        load_public_key("00" * 31)
    with pytest.raises(KeyLoadError, match="64 hex characters"):
        load_public_key("g" * 64)


def test_load_secret_env_file_inline_none(tmp_path):
    env = {"PW": "secret"}
    assert load_secret("PW", None, None, "pw", env=env) == "secret"
    assert "PW" not in env  # consumed
    f = tmp_path / "pf"
    _write_600(str(f), "filesecret\n")
    assert load_secret(None, str(f), None, "pw") == "filesecret"
    assert load_secret(None, None, "inline", "pw") == "inline"
    assert load_secret(None, None, None, "pw") is None


def test_load_secret_idempotent_with_consume_false():
    env = {"PW": "secret"}
    assert load_secret("PW", None, None, "pw", env=env, consume=False) == "secret"
    assert load_secret("PW", None, None, "pw", env=env, consume=False) == "secret"
    assert "PW" in env


def test_verify_keypair_ok(keypair):
    pub, priv, _ = keypair
    verify_keypair(pub, priv)  # must not raise


def test_verify_keypair_mismatch(keypair):
    pub, _priv, _ = keypair
    _pub2, priv2, _ = ed25519_create_keypair()
    with pytest.raises(KeyLoadError):
        verify_keypair(pub, priv2)
