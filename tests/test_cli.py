"""CLI exit-code tests: --check, --init-config, jwt sign, key generate.

These tests never start the daemon (no network): --check exits before any
connection, and the helper subcommands do not connect at all.
"""
from __future__ import annotations

import os
import stat

import pytest

from meshfan.cli import main, _load_example_config
from meshfan.config import loads
from meshfan import verify

from helpers import valid_config_dict, write_yaml


def test_check_ok(tmp_path, keypair, monkeypatch, capsys):
    pub, priv, _ = keypair
    cfg = write_yaml(tmp_path / "m.yaml", valid_config_dict(pub.hex()))
    monkeypatch.setenv("MESHFAN_TEST_KEY", priv.hex())
    assert main(["--config", cfg, "--check"]) == 0
    out = capsys.readouterr().out
    assert "OK: config valid, keypair verified" in out
    assert "1 broker(s)" in out


def test_check_missing_config(tmp_path):
    assert main(["--config", str(tmp_path / "nope.yaml")]) == 2


def test_check_bad_config(tmp_path, keypair, monkeypatch):
    pub, priv, _ = keypair
    raw = valid_config_dict(pub.hex())
    raw["source"]["port"] = "abc"
    p = write_yaml(tmp_path / "m.yaml", raw)
    monkeypatch.setenv("MESHFAN_TEST_KEY", priv.hex())
    assert main(["--config", p, "--check"]) == 2


def test_check_key_not_set(tmp_path, keypair, monkeypatch):
    pub, _priv, _ = keypair
    cfg = write_yaml(tmp_path / "m.yaml", valid_config_dict(pub.hex()))
    monkeypatch.delenv("MESHFAN_TEST_KEY", raising=False)
    assert main(["--config", cfg, "--check"]) == 2


def test_check_key_mismatch(tmp_path, keypair, monkeypatch):
    pub, _priv, _ = keypair
    from ed25519_orlp import ed25519_create_keypair

    _pub2, priv2, _ = ed25519_create_keypair()
    cfg = write_yaml(tmp_path / "m.yaml", valid_config_dict(pub.hex()))
    monkeypatch.setenv("MESHFAN_TEST_KEY", priv2.hex())
    assert main(["--config", cfg, "--check"]) == 2


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0


def test_init_config_writes_0600_starter(tmp_path):
    out = tmp_path / "starter.yaml"
    assert main(["--init-config", str(out)]) == 0
    assert out.exists()
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert "source:" in out.read_text()
    # refuses to overwrite
    assert main(["--init-config", str(out)]) == 2


def test_example_config_has_only_placeholders():
    text = _load_example_config()
    assert text is not None
    assert "MESHFAN_PRIVATE_KEY" in text
    assert "0" * 64 in text  # the placeholder public key
    import re

    assert not re.search(r"\b[0-9A-Fa-f]{128}\b", text)  # no private key material


def test_example_config_parses_with_default_client():
    text = _load_example_config()
    cfg = loads(text)
    assert len(cfg.brokers) == 1
    assert cfg.brokers[0].client == "meshfan-meshomatic"  # default resolved


def test_jwt_sign_prints_token_and_exp(tmp_path, keypair, monkeypatch, capsys):
    pub, priv, _ = keypair
    cfg = write_yaml(tmp_path / "m.yaml", valid_config_dict(pub.hex()))
    monkeypatch.setenv("MESHFAN_TEST_KEY", priv.hex())
    rc = main(
        [
            "--config", cfg,
            "jwt", "sign",
            "--aud", "map.example.net",
            "--client", "meshfan-1",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    lines = out.splitlines()
    assert lines[0].startswith("token: ")
    assert lines[1].startswith("exp: ")
    tok = lines[0].split("token: ", 1)[1]
    assert verify(tok, pub) is True
    # the private key is never printed
    assert priv.hex() not in out


def test_key_generate_writes_0600_keys(tmp_path):
    out = tmp_path / "k.plain"
    pub = tmp_path / "k.pub"
    assert main(["key", "generate", "--out", str(out), "--pub-out", str(pub)]) == 0
    priv_hex = out.read_text().strip()
    pub_hex = pub.read_text().strip()
    assert len(priv_hex) == 128
    assert len(pub_hex) == 64
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(pub).st_mode) == 0o600
    # the generated keypair verifies
    from meshfan import sign_jwt

    tok = sign_jwt(
        public_key=bytes.fromhex(pub_hex),
        private_key=bytes.fromhex(priv_hex),
        audience="a",
        client="c",
    )
    assert verify(tok.value, bytes.fromhex(pub_hex)) is True


def test_key_generate_refuses_overwrite(tmp_path):
    out = tmp_path / "k.plain"
    pub = tmp_path / "k.pub"
    assert main(["key", "generate", "--out", str(out), "--pub-out", str(pub)]) == 0
    assert main(["key", "generate", "--out", str(out), "--pub-out", str(pub)]) == 2


def test_unknown_subcommand_exits_2():
    assert main(["key"]) == 2
    assert main(["jwt"]) == 2
