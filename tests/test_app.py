"""Secret handling: ResolvedSecrets, frozen Config, idempotent prepare."""
from __future__ import annotations

import dataclasses

import pytest
from helpers import valid_config_dict

from meshfan import KeyLoadError, from_dict
from meshfan.app import MeshfanApp, prepare
from meshfan.errors import MeshfanError


def test_frozen_config_rejects_mutation():
    cfg = from_dict(valid_config_dict("00" * 32))
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.source.password = "SUPERSECRET"
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.source = None


def test_repr_never_contains_a_secret():
    raw = valid_config_dict("00" * 32)
    raw["source"]["password"] = "SUPERSECRET"
    cfg = from_dict(raw)
    assert "SUPERSECRET" not in repr(cfg)
    assert "SUPERSECRET" not in repr(cfg.source)


def test_prepare_returns_resolved_secrets(keypair):
    pub, priv, _ = keypair
    raw = valid_config_dict(pub.hex())
    raw["source"]["password_env"] = "MESHFAN_TEST_PW"
    cfg = from_dict(raw)
    env = {"MESHFAN_TEST_KEY": priv.hex(), "MESHFAN_TEST_PW": "pw-secret"}
    secrets = prepare(cfg, env=env, consume=False)
    assert secrets.private_key == priv
    assert secrets.public_key == pub
    assert secrets.source_password == "pw-secret"
    # the Config is untouched: no resolved secret was written onto it
    assert cfg.source.password is None


def test_resolved_secrets_repr_is_redacted(keypair):
    pub, priv, _ = keypair
    raw = valid_config_dict(pub.hex())
    raw["source"]["password"] = "inline-secret"
    cfg = from_dict(raw)
    env = {"MESHFAN_TEST_KEY": priv.hex()}
    secrets = prepare(cfg, env=env, consume=False)
    r = repr(secrets)
    assert "inline-secret" not in r
    assert priv.hex() not in r


def test_prepare_idempotent_with_consume_false(keypair):
    pub, priv, _ = keypair
    cfg = from_dict(valid_config_dict(pub.hex()))
    env = {"MESHFAN_TEST_KEY": priv.hex()}
    s1 = prepare(cfg, env=env, consume=False)
    s2 = prepare(cfg, env=env, consume=False)
    assert s1.private_key == s2.private_key
    assert "MESHFAN_TEST_KEY" in env


def test_prepare_consume_pops_and_second_call_fails(keypair):
    pub, priv, _ = keypair
    cfg = from_dict(valid_config_dict(pub.hex()))
    env = {"MESHFAN_TEST_KEY": priv.hex()}
    prepare(cfg, env=env, consume=True)
    assert "MESHFAN_TEST_KEY" not in env
    with pytest.raises(KeyLoadError, match="not set"):
        prepare(cfg, env=env, consume=True)


def test_app_double_start_raises(keypair):
    pub, priv, _ = keypair
    cfg = from_dict(valid_config_dict(pub.hex()))
    env = {"MESHFAN_TEST_KEY": priv.hex()}
    secrets = prepare(cfg, env=env, consume=False)
    app = MeshfanApp(cfg, secrets=secrets)
    app._started = True  # simulate an already-started app (no network)
    with pytest.raises(MeshfanError, match="already started"):
        app.start()


def test_stop_event_property(keypair):
    pub, priv, _ = keypair
    cfg = from_dict(valid_config_dict(pub.hex()))
    env = {"MESHFAN_TEST_KEY": priv.hex()}
    secrets = prepare(cfg, env=env, consume=False)
    app = MeshfanApp(cfg, secrets=secrets)
    import threading

    assert isinstance(app.stop_event, threading.Event)
    assert not app.stop_event.is_set()
