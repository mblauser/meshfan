"""Config validation: one case per ConfigError branch + loader equivalence.

The table covers every raise site in config.py. Cases that need the YAML
path (loads/load) are separate.
"""
from __future__ import annotations

import dataclasses
import os
import re

import pytest
from helpers import valid_config_dict

from meshfan import (
    ConfigError,
    MeshfanError,
    from_dict,
    load_config,
    loads,
)
from meshfan.config import default_client_id

PUB = "00" * 32

# (label, mutator, expected-message-substring)
CASES = [
    # root
    ("unknown root key", lambda d: d.update(bogus=1), "unknown key 'bogus'"),
    ("missing source", lambda d: d.pop("source"), "missing required key 'source'"),
    ("missing key section", lambda d: d.pop("key"), "missing required key 'key'"),
    ("missing brokers", lambda d: d.pop("brokers"), "missing required key 'brokers'"),
    # source
    ("source not a mapping", lambda d: d.update(source=[1]), "source must be a mapping"),
    ("source host missing", lambda d: d["source"].pop("host"), "missing required key 'host'"),
    ("source host whitespace", lambda d: d["source"].update(host="12 7.0.0.1"), "host contains whitespace"),
    ("source host too long", lambda d: d["source"].update(host="a" * 254), "host must be 1-253"),
    ("source host bad ipv6", lambda d: d["source"].update(host="1234:::gg"), "invalid IPv6 address"),
    ("source host bad label", lambda d: d["source"].update(host="a..b"), "invalid hostname"),
    ("source port zero", lambda d: d["source"].update(port=0), "must be between 1 and 65535"),
    ("source port too big", lambda d: d["source"].update(port=70000), "must be between 1 and 65535"),
    ("source port not an int", lambda d: d["source"].update(port="abc"), "'port' must be an integer"),
    ("source port is a bool", lambda d: d["source"].update(port=True), "'port' must be an integer"),
    ("source port non-integer float", lambda d: d["source"].update(port=1883.5), "'port' must be an integer"),
    ("source topic empty", lambda d: d["source"].update(topic=""), "topic must be 1-512"),
    ("source topic non-printable", lambda d: d["source"].update(topic="ab\x01c"), "topic must be 1-512"),
    ("source topic too long", lambda d: d["source"].update(topic="a" * 513), "topic must be 1-512"),
    ("source keepalive zero", lambda d: d["source"].update(keepalive=0), "keepalive must be >= 1"),
    ("source qos invalid", lambda d: d["source"].update(qos=3), "qos must be 0, 1, or 2"),
    ("source username not a string", lambda d: d["source"].update(username=123), "'username' must be a string"),
    ("source password + env", lambda d: d["source"].update(password="x", password_env="P"), "use only one of password, password_env, password_file"),
    ("source env + file", lambda d: d["source"].update(password_env="P", password_file="/f"), "use only one of password_env, password_file"),
    ("source client_id invalid", lambda d: d["source"].update(client_id="has space"), "client must be 1-128"),
    ("source tls enabled+plaintext", lambda d: d["source"]["tls"].update(enabled=True, plaintext=True), "contradictory"),
    ("source tls disabled without plaintext", lambda d: d["source"]["tls"].update(enabled=False, plaintext=False), "tls.enabled=false sends traffic"),
    ("source tls disabled with insecure", lambda d: d["source"]["tls"].update(enabled=False, plaintext=True, insecure=True), "tls.insecure has no effect"),
    ("source tls not a mapping", lambda d: d["source"].update(tls=[1]), "source.tls must be a mapping"),
    ("source tls.enabled not a bool", lambda d: d["source"]["tls"].update(enabled="false"), "'enabled' must be a boolean"),
    # key
    ("key not a mapping", lambda d: d.update(key=[1]), "key must be a mapping"),
    ("key public_key missing", lambda d: d["key"].pop("public_key"), "missing required key 'public_key'"),
    ("key public_key not a string", lambda d: d["key"].update(public_key=123), "key.public_key must be a string"),
    ("key bad encryption", lambda d: d["key"].update(encryption="rot13"), "key.encryption must be 'none' or 'age'"),
    ("key age without file", lambda d: d["key"].update(encryption="age", private_key_file=None, passphrase_env="P"), "requires key.private_key_file"),
    ("key age + env", lambda d: d["key"].update(encryption="age", private_key_file="/f", passphrase_env="P"), "cannot be combined with private_key_env"),
    ("key age without passphrase", lambda d: d["key"].update(encryption="age", private_key_file="/f", private_key_env=None), "requires key.passphrase_env"),
    ("key neither env nor file", lambda d: d["key"].pop("private_key_env"), "set private_key_env or private_key_file"),
    ("key age_timeout zero", lambda d: d["key"].update(age_timeout_seconds=0), "age_timeout_seconds must be > 0"),
    # brokers
    ("brokers empty list", lambda d: d.update(brokers=[]), "brokers must be a non-empty list"),
    ("broker not a mapping", lambda d: d.update(brokers=[1]), "brokers[0] must be a mapping"),
    ("broker name missing", lambda d: d["brokers"][0].pop("name"), "missing required key 'name'"),
    ("broker name empty", lambda d: d["brokers"][0].update(name=""), "name must not be empty"),
    ("broker duplicate name", lambda d: d.update(brokers=[dict(d["brokers"][0]), dict(d["brokers"][0])]), "duplicate name"),
    ("broker keepalive zero", lambda d: d["brokers"][0].update(keepalive=0), "keepalive must be >= 1"),
    ("broker host invalid", lambda d: d["brokers"][0].update(host="bad host"), "host contains whitespace"),
    ("broker port invalid", lambda d: d["brokers"][0].update(port=0), "must be between 1 and 65535"),
    ("broker path invalid", lambda d: d["brokers"][0].update(path="noslash"), "path must start with '/'"),
    ("broker audience invalid", lambda d: d["brokers"][0].update(audience="has space"), "audience must be 1-255"),
    ("broker client invalid", lambda d: d["brokers"][0].update(client="bad space"), "client must be 1-128"),
    ("broker tls disabled without plaintext", lambda d: d["brokers"][0].setdefault("tls", {}).update(enabled=False, plaintext=False), "sends the signed JWT in the clear"),
    ("broker tls enabled+plaintext", lambda d: d["brokers"][0].setdefault("tls", {}).update(enabled=True, plaintext=True), "contradictory"),
    ("broker unknown key", lambda d: d["brokers"][0].update(bogus=1), "unknown key 'bogus'"),
    # token
    ("token ttl zero", lambda d: d.setdefault("token", {}).update(ttl_seconds=0), "ttl_seconds must be in 1..86400"),
    ("token ttl too big", lambda d: d.setdefault("token", {}).update(ttl_seconds=90000), "ttl_seconds must be in 1..86400"),
    ("token renew_before == ttl", lambda d: d.setdefault("token", {}).update(ttl_seconds=100, renew_before_seconds=100), "0 <= renew_before_seconds < ttl_seconds"),
    ("token renew_before negative", lambda d: d.setdefault("token", {}).update(renew_before_seconds=-1), "0 <= renew_before_seconds < ttl_seconds"),
    # reconnect
    ("reconnect base > max", lambda d: d.setdefault("reconnect", {}).update(base_delay=61.0, max_delay=60.0), "0 < base_delay <= max_delay"),
    ("reconnect multiplier < 1", lambda d: d.setdefault("reconnect", {}).update(multiplier=0.5), "multiplier must be >= 1.0"),
    ("reconnect jitter == 1", lambda d: d.setdefault("reconnect", {}).update(jitter=1.0), "0.0 <= jitter < 1.0"),
    ("reconnect jitter negative", lambda d: d.setdefault("reconnect", {}).update(jitter=-0.1), "0.0 <= jitter < 1.0"),
    # runtime
    ("runtime max_queued negative", lambda d: d.setdefault("runtime", {}).update(max_queued_messages=-1), "max_queued_messages must be >= 0"),
    ("runtime shutdown zero", lambda d: d.setdefault("runtime", {}).update(shutdown_timeout=0.0), "shutdown_timeout must be > 0"),
    ("runtime token_check zero", lambda d: d.setdefault("runtime", {}).update(token_check_seconds=0.0), "token_check_seconds must be > 0"),
    ("runtime connect_timeout zero", lambda d: d.setdefault("runtime", {}).update(connect_timeout_seconds=0.0), "connect_timeout_seconds must be > 0"),
    ("runtime summary negative", lambda d: d.setdefault("runtime", {}).update(summary_interval_seconds=-1.0), "summary_interval_seconds must be >= 0"),
    ("runtime username_prefix non-printable", lambda d: d.setdefault("runtime", {}).update(username_prefix="a\x01b"), "username_prefix must be printable ASCII"),
    # logging
    ("logging output invalid", lambda d: d.setdefault("logging", {}).update(output="console"), "logging.output must be stdout, file, or syslog"),
    ("logging level invalid", lambda d: d.setdefault("logging", {}).update(level="TRACE"), "logging.level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL"),
    ("logging file without path", lambda d: d.setdefault("logging", {}).update(output="file"), "file output requires file_path"),
    ("logging max_bytes negative", lambda d: d.setdefault("logging", {}).update(max_bytes=-1), "max_bytes must be >= 0"),
    ("logging backup negative", lambda d: d.setdefault("logging", {}).update(backup_count=-1), "backup_count must be >= 0"),
    # debug
    ("debug messages not a bool", lambda d: d.setdefault("debug", {}).update(messages="yes"), "'messages' must be a boolean"),
]


@pytest.mark.parametrize(
    "label,mutate,expected", CASES, ids=[c[0] for c in CASES]
)
def test_config_error_branch(label, mutate, expected):
    raw = valid_config_dict(PUB)
    mutate(raw)
    with pytest.raises(ConfigError, match=re.escape(expected)):
        from_dict(raw)


def test_loads_bad_yaml():
    with pytest.raises(ConfigError, match="invalid YAML"):
        loads("source: [1\n")


def test_loads_root_not_a_mapping():
    with pytest.raises(ConfigError, match="config root must be a mapping"):
        loads("- 1\n- 2\n")


def test_load_file_not_found(tmp_path):
    with pytest.raises(ConfigError, match="config file not found"):
        load_config(str(tmp_path / "nope.yaml"))


def test_load_mode_warning(tmp_path):
    import yaml
    from helpers import valid_config_dict

    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(valid_config_dict(PUB)))
    os.chmod(p, 0o644)
    cfg = load_config(str(p))
    assert any("mode" in w for w in cfg.warnings)
    # a 0600 file produces no warning
    os.chmod(p, 0o600)
    cfg2 = load_config(str(p))
    assert not any("mode" in w for w in cfg2.warnings)


def test_loads_from_dict_load_equivalence(tmp_path):
    raw = valid_config_dict(PUB)
    import yaml

    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(raw))
    os.chmod(p, 0o600)
    via_load = load_config(str(p))
    via_loads = loads(yaml.safe_dump(raw))
    via_dict = from_dict(raw)
    assert via_load == via_loads == via_dict


def test_from_dict_is_deterministic():
    raw = valid_config_dict(PUB)
    a = from_dict(raw)
    b = from_dict(raw)
    assert a == b
    # the broker client default is derived from the name (deterministic)
    assert a.brokers[0].client == "meshfan-testbroker"
    # the source client id is NOT derived here (resolved at startup)
    assert a.source.client_id is None


def test_broker_client_default_and_override():
    raw = valid_config_dict(PUB)
    cfg = from_dict(raw)
    assert cfg.brokers[0].client == "meshfan-testbroker"
    raw["brokers"][0]["client"] = "custom-id"
    cfg2 = from_dict(raw)
    assert cfg2.brokers[0].client == "custom-id"


def test_frozen_config_rejects_mutation():
    cfg = from_dict(valid_config_dict(PUB))
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.source.password = "SUPERSECRET"
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.source = None
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.brokers = ()


def test_repr_never_contains_password():
    raw = valid_config_dict(PUB)
    raw["source"]["password"] = "SUPERSECRET"
    cfg = from_dict(raw)
    assert "SUPERSECRET" not in repr(cfg)
    assert "SUPERSECRET" not in repr(cfg.source)


def test_loads_without_yaml_raises_meshfan_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("No module named 'yaml'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(MeshfanError, match="PyYAML"):
        loads("source: {}\n")


def test_default_client_id_format():
    cid = default_client_id()
    assert cid.startswith("meshfan-")
    assert str(os.getpid()) in cid
