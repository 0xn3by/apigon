from __future__ import annotations

import json
import os

import pytest

from config import AuthSpec, Config, load_dotenv, resolve_env


# ---------------------------------------------------------------------------
# resolve_env
# ---------------------------------------------------------------------------

def test_resolve_env_substitutes_scalar(monkeypatch):
    monkeypatch.setenv("FOO", "bar")
    assert resolve_env("${FOO}") == "bar"


def test_resolve_env_substitutes_inside_larger_string(monkeypatch):
    monkeypatch.setenv("HOST", "api.example.com")
    assert resolve_env("https://${HOST}/v1") == "https://api.example.com/v1"


def test_resolve_env_missing_var_raises_keyerror(monkeypatch):
    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)
    with pytest.raises(KeyError):
        resolve_env("${DOES_NOT_EXIST}")


def test_resolve_env_recurses_dict_and_list(monkeypatch):
    monkeypatch.setenv("A", "1")
    monkeypatch.setenv("B", "2")
    raw = {"x": "${A}", "y": ["${B}", {"z": "${A}"}]}
    assert resolve_env(raw) == {"x": "1", "y": ["2", {"z": "1"}]}


def test_resolve_env_passes_through_non_string_scalars():
    assert resolve_env(10) == 10
    assert resolve_env(True) is True
    assert resolve_env(None) is None


# ---------------------------------------------------------------------------
# load_dotenv
# ---------------------------------------------------------------------------

def test_load_dotenv_sets_unset_vars(tmp_path, monkeypatch):
    dotenv = tmp_path / ".env"
    dotenv.write_text('FOO=hello\nBAR="quoted"\n# a comment\n\nBAZ=\'single\'\n')
    monkeypatch.delenv("FOO", raising=False)
    monkeypatch.delenv("BAR", raising=False)
    monkeypatch.delenv("BAZ", raising=False)

    load_dotenv(str(dotenv))

    assert os.environ["FOO"] == "hello"
    assert os.environ["BAR"] == "quoted"
    assert os.environ["BAZ"] == "single"


def test_load_dotenv_never_overwrites_real_env(tmp_path, monkeypatch):
    dotenv = tmp_path / ".env"
    dotenv.write_text("FOO=from_dotenv\n")
    monkeypatch.setenv("FOO", "from_real_env")

    load_dotenv(str(dotenv))

    assert os.environ["FOO"] == "from_real_env"


def test_load_dotenv_skips_blank_values(tmp_path, monkeypatch):
    dotenv = tmp_path / ".env"
    dotenv.write_text("EMPTY=\n")
    monkeypatch.delenv("EMPTY", raising=False)

    load_dotenv(str(dotenv))

    assert "EMPTY" not in os.environ


def test_load_dotenv_missing_file_is_noop(tmp_path):
    load_dotenv(str(tmp_path / "does_not_exist.env"))  # must not raise


# ---------------------------------------------------------------------------
# AuthSpec.apply
# ---------------------------------------------------------------------------

def test_authspec_bearer_sets_header():
    headers, cookies = {}, {}
    AuthSpec(type="bearer", token="tok123").apply(headers, cookies)
    assert headers["Authorization"] == "Bearer tok123"
    assert cookies == {}


def test_authspec_header_sets_named_header():
    headers, cookies = {}, {}
    AuthSpec(type="header", name="X-Api-Key", value="secret").apply(headers, cookies)
    assert headers["X-Api-Key"] == "secret"


def test_authspec_cookie_sets_named_cookie():
    headers, cookies = {}, {}
    AuthSpec(type="cookie", name="session", value="abc").apply(headers, cookies)
    assert cookies["session"] == "abc"


def test_authspec_none_is_noop():
    headers, cookies = {}, {}
    AuthSpec(type="none").apply(headers, cookies)
    assert headers == {} and cookies == {}


def test_authspec_unknown_type_raises():
    with pytest.raises(ValueError):
        AuthSpec(type="carrier-pigeon").apply({}, {})


def test_authspec_type_is_case_insensitive():
    headers, cookies = {}, {}
    AuthSpec(type="BEARER", token="tok").apply(headers, cookies)
    assert headers["Authorization"] == "Bearer tok"


# ---------------------------------------------------------------------------
# Config.from_dict / Config.load
# ---------------------------------------------------------------------------

def _base_raw(**overrides):
    raw = {
        "base_url": "https://api.example.com/",
        "user_a": {"auth": {"type": "bearer", "token": "a-tok"}},
        "user_b": {"auth": {"type": "bearer", "token": "b-tok"}},
        "create": {"method": "POST", "path": "/orders", "json": {"item": "demo"}},
        "fetch": {"method": "GET", "path": "/orders/{id}"},
    }
    raw.update(overrides)
    return raw


def test_from_dict_happy_path_strips_trailing_slash():
    config = Config.from_dict(_base_raw())
    assert config.base_url == "https://api.example.com"
    assert config.user_a.auth.token == "a-tok"
    assert config.timeout == 10.0
    assert config.verify_tls is True


def test_from_dict_missing_required_key_raises_valueerror():
    raw = _base_raw()
    del raw["fetch"]
    with pytest.raises(ValueError):
        Config.from_dict(raw)


def test_from_dict_parses_login_spec():
    raw = _base_raw(login={"method": "POST", "path": "/auth/login", "token_field": "data.token"})
    config = Config.from_dict(raw)
    assert config.login is not None
    assert config.login.token_field == "data.token"


def test_from_dict_no_login_is_none():
    config = Config.from_dict(_base_raw())
    assert config.login is None


def test_from_dict_optional_checks_default_to_none():
    config = Config.from_dict(_base_raw())
    assert config.update is None
    assert config.delete is None
    assert config.admin is None
    assert config.privileged_fields is None


def test_from_dict_parses_optional_checks_when_present():
    raw = _base_raw(
        update={"method": "PATCH", "path": "/orders/{id}", "json": {"item": "pwned"}},
        delete={"method": "DELETE", "path": "/orders/{id}"},
        admin={"method": "GET", "path": "/admin/users"},
        privileged_fields={"role": "admin"},
    )
    config = Config.from_dict(raw)
    assert config.update.method == "PATCH"
    assert config.delete.method == "DELETE"
    assert config.admin.path == "/admin/users"
    assert config.privileged_fields == {"role": "admin"}


def test_from_dict_resolves_env_vars(monkeypatch):
    monkeypatch.setenv("TOK", "resolved-token")
    raw = _base_raw()
    raw["user_a"]["auth"]["token"] = "${TOK}"
    config = Config.from_dict(raw)
    assert config.user_a.auth.token == "resolved-token"


def test_load_reads_json_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(_base_raw()))
    config = Config.load(str(path))
    assert config.base_url == "https://api.example.com"
