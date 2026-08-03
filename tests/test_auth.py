from __future__ import annotations

import httpx
import pytest

from auth import _dig, login
from config import LoginSpec


# ---------------------------------------------------------------------------
# _dig
# ---------------------------------------------------------------------------

def test_dig_top_level_key():
    assert _dig({"token": "abc"}, "token") == "abc"


def test_dig_nested_path():
    assert _dig({"data": {"token": "abc"}}, "data.token") == "abc"


def test_dig_missing_key_returns_none():
    assert _dig({"data": {}}, "data.token") is None


def test_dig_non_dict_intermediate_returns_none():
    assert _dig({"data": "not-a-dict"}, "data.token") is None


def test_dig_missing_top_level_returns_none():
    assert _dig({}, "data.token") is None


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------

def _transport(handler):
    return httpx.MockTransport(handler)


def test_login_returns_token_top_level():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/auth/login"
        assert request.method == "POST"
        return httpx.Response(200, json={"access_token": "shiny-token"})

    spec = LoginSpec(method="POST", path="/auth/login", token_field="access_token")
    token = login(
        "https://api.test",
        spec,
        {"email": "a@b.com", "password": "pw"},
        timeout=5.0,
        verify_tls=True,
        transport=_transport(handler),
    )
    assert token == "shiny-token"


def test_login_returns_token_nested_path():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"token": "nested-token"}})

    spec = LoginSpec(method="POST", path="/auth/login", token_field="data.token")
    token = login(
        "https://api.test",
        spec,
        {"email": "a@b.com", "password": "pw"},
        timeout=5.0,
        verify_tls=True,
        transport=_transport(handler),
    )
    assert token == "nested-token"


def test_login_sends_credentials_as_json_body():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"access_token": "tok"})

    spec = LoginSpec(method="POST", path="/auth/login", token_field="access_token")
    login(
        "https://api.test",
        spec,
        {"email": "attacker@x.com", "password": "hunter2"},
        timeout=5.0,
        verify_tls=True,
        transport=_transport(handler),
    )
    assert seen["body"] == {"email": "attacker@x.com", "password": "hunter2"}


def test_login_raises_on_non_json_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    spec = LoginSpec()
    with pytest.raises(ValueError, match="not JSON"):
        login(
            "https://api.test",
            spec,
            {},
            timeout=5.0,
            verify_tls=True,
            transport=_transport(handler),
        )


def test_login_raises_when_token_field_missing():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unrelated": "field"})

    spec = LoginSpec(token_field="access_token")
    with pytest.raises(ValueError, match="no token found"):
        login(
            "https://api.test",
            spec,
            {},
            timeout=5.0,
            verify_tls=True,
            transport=_transport(handler),
        )


def test_login_raises_when_token_field_is_falsy():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": ""})

    spec = LoginSpec(token_field="access_token")
    with pytest.raises(ValueError, match="no token found"):
        login(
            "https://api.test",
            spec,
            {},
            timeout=5.0,
            verify_tls=True,
            transport=_transport(handler),
        )


def test_login_raises_httpstatuserror_on_failed_auth():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad credentials"})

    spec = LoginSpec()
    with pytest.raises(httpx.HTTPStatusError):
        login(
            "https://api.test",
            spec,
            {"email": "x", "password": "wrong"},
            timeout=5.0,
            verify_tls=True,
            transport=_transport(handler),
        )


def test_login_coerces_non_string_token_to_str():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": 12345})

    spec = LoginSpec(token_field="access_token")
    token = login(
        "https://api.test",
        spec,
        {},
        timeout=5.0,
        verify_tls=True,
        transport=_transport(handler),
    )
    assert token == "12345"
