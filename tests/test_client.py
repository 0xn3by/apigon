from __future__ import annotations

import json

import httpx
import pytest

from client import build_client, make_create, make_fetch, make_update
from config import AuthSpec, RequestSpec, UserSpec


def _transport(handler):
    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# build_client
# ---------------------------------------------------------------------------

def test_build_client_applies_bearer_auth_and_base_url():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret-tok"
        assert request.url.host == "api.test"
        return httpx.Response(200, json={"ok": True})

    user = UserSpec(auth=AuthSpec(type="bearer", token="secret-tok"))
    client = build_client(
        "https://api.test", user, timeout=5.0, verify_tls=True, transport=_transport(handler)
    )
    resp = client.get("/ping")
    assert resp.status_code == 200


def test_build_client_merges_extra_headers():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-custom"] == "yes"
        assert request.headers["accept"] == "application/json"
        return httpx.Response(200, json={})

    user = UserSpec(headers={"X-Custom": "yes"})
    client = build_client(
        "https://api.test", user, timeout=5.0, verify_tls=True, transport=_transport(handler)
    )
    client.get("/ping")


def test_build_client_applies_cookie_auth():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "session=abc123" in request.headers.get("cookie", "")
        return httpx.Response(200, json={})

    user = UserSpec(auth=AuthSpec(type="cookie", name="session", value="abc123"))
    client = build_client(
        "https://api.test", user, timeout=5.0, verify_tls=True, transport=_transport(handler)
    )
    client.get("/ping")


def test_build_client_unknown_auth_type_raises():
    user = UserSpec(auth=AuthSpec(type="smoke-signal"))
    with pytest.raises(ValueError):
        build_client("https://api.test", user, timeout=5.0, verify_tls=True)


# ---------------------------------------------------------------------------
# make_create
# ---------------------------------------------------------------------------

def test_make_create_sends_method_path_json_params():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/orders"
        assert request.url.params["debug"] == "1"
        assert json.loads(request.content) == {"item": "demo"}
        return httpx.Response(201, json={"id": 42})

    client = httpx.Client(base_url="https://api.test", transport=_transport(handler))
    create_fn = make_create(RequestSpec(method="POST", path="/orders", json={"item": "demo"}, params={"debug": "1"}))
    resp = create_fn(client)
    assert resp.status_code == 201
    assert resp.json()["id"] == 42


def test_make_create_with_no_json_or_params():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.content == b""
        return httpx.Response(200, json={})

    client = httpx.Client(base_url="https://api.test", transport=_transport(handler))
    create_fn = make_create(RequestSpec(method="GET", path="/admin/users"))
    create_fn(client)


# ---------------------------------------------------------------------------
# make_fetch (also used for delete specs)
# ---------------------------------------------------------------------------

def test_make_fetch_substitutes_id_in_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/orders/99"
        assert request.method == "GET"
        return httpx.Response(200, json={"id": 99})

    client = httpx.Client(base_url="https://api.test", transport=_transport(handler))
    fetch_fn = make_fetch(RequestSpec(method="GET", path="/orders/{id}"))
    fetch_fn(client, 99)


def test_make_fetch_sends_no_body():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.content == b""
        return httpx.Response(204)

    client = httpx.Client(base_url="https://api.test", transport=_transport(handler))
    delete_fn = make_fetch(RequestSpec(method="DELETE", path="/orders/{id}"))
    resp = delete_fn(client, 7)
    assert resp.status_code == 204


def test_make_fetch_string_id_substitution():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/orders/uuid-abc-123"
        return httpx.Response(200, json={})

    client = httpx.Client(base_url="https://api.test", transport=_transport(handler))
    fetch_fn = make_fetch(RequestSpec(method="GET", path="/orders/{id}"))
    fetch_fn(client, "uuid-abc-123")


# ---------------------------------------------------------------------------
# make_update
# ---------------------------------------------------------------------------

def test_make_update_substitutes_id_and_sends_json():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/orders/5"
        assert request.method == "PATCH"
        assert json.loads(request.content) == {"item": "pwned"}
        return httpx.Response(200, json={"id": 5, "item": "pwned"})

    client = httpx.Client(base_url="https://api.test", transport=_transport(handler))
    update_fn = make_update(RequestSpec(method="PATCH", path="/orders/{id}", json={"item": "pwned"}))
    resp = update_fn(client, 5)
    assert resp.status_code == 200
