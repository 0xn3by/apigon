from __future__ import annotations

import itertools
import json

import httpx
import pytest

from config import Config
from runner import run

_CONFIG_RAW = {
    "base_url": "https://api.test",
    "login": {"method": "POST", "path": "/auth/login", "token_field": "access_token"},
    "user_a": {"credentials": {"email": "attacker@x.com", "password": "pw"}},
    "user_b": {"credentials": {"email": "victim@x.com", "password": "pw"}},
    "create": {"method": "POST", "path": "/orders", "json": {"item": "demo"}},
    "fetch": {"method": "GET", "path": "/orders/{id}"},
    "update": {"method": "PATCH", "path": "/orders/{id}", "json": {"item": "pwned"}},
    "delete": {"method": "DELETE", "path": "/orders/{id}"},
    "admin": {"method": "GET", "path": "/admin/users"},
    "privileged_fields": {"role": "admin"},
}

_TOKEN_FOR_EMAIL = {"attacker@x.com": "attacker-token", "victim@x.com": "victim-token"}
_USER_FOR_TOKEN = {"attacker-token": "attacker", "victim-token": "victim"}


def _current_user(request: httpx.Request) -> str | None:
    auth = request.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    return _USER_FOR_TOKEN.get(token)


def _login_response(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    token = _TOKEN_FOR_EMAIL.get(body.get("email"))
    if not token:
        return httpx.Response(401, json={"error": "bad credentials"})
    return httpx.Response(200, json={"access_token": token})


def make_vulnerable_transport() -> httpx.MockTransport:
    """A fake API with no object-level or function-level authorization at
    all — every check apigon runs should flag it."""
    objects: dict[int, dict] = {}
    ids = itertools.count(1)

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method

        if path == "/auth/login" and method == "POST":
            return _login_response(request)

        if path == "/orders" and method == "POST":
            oid = next(ids)
            body = json.loads(request.content or b"{}")
            objects[oid] = {"id": oid, "owner": _current_user(request), **body}
            return httpx.Response(201, json=objects[oid])

        if path.startswith("/orders/"):
            oid = int(path.rsplit("/", 1)[-1])
            obj = objects.get(oid)
            if method == "GET":
                if obj is None:
                    return httpx.Response(404, json={"error": "not found"})
                return httpx.Response(200, json=obj)  # no ownership check
            if method == "PATCH":
                if obj is None:
                    return httpx.Response(404)
                obj.update(json.loads(request.content or b"{}"))  # no ownership check
                return httpx.Response(200, json=obj)
            if method == "DELETE":
                if obj is None:
                    return httpx.Response(404)
                del objects[oid]  # no ownership check
                return httpx.Response(204)

        if path == "/admin/users" and method == "GET":
            return httpx.Response(200, json=[{"user": "victim"}])  # no role check

        return httpx.Response(404, json={"error": "no route"})

    return httpx.MockTransport(handler)


def make_secure_transport() -> httpx.MockTransport:
    """A fake API that properly enforces object ownership and roles — apigon
    should report every check as not vulnerable, i.e. no false positives."""
    objects: dict[int, dict] = {}
    ids = itertools.count(1)

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        user = _current_user(request)

        if path == "/auth/login" and method == "POST":
            return _login_response(request)

        if path == "/orders" and method == "POST":
            oid = next(ids)
            objects[oid] = {"id": oid, "item": "demo", "owner": user}  # extra fields ignored
            return httpx.Response(201, json=objects[oid])

        if path.startswith("/orders/"):
            oid = int(path.rsplit("/", 1)[-1])
            obj = objects.get(oid)
            owns = obj is not None and obj["owner"] == user
            if method == "GET":
                if not owns:
                    return httpx.Response(404, json={"error": "not found"})
                return httpx.Response(200, json=obj)
            if method == "PATCH":
                if not owns:
                    return httpx.Response(404)
                body = json.loads(request.content or b"{}")
                if "item" in body:
                    obj["item"] = body["item"]
                return httpx.Response(200, json=obj)
            if method == "DELETE":
                if not owns:
                    return httpx.Response(404)
                del objects[oid]
                return httpx.Response(204)

        if path == "/admin/users" and method == "GET":
            return httpx.Response(403, json={"error": "forbidden"})

        return httpx.Response(404, json={"error": "no route"})

    return httpx.MockTransport(handler)


def test_run_flags_every_check_against_vulnerable_api():
    config = Config.from_dict(_CONFIG_RAW)
    results = run(config, transport=make_vulnerable_transport())

    by_name = {r["name"]: r for r in results}
    assert set(by_name) == {"bola_read", "bola_update", "bola_delete", "bfla", "mass_assignment"}
    assert all(r["is_vulnerable"] for r in results), by_name


def test_run_reports_clean_against_secure_api():
    config = Config.from_dict(_CONFIG_RAW)
    results = run(config, transport=make_secure_transport())

    by_name = {r["name"]: r for r in results}
    assert not any(r["is_vulnerable"] for r in results), by_name


def test_run_only_executes_configured_optional_checks():
    minimal_raw = {
        "base_url": "https://api.test",
        "user_a": {"auth": {"type": "bearer", "token": "attacker-token"}},
        "user_b": {"auth": {"type": "bearer", "token": "victim-token"}},
        "create": _CONFIG_RAW["create"],
        "fetch": _CONFIG_RAW["fetch"],
    }
    config = Config.from_dict(minimal_raw)
    results = run(config, transport=make_secure_transport())

    assert [r["name"] for r in results] == ["bola_read"]


def test_run_logs_in_each_user_independently_via_credentials():
    """Regression check: user_a and user_b must each get their own token, not
    accidentally share one client's auth state."""
    config = Config.from_dict(_CONFIG_RAW)
    results = run(config, transport=make_secure_transport())
    # bola_read on the secure API only succeeds (200) for the resource owner;
    # since it comes back not-vulnerable, both clients were correctly scoped
    # to their own identity rather than colliding.
    read_result = next(r for r in results if r["name"] == "bola_read")
    assert read_result["is_vulnerable"] is False


def test_run_closes_clients_even_if_a_check_raises(monkeypatch):
    closed = []

    config = Config.from_dict(
        {
            "base_url": "https://api.test",
            "user_a": {"auth": {"type": "bearer", "token": "a"}},
            "user_b": {"auth": {"type": "bearer", "token": "b"}},
            "create": {"method": "POST", "path": "/orders", "json": {}},
            "fetch": {"method": "GET", "path": "/orders/{id}"},
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"error": "no id field returned"})

    import runner as runner_module

    original_build_client = runner_module.build_client

    def spying_build_client(*args, **kwargs):
        client = original_build_client(*args, **kwargs)
        original_close = client.close

        def spy_close():
            closed.append(True)
            original_close()

        client.close = spy_close
        return client

    monkeypatch.setattr(runner_module, "build_client", spying_build_client)

    with pytest.raises(KeyError):
        # create response has no "id" key -> bola_read_test raises KeyError
        run(config, transport=httpx.MockTransport(handler))

    assert closed == [True, True]
