from __future__ import annotations

import httpx
import pytest

from checks import (
    bfla_test,
    bola_delete_test,
    bola_read_test,
    bola_update_test,
    mass_assignment_test,
)
from config import RequestSpec


def _client(handler):
    return httpx.Client(base_url="https://api.test", transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# bola_read_test — the oracle-problem fix
# ---------------------------------------------------------------------------

def test_bola_read_vulnerable_when_attacker_body_matches_owner_body():
    owner_view = {"id": 1, "item": "secret order", "amount": 999}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 1})
        # both owner and attacker get identical real data back
        return httpx.Response(200, json=owner_view)

    client_a = client_b = _client(handler)
    result = bola_read_test(client_a, client_b, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}"))
    assert result["is_vulnerable"] is True
    assert result["target_id"] == 1


def test_bola_read_not_vulnerable_when_attacker_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 2})
        auth = request.headers.get("authorization")
        if auth == "Bearer owner":
            return httpx.Response(200, json={"id": 2, "item": "real"})
        return httpx.Response(403, json={"error": "forbidden"})

    client_owner = httpx.Client(
        base_url="https://api.test",
        headers={"Authorization": "Bearer owner"},
        transport=httpx.MockTransport(handler),
    )
    client_attacker = httpx.Client(
        base_url="https://api.test",
        headers={"Authorization": "Bearer attacker"},
        transport=httpx.MockTransport(handler),
    )
    result = bola_read_test(
        client_attacker, client_owner, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}")
    )
    assert result["is_vulnerable"] is False
    assert result["attack_status"] == 403


def test_bola_read_not_vulnerable_soft_404_oracle_guard():
    """This is the fix for the 'oracle problem' noted in planner.md: an API that
    returns HTTP 200 with a generic/placeholder body for *any* id (rather than a
    real 404) must not be flagged as vulnerable just because the attacker's
    response happens to echo the requested id."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 3})
        auth = request.headers.get("authorization")
        if auth == "Bearer owner":
            return httpx.Response(200, json={"id": 3, "item": "real secret", "amount": 42})
        # soft-404 oracle: always 200, always echoes the id, but with fake data
        target_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"id": int(target_id), "item": None, "amount": 0})

    client_owner = httpx.Client(
        base_url="https://api.test",
        headers={"Authorization": "Bearer owner"},
        transport=httpx.MockTransport(handler),
    )
    client_attacker = httpx.Client(
        base_url="https://api.test",
        headers={"Authorization": "Bearer attacker"},
        transport=httpx.MockTransport(handler),
    )
    result = bola_read_test(
        client_attacker, client_owner, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}")
    )
    assert result["is_vulnerable"] is False


def test_bola_read_falls_back_to_id_match_when_owner_fetch_unavailable():
    """When the API has no self-read path for the owner to establish ground
    truth against, we fall back to the weaker id-match heuristic rather than
    silently reporting a false negative."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 4})
        auth = request.headers.get("authorization")
        if auth == "Bearer owner":
            return httpx.Response(404, json={"error": "no self-read endpoint"})
        return httpx.Response(200, json={"id": 4, "item": "leaked"})

    client_owner = httpx.Client(
        base_url="https://api.test",
        headers={"Authorization": "Bearer owner"},
        transport=httpx.MockTransport(handler),
    )
    client_attacker = httpx.Client(
        base_url="https://api.test",
        headers={"Authorization": "Bearer attacker"},
        transport=httpx.MockTransport(handler),
    )
    result = bola_read_test(
        client_attacker, client_owner, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}")
    )
    assert result["is_vulnerable"] is True


def test_bola_read_not_vulnerable_on_non_json_attacker_body():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 5})
        return httpx.Response(200, text="<html>not json</html>")

    client = _client(handler)
    result = bola_read_test(client, client, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}"))
    assert result["is_vulnerable"] is False


def test_bola_read_not_vulnerable_when_json_body_is_a_list():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 6})
        return httpx.Response(200, json=[1, 2, 3])

    client = _client(handler)
    result = bola_read_test(client, client, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}"))
    assert result["is_vulnerable"] is False


# ---------------------------------------------------------------------------
# bola_update_test
# ---------------------------------------------------------------------------

def test_bola_update_vulnerable_when_object_actually_changes():
    store = {"item": "original"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 1})
        if request.method == "PATCH":
            import json as _json

            store.update(_json.loads(request.content))
            return httpx.Response(200, json={"id": 1, **store})
        return httpx.Response(200, json={"id": 1, **store})

    client = _client(handler)
    result = bola_update_test(
        client,
        client,
        lambda c: c.post("/orders"),
        lambda c, i: c.get(f"/orders/{i}"),
        lambda c, i: c.request("PATCH", f"/orders/{i}", json={"item": "pwned"}),
    )
    assert result["is_vulnerable"] is True


def test_bola_update_not_vulnerable_when_attack_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 2})
        if request.method == "PATCH":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json={"id": 2, "item": "unchanged"})

    client = _client(handler)
    result = bola_update_test(
        client,
        client,
        lambda c: c.post("/orders"),
        lambda c, i: c.get(f"/orders/{i}"),
        lambda c, i: c.request("PATCH", f"/orders/{i}", json={"item": "pwned"}),
    )
    assert result["is_vulnerable"] is False


def test_bola_update_not_vulnerable_when_status_ok_but_noop():
    """Guards against APIs that return 200 for an update request without
    actually applying it (e.g. silently ignored writes)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 3})
        if request.method == "PATCH":
            return httpx.Response(200, json={"id": 3, "item": "original"})
        return httpx.Response(200, json={"id": 3, "item": "original"})

    client = _client(handler)
    result = bola_update_test(
        client,
        client,
        lambda c: c.post("/orders"),
        lambda c, i: c.get(f"/orders/{i}"),
        lambda c, i: c.request("PATCH", f"/orders/{i}", json={"item": "pwned"}),
    )
    assert result["is_vulnerable"] is False


# ---------------------------------------------------------------------------
# bola_delete_test
# ---------------------------------------------------------------------------

def test_bola_delete_vulnerable_when_object_actually_removed():
    deleted = set()

    def handler(request: httpx.Request) -> httpx.Response:
        target_id = request.url.path.rsplit("/", 1)[-1]
        if request.method == "POST":
            return httpx.Response(201, json={"id": 1})
        if request.method == "DELETE":
            deleted.add(target_id)
            return httpx.Response(204)
        if target_id in deleted:
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json={"id": 1})

    client = _client(handler)
    result = bola_delete_test(
        client, client, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}"), lambda c, i: c.delete(f"/orders/{i}")
    )
    assert result["is_vulnerable"] is True


def test_bola_delete_not_vulnerable_when_attack_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 2})
        if request.method == "DELETE":
            return httpx.Response(403)
        return httpx.Response(200, json={"id": 2})

    client = _client(handler)
    result = bola_delete_test(
        client, client, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}"), lambda c, i: c.delete(f"/orders/{i}")
    )
    assert result["is_vulnerable"] is False


def test_bola_delete_not_vulnerable_when_claims_success_but_object_persists():
    """Guards against APIs that return a success status for delete without
    actually deleting anything."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": 3})
        if request.method == "DELETE":
            return httpx.Response(200, json={"ok": True})  # claims success...
        return httpx.Response(200, json={"id": 3})  # ...but object is still there

    client = _client(handler)
    result = bola_delete_test(
        client, client, lambda c: c.post("/orders"), lambda c, i: c.get(f"/orders/{i}"), lambda c, i: c.delete(f"/orders/{i}")
    )
    assert result["is_vulnerable"] is False


# ---------------------------------------------------------------------------
# bfla_test
# ---------------------------------------------------------------------------

def test_bfla_vulnerable_when_low_priv_reaches_admin_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"user": "victim"}])

    client = _client(handler)
    result = bfla_test(client, lambda c: c.get("/admin/users"))
    assert result["is_vulnerable"] is True


@pytest.mark.parametrize("status", [401, 403, 404])
def test_bfla_not_vulnerable_when_properly_restricted(status):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": "nope"})

    client = _client(handler)
    result = bfla_test(client, lambda c: c.get("/admin/users"))
    assert result["is_vulnerable"] is False


# ---------------------------------------------------------------------------
# mass_assignment_test
# ---------------------------------------------------------------------------

def test_mass_assignment_vulnerable_when_privileged_field_honored():
    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        body = _json.loads(request.content)
        return httpx.Response(201, json={"id": 1, **body})

    client = _client(handler)
    result = mass_assignment_test(
        client, RequestSpec(method="POST", path="/orders", json={"item": "demo"}), {"role": "admin"}
    )
    assert result["is_vulnerable"] is True
    assert result["leaked_fields"] == {"role": "admin"}


def test_mass_assignment_not_vulnerable_when_field_stripped():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"id": 1, "item": "demo"})  # role silently dropped

    client = _client(handler)
    result = mass_assignment_test(
        client, RequestSpec(method="POST", path="/orders", json={"item": "demo"}), {"role": "admin"}
    )
    assert result["is_vulnerable"] is False
    assert result["leaked_fields"] == {}


def test_mass_assignment_partial_leak_only_reports_leaked_fields():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"id": 1, "role": "admin", "price": 9.99})

    client = _client(handler)
    result = mass_assignment_test(
        client,
        RequestSpec(method="POST", path="/orders", json={"item": "demo"}),
        {"role": "admin", "price": 0},
    )
    assert result["is_vulnerable"] is True
    assert result["leaked_fields"] == {"role": "admin"}


def test_mass_assignment_not_vulnerable_on_non_json_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, text="created")

    client = _client(handler)
    result = mass_assignment_test(
        client, RequestSpec(method="POST", path="/orders", json={"item": "demo"}), {"role": "admin"}
    )
    assert result["is_vulnerable"] is False
