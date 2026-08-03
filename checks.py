"""Authorization checks. Each check probes a specific API vulnerability class."""

from __future__ import annotations

from typing import Any

import httpx

from client import CreateFn, FetchFn
from config import RequestSpec


def _safe_json(res: httpx.Response) -> dict[str, Any] | None:
    """Parse a JSON object body, or None if it isn't one."""
    try:
        body = res.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def bola_read_test(
    client_a: httpx.Client,
    client_b: httpx.Client,
    create_res: CreateFn,
    fetch_res: FetchFn,
) -> dict[str, Any]:
    """Run one BOLA check: can client A read an object owned by client B?"""
    b_create_res = create_res(client_b)
    target_id = b_create_res.json()["id"]

    owner_fetch_res = fetch_res(client_b, target_id)
    attacker_fetch_res = fetch_res(client_a, target_id)

    is_vulnerable = _leak_confirmed(owner_fetch_res, attacker_fetch_res, target_id)

    return {
        "name": "bola_read",
        "target_id": target_id,
        "create_status": b_create_res.status_code,
        "attack_status": attacker_fetch_res.status_code,
        "is_vulnerable": is_vulnerable,
    }


def _leak_confirmed(owner_res: httpx.Response, attacker_res: httpx.Response, target_id: Any) -> bool:
    """Decide whether the attacker actually read the victim's data.

    Trusting the attacker's response in isolation is an unreliable oracle: some
    APIs return a 200 with a plausible-looking body for any id ("soft 404"),
    which would read as a false positive under a naive status/id check. Cross-
    checking against the owner's own view of the same object is the stronger
    signal — if the bodies match exactly, the attacker definitely got real data.
    """
    if attacker_res.status_code != 200:
        return False
    attacker_body = _safe_json(attacker_res)
    if attacker_body is None:
        return False

    owner_body = _safe_json(owner_res) if owner_res.status_code == 200 else None
    if owner_body is not None:
        return attacker_body == owner_body

    # Owner's own fetch didn't come back clean (e.g. no self-read endpoint) —
    # fall back to the weaker id-match signal.
    return attacker_body.get("id") == target_id


def bola_update_test(
    client_a: httpx.Client,
    client_b: httpx.Client,
    create_res: CreateFn,
    fetch_res: FetchFn,
    update_res: FetchFn,
) -> dict[str, Any]:
    """Can client A modify an object owned by client B?"""
    b_create_res = create_res(client_b)
    target_id = b_create_res.json()["id"]

    before_body = _safe_json(fetch_res(client_b, target_id))
    attack_res = update_res(client_a, target_id)
    after_body = _safe_json(fetch_res(client_b, target_id))

    is_vulnerable = (
        attack_res.status_code in (200, 201, 204)
        and before_body is not None
        and after_body is not None
        and after_body != before_body
    )

    return {
        "name": "bola_update",
        "target_id": target_id,
        "attack_status": attack_res.status_code,
        "is_vulnerable": is_vulnerable,
    }


def bola_delete_test(
    client_a: httpx.Client,
    client_b: httpx.Client,
    create_res: CreateFn,
    fetch_res: FetchFn,
    delete_res: FetchFn,
) -> dict[str, Any]:
    """Can client A delete an object owned by client B?"""
    b_create_res = create_res(client_b)
    target_id = b_create_res.json()["id"]

    attack_res = delete_res(client_a, target_id)
    owner_refetch_res = fetch_res(client_b, target_id)

    is_vulnerable = attack_res.status_code in (200, 202, 204) and owner_refetch_res.status_code in (404, 410)

    return {
        "name": "bola_delete",
        "target_id": target_id,
        "attack_status": attack_res.status_code,
        "owner_refetch_status": owner_refetch_res.status_code,
        "is_vulnerable": is_vulnerable,
    }


def bfla_test(client: httpx.Client, admin_res: CreateFn) -> dict[str, Any]:
    """Broken Function Level Authorization: can a low-privilege client reach an
    endpoint that should be restricted to a higher-privilege role?"""
    res = admin_res(client)
    return {
        "name": "bfla",
        "attack_status": res.status_code,
        "is_vulnerable": res.status_code == 200,
    }


def mass_assignment_test(
    client: httpx.Client,
    create_spec: RequestSpec,
    privileged_fields: dict[str, Any],
) -> dict[str, Any]:
    """Does the API honor attacker-supplied fields it shouldn't (e.g. role,
    is_admin, price) when creating an object?"""
    payload = {**(create_spec.json or {}), **privileged_fields}
    res = client.request(create_spec.method, create_spec.path, json=payload, params=create_spec.params)

    body = _safe_json(res)
    leaked_fields = {}
    if body is not None:
        leaked_fields = {k: v for k, v in privileged_fields.items() if body.get(k) == v}

    return {
        "name": "mass_assignment",
        "attack_status": res.status_code,
        "leaked_fields": leaked_fields,
        "is_vulnerable": bool(leaked_fields),
    }
