from __future__ import annotations
from dataclasses import replace
from typing import Any
import httpx
from auth import login
from checks import (
    bfla_test,
    bola_delete_test,
    bola_read_test,
    bola_update_test,
    mass_assignment_test,
)
from client import build_client, make_create, make_fetch, make_update
from config import AuthSpec, Config, UserSpec


def _build(
    config: Config,
    user: UserSpec,
    *,
    transport: httpx.BaseTransport | None,
) -> httpx.Client:
    """Build a client for one user, logging in first if credentials are given."""
    if config.login and user.credentials:
        token = login(
            config.base_url,
            config.login,
            user.credentials,
            timeout=config.timeout,
            verify_tls=config.verify_tls,
            transport=transport,
        )
        user = replace(user, auth=AuthSpec(type="bearer", token=token))
    return build_client(
        config.base_url,
        user,
        timeout=config.timeout,
        verify_tls=config.verify_tls,
        transport=transport,
    )


def run(config: Config, *, transport: httpx.BaseTransport | None = None) -> list[dict[str, Any]]:
    """Wire up clients from config and run every check the config enables.

    `bola_read` always runs (create/fetch are required). `update`, `delete`,
    `admin`, and `privileged_fields` are each optional and turn on one more
    check. `transport` is for tests (httpx.MockTransport); production callers
    leave it unset.
    """
    client_a = _build(config, config.user_a, transport=transport)
    client_b = _build(config, config.user_b, transport=transport)
    try:
        create_fn = make_create(config.create)
        fetch_fn = make_fetch(config.fetch)

        results = [bola_read_test(client_a, client_b, create_fn, fetch_fn)]

        if config.update:
            update_fn = make_update(config.update)
            results.append(bola_update_test(client_a, client_b, create_fn, fetch_fn, update_fn))

        if config.delete:
            delete_fn = make_fetch(config.delete)
            results.append(bola_delete_test(client_a, client_b, create_fn, fetch_fn, delete_fn))

        if config.admin:
            admin_fn = make_create(config.admin)
            results.append(bfla_test(client_a, admin_fn))

        if config.privileged_fields:
            results.append(mass_assignment_test(client_a, config.create, config.privileged_fields))

        return results
    finally:
        client_a.close()
        client_b.close()


def report(results: list[dict[str, Any]]) -> None:
    print("apigon — authorization test results")
    print("-" * 40)
    for result in results:
        verdict = "VULNERABLE" if result["is_vulnerable"] else "not vulnerable"
        print(f"[{result['name']}] {verdict}")
        for key, value in result.items():
            if key in ("name", "is_vulnerable"):
                continue
            print(f"    {key}: {value}")
    print("-" * 40)
    overall = "VULNERABLE" if any(r["is_vulnerable"] for r in results) else "not vulnerable"
    print(f"overall verdict: {overall}")
