"""Wires config -> clients -> checks, and reports the result."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from auth import login
from checks import single_bola_test
from client import build_client, make_create, make_fetch
from config import AuthSpec, Config, UserSpec


def _build(config: Config, user: UserSpec):
    """Build a client for one user, logging in first if credentials are given."""
    if config.login and user.credentials:
        token = login(
            config.base_url,
            config.login,
            user.credentials,
            timeout=config.timeout,
            verify_tls=config.verify_tls,
        )
        user = replace(user, auth=AuthSpec(type="bearer", token=token))
    return build_client(config.base_url, user, timeout=config.timeout, verify_tls=config.verify_tls)


def run(config: Config) -> dict[str, Any]:
    """Wire up clients from config and execute one BOLA test."""
    client_a = _build(config, config.user_a)
    client_b = _build(config, config.user_b)
    try:
        return single_bola_test(
            client_a,
            client_b,
            make_create(config.create),
            make_fetch(config.fetch),
        )
    finally:
        client_a.close()
        client_b.close()


def report(result: dict[str, Any]) -> None:
    verdict = "VULNERABLE" if result["is_vulnerable"] else "not vulnerable"
    print("apigon — BOLA test result")
    print("-" * 32)
    print(f"  target object id : {result['target_id']}")
    print(f"  victim create    : HTTP {result['create_status']}")
    print(f"  attacker fetch   : HTTP {result['attack_status']}")
    print(f"  verdict          : {verdict}")
