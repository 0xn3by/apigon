"""Wires config -> clients -> checks, and reports the result."""

from __future__ import annotations

from typing import Any

from checks import single_bola_test
from client import build_client, make_create, make_fetch
from config import Config


def run(config: Config) -> dict[str, Any]:
    """Wire up clients from config and execute one BOLA test."""
    client_a = build_client(config.base_url, config.user_a, timeout=config.timeout, verify_tls=config.verify_tls)
    client_b = build_client(config.base_url, config.user_b, timeout=config.timeout, verify_tls=config.verify_tls)
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
