from __future__ import annotations

from typing import Any

import httpx

from config import LoginSpec


def _dig(data: Any, dotpath: str) -> Any:
    """Walk a dot-separated path into nested JSON, e.g. 'data.token'."""
    cur = data
    for key in dotpath.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def login(
    base_url: str,
    spec: LoginSpec,
    credentials: dict[str, Any],
    *,
    timeout: float,
    verify_tls: bool,
    transport: httpx.BaseTransport | None = None,
) -> str:
    """POST credentials to the login endpoint and return the issued token."""
    with httpx.Client(
        base_url=base_url,
        timeout=timeout,
        verify=verify_tls,
        follow_redirects=True,
        headers={"Accept": "application/json"},
        transport=transport,
    ) as client:
        resp = client.request(spec.method, spec.path, json=credentials)
    resp.raise_for_status()

    try:
        data = resp.json()
    except ValueError as exc:
        raise ValueError("login response was not JSON") from exc

    token = _dig(data, spec.token_field)
    if not token:
        raise ValueError(
            f"login succeeded (HTTP {resp.status_code}) but no token found at "
            f"'{spec.token_field}' in the response"
        )
    return str(token)
