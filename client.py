from __future__ import annotations

from typing import Any, Callable

import httpx

from config import RequestSpec, UserSpec

# A callable that asks a client to create an object and returns the raw response.
CreateFn = Callable[[httpx.Client], httpx.Response]
# A callable that asks a client to fetch an object by id and returns the response.
FetchFn = Callable[[httpx.Client, Any], httpx.Response]


def build_client(
    base_url: str,
    user: UserSpec,
    *,
    timeout: float,
    verify_tls: bool,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """Construct an authenticated, ready-to-use HTTP client for one user.

    `transport` is left unset in normal operation (httpx picks its real network
    transport); tests pass an `httpx.MockTransport` here to exercise the same
    client-building and request code without hitting the network.
    """
    headers = {"Accept": "application/json", **user.headers}
    cookies: dict[str, str] = {}
    user.auth.apply(headers, cookies)
    return httpx.Client(
        base_url=base_url,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
        verify=verify_tls,
        follow_redirects=True,
        transport=transport,
    )


def make_create(spec: RequestSpec) -> CreateFn:
    """Build the create-object callable from a request spec."""
    def _create(client: httpx.Client) -> httpx.Response:
        return client.request(spec.method, spec.path, json=spec.json, params=spec.params)

    return _create


def make_fetch(spec: RequestSpec) -> FetchFn:
    """Build an id-targeted, bodyless callable; `{id}` in the path is substituted.

    Used for both the `fetch` spec (GET) and the `delete` spec (DELETE) — neither
    sends a request body, they just target a specific object by id.
    """
    def _fetch(client: httpx.Client, target_id: Any) -> httpx.Response:
        path = spec.path.replace("{id}", str(target_id))
        return client.request(spec.method, path, params=spec.params)

    return _fetch


def make_update(spec: RequestSpec) -> FetchFn:
    """Build the update-by-id callable; `{id}` in the path is substituted."""
    def _update(client: httpx.Client, target_id: Any) -> httpx.Response:
        path = spec.path.replace("{id}", str(target_id))
        return client.request(spec.method, path, json=spec.json, params=spec.params)

    return _update
