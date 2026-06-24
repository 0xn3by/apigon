"""HTTP client factory and request builders for apigon."""

from __future__ import annotations

from typing import Any, Callable

import httpx

from config import RequestSpec, UserSpec

# A callable that asks a client to create an object and returns the raw response.
CreateFn = Callable[[httpx.Client], httpx.Response]
# A callable that asks a client to fetch an object by id and returns the response.
FetchFn = Callable[[httpx.Client, Any], httpx.Response]


def build_client(base_url: str, user: UserSpec, *, timeout: float, verify_tls: bool) -> httpx.Client:
    """Construct an authenticated, ready-to-use HTTP client for one user."""
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
    )


def make_create(spec: RequestSpec) -> CreateFn:
    """Build the create-object callable from a request spec."""
    def _create(client: httpx.Client) -> httpx.Response:
        return client.request(spec.method, spec.path, json=spec.json, params=spec.params)

    return _create


def make_fetch(spec: RequestSpec) -> FetchFn:
    """Build the fetch-by-id callable; `{id}` in the path is substituted."""
    def _fetch(client: httpx.Client, target_id: Any) -> httpx.Response:
        path = spec.path.replace("{id}", str(target_id))
        return client.request(spec.method, path, params=spec.params)

    return _fetch
