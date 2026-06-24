"""Config model for apigon: typed specs loaded from JSON with ${ENV} support."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")

# Load .env from the project directory regardless of the caller's CWD.
_DOTENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def load_dotenv(path: str = _DOTENV_PATH) -> None:
    """Load KEY=VALUE pairs from a .env file into the environment.

    Real environment variables always win (we never overwrite them), and blank
    values are skipped so an unfilled placeholder still trips the missing-var
    error in resolve_env instead of silently sending an empty credential.
    """
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and val and key not in os.environ:
                os.environ[key] = val


def resolve_env(value: Any) -> Any:
    """Recursively replace ${VAR} placeholders with environment variables.

    Lets secrets live in the environment instead of the config file. A missing
    variable is a hard error so we never silently send an empty credential.
    """
    if isinstance(value, str):
        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise KeyError(f"environment variable {name!r} referenced in config is not set")
            return os.environ[name]

        return _ENV_PATTERN.sub(_sub, value)
    if isinstance(value, dict):
        return {k: resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_env(v) for v in value]
    return value


@dataclass
class AuthSpec:
    """How to authenticate a single client."""

    type: str = "none"  # bearer | header | cookie | none
    token: str = ""
    name: str = ""   # header/cookie name (for type=header/cookie)
    value: str = ""  # header/cookie value (for type=header/cookie)

    def apply(self, headers: dict[str, str], cookies: dict[str, str]) -> None:
        kind = self.type.lower()
        if kind == "bearer":
            headers["Authorization"] = f"Bearer {self.token}"
        elif kind == "header":
            headers[self.name] = self.value
        elif kind == "cookie":
            cookies[self.name] = self.value
        elif kind != "none":
            raise ValueError(f"unknown auth type: {self.type!r}")


@dataclass
class UserSpec:
    """Per-user auth plus any extra static headers."""

    auth: AuthSpec = field(default_factory=AuthSpec)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class RequestSpec:
    """A templated HTTP request (create or fetch)."""

    method: str = "GET"
    path: str = "/"
    json: dict[str, Any] | None = None
    params: dict[str, Any] | None = None


@dataclass
class Config:
    base_url: str
    user_a: UserSpec
    user_b: UserSpec
    create: RequestSpec
    fetch: RequestSpec
    timeout: float = 10.0
    verify_tls: bool = True

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "Config":
        load_dotenv()
        raw = resolve_env(raw)

        def _user(d: dict[str, Any]) -> UserSpec:
            return UserSpec(
                auth=AuthSpec(**d.get("auth", {})),
                headers=d.get("headers", {}),
            )

        try:
            return Config(
                base_url=raw["base_url"].rstrip("/"),
                user_a=_user(raw["user_a"]),
                user_b=_user(raw["user_b"]),
                create=RequestSpec(**raw["create"]),
                fetch=RequestSpec(**raw["fetch"]),
                timeout=float(raw.get("timeout", 10.0)),
                verify_tls=bool(raw.get("verify_tls", True)),
            )
        except KeyError as exc:
            raise ValueError(f"config is missing required key: {exc}") from exc

    @staticmethod
    def load(path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as fh:
            return Config.from_dict(json.load(fh))


SAMPLE_CONFIG = {
    "base_url": "https://api.example.com",
    "timeout": 10,
    "verify_tls": True,
    "user_a": {
        "auth": {"type": "bearer", "token": "${ATTACKER_TOKEN}"},
        "headers": {},
    },
    "user_b": {
        "auth": {"type": "bearer", "token": "${VICTIM_TOKEN}"},
        "headers": {},
    },
    "create": {"method": "POST", "path": "/orders", "json": {"item": "demo"}},
    "fetch": {"method": "GET", "path": "/orders/{id}"},
}
