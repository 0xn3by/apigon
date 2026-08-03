# apigon

An API authorization (BOLA/BFLA/mass-assignment) testing CLI written in Python using `httpx`, differential response comparison, and a JSON-driven check config.

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/0xn3by/apigon)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-78%20passing-brightgreen)](tests/)

## Overview

- Logs in as two distinct users (attacker/low-priv and victim/high-priv) and drives every check through their authenticated `httpx` clients
- Runs a BOLA read check by default; update, delete, BFLA, and mass-assignment checks turn on automatically when their config keys are present
- Resolves the "oracle problem" for BOLA detection by diffing the attacker's response against the resource owner's own ground-truth view, instead of trusting a bare `200 + id-match`
- Confirms update/delete attacks by re-fetching the object as its owner and diffing before/after state, so a `200 OK` that silently no-ops isn't reported as a false positive
- Fetches fresh bearer tokens at runtime via a configurable login endpoint, or accepts pre-issued tokens/headers/cookies directly
- Reads secrets from `${ENV_VAR}` placeholders (with `.env` support) so credentials never live in the config file
- Exits non-zero on any finding, making it a CI-friendly authorization regression gate

## Key Features

- `_leak_confirmed()` cross-checks the attacker's JSON body against the owner's own fetch of the same object — exact dict equality is the strong signal; a bare `id` match is only used as a fallback when the owner has no self-read path
- `bola_update_test()` / `bola_delete_test()` fetch the object as its owner before and after the attack and compare state, catching APIs that return a success status without actually applying the mutation
- `bfla_test()` hits a configured admin/privileged endpoint with the low-privilege client and flags a `200` as broken function-level authorization
- `mass_assignment_test()` injects extra fields (e.g. `role: admin`) into the create payload and reports exactly which fields the server echoed back as accepted
- `AuthSpec.apply()` supports `bearer`, `header`, and `cookie` auth, raising `ValueError` on an unrecognized type instead of silently sending an unauthenticated request
- `login()` digs a token out of any JSON response shape via a dot-path (e.g. `data.token`) so apigon never has to mint or hardcode a JWT itself
- `resolve_env()` recursively substitutes `${VAR}` placeholders through the whole config tree; a missing variable is a hard `KeyError`, never a silently empty credential
- Every HTTP-facing function (`build_client`, `login`, `run`) accepts an injectable `transport`, so the full request pipeline is unit-testable against `httpx.MockTransport` with zero network calls

## Tech Stack

- Python 3.10+
- `httpx` — authenticated HTTP clients, request building, mockable transports
- `dataclasses` — typed config model (`Config`, `AuthSpec`, `LoginSpec`, `UserSpec`, `RequestSpec`)
- `argparse` — CLI argument parsing (`--config`, `--init-config`)
- `re`, `os`, `json` — `${VAR}` env resolution, `.env` loading, config (de)serialization
- `pytest` + `httpx.MockTransport` — unit and integration tests, no live API required

## Installation

### Prerequisites

- Python 3.10 or later
- `pip`

### Run locally

```bash
git clone https://github.com/0xn3by/apigon.git
cd apigon
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python main.py --init-config config.json
```

### Run against a real target

```bash
# edit config.json (and .env, if using the login flow) with your target's
# base_url, credentials or tokens, and endpoint paths, then:
.venv/bin/python main.py --config config.json
```

## Configuration

apigon is entirely config-driven — no check-specific CLI flags. Everything lives in the JSON file passed via `--config`.

```
base_url            Target API base URL (required)
timeout             Request timeout in seconds (default: 10)
verify_tls          Verify TLS certificates (default: true)
login               { method, path, token_field } — POST credentials and dig a token out of the response (optional)
user_a              Attacker identity: `auth` (existing token/header/cookie) or `credentials` (used with `login`)
user_b              Victim identity: same shape as user_a
create              RequestSpec to create an object as the victim (required)
fetch               RequestSpec to fetch an object by id — `{id}` is substituted (required)
update              RequestSpec — presence alone enables the BOLA-update check (optional)
delete              RequestSpec — presence alone enables the BOLA-delete check (optional)
admin                RequestSpec — presence alone enables the BFLA check (optional)
privileged_fields    dict of fields to inject into `create` — presence alone enables the mass-assignment check (optional)
```

**Notes**

- `base_url`, `user_a`, `user_b`, `create`, and `fetch` are the only required keys — `bola_read` always runs off of them
- Any string value may reference `${ENV_VAR}`; apigon also auto-loads a `.env` file from the project directory (real environment variables always take precedence)
- A referenced `${ENV_VAR}` that isn't set raises a hard error at load time rather than sending an empty credential
- Exit code is `1` if any check finds a vulnerability, `0` if every check is clean, `2` on a config or network error

## Usage Examples

Generate a starter config:

```bash
python main.py --init-config config.json
```

Run with tokens you already have:

```json
{
  "base_url": "https://api.example.com",
  "user_a": { "auth": { "type": "bearer", "token": "${ATTACKER_TOKEN}" } },
  "user_b": { "auth": { "type": "bearer", "token": "${VICTIM_TOKEN}" } },
  "create": { "method": "POST", "path": "/orders", "json": { "item": "demo" } },
  "fetch":  { "method": "GET", "path": "/orders/{id}" }
}
```

Run with the login flow so apigon fetches fresh tokens itself:

```json
{
  "base_url": "https://api.example.com",
  "login": { "method": "POST", "path": "/auth/login", "token_field": "access_token" },
  "user_a": { "credentials": { "email": "${ATTACKER_EMAIL}", "password": "${ATTACKER_PASSWORD}" } },
  "user_b": { "credentials": { "email": "${VICTIM_EMAIL}", "password": "${VICTIM_PASSWORD}" } },
  "create": { "method": "POST", "path": "/orders", "json": { "item": "demo" } },
  "fetch":  { "method": "GET", "path": "/orders/{id}" }
}
```

Enable every check (update, delete, BFLA, mass assignment) on top of the base config:

```json
{
  "update": { "method": "PATCH", "path": "/orders/{id}", "json": { "item": "pwned" } },
  "delete": { "method": "DELETE", "path": "/orders/{id}" },
  "admin": { "method": "GET", "path": "/admin/users" },
  "privileged_fields": { "role": "admin" }
}
```

Use the exit code in CI:

```bash
python main.py --config config.json || echo "authorization findings detected"
```

## Testing

The whole suite runs against `httpx.MockTransport` fakes — no live API, no network calls.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -v
```

`tests/test_runner.py` is the most informative file: it stands up an in-memory "vulnerable" API (no ownership checks at all) and a "secure" API (ownership and role checks enforced) and asserts apigon flags every check against the first and stays clean against the second — the regression test for false positives.

## Core Modules

### `main.py`

- `main(argv)` — parses `--config`/`--init-config`, loads the config, calls `run()`, prints the report, and returns the process exit code
- `--init-config PATH` writes `SAMPLE_CONFIG` to disk and exits without running any checks

### `config.py`

- `Config.load()` / `Config.from_dict()` — parse and validate the JSON config into typed dataclasses, wrapping any missing required key in a `ValueError`
- `resolve_env()` — recursively substitutes `${VAR}` placeholders through strings, dicts, and lists
- `load_dotenv()` — loads a `.env` file without ever overriding a real environment variable
- `AuthSpec`, `LoginSpec`, `UserSpec`, `RequestSpec` — typed specs for auth, login, per-user identity, and templated requests

### `auth.py`

- `login()` — POSTs credentials to the configured login endpoint and returns the issued token, raising on a failed request, non-JSON response, or missing token field
- `_dig()` — walks a dot-separated path (e.g. `data.token`) into a nested JSON response

### `client.py`

- `build_client()` — constructs an authenticated `httpx.Client` for one user, with an injectable `transport` for tests
- `make_create()` / `make_fetch()` / `make_update()` — turn a `RequestSpec` into a callable; `make_fetch` is reused for both `fetch` and `delete` since neither sends a body

### `checks.py`

- `bola_read_test()` / `_leak_confirmed()` — the oracle-safe BOLA read check
- `bola_update_test()` / `bola_delete_test()` — confirm real mutation by diffing the owner's before/after state
- `bfla_test()` — flags a low-privilege client reaching a restricted endpoint
- `mass_assignment_test()` — flags privileged fields the server accepts from an untrusted create payload

### `runner.py`

- `run()` — logs in both users, builds their clients, and runs every check the config enables
- `report()` — prints a per-check verdict plus an overall verdict to stdout

## Project Structure

```text
apigon/
├── main.py               # CLI entry point and argument parsing
├── config.py              # Typed config model, env/`.env` resolution
├── auth.py                 # Login flow and token extraction
├── client.py                # httpx client + request builders
├── checks.py                 # BOLA/BFLA/mass-assignment check logic
├── runner.py                  # Wires config -> clients -> checks -> report
├── config.json                 # Example config
├── requirements.txt             # Runtime dependency (httpx)
├── requirements-dev.txt          # Adds pytest for local testing
├── pytest.ini                     # Test discovery + import path config
├── tests/                          # Unit + integration tests (MockTransport, no network)
├── .gitignore                       # Excludes .env, __pycache__, .venv, .pytest_cache
└── LICENSE                           # MIT License
```

## Current Limitations

- No object-id range or enumeration brute-forcing — each check probes exactly one freshly created object, not a swept range of ids
- No retry or backoff logic — a `429`/`5xx` from the target is reported as-is rather than retried
- Checks run sequentially, one HTTP round-trip at a time — no concurrency
- Assumes `create` responses return an `id` field in the JSON body; APIs that key objects differently aren't supported out of the box
- The BFLA check only probes a single configured endpoint per run, not a set of role-restricted routes

## License

Licensed under the [MIT License](LICENSE).
