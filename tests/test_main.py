from __future__ import annotations

import json

import httpx
import pytest

import main


def test_init_config_writes_sample_and_returns_zero(tmp_path, capsys):
    out_path = tmp_path / "config.json"
    rc = main.main(["--init-config", str(out_path)])
    assert rc == 0
    written = json.loads(out_path.read_text())
    assert written["base_url"] == "https://api.example.com"
    assert "wrote starter config" in capsys.readouterr().out


def test_missing_config_and_init_config_exits_nonzero():
    with pytest.raises(SystemExit) as exc_info:
        main.main([])
    assert exc_info.value.code == 2


def test_config_load_error_returns_two(tmp_path, capsys):
    bad_path = tmp_path / "missing.json"
    rc = main.main(["--config", str(bad_path)])
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_invalid_config_contents_returns_two(tmp_path, capsys):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"base_url": "https://x"}))  # missing required keys
    rc = main.main(["--config", str(path)])
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_exit_code_zero_when_not_vulnerable(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "base_url": "https://api.test",
                "user_a": {"auth": {"type": "bearer", "token": "a"}},
                "user_b": {"auth": {"type": "bearer", "token": "b"}},
                "create": {"method": "POST", "path": "/orders", "json": {}},
                "fetch": {"method": "GET", "path": "/orders/{id}"},
            }
        )
    )
    monkeypatch.setattr(main, "run", lambda config: [{"name": "bola_read", "is_vulnerable": False}])
    rc = main.main(["--config", str(path)])
    assert rc == 0
    assert "not vulnerable" in capsys.readouterr().out


def test_exit_code_one_when_any_check_vulnerable(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "base_url": "https://api.test",
                "user_a": {"auth": {"type": "bearer", "token": "a"}},
                "user_b": {"auth": {"type": "bearer", "token": "b"}},
                "create": {"method": "POST", "path": "/orders", "json": {}},
                "fetch": {"method": "GET", "path": "/orders/{id}"},
            }
        )
    )
    monkeypatch.setattr(
        main,
        "run",
        lambda config: [
            {"name": "bola_read", "is_vulnerable": False},
            {"name": "bfla", "is_vulnerable": True},
        ],
    )
    rc = main.main(["--config", str(path)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "VULNERABLE" in out


def test_httpx_error_from_run_returns_two(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "base_url": "https://api.test",
                "user_a": {"auth": {"type": "bearer", "token": "a"}},
                "user_b": {"auth": {"type": "bearer", "token": "b"}},
                "create": {"method": "POST", "path": "/orders", "json": {}},
                "fetch": {"method": "GET", "path": "/orders/{id}"},
            }
        )
    )

    def boom(config):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(main, "run", boom)
    rc = main.main(["--config", str(path)])
    assert rc == 2
    assert "error:" in capsys.readouterr().err
