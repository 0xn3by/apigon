from __future__ import annotations
import argparse
import json
import sys
import httpx
from config import SAMPLE_CONFIG, Config
from runner import report, run

_BANNER_ART = r"""
 ███   ████   █████   ███    ███   █   █
█   █  █   █    █    █   █  █   █  ██  █
█   █  █   █    █    █      █   █  █ █ █
█████  ████     █    █  ██  █   █  █ █ █
█   █  █        █    █   █  █   █  █  ██
█   █  █        █    █   █  █   █  █   █
█   █  █      █████   ████   ███   █   █
"""

_SHORTCUTS = """\
  -c, --config <path>    run every check the config enables
  --init-config <path>   write a starter config and exit
  ctrl+c                 abort mid-run
  exit codes             0 clean  1 vulnerable  2 error"""


def _print_banner() -> None:
    color = sys.stdout.isatty()
    green, cyan, dim, bold, reset = (
        ("\033[92m", "\033[96m", "\033[2m", "\033[1m", "\033[0m") if color else ("", "", "", "", "")
    )
    print(f"{green}{bold}{_BANNER_ART}{reset}")
    print(f"{cyan}  API authorization (BOLA / BFLA / mass-assignment) testing CLI{reset}")
    print(f"{dim}  ---------------------------------------------------------------{reset}")
    print(f"{dim}{_SHORTCUTS}{reset}")
    print(f"{dim}  ---------------------------------------------------------------{reset}\n")


def main(argv: list[str] | None = None) -> int:
    _print_banner()
    parser = argparse.ArgumentParser(prog="apigon", description="API BOLA authorization tester")
    parser.add_argument("-c", "--config", help="path to JSON config file")
    parser.add_argument("--init-config", metavar="PATH", help="write a starter config to PATH and exit")
    args = parser.parse_args(argv)

    if args.init_config:
        with open(args.init_config, "w", encoding="utf-8") as fh:
            json.dump(SAMPLE_CONFIG, fh, indent=2)
            fh.write("\n")
        print(f"wrote starter config to {args.init_config}")
        return 0

    if not args.config:
        parser.error("either --config or --init-config is required")

    try:
        config = Config.load(args.config)
        results = run(config)
    except (ValueError, KeyError, httpx.HTTPError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report(results)
    # Exit 1 on any finding so the tool is CI-friendly.
    return 1 if any(r["is_vulnerable"] for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
