from __future__ import annotations

import argparse
import json
import sys

import httpx

from config import SAMPLE_CONFIG, Config
from runner import report, run


def main(argv: list[str] | None = None) -> int:
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
