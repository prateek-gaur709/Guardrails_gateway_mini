"""SentraGuard Lite CLI — single command: analyze."""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000")


def cmd_analyze(input_path: str, output_path: str) -> int:
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except FileNotFoundError:
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {input_path}: {exc}", file=sys.stderr)
        return 2

    try:
        resp = requests.post(f"{API_BASE_URL}/analyze", json=payload, timeout=30)
    except requests.RequestException as exc:
        print(f"error: could not reach API at {API_BASE_URL}: {exc}", file=sys.stderr)
        return 3

    # Any non-2xx (including 3xx and the 4xx/5xx range) is an error; surface the
    # actual status and body (e.g. 422 validation details).
    if not 200 <= resp.status_code < 300:
        print(f"error: API returned status {resp.status_code}: {resp.text}", file=sys.stderr)
        return 5

    try:
        data = resp.json()
    except ValueError as exc:
        print(f"error: API returned a non-JSON response: {exc}", file=sys.stderr)
        return 6

    # Validate the response shape BEFORE writing the file so we never persist a
    # half-valid artifact or crash on a missing key.
    required = ("decision", "risk_score", "risk_tags")
    if not isinstance(data, dict) or any(key not in data for key in required):
        print(
            "error: API response missing expected fields (decision/risk_score/risk_tags)",
            file=sys.stderr,
        )
        return 7

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError as exc:
        print(f"error: could not write output file {output_path}: {exc}", file=sys.stderr)
        return 4

    print(
        f"decision={data['decision']} risk_score={data['risk_score']} "
        f"tags={data['risk_tags']} -> wrote {output_path}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cli.py", description="SentraGuard Lite CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Analyze a request via the API")
    analyze_p.add_argument("--input", required=True, help="Path to input JSON")
    analyze_p.add_argument("--output", required=True, help="Path to output JSON")

    # "analyze" is the only (required) subcommand, so argparse guarantees it.
    args = parser.parse_args(argv)
    return cmd_analyze(args.input, args.output)


if __name__ == "__main__":
    sys.exit(main())
