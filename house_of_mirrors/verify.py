"""Verify the integrity chain of a House of Mirrors event log."""

from __future__ import annotations

import argparse
from pathlib import Path

from .telemetry import verify_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify hash-chained JSONL telemetry")
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    valid, count, message = verify_file(args.log)
    print(f"{'PASS' if valid else 'FAIL'}: {message} ({count} records checked)")
    raise SystemExit(0 if valid else 1)


if __name__ == "__main__":
    main()
