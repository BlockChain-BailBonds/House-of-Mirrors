"""Privacy-aware, hash-chained JSONL telemetry."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def verify_file(path: Path) -> tuple[bool, int, str]:
    previous = GENESIS
    count = 0
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            for count, line in enumerate(handle, start=1):
                if not line.strip():
                    return False, count, "blank line in log"
                record = json.loads(line)
                if not isinstance(record, dict):
                    return False, count, "record is not a JSON object"
                claimed_hash = record.get("hash")
                if not isinstance(claimed_hash, str):
                    return False, count, "record has no string hash"
                if record.get("previous_hash") != previous:
                    return False, count, "previous hash mismatch"
                body = {key: value for key, value in record.items() if key != "hash"}
                actual_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
                if claimed_hash != actual_hash:
                    return False, count, "record hash mismatch"
                previous = claimed_hash
    except FileNotFoundError:
        return False, 0, "file not found"
    except (OSError, ValueError, TypeError) as exc:
        return False, count, f"invalid log: {exc}"
    return True, count, "chain valid"


class EventLog:
    """Append-only event log that refuses to continue a damaged chain."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._previous = self._recover_tail()

    def _recover_tail(self) -> str:
        if not self.path.exists():
            return GENESIS
        valid, count, message = verify_file(self.path)
        if not valid:
            raise ValueError(
                f"refusing to append to invalid event log at {self.path}: {message} (record {count})"
            )
        if count == 0:
            return GENESIS
        with self.path.open("r", encoding="utf-8") as handle:
            last = None
            for line in handle:
                last = json.loads(line)
        return last["hash"]

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = dict(event)
            record["previous_hash"] = self._previous
            record["hash"] = hashlib.sha256(canonical_json(record).encode()).hexdigest()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(record) + "\n")
            self._previous = record["hash"]
            return record
