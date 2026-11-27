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


class EventLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._previous = self._recover_tail()

    def _recover_tail(self) -> str:
        if not self.path.exists():
            return GENESIS
        previous = GENESIS
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        previous = json.loads(line)["hash"]
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return GENESIS
        return previous

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = dict(event)
            record["previous_hash"] = self._previous
            record["hash"] = hashlib.sha256(canonical_json(record).encode()).hexdigest()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(record) + "\n")
            self._previous = record["hash"]
            return record


def verify_file(path: Path) -> tuple[bool, int, str]:
    previous = GENESIS
    count = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for count, line in enumerate(handle, start=1):
                record = json.loads(line)
                claimed_hash = record.pop("hash")
                if record.get("previous_hash") != previous:
                    return False, count, "previous hash mismatch"
                actual_hash = hashlib.sha256(canonical_json(record).encode()).hexdigest()
                if claimed_hash != actual_hash:
                    return False, count, "record hash mismatch"
                previous = claimed_hash
    except FileNotFoundError:
        return False, 0, "file not found"
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        return False, count, f"invalid log: {exc}"
    return True, count, "chain valid"
