import json
import tempfile
import unittest
from pathlib import Path

from house_of_mirrors.telemetry import EventLog, verify_file


class TelemetryTests(unittest.TestCase):
    def test_append_and_verify_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = EventLog(path)
            first = log.append({"event_type": "admin_discovery"})
            second = log.append({"event_type": "credential_probe"})
            self.assertEqual(second["previous_hash"], first["hash"])
            self.assertEqual(verify_file(path), (True, 2, "chain valid"))

    def test_tampering_is_detected_and_append_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            EventLog(path).append({"event_type": "admin_discovery"})
            record = json.loads(path.read_text())
            record["event_type"] = "changed"
            path.write_text(json.dumps(record) + "\n")
            self.assertFalse(verify_file(path)[0])
            with self.assertRaisesRegex(ValueError, "refusing to append"):
                EventLog(path)

    def test_blank_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("\n")
            self.assertFalse(verify_file(path)[0])


if __name__ == "__main__":
    unittest.main()
