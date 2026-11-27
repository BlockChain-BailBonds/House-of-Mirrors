import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from house_of_mirrors.catalog import EMULATION_SEQUENCE
from house_of_mirrors.server import MirrorServer
from house_of_mirrors.simulator import allowed_host, parse_target, run_probe, validate_target
from house_of_mirrors.telemetry import EventLog, verify_file


class SimulatorTests(unittest.TestCase):
    def test_only_literal_private_and_loopback_targets_are_accepted(self):
        self.assertTrue(allowed_host("127.0.0.1"))
        self.assertTrue(allowed_host("10.20.30.40"))
        self.assertTrue(allowed_host("localhost"))
        self.assertFalse(allowed_host("8.8.8.8"))
        self.assertFalse(allowed_host("0.0.0.0"))
        self.assertFalse(allowed_host("::"))
        self.assertFalse(allowed_host("example.com"))
        self.assertEqual(validate_target("http://localhost:8080"), ("127.0.0.1", 8080))
        self.assertEqual(parse_target("http://127.0.0.1:8080"), ("127.0.0.1", 8080))
        for target in (
            "https://127.0.0.1:8080",
            "http://example.com",
            "http://127.0.0.1@evil.example",
            "http://127.0.0.1:8080/admin",
            "http://127.0.0.1:8080/?token=value",
            "http://0.0.0.0:8080",
            "http://[::]:8080",
            "http://127.0.0.1:99999",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target)

    def test_authorization_is_required_before_network_access(self):
        with self.assertRaisesRegex(PermissionError, "explicit"):
            run_probe("http://127.0.0.1:1", authorized=False)

    def test_fixed_probe_integrates_with_adaptive_decoy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            server = MirrorServer(("127.0.0.1", 0), EventLog(path))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = run_probe(
                    f"http://127.0.0.1:{server.server_port}",
                    authorized=True,
                    pace=0.05,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertEqual(result["status"], "VERIFIED")
            self.assertEqual(result["requests_completed"], len(EMULATION_SEQUENCE))
            self.assertEqual(verify_file(path)[0], True)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), len(EMULATION_SEQUENCE))
            self.assertTrue(all(record["request_id"].startswith("hom-") for record in records))
            signals = {record["signal"] for record in records}
            self.assertTrue(
                {"admin_discovery", "credential_probe", "secret_file_probe", "backup_probe", "automation_probe"}
                <= signals
            )
            self.assertEqual(records[-1]["assimilation_stage"], "contained")
            text = path.read_text()
            self.assertNotIn("DECOY", text)
            self.assertNotIn("exercise", text)


if __name__ == "__main__":
    unittest.main()
