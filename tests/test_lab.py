from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from house_of_mirrors.server import MirrorServer
from house_of_mirrors.simulator import allowed_host, validate_target
from house_of_mirrors.telemetry import EventLog, verify_file


class TargetSafetyTests(unittest.TestCase):
    def test_target_guardrails(self) -> None:
        self.assertTrue(allowed_host("127.0.0.1"))
        self.assertTrue(allowed_host("10.0.0.8"))
        self.assertFalse(allowed_host("8.8.8.8"))
        self.assertFalse(allowed_host("example.com"))
        with self.assertRaises(ValueError):
            validate_target("https://127.0.0.1")


class LabTests(unittest.TestCase):
    def test_chain_and_containment_without_secret_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            server = MirrorServer(("127.0.0.1", 0), EventLog(path))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cookie = ""
            for method, route, body in (
                ("GET", "/robots.txt", None),
                ("GET", "/.env", None),
                ("GET", "/backup.zip", None),
                ("POST", "/login", "username=operator&password=must-not-appear"),
            ):
                headers = {"Cookie": cookie} if cookie else {}
                if body:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request(method, route, body=body, headers=headers)
                response = connection.getresponse()
                response.read()
                if response.getheader("Set-Cookie"):
                    cookie = response.getheader("Set-Cookie").split(";", 1)[0]
                connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

            contents = path.read_text(encoding="utf-8")
            records = [json.loads(line) for line in contents.splitlines()]
            self.assertNotIn("must-not-appear", contents)
            self.assertEqual(records[-1]["assimilation_stage"], "contained")
            self.assertEqual(records[-1]["body_fields"], ["password", "username"])
            self.assertTrue(verify_file(path)[0])


if __name__ == "__main__":
    unittest.main()
