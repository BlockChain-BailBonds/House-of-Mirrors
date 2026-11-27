import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from house_of_mirrors.server import MirrorServer
from house_of_mirrors.simulator import run_probe
from house_of_mirrors.telemetry import EventLog, verify_file


class DefenseModeTests(unittest.TestCase):
    def test_control_is_disabled_without_token_and_token_is_not_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            server = MirrorServer(("127.0.0.1", 0), EventLog(path))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request("GET", "/__mirror__/control/mode", headers={"X-Control-Token": "unused"})
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                self.assertEqual(json.loads(response.read())["error"], "control API disabled")
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertFalse(path.exists(), "unauthenticated control requests should not create telemetry")

    def test_control_token_gates_mode_changes_and_is_not_logged(self):
        token = "t" * 32
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            server = MirrorServer(("127.0.0.1", 0), EventLog(path), control_token=token, tarpit_ms=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request("GET", "/__mirror__/control/mode")
                self.assertEqual(connection.getresponse().status, 403)
                connection.close()

                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request(
                    "POST",
                    "/__mirror__/control/mode",
                    body=json.dumps({"mode": "wartime"}),
                    headers={"Content-Type": "application/json", "X-Control-Token": token},
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())["mode"], "wartime")
                connection.close()

                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                connection.request(
                    "POST",
                    "/__mirror__/control/mode",
                    body=json.dumps({"mode": "unrecognized"}),
                    headers={"Content-Type": "application/json", "X-Control-Token": token},
                )
                self.assertEqual(connection.getresponse().status, 400)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            contents = path.read_text()
            self.assertNotIn(token, contents)
            records = [json.loads(line) for line in contents.splitlines()]
            self.assertEqual([record["signal"] for record in records], ["defense_mode_changed"])
            self.assertEqual(records[0]["defense_mode"], "wartime")
            self.assertTrue(verify_file(path)[0])

    def test_wartime_mode_denies_contained_session_without_external_action(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            server = MirrorServer(("127.0.0.1", 0), EventLog(path), mode="wartime", tarpit_ms=0)
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
            records = [json.loads(line) for line in path.read_text().splitlines()]
            denied = [record for record in records if record["defense_action"] == "deny_and_tarpit"]
            self.assertGreaterEqual(len(denied), 1)
            self.assertTrue(all(record["assimilation_stage"] == "contained" for record in denied))
            self.assertTrue(all(response["http_status"] == 429 for response in result["responses"][3:]))
            self.assertTrue(verify_file(path)[0])


if __name__ == "__main__":
    unittest.main()
