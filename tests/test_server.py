import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from house_of_mirrors.server import MirrorServer
from house_of_mirrors.telemetry import EventLog, verify_file


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tempdir.name) / "events.jsonl"
        self.server = MirrorServer(
            ("127.0.0.1", 0),
            EventLog(self.log_path),
            control_token="test-control-token-that-is-at-least-32-characters",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def test_decoy_routes_and_privacy_aware_telemetry(self):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request("GET", "/.env?token=query-value-must-not-be-logged")
        first = connection.getresponse()
        self.assertEqual(first.status, 200)
        cookie_header = first.getheader("Set-Cookie")
        first.read()
        connection.close()
        cookie_value = cookie_header.split(";", 1)[0].split("=", 1)[1]

        body = "username=demo-user&password=body-value-must-not-be-logged"
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(
            "POST",
            "/login",
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": cookie_header.split(";", 1)[0],
            },
        )
        self.assertEqual(connection.getresponse().status, 401)
        connection.close()

        text = self.log_path.read_text()
        self.assertNotIn("query-value-must-not-be-logged", text)
        self.assertNotIn("body-value-must-not-be-logged", text)
        self.assertNotIn("demo-user", text)
        self.assertNotIn(cookie_value, text)
        records = [json.loads(line) for line in text.splitlines()]
        self.assertEqual([record["signal"] for record in records], ["secret_file_probe", "credential_probe"])
        self.assertEqual(records[1]["body_fields"], ["password", "username"])
        self.assertEqual(records[1]["body_bytes"], len(body.encode()))
        self.assertEqual(records[0]["session_id"], records[1]["session_id"])
        self.assertEqual(verify_file(self.log_path), (True, 2, "chain valid"))

    def test_local_toggle_enables_active_wartime_containment(self):
        cookie = ""
        for route in ("/.env", "/backup.zip", "/admin"):
            connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
            headers = {"Cookie": cookie} if cookie else {}
            connection.request("GET", route, headers=headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            if response.getheader("Set-Cookie"):
                cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            response.read()
            connection.close()

        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(
            "POST",
            "/__mirror__/control/mode",
            body='{"mode":"wartime"}',
            headers={
                "Content-Type": "application/json",
                "X-Control-Token": self.server.defense.control_token,
            },
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read()), {"mode": "wartime"})
        connection.close()

        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request("GET", "/api/users", headers={"Cookie": cookie})
        response = connection.getresponse()
        self.assertEqual(response.status, 429)
        self.assertEqual(response.getheader("Retry-After"), "60")
        response.read()
        connection.close()

        records = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        self.assertEqual(records[-2]["signal"], "defense_mode_changed")
        self.assertEqual(records[-1]["defense_mode"], "wartime")
        self.assertEqual(records[-1]["defense_action"], "deny_and_tarpit")
        self.assertEqual(records[-1]["assimilation_stage"], "contained")

    def test_mode_control_rejects_missing_token(self):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request("GET", "/__mirror__/control/mode")
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        connection.close()
        self.assertEqual(self.server.defense.mode, "simulation")

    def test_wartime_correlates_and_blocks_cookie_less_scanner(self):
        self.server.defense.set_mode("wartime")
        statuses = []
        for route in ("/.env", "/backup.zip", "/admin"):
            connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
            connection.request("GET", route, headers={"User-Agent": "cookie-less-scanner"})
            response = connection.getresponse()
            statuses.append(response.status)
            response.read()
            connection.close()
        self.assertEqual(statuses, [200, 200, 429])
        records = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        self.assertEqual(len({record["session_id"] for record in records}), 1)
        self.assertEqual(records[-1]["defense_action"], "deny_and_tarpit")


if __name__ == "__main__":
    unittest.main()
