"""Adaptive local HTTP deception service."""

from __future__ import annotations

import argparse
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .catalog import BY_ROUTE, Scenario
from .telemetry import EventLog

MAX_BODY = 8192


@dataclass
class SyntheticSession:
    session_id: str
    score: int = 0
    stage: str = "observed"
    visited: set[str] = field(default_factory=set)


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, SyntheticSession] = {}
        self._lock = threading.Lock()

    def get_or_create(self, requested_id: str | None) -> tuple[SyntheticSession, bool]:
        with self._lock:
            if requested_id and requested_id in self._sessions:
                return self._sessions[requested_id], False
            session = SyntheticSession(secrets.token_hex(12))
            self._sessions[session.session_id] = session
            return session, True

    def advance(self, session: SyntheticSession, scenario: Scenario | None) -> None:
        if scenario is None:
            session.score += 1
        elif scenario.name not in session.visited:
            session.score += scenario.score
            session.visited.add(scenario.name)
        session.stage = "contained" if session.score >= 10 else "engaged" if session.score >= 4 else "observed"


class MirrorHandler(BaseHTTPRequestHandler):
    server_version = "NorthstarGateway/2.4"
    sys_version = ""

    @property
    def event_log(self) -> EventLog:
        return self.server.event_log  # type: ignore[attr-defined]

    @property
    def sessions(self) -> SessionStore:
        return self.server.sessions  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        return

    def _session(self) -> tuple[SyntheticSession, bool]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        morsel = cookie.get("mirror_session")
        return self.sessions.get_or_create(morsel.value if morsel else None)

    def _read_body_metadata(self) -> dict[str, object]:
        try:
            length = min(max(int(self.headers.get("Content-Length", "0")), 0), MAX_BODY)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        fields: list[str] = []
        content_type = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            fields = sorted(parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True))[:20]
        elif "application/json" in content_type:
            try:
                value = json.loads(body)
                if isinstance(value, dict):
                    fields = sorted(str(key) for key in value)[:20]
            except json.JSONDecodeError:
                pass
        return {"body_bytes": len(body), "body_fields": fields}

    def _respond(self, status: HTTPStatus, content_type: str, payload: str, event_id: str, session: SyntheticSession, is_new: bool) -> None:
        encoded = payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Decoy-Event", event_id)
        if is_new:
            self.send_header("Set-Cookie", f"mirror_session={session.session_id}; HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _handle(self) -> None:
        path = urlsplit(self.path).path
        session, is_new = self._session()
        body = self._read_body_metadata() if self.command in {"POST", "PUT", "PATCH"} else {}
        scenario = BY_ROUTE.get((self.command, path))
        self.sessions.advance(session, scenario)
        signal = scenario.signal if scenario else "unknown_path_probe"
        event_id = secrets.token_hex(8)
        self.event_log.append({
            "schema": 1,
            "event_id": event_id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
            "source_ip": self.client_address[0],
            "method": self.command,
            "path": path[:256],
            "signal": signal,
            "session_id": session.session_id,
            "assimilation_stage": session.stage,
            "risk_score": session.score,
            "user_agent": self.headers.get("User-Agent", "")[:256],
            "request_id": self.headers.get("X-Exercise-ID", "")[:64],
            **body,
        })
        if path == "/__mirror__/health":
            self._respond(HTTPStatus.OK, "application/json", '{"status":"ready"}', event_id, session, is_new)
        elif scenario:
            status = HTTPStatus.UNAUTHORIZED if scenario.name == "login" else HTTPStatus.OK
            self._respond(status, scenario.content_type, scenario.response, event_id, session, is_new)
        else:
            self._respond(HTTPStatus.NOT_FOUND, "text/html", "<h1>Not found</h1>", event_id, session, is_new)

    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle


class MirrorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], event_log: EventLog):
        super().__init__(address, MirrorHandler)
        self.event_log = event_log
        self.sessions = SessionStore()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the House of Mirrors adaptive HTTP decoy")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log", type=Path, default=Path("logs/events.jsonl"))
    args = parser.parse_args()
    server = MirrorServer((args.bind, args.port), EventLog(args.log))
    host, port = server.server_address[:2]
    print(f"House of Mirrors listening on http://{host}:{port}")
    print(f"Telemetry: {args.log}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
