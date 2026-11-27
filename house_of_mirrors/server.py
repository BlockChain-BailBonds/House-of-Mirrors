"""Adaptive local HTTP deception service."""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .catalog import BY_ROUTE, Scenario
from .telemetry import EventLog

MAX_BODY = 8192
MAX_FIELDS = 64
EXERCISE_ID = re.compile(r"hom-[0-9a-f]{12}\Z")
FAKE_PASSWD = "root:x:0:0:decoy:/nonexistent:/usr/sbin/nologin\nmirror:x:1000:1000:decoy:/nonexistent:/usr/sbin/nologin\n"
VALID_MODES = {"simulation", "wartime"}
CONTROL_PATH = "/__mirror__/control/mode"


@dataclass
class SyntheticSession:
    session_id: str
    cookie_value: str = field(repr=False)
    score: int = 0
    stage: str = "observed"
    request_count: int = 0
    visited: set[str] = field(default_factory=set)


class DefenseController:
    """Thread-safe defensive posture shared by every request handler."""

    def __init__(self, mode: str, control_token: str | None, tarpit_ms: int = 150) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of: {', '.join(sorted(VALID_MODES))}")
        if not 0 <= tarpit_ms <= 1000:
            raise ValueError("tarpit_ms must be between 0 and 1000")
        if control_token is not None and (len(control_token) < 32 or not control_token.isascii()):
            raise ValueError("control_token must be at least 32 ASCII characters")
        self._mode = mode
        self.control_token = control_token
        self.tarpit_ms = tarpit_ms
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        with self._lock:
            return self._mode

    def set_mode(self, mode: str) -> str:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of: {', '.join(sorted(VALID_MODES))}")
        with self._lock:
            self._mode = mode
            return self._mode


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, SyntheticSession] = {}
        self._sources: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def get_or_create(
        self,
        requested_cookie: str | None,
        source_fingerprint: tuple[str, str],
    ) -> tuple[SyntheticSession, bool]:
        with self._lock:
            if requested_cookie and requested_cookie in self._sessions:
                return self._sessions[requested_cookie], False
            known_cookie = self._sources.get(source_fingerprint)
            if known_cookie and known_cookie in self._sessions:
                return self._sessions[known_cookie], False
            session = SyntheticSession(secrets.token_hex(8), secrets.token_urlsafe(24))
            self._sessions[session.cookie_value] = session
            self._sources[source_fingerprint] = session.cookie_value
            return session, True

    def advance(self, session: SyntheticSession, scenario: Scenario | None) -> None:
        with self._lock:
            session.request_count += 1
            if scenario is None:
                session.score += 1
            elif scenario.name not in session.visited:
                session.score += scenario.score
                session.visited.add(scenario.name)
            session.stage = (
                "contained" if session.score >= 10 else "engaged" if session.score >= 4 else "observed"
            )


class MirrorHandler(BaseHTTPRequestHandler):
    server_version = "NorthstarGateway/2.4"
    sys_version = ""

    @property
    def event_log(self) -> EventLog:
        return self.server.event_log  # type: ignore[attr-defined]

    @property
    def sessions(self) -> SessionStore:
        return self.server.sessions  # type: ignore[attr-defined]

    @property
    def defense(self) -> DefenseController:
        return self.server.defense  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        return

    def _control_response(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _handle_control(self) -> None:
        if self.client_address[0] not in {"127.0.0.1", "::1"}:
            self._control_response(HTTPStatus.FORBIDDEN, {"error": "local control only"})
            return
        expected = self.defense.control_token
        supplied = self.headers.get("X-Control-Token", "")
        try:
            authorized = expected is not None and hmac.compare_digest(supplied, expected)
        except TypeError:
            authorized = False
        if not authorized:
            if self.headers.get("Content-Length", "0") != "0":
                self.close_connection = True
            message = "control API disabled" if expected is None else "invalid control token"
            self._control_response(HTTPStatus.FORBIDDEN, {"error": message})
            return
        if self.command in {"GET", "HEAD"}:
            self._control_response(HTTPStatus.OK, {"mode": self.defense.mode})
            return
        if self.command != "POST":
            self._control_response(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 256:
                self.close_connection = True
                raise ValueError
            if not 1 <= length <= 256:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            mode = payload.get("mode") if isinstance(payload, dict) else None
            if not isinstance(mode, str):
                raise ValueError
            previous = self.defense.mode
            current = self.defense.set_mode(mode)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._control_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "body must be JSON with mode simulation or wartime"},
            )
            return
        self.event_log.append(
            {
                "schema": 1,
                "event_id": secrets.token_hex(8),
                "observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "signal": "defense_mode_changed",
                "previous_mode": previous,
                "defense_mode": current,
                "source_ip": self.client_address[0],
            }
        )
        self._control_response(HTTPStatus.OK, {"mode": current})

    def _session(self) -> tuple[SyntheticSession, bool]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            pass
        morsel = cookie.get("mirror_session")
        source_fingerprint = (
            self.client_address[0],
            self.headers.get("User-Agent", "")[:256],
        )
        return self.sessions.get_or_create(
            morsel.value if morsel else None,
            source_fingerprint,
        )

    def _read_body_metadata(self) -> tuple[dict[str, object], bool]:
        try:
            declared_length = max(int(self.headers.get("Content-Length", "0")), 0)
        except ValueError:
            declared_length = 0
        if declared_length > MAX_BODY:
            return {"body_bytes": declared_length, "body_fields": []}, True
        body = self.rfile.read(declared_length) if declared_length else b""
        fields: list[str] = []
        content_type = self.headers.get("Content-Type", "").lower()
        if "application/x-www-form-urlencoded" in content_type:
            try:
                fields = sorted(
                    {key for key, _ in parse_qsl(
                        body.decode("utf-8", errors="replace"),
                        keep_blank_values=True,
                        max_num_fields=MAX_FIELDS,
                    )}
                )[:MAX_FIELDS]
            except ValueError:
                fields = []
        elif "application/json" in content_type:
            try:
                value = json.loads(body)
                if isinstance(value, dict):
                    fields = sorted(str(key) for key in value)[:MAX_FIELDS]
            except (json.JSONDecodeError, UnicodeDecodeError):
                fields = []
        return {"body_bytes": len(body), "body_fields": fields}, False

    def _respond(
        self,
        status: HTTPStatus,
        content_type: str,
        payload: str,
        event_id: str,
        session: SyntheticSession,
        is_new: bool,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        encoded = payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Decoy-Event", event_id)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        if is_new:
            self.send_header(
                "Set-Cookie",
                f"mirror_session={session.cookie_value}; HttpOnly; SameSite=Strict; Path=/",
            )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _handle(self) -> None:
        path = urlsplit(self.path).path[:256] or "/"
        if path == CONTROL_PATH:
            self._handle_control()
            return
        session, is_new = self._session()
        body: dict[str, object] = {}
        too_large = False
        if self.command in {"POST", "PUT", "PATCH"}:
            body, too_large = self._read_body_metadata()
        if too_large:
            self.close_connection = True

        scenario = BY_ROUTE.get((self.command, path))
        if path != "/__mirror__/health":
            self.sessions.advance(session, scenario)
        signal = "health_probe" if path == "/__mirror__/health" else scenario.signal if scenario else "unknown_path_probe"
        defense_mode = self.defense.mode
        defense_active = defense_mode == "wartime" and session.stage == "contained"
        defense_action = "deny_and_tarpit" if defense_active else "observe"
        event_id = secrets.token_hex(8)
        raw_request_id = self.headers.get("X-Exercise-ID", "")
        request_id = raw_request_id if EXERCISE_ID.fullmatch(raw_request_id) else ""
        self.event_log.append(
            {
                "schema": 1,
                "event_id": event_id,
                "observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "monotonic_ns": time.monotonic_ns(),
                "source_ip": self.client_address[0],
                "method": self.command,
                "path": path,
                "signal": signal,
                "session_id": session.session_id,
                "assimilation_stage": session.stage,
                "risk_score": session.score,
                "request_count": session.request_count,
                "defense_mode": defense_mode,
                "defense_action": defense_action,
                "user_agent": self.headers.get("User-Agent", "")[:256],
                "request_id": request_id,
                **body,
            }
        )
        if too_large:
            self._respond(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "text/plain", "Request too large", event_id, session, is_new)
        elif path == "/__mirror__/health":
            self._respond(HTTPStatus.OK, "application/json", '{"status":"ready"}', event_id, session, is_new)
        elif defense_active:
            if self.defense.tarpit_ms:
                time.sleep(self.defense.tarpit_ms / 1000)
            self.close_connection = True
            self._respond(
                HTTPStatus.TOO_MANY_REQUESTS,
                "application/json",
                '{"status":"contained","retry_after":60}',
                event_id,
                session,
                is_new,
                {"Retry-After": "60", "Connection": "close"},
            )
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
    do_DELETE = _handle
    do_OPTIONS = _handle
    do_TRACE = _handle
    do_CONNECT = _handle


class MirrorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        event_log: EventLog,
        *,
        mode: str = "simulation",
        control_token: str | None = None,
        tarpit_ms: int = 150,
    ):
        super().__init__(address, MirrorHandler)
        self.event_log = event_log
        self.sessions = SessionStore()
        self.defense = DefenseController(
            mode,
            control_token,
            tarpit_ms,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the House of Mirrors adaptive HTTP decoy")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log", type=Path, default=Path("logs/events.jsonl"))
    parser.add_argument("--mode", choices=sorted(VALID_MODES), default="simulation")
    parser.add_argument("--tarpit-ms", type=int, default=150, help="wartime denial delay, 0-1000 ms")
    parser.add_argument(
        "--control-token",
        default=os.environ.get("HOM_CONTROL_TOKEN"),
        help="local mode-control token; HOM_CONTROL_TOKEN is preferred",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        server = MirrorServer(
            (args.bind, args.port),
            EventLog(args.log),
            mode=args.mode,
            control_token=args.control_token,
            tarpit_ms=args.tarpit_ms,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    host, port = server.server_address[:2]
    print(f"House of Mirrors listening on http://{host}:{port}")
    print(f"Telemetry: {args.log}")
    print(f"Defense mode: {server.defense.mode}")
    if server.defense.control_token is None:
        print("Local mode control disabled; set HOM_CONTROL_TOKEN to enable it.")
    else:
        print("Local mode control enabled; token omitted from output.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
