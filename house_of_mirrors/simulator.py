"""Constrained real-traffic emulator for an authorized lab."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import time
import uuid
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urlsplit

from .catalog import EMULATION_SEQUENCE


def allowed_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def validate_target(target: str) -> tuple[str, int]:
    parsed = urlsplit(target)
    if parsed.scheme != "http":
        raise ValueError("only plain HTTP lab targets are supported")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("target must contain only scheme, host, and optional port")
    if not allowed_host(parsed.hostname):
        raise ValueError("target must be localhost or a literal loopback/private IP address")
    return parsed.hostname or "", parsed.port or 80


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded real HTTP probes against an authorized decoy")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--pace", type=float, default=0.2)
    args = parser.parse_args()
    if not args.authorized:
        raise SystemExit("refusing to run: pass --authorized after confirming written authorization")
    if not 0.0 <= args.pace <= 5.0:
        raise SystemExit("--pace must be between 0.0 and 5.0 seconds")
    try:
        host, port = validate_target(args.target)
    except ValueError as exc:
        raise SystemExit(f"invalid target: {exc}") from exc

    exercise_id = f"hom-{uuid.uuid4().hex[:12]}"
    cookie_value = ""
    print(f"Exercise {exercise_id}: {len(EMULATION_SEQUENCE)} real, bounded probes to {host}:{port}")
    for scenario in EMULATION_SEQUENCE:
        body = urlencode(scenario.request_fields) if scenario.request_fields else None
        headers = {"User-Agent": "HouseOfMirrors-AuthorizedExercise/0.1", "X-Exercise-ID": exercise_id}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie_value:
            headers["Cookie"] = cookie_value
        connection = http.client.HTTPConnection(host, port, timeout=3)
        try:
            connection.request(scenario.method, scenario.path, body=body, headers=headers)
            response = connection.getresponse()
            response.read(4096)
            set_cookie = response.getheader("Set-Cookie")
            if set_cookie:
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(set_cookie)
                if "mirror_session" in parsed_cookie:
                    cookie_value = f"mirror_session={parsed_cookie['mirror_session'].value}"
            print(f"{scenario.method:4} {scenario.path:20} -> {response.status} [{scenario.signal}]")
        except OSError as exc:
            print(f"{scenario.method:4} {scenario.path:20} -> connection error: {exc}")
        finally:
            connection.close()
        time.sleep(args.pace)


if __name__ == "__main__":
    main()
