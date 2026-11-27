"""Constrained real-traffic emulator for an authorized lab."""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
import uuid
from http.client import HTTPConnection
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urlsplit

from .catalog import EMULATION_SEQUENCE


def allowed_host(hostname: str | None) -> bool:
    if hostname is None or "%" in hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return (
        not address.is_unspecified
        and not address.is_multicast
        and (address.is_loopback or address.is_private)
    )


def validate_target(target: str) -> tuple[str, int]:
    parsed = urlsplit(target)
    if parsed.scheme.lower() != "http":
        raise ValueError("only plain HTTP lab targets are supported")
    if (
        parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("target must contain only scheme, host, and optional port")
    if not allowed_host(parsed.hostname):
        raise ValueError("target must be localhost or a literal loopback/private IP address")
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise ValueError("target port is invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("target port must be between 1 and 65535")
    if parsed.hostname and parsed.hostname.lower() == "localhost":
        return "127.0.0.1", port
    address = ipaddress.ip_address(parsed.hostname or "")
    return str(address), port


parse_target = validate_target


def run_probe(
    target: str,
    *,
    authorized: bool,
    pace: float = 0.4,
    timeout: float = 3.0,
) -> dict:
    if not authorized:
        raise PermissionError("explicit --authorized confirmation is required")
    if not 0.0 <= pace <= 5.0:
        raise ValueError("pace must be between 0 and 5 seconds")
    if not 0.1 <= timeout <= 10.0:
        raise ValueError("timeout must be between 0.1 and 10 seconds")
    host, port = validate_target(target)
    exercise_id = f"hom-{uuid.uuid4().hex[:12]}"
    cookie_value = ""
    responses = []
    for index, scenario in enumerate(EMULATION_SEQUENCE):
        body = urlencode(scenario.request_fields) if scenario.request_fields else None
        headers = {
            "User-Agent": "HouseOfMirrors-AuthorizedExercise/0.1",
            "X-Exercise-ID": exercise_id,
            "Connection": "close",
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie_value:
            headers["Cookie"] = cookie_value
        connection = HTTPConnection(host, port, timeout=timeout)
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
            identified = bool(response.getheader("X-Decoy-Event"))
            responses.append(
                {
                    "method": scenario.method,
                    "path": scenario.path,
                    "signal": scenario.signal,
                    "http_status": response.status,
                    "identified_decoy": identified,
                }
            )
        except OSError as exc:
            responses.append(
                {
                    "method": scenario.method,
                    "path": scenario.path,
                    "signal": scenario.signal,
                    "error": type(exc).__name__,
                    "identified_decoy": False,
                }
            )
        finally:
            connection.close()
        if index + 1 < len(EMULATION_SEQUENCE) and pace:
            time.sleep(pace)

    succeeded = len(responses) == len(EMULATION_SEQUENCE) and all(
        response.get("identified_decoy") for response in responses
    )
    return {
        "status": "VERIFIED" if succeeded else "FAILED",
        "scope": "fixed requests to an authorized loopback/private HTTP target",
        "target": f"http://{host}:{port}",
        "exercise_id": exercise_id,
        "requests_completed": sum("http_status" in response for response in responses),
        "signals": [scenario.signal for scenario in EMULATION_SEQUENCE],
        "responses": responses,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded real HTTP probes against an authorized decoy")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--pace", type=float, default=0.4)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    try:
        result = run_probe(
            args.target,
            authorized=args.authorized,
            pace=args.pace,
            timeout=args.timeout,
        )
    except (OSError, ValueError, PermissionError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "VERIFIED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
