"""Shared red/blue scenario catalog."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Scenario:
    name: str
    method: str
    path: str
    signal: str
    score: int
    content_type: str
    response: str
    request_fields: dict[str, str] = field(default_factory=dict)


SCENARIOS = (
    Scenario("landing", "GET", "/", "landing", 0, "text/html", "<h1>Northstar Intranet</h1><a href='/admin'>Admin console</a>"),
    Scenario("robots", "GET", "/robots.txt", "automation_probe", 1, "text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n"),
    Scenario("admin", "GET", "/admin", "admin_discovery", 2, "text/html", "<h1>Administrator Console</h1><form method='post' action='/login'><input name='username'><input name='password' type='password'><button>Sign in</button></form>"),
    Scenario("environment", "GET", "/.env", "secret_file_probe", 4, "text/plain", "APP_ENV=production\nAPI_KEY=DECOY-NOT-A-REAL-SECRET\nARCHIVE=/backup.zip\n"),
    Scenario("backup", "GET", "/backup.zip", "backup_probe", 4, "application/octet-stream", "DECOY_BACKUP_NOT_AN_ARCHIVE\nNEXT=/api/users\n"),
    Scenario("users", "GET", "/api/users", "api_discovery", 3, "application/json", '{"users":[{"id":"DECOY-17","role":"operator"}],"synthetic":true}'),
    Scenario("login", "POST", "/login", "credential_probe", 5, "text/html", "<h1>Verification required</h1><p>Audit service is temporarily unavailable.</p>", {"username": "exercise", "password": "DECOY"}),
)

BY_ROUTE = {(scenario.method, scenario.path): scenario for scenario in SCENARIOS}
EMULATION_SEQUENCE = tuple(scenario for scenario in SCENARIOS if scenario.name != "landing")
