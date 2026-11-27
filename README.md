# House of Mirrors

House of Mirrors is a dependency-free defensive deception lab. It exposes fake
administrative and secret-looking HTTP routes, records interaction telemetry in
a hash-chained JSONL log, and includes a constrained probe simulator for an
authorized detection exercise.

Each visitor is correlated into an isolated synthetic session that progresses
from `observed` to `engaged` to `contained`. Containment means the visitor stays
inside fabricated services and data; the system never attacks the visitor.

It is intentionally **not** an exploit framework. The simulator sends a small,
fixed set of harmless HTTP requests, accepts only literal loopback/private IP
targets (or `localhost`), and requires an explicit authorization flag.

## Quick start

Python 3.10 or newer is recommended.

Terminal 1:

```sh
python -m house_of_mirrors.server
```

Terminal 2:

```sh
python -m house_of_mirrors.simulator \
  --target http://127.0.0.1:8080 \
  --authorized
```

Then stop the server with `Ctrl-C` and inspect the telemetry:

```sh
python -m house_of_mirrors.verify logs/events.jsonl
```

## Defense modes

- `simulation` is the default. It serves every decoy and records the complete
  exercise without blocking the synthetic attacker.
- `wartime` actively contains sessions once their risk score reaches the
  threshold. Contained requests receive a bounded delay, HTTP 429 denial, and a
  `Retry-After` response. This is local defense; the server never makes an
  outbound request to the visitor.

Cookie-less scanners are correlated in memory by source address and user agent,
so simply refusing the decoy cookie does not reset the wartime risk score. This
state disappears when the server stops.

Start directly in wartime mode:

```sh
export HOM_CONTROL_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m house_of_mirrors.server --mode wartime --tarpit-ms 150
```

Toggle a running server from the same host using the `HOM_CONTROL_TOKEN` value
supplied at launch (the service never prints it; remote control attempts are rejected):

```sh
curl -sS -X POST http://127.0.0.1:8080/__mirror__/control/mode \
  -H 'Content-Type: application/json' \
  -H "X-Control-Token: $HOM_CONTROL_TOKEN" \
  -d '{"mode":"wartime"}'
```

Use `{"mode":"simulation"}` to switch back. Mode changes and defensive
actions are written to the hash-chained event log.

## Defensive exercise

Scenario: an authorized red-team operator performs discovery against a decoy
web service. The blue team should detect reconnaissance, credential guessing,
secret-file discovery, and automation based on the generated events.

1. Start the honeypot with a clean log.
2. Have the blue team observe `logs/events.jsonl` without seeing the simulator.
3. Run the simulator with `--pace 0.4` from the authorized lab host.
4. Record time-to-first-alert, classification accuracy, and whether the source
   and affected decoys were correctly identified.
5. Verify the log chain, review missed signals, and tune alert rules.

Expected signals include `admin_discovery`, `credential_probe`,
`secret_file_probe`, `backup_probe`, and `automation_probe`. A sample detection
rule is in `detections/example_rules.yml`.

## Safer deployment defaults

- The service binds to `127.0.0.1`. Use `--bind 0.0.0.0` only inside an isolated,
  owned lab network with ingress controls.
- No submitted password, token, cookie, or authorization value is written to
  disk. Body telemetry contains field names and byte count only.
- Decoys contain fabricated data only. Never place real credentials in them.
- Logs may contain source addresses and user-agent strings; handle them under
  your organization's retention and privacy policy.
- Optional defense modes are `simulation` (default) and `wartime`. Wartime mode
  returns a bounded 429 response with a configurable delay after a synthetic
  session reaches `contained`; it never contacts or attacks the visitor.
- The local mode-control endpoint is disabled unless `HOM_CONTROL_TOKEN` is set
  (or `--control-token` is supplied). It accepts requests only from loopback and
  requires `X-Control-Token`. Use the environment variable rather than a
  command-line token; the service never prints the token or writes it to telemetry.

## Commands

```sh
python -m house_of_mirrors.server --help
python -m house_of_mirrors.simulator --help
python -m house_of_mirrors.verify logs/events.jsonl
python -m unittest discover -s tests -v
```
