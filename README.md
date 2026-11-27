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

## Commands

```sh
python -m house_of_mirrors.server --help
python -m house_of_mirrors.simulator --help
python -m house_of_mirrors.verify logs/events.jsonl
python -m unittest discover -s tests -v
```
