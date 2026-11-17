# Sentryline — SOC Log Analysis Workspace

![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue)
![Flask](https://img.shields.io/badge/flask-3.x-black)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A local Flask application for detection engineering and analyst practice: upload logs, investigate explainable rule findings, review chronological evidence, record decisions, and export investigations. Ruleset `2026.10.11.1`.

## Quick start

Requires Python 3.12–3.14.

**Windows (PowerShell)**

```powershell
git clone https://github.com/Dev384-code/sentryline.git
cd sentryline
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python serve.py --open
```

**macOS / Linux**

```bash
git clone https://github.com/Dev384-code/sentryline.git
cd sentryline
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python serve.py --open
```

Open http://127.0.0.1:5000 in a normal browser. Keep the terminal open; Ctrl+C stops the server. `serve.py` prints the URL and reports port conflicts. For another port use `python serve.py --port 5010 --open`. Try the bundled synthetic incident at `tests/fixtures/sample_incident.log` for a first upload.

If the page times out, run `python scripts/doctor.py --port 5000` in another terminal using the same virtual environment. The diagnostic checks dependencies and `/health`, bypassing proxy settings only for its local request. It does not change firewall or browser settings. Browser iframe embedding is intentionally blocked.

## Features

- Rule findings for authentication bursts, possible account compromise, suspicious commands, web payloads, port scanning, beacon timing, and archive/transfer correlations, with ATT&CK associations and supporting source lines.
- Searchable alert report, severity/status filters, append-only analyst notes and dispositions, and audit entries for alert status changes.
- Chronological UTC evidence timeline with filters and links to relevant findings. Chronology does not establish causality.
- SQLite scan history, scoped exports, unique alert IDs, and transactional updates. Up to 20 scans are retained.
- Opt-in historical login-hour profiles, restricted to approved successful logins strictly earlier than the new upload's first timestamp. Profiles require 10 unique timestamps across 3 days per host/user; at most 200 recent observations are used. Revoke approval to exclude that scan from future training. Existing results remain unchanged.
- Windows Security JSON Lines adapter for events 4624, 4625, and 4688. Windows export helper and local labeled-dataset evaluator.
- UTF-8/BOM input support, validated IP addresses, upload/parser bounds, CSRF checks, escaped output, security headers, and Waitress with debug disabled.

## Supported inputs

Upload `.log`, `.txt`, or `.jsonl` files. Limits: 5 MiB for the request, 50,000 parsed events, 100,000 physical lines, and a 64 KiB per-line parsing bound. Detailed parser warnings are bounded. Temporary upload files are deleted after processing. Complete original bytes, a per-line audit and normalized evidence are retained in the local SQLite scan and included in JSON investigation exports. Download source evidence before the 20-scan retention expires.

Key/value example:

```text
2026-09-01T10:00:00Z host=demo-host user=alice ip=192.0.2.10 country=US action=login status=success
```

Generic JSON accepts timestamp, user, ip, country, action, status and optional host/command/process metadata. Windows JSON supports named `System`/`EventData`, flat exports from the included script, and selected `winlog` fields. Binary `.evtx` and XML files are unsupported. Service/batch/new-credential logons are separated from ordinary login detections; absent source IPs do not form brute-force groups.

Country values and configured IP indicators are supplied evidence, not live geolocation or threat intelligence. Traditional syslog assumes the current UTC year/timezone; explicit ISO timestamps are preferable.

## Demonstrate and verify

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python scripts/evaluate_scenarios.py
python scripts/benchmark.py --events 50000 --users 1000
```

See [demo guide](docs/guides/DEMO_GUIDE.md), [engineering review](docs/reviews/REVIEW.md), [logic review](docs/reviews/LOGIC_REVIEW.md), and [resume case study](docs/portfolio/RESUME_CASE_STUDY.md).

213 regression tests pass locally on Python 3.14. All 25 reviewed synthetic scenarios match expected rule types. These authored fixtures are regression coverage, not independent field accuracy measurements. GitHub Actions runs the suite and scenario evaluation on Ubuntu (Python 3.12/3.13/3.14) and Windows (Python 3.14).

Use `scripts/evaluate_dataset.py` with your own supported corpus and CSV labels (`line,type`). Specify dataset name and provenance. Precision and false-positive rate are withheld unless `--complete-labels` declares all event/rule pairs adjudicated; software cannot verify dataset independence. See the demo guide for commands.

## Storage and local access

The default database is `data/sentryline.sqlite3`; override with `SENTRYLINE_DATABASE`. Notes allow 500 entries per scan and 5,000 characters per entry. Retention removes notes, audit history and training observations associated with expired scans. Save exports before scans expire. JSON exports include notes and the most recent 50 status audit entries.

Optional environment variables: `SENTRYLINE_AUTH_USER` and `SENTRYLINE_AUTH_PASSWORD` enable Basic Auth; `SECRET_KEY` sets a stable Flask session secret; `SENTRYLINE_HTTPS=1` marks session cookies secure when actually served through HTTPS. The app binds to loopback by default. This is a shared analyst workspace, with no per-user scan isolation or role-based authorization.

## Scope

This project supports a reproducible portfolio demonstration and small trusted offline workflows. Alerts and risk scores are investigation heuristics; they do not prove compromise, intent, exfiltrated bytes, or impossible travel. Historical training depends on analyst-approved evidence and can be contaminated. Missing fields, unsupported vendor formats and obfuscation can cause missed findings. Independent organizational validation, browser visual QA, multi-user isolation and deployment-specific operations remain future work.

The GitHub package excludes virtual environments, local databases, private uploads and caches. Review any newly added logs before publishing; do not upload real employee/security telemetry.

## Updated detection coverage

See [DETECTION_RULES.md](docs/reference/DETECTION_RULES.md) for normalization, distributed and slow authentication thresholds, command review signals, upload correlation, explicit backup trust and limitations. An external backup without approved destination context now produces a medium review finding; this is a documented policy change.

## Read the incident report

The report presents plain-language finding cards: why the event matters, what remains uncertain, and what to check next. Open the source-evidence and technical-details sections for the original finding, ATT&CK association, confidence, baseline and related signals. Search accepts plain-language titles as well as technical rule names. Review status records your decision; marking a finding complete does not fix a system. Test-fixture metrics are collapsed and do not describe upload accuracy.

## Every accepted line accounted for

The input audit shows parsed, unparsed, unclassified and blank lines, with an exact original-file download and checksum. Unsupported-only files show Not assessed, with no numeric risk score. Arbitrary JSON is not automatically treated as a login event. This accounts for input within the limits; it does not guarantee recognition of every attack. See [INPUT_COVERAGE.md](docs/reference/INPUT_COVERAGE.md) for retention, diagnostics, privacy and field validation.

## Project structure

```text
sentryline/
  requirements.txt       Runtime dependencies (Flask, Waitress)
  requirements-dev.txt   Test dependencies
  app.py                 Flask routes and analysis workflow
  config.py              Limits, ruleset and local settings
  serve.py               Local server launcher
  analyzer/              Parsing, detection, explanations and storage
  templates/             Application pages and shared components
  static/                CSS and browser JavaScript
  scripts/               Diagnostics, evaluation and Windows export tools
  tests/
    fixtures/            Synthetic logs, scenarios and reviewed labels
    test_*.py            Regression tests
  docs/
    guides/              Setup and demonstration
    reference/           Detection rules and input coverage
    reviews/             Engineering findings and validation
    portfolio/           Resume and interview material
  data/                  Private local database (excluded from Git)
  logs/uploads/          Temporary uploads (excluded from Git)
  .github/workflows/     CI configuration
```

See [documentation index](docs/README.md). The virtual environment and Python caches are generated locally and excluded from Git.

## Continuous local monitoring

Open **Local monitoring** after starting `python serve.py --open`. Explicit owner consent enables Windows Security collection, rolling correlation, resumable checkpoints, and high/critical review notifications. Collection stays stopped after a server restart. See [monitoring setup and limits](docs/guides/LOCAL_MONITORING.md). Run one server per database.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Released under the [MIT License](LICENSE).
