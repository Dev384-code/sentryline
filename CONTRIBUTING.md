# Contributing

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

## Before opening a pull request

```bash
python -m pytest -q
python scripts/evaluate_scenarios.py
```

- Add or update a synthetic fixture in `tests/fixtures/` for any parser or rule change.
- Document new rules, thresholds and limitations in `docs/reference/DETECTION_RULES.md` and bump `RULESET_VERSION` in `config.py`.
- Use only synthetic or fully redacted log data. Documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are preferred.
