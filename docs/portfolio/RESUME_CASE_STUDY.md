# Resume case study — Sentryline

## Defensible project description

Built a Flask SOC log analysis workspace that parses supported logs, explains rule findings with source evidence and ATT&CK associations, and supports investigation notes, alert triage, retained scan history and scoped exports.

## Suggested resume bullets

- Implemented a SOC investigation workflow with SQLite scan history, chronological evidence, analyst dispositions, audit entries and JSON/CSV exports.
- Added opt-in historical login-hour baselines with strict timestamp cutoffs, host/user isolation, duplicate-resistant training support and revocable approval; normalized Windows Security JSON events 4624/4625/4688.
- Verified detection and application behavior with 213 regression tests and 25 reviewed synthetic scenarios; built a provenance-aware dataset evaluator that withholds precision claims when labels are incomplete.
- Hardened log ingestion with upload/event/line bounds, validated IPs, CSRF checks and transactional updates; measured 0.344 seconds for a 50,000-event synthetic detector-only run on the review machine.

Use three bullets if space is limited. State the benchmark scope and measured machine context when discussing performance. Do not describe 25 authored scenarios as production accuracy, assert confirmed compromise from an alert, or call this a production SIEM.

## Interview walkthrough

Explain an authentication burst followed by a successful login as a compromise hypothesis. Show contributing source lines and mention legitimate password recovery as another explanation. Add a needs-context note, inspect the UTC timeline, and show historical baseline provenance. Explain why training is explicit, excludes future observations and deduplicates timestamps. Discuss the shared workspace and retention tradeoffs.

Independent organizational evaluation, browser visual QA, production operations, identities/roles and live telemetry connectors remain future work. See DEMO_GUIDE.md for a reproducible demonstration.

- Added an owner-approved Windows Security collector with saved checkpoints, rolling detection, visible collection gaps, bounded retention, and high/critical browser notifications; live Windows delivery still requires validation.
