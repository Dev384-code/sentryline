# Current engineering review — 2026.10.11.1

The detection pass adds bounded web normalization, distributed/slow authentication patterns, success-after-source-failures context, upload-to-command-request correlation, sensitive-file reads, contextual account/cron changes, history/log clearing and same-archive external transfer review. Dashboard coverage now includes these rule families. See DETECTION_RULES.md for thresholds and limitations.

187 tests pass on Python 3.12 and 3.14. All 25 reviewed scenarios pass after openly changing the unapproved external-backup expectation to medium review. A separate trusted-backup test verifies explicit owner approval suppresses that review signal. No accuracy percentage is asserted from these authored tests.

Provided file checks, using within-upload context only:

| File | Events | Warnings | Findings | Principal outcome |
| --- | --- | --- | --- | --- |
| sentryline_test.log | 91 | 0 | 17 | Existing attack signals plus sensitive-file, account/cron, clearing and transfer review |
| sentryline_test_hard.log | 77 | 0 | 17 | 5 payload findings, 4 contextual authentication/upload findings, 8 static indicator matches |

Both files passed CSRF-enabled upload, report, timeline and JSON/CSV export checks with an isolated temporary database. Their content is not shipped in the clean GitHub package. Static indicator matches are reported separately and do not count as payload recognition. Labels and collection provenance for these files remain unverified.

A 50,000-event benign detector-only run took 0.344 seconds during this review. This excludes ingestion, persistence, rendering and concurrent capacity. The built-in incident remains 27 events, 9 findings and zero parser warnings.

Browser visual QA, independently labeled field validation and live collector delivery validation remain pending. README, DEMO_GUIDE.md and RESUME_CASE_STUDY.md provide reproduction and portfolio guidance.

The beginner report redesign adds complete plain-language guidance for every enabled rule, expandable source/technical evidence, review-status labels, and matching title search. Existing detection results, JSON/CSV exports, notes and status values remain unchanged. Four new tests cover guidance completeness, source-detail retention, title search and honest fallback for historical rules. Responsive CSS replaces the horizontal incident table with cards; browser visual QA remains pending.

The input-integrity pass retains a byte-exact source snapshot and complete line ledger, surfaces incomplete coverage, and checks source checksum on download. Sixteen new input/coverage tests plus two timestamp/deep-JSON tests bring the suite to 187. Evaluation now counts labeled unparsed source lines as misses. See INPUT_COVERAGE.md for the scope of the input guarantee.

## Local monitoring extension

A consent-controlled Windows Security polling collector, durable checkpoints, rolling correlation window, bounded local retention, gap/error display, and optional browser notifications are implemented. Twelve monitoring regression tests bring the suite to 199. Live Windows delivery and audit-policy validation remain pending. See [monitoring guide](../guides/LOCAL_MONITORING.md).

## Monitoring diagnostics and rates

Fixed status blocking during a Windows read, added explicit permission/timeout diagnostics and consented recent backfill, and displayed observed per-second authentication metrics with source-scoped brute-force thresholds. Fourteen added regressions include executing the actual PowerShell script against mocked records. All 213 tests pass on Python 3.12 and 3.14. The live read in the review environment was denied; OS permission and audit-policy validation remain required.
