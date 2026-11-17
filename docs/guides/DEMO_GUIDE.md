# Reproducible portfolio demo

## 1. Start and diagnose

Follow README setup and run `python serve.py --open`. Keep the terminal open. In a second terminal run `python scripts/doctor.py`; a healthy response confirms that this diagnostic can reach the local process. It does not establish browser reachability.

## 2. Investigate the built-in sample

Select Load sample, then open the alert report. Expect 27 parsed events, 9 findings and no parser warnings. Select one finding, inspect its evidence lines and ATT&CK association, change its triage status, and add a note with disposition `needs_context`. A disposition is analyst judgment, not a ground-truth label.

Open Evidence timeline, enable the findings-only filter and follow an alert link. The report search includes the alert ID so the link selects the corresponding alert. Export JSON and CSV. JSON includes the selected scan, parsed evidence, notes and the most recent 50 status updates.

## 3. Demonstrate historical context

1. Upload `tests/fixtures/baseline_training.jsonl`: 12 successful alice/demo-host logins over three days.
2. On the dashboard, explicitly confirm that the scan is trusted, then approve it for historical training.
3. Upload `tests/fixtures/baseline_new_login.jsonl`: one later 23:00 login. Inspect the unusual-time finding and its `approved_history` provenance in JSON.
4. Select the training scan from history and revoke its approval. Upload the later login again; no approved historical profile is used. Earlier results remain snapshots of their original analysis context.

At least 10 distinct timestamps across 3 days are required. Re-uploading identical events does not create extra support. Observations at or after the new scan's earliest event are excluded. If no qualifying historical profile exists, the detector can use successful logins within the upload; findings identify this fallback as `current_upload`. Both approaches require analyst review.

## 4. Windows export demonstration

Upload `tests/fixtures/windows_security.jsonl`. Expect 5 parsed events with no parser warnings. Inspect the failure/success sequence and encoded PowerShell evidence.

For an authorized Windows machine, export supported Security events explicitly:

```powershell
.\scripts\export_windows.ps1 -Path .\security-export.jsonl -MaxEvents 1000
```

The script reads local Security events 4624, 4625 and 4688; appropriate read privileges and audit configuration are required. It does not change audit policy. Command-line evidence is available only if Windows recorded it. Treat the output as private telemetry; do not commit it. JSON Lines is supported, binary EVTX and XML are not.

Schema references: Microsoft [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) and [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688).

## 5. Evaluate a separately labeled corpus

CSV labels use physical file line numbers and supported rule types:

```csv
line,type
3,brute_force
4,account_takeover
```

```powershell
python scripts/evaluate_dataset.py .\authorized.log .\labels.csv --dataset-name "Reviewed internal exercise" --provenance "Describe source, consent, label process and date" --output .\evaluation.json
```

With partial labels, unmatched findings require adjudication and precision/FPR remain null. Add `--complete-labels` only when every event/rule pair has been adjudicated; missing pairs then count as negative. Metrics compare each finding's anchor line and rule type, not every contributing evidence line. A program accepting a provenance string cannot certify independence. No independent field dataset has been evaluated in this project review.

## 6. Prepare GitHub and interview material

Run the tests and scenario evaluator. Record a short demo showing sample upload, evidence timeline, analyst note, JSON export, and historical baseline provenance. Capture desktop/mobile screenshots after checking layout in a normal browser; screenshots and a video have not been produced by this review.

Use the provided clean ZIP as the repository starting point. Include README, tests, CI and docs. Choose your own license before publication; this review does not assign one. Keep `.venv`, databases and real logs out of Git. Resume wording is in RESUME_CASE_STUDY.md; replace benchmark figures if your own measured environment differs.

## Inspect input completeness

Open Input audit from the report, review unparsed/unclassified lines and download the original. Try an unsupported text file: it should be retained for review and show Not assessed. Use validate_input.py to check input before an upload. JSON exports now include the complete original source snapshot, so keep them private. See INPUT_COVERAGE.md.
