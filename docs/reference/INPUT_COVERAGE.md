# Input integrity and realistic coverage — 2026.10.11.1

## What this release guarantees within its input limits

For an accepted UTF-8 `.log`, `.txt` or `.jsonl` upload, every physical CR/LF-delimited line is recorded as parsed, parsed without a supported action interpretation, unparsed or blank. Parsed-unclassified lines are included in the parsed total. Total lines equals parsed + unparsed + blank. Warning display is capped, but the ledger accounts for all lines.

The complete original byte snapshot, including BOM, whitespace, line endings and fields unused by normalization, is retained with the scan as base64. Base64 is encoding, not encryption. Download original input through the audit page or `/export/source?run=<scan>`. The byte length and SHA-256 are checked before source download and audit rendering. A checksum failure returns an explicit error; it does not silently serve a damaged copy. This check detects mismatch with the stored checksum, not authenticity of the source system or deliberate modification of both data and checksum.

Temporary upload files are removed after processing. The SQLite scan now retains complete source evidence as well as normalized events. JSON investigation exports contain the complete source snapshot and ledger; handle them as private logs. Summary API responses omit the source snapshot and ledger. No source content is included in the GitHub ZIP.

Retention is still 20 scans. Expired scans, raw source, notes and training observations are pruned. This is not unlimited archival storage. Download the source/investigation before retention expires. Older scans cannot recover raw lines already discarded; re-upload the original file for the new audit.

## Input bounds and rejection

The whole upload is rejected for invalid UTF-8, requests above 5 MiB, more than 50,000 parsed events, or more than 100,000 physical lines. Binary EVTX, compressed files, multiline vendor records and arbitrary encodings are not universally supported. Lines beyond the 64 KiB per-line parsing bound remain in the original source and are marked unparsed, provided the entire file remains within the other bounds.

Empty, unsupported-only or malformed-only accepted text can be retained for audit, but it gets `analysis_status=not_assessed` and `risk_score=null`. It does not receive a clean result. Malformed/deeply nested JSON is accounted for instead of crashing the analysis. Arbitrary JSON without explicit action semantics is not guessed to be a login event; nested vendor identity objects require an adapter. Explicit local process JSON can be assessed without a network address.

## What remains outside any completeness claim

Line preservation is not universal detection. Parsed data can still lack the fields or telemetry necessary for rules. The report identifies unsupported action categories, missing computer names/addresses, unknown login outcomes and assumed years/timezones. The source may omit events, have inaccurate clocks or contain fabricated records. Requests without bodies do not reveal POST payloads; a command log does not establish its outcome; an HTTP response does not prove exploitation; source-IP identity may merge NAT users.

No rule system can promise zero false positives or zero false negatives for every organization, vendor, format and unknown attack. Severity is configured review priority, not measured true danger. This release remains a local shared analyst workspace; public multi-user deployment requires separate identity, isolation and operational work. The local Windows collector has the explicitly bounded scope described in [monitoring setup](../guides/LOCAL_MONITORING.md).

## Reproduce

```powershell
python -m pytest -q
python scripts/validate_input.py .\your-file.log
python scripts/evaluate_dataset.py .\your-file.log .\labels.csv --dataset-name "Reviewed corpus" --provenance "Describe collection and independent labeling"
```

The validator writes no database. Exit code 0 means structurally parsed supported input categories, never safe; 1 means partial/no-event input, and 2 means rejection. It outputs counts and diagnostic examples, not the full original source.

Dataset labels can refer to any nonblank original line, including unparsed lines. A labeled attack that the parser cannot consume counts as a false negative. Completeness/provenance are operator declarations; independence is not verified. Precision/FPR are withheld for partial labels.

## Verification and next field-validation step

187 regression tests pass on Python 3.12 and Python 3.14. They include exact-byte round trips, every-line balance, warning-cap accounting, unsupported-only uploads, source checksums, legacy scans, malformed JSON, source-aware evaluation and preserved UI evidence. Both supplied log files retain 17 findings each with no unparsed lines; generic syslog messages and timestamp assumptions still receive explicit coverage caveats.

For field validation, obtain authorized, separately labeled benign and incident logs from each target source, including malformed and missing-field cases. Freeze rule versions, record disagreements and report metrics per source against original nonblank lines. Add a named adapter and regression cases when a format is unsupported. No independent organizational dataset or public deployment was validated during this release. Browser visual QA remains pending.
