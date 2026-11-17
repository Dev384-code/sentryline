# Contextual detection rules — 2026.10.11.1

These rules generate investigation leads from supported log evidence. They do not prove intent, command success, exploitation, persistence or transferred bytes. Severity is a triage heuristic. The same behavior can occur during authorized testing or administration.

## Web requests

The engine decodes URL encoding at most twice, replaces SQL block comments with spaces and recognizes UNION/SELECT separator variants. It looks for SQL-like expressions, script tags/event-handler payloads and parent-directory traversal. The request must be web evidence; command prose is not scanned as a web request. Pattern matches are medium confidence even when severity is high. Access-log HTTP status is preserved; all status codes >=400 normalize as failed requests. HTTP 200 does not prove exploitation, and POST bodies absent from access logs cannot be inspected.

A successful POST to `/upload` or `/uploads` followed within 600 seconds by a command-parameter request to `/uploads/<script>.php|jsp|asp|aspx` generates `upload_command_request`. Host and source IP must match. The upload must have a recorded 2xx status. This does not link an actual uploaded filename or prove code execution; proxy/NAT addresses can merge clients. Unknown IPs/hosts cannot establish this correlation.

## Authentication

Existing burst and same-account takeover rules remain. New rules require a host and source IP:

- `distributed_authentication`: at least 12 failures, 6 distinct source IPs and 2 accounts on one host within 10 minutes. One finding per host per 10-minute cooldown.
- `slow_authentication`: at least 8 failures across 4 accounts from one source on one host within 120 minutes, spanning at least 20 minutes. One finding per source/host per 120-minute cooldown.
- `success_after_source_failures`: a successful login after that prolonged source pattern. Accounts may differ, so the message describes source context rather than confirmed same-account takeover. A successful login resets its source history.

Shared proxies, expired credentials and fleet automation can meet these thresholds. No source address is permanently labeled malicious by these rules. Rolling counters avoid rescanning entire histories; supporting evidence for these windows is bounded to the latest 100 events and the successful event where applicable. Window counts can exceed displayed supporting lines.

## Commands

Command rules use parsed command fields, not raw log prose:

- Read/copy commands targeting `/etc/shadow` produce `sensitive_file_read`; `ls` and `stat` metadata checks remain quiet. Shell syntax coverage is limited to recognized forms.
- Account creation or `crontab -e` within 600 seconds after same-host/user takeover or download/execution findings produces contextual review. Ordinary account provisioning and cron editing alone remain quiet. Cron editor invocation does not prove a scheduled job was installed.
- `history -c`, log-removal/truncation commands targeting `/var/log`, and journal pruning with zero or one-second retention generate review findings. Normal temporary backup cleanup and seven-day journal retention remain quiet. Authorized maintenance may still need a benign disposition.

## Archive transfer policy

Tar must create an archive; extraction does not establish staging. The subsequent simple scp/rsync/curl upload must reference the same archive within 600 seconds and the same host/user/session context. A destination with existing indicator or earlier beacon context keeps the existing stronger transfer signal. Otherwise a non-local IP destination creates medium `archive_transfer_review`; no transferred bytes or bad reputation are asserted.

RFC1918, loopback, link-local and IPv6 local address ranges remain quiet for this review rule. Domain-name destinations and complex option syntax are not fully handled. Private destinations can still be used maliciously; silence is not proof of safety.

An owner can explicitly configure external backup destinations in config.py:

```python
TRUSTED_TRANSFER_NETWORKS = ("203.0.113.250/32",)
```

Replace this documentation address with your approved endpoint. Use narrow CIDRs and restart the app after editing. This exemption only suppresses `archive_transfer_review`, not the independent configured-indicator/exfiltration rules. Defaults trust no external destination.

The reviewed synthetic `ordinary_archive_backup` scenario now expects this medium review finding for an external destination with no trust configuration. Its label changed openly to reflect the policy; it is not scored as confirmed exfiltration. A separate test verifies owner-approved external backups remain quiet.

## Validation and scope

187 regression tests cover prior behavior and 30 new cases, including benign controls, source/host isolation, successful-login resets, failed uploads, malformed URLs, archive extraction and explicit backup trust. Both provided files were exercised through CSRF-enabled Flask upload/report/timeline/export workflows in isolated temporary storage. The test files remain outside the GitHub package.

Independent ground-truth evaluation and browser visual QA remain pending. These changes improve supported-pattern coverage, not production accuracy guarantees. Owner-approved Windows Security collection is now available; see [setup and limitations](../guides/LOCAL_MONITORING.md). Live event delivery validation remains pending.

Mappings are review hypotheses based on MITRE [Brute Force](https://attack.mitre.org/techniques/T1110/), [Web Shell](https://attack.mitre.org/techniques/T1505/003/), [Credential Files](https://attack.mitre.org/techniques/T1003/008/), [Cron](https://attack.mitre.org/techniques/T1053/003/), [Local Account](https://attack.mitre.org/techniques/T1136/001/) and [Indicator Removal](https://attack.mitre.org/techniques/T1070/).
