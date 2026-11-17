# Sentryline logic and scenario review

The reviewed ruleset is `2026.10.11.1`. This project is a local detection-engineering and analyst-triage portfolio tool. It can analyze supported real log formats, but has not been validated on independently labeled organizational data. Its alerts are investigation leads.

## Defects corrected in this review

- Routine sudo and ordinary certificate hashing no longer produce privilege/LOLBin alerts.
- A single firewall block is no longer called a network scan; distinct-port windows tolerate repeated probes.
- Authentication, scan, baseline, beacon, and correlation context respect host boundaries.
- Authentication success resets preceding failures, preventing repeated compromise alerts on subsequent normal successes.
- First observation of a source alone no longer escalates an admin installation chain to critical.
- Web signatures are limited to web/request evidence and decode at most two URL-encoding layers.
- PowerShell has its own T1059.001 association, rather than being treated generically as T1218.
- Archive/transfer correlation requires the same file. An arbitrary destination address is not automatically suspicious. Timing-based beacon context must precede the transfer on the same host.
- Country-change findings attach to successful login evidence, not a later failed attempt. They do not establish impossible travel.
- Alert reports expose the physical source lines contributing to grouped detections.
- The synthetic fixture label calling one firewall drop a scan was corrected. This is an explicitly reviewed label change, not a hidden threshold adjustment to preserve benchmark scores.

## Scenario outcomes

All 25 explicitly reviewed scenarios matched their expected rule types, both directly and after file parsing. The labels and scenarios were authored during this review; they are not an independent benchmark or a measurement of production accuracy.

| Scenario | Expected signals | Outcome |
| --- | --- | --- |
| normal successful authentication | No alerts | Pass |
| two password typos | No alerts | Pass |
| authentication failure burst | brute_force | Pass |
| failure then success | brute_force, account_takeover | Pass |
| successful auth resets failure sequence | brute_force, account_takeover | Pass |
| host boundary authentication | No alerts | Pass |
| single firewall drop | No alerts | Pass |
| distinct port scan with retries | network_scan | Pass |
| firewall host boundary | No alerts | Pass |
| routine sudo administration | No alerts | Pass |
| privilege group change | privilege_escalation | Pass |
| routine powershell script | No alerts | Pass |
| encoded powershell review | suspicious_powershell | Pass |
| routine certificate hash | No alerts | Pass |
| certificate tool remote fetch | lolbin_execution | Pass |
| authorized install after first login | No alerts | Pass |
| compromised auth download execute | brute_force, account_takeover, post_auth_download_execute | Pass |
| ordinary archive backup | archive_transfer_review (unapproved external destination) | Pass |
| archive to configured indicator | data_exfiltration | Pass |
| unrelated archive and transfer | No alerts | Pass |
| encoded web traversal | web_attack | Pass |
| sql text in admin command | No alerts | Pass |
| country change then failed login | country_change | Pass |
| periodic checkin pattern | c2_beaconing | Pass |
| beacon host boundary | No alerts | Pass |

## Built-in incident: observed result

This is a synthetic multi-stage fixture, not a confirmed live intrusion. The chronology below follows parsed timestamps rather than arranging events into an assumed kill chain.

Parsed events: **27**. Parser warnings: **0**. Rule findings: **9**.

| Time (UTC) | Host | Rule | Evidence lines | Interpretation |
| --- | --- | --- | --- | --- |
| 02:03:18 | db02 | brute_force | 1, 2, 3 | 3 failed login attempts within 10 minutes |
| 02:03:29 | db02 | account_takeover | 1, 2, 3, 4, 5 | Possible account compromise: successful authentication followed 4 failed attempts from 41.202.19.63 for backup |
| 02:03:31 | db02 | country_change | 7 | GeoIP changed from US to RO for backup |
| 02:04:03 | db02 | network_scan | 8, 9, 10, 11 | 4 destination ports probed on 10.0.0.12 from 41.202.19.63 within 10 seconds |
| 02:05:10 | web03 | web_attack | 15 | Web attack payload detected in request content |
| 02:05:12 | web03 | web_attack | 16 | Web attack payload detected in request content |
| 02:06:03 | db02 | post_auth_download_execute | 18, 19, 20 | Suspicious post-auth download, chmod, and execution chain |
| 02:20:04 | db02 | c2_beaconing | 23 | Periodic outbound check-ins to 185.44.77.12:443; C2 hypothesis requires investigation |
| 02:32:10 | db02 | data_exfiltration | 25, 26 | Archive operation followed by outbound transfer to a configured suspicious endpoint |

## What remains uncertain

- Successful authentication after failures suggests possible compromise; logs cannot prove the credential holder's intent.
- Encoded PowerShell, regular agent check-ins, country changes, and privilege-policy changes can be legitimate.
- Network patterns can be authorized security scanning. ATT&CK associations are analyst hypotheses, not proof.
- Login-hour baselines use qualifying approved history when available, otherwise successful events from the current upload. Historical support requires 10 distinct timestamps across 3 days per host/user and excludes events at or after the new scan starts. Approval is reversible for future scans; trusted successful events can still contaminate training. This is not independent field validation.
- Exfiltration correlation currently recognizes a subset of tar/zip and curl/simple scp/rsync syntax. It does not inspect file content, prove transferred bytes, or reliably support domain-name reputation.
- Unsupported vendor formats, obfuscated commands, non-adjacent installation chains, sparse logs, and missing host/session fields can cause missed detections.
- Traditional syslog assumes the current UTC year/timezone. Explicit ISO timestamps are preferable.
- The risk score is an investigation-priority heuristic, not a probability. Count-based risk can saturate on busy logs.
- Public operation still needs deployment-specific TLS, identity/roles, rate limiting, monitoring, secret management, and independent rule validation.
- Browser accessibility from this execution environment remains unresolved; prior HTTP checks used a WSGI server and client within one execution process.

## Reproduce

```powershell
python -m pytest -q
python scripts/evaluate_scenarios.py
python scripts/benchmark.py --events 50000 --users 1000
python serve.py --open
```

Verification at delivery: 187 tests passed on both the bundled Python 3.12 runtime and the project's Python 3.14 environment. A single 50,000-event/1,000-user synthetic detector-only run took 0.344 seconds on the review machine. This does not measure ingestion, persistence, browser rendering, adversarial worst-case cost, or concurrent workload capacity.

## Mapping references

Mapping corrections were checked against MITRE's [PowerShell](https://attack.mitre.org/techniques/T1059/001/), [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/), and [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) entries. A mapping describes a hypothesis about behavior, not confirmed maliciousness.

## Investigation and input improvements

The timeline orders parsed evidence by UTC timestamp and physical source line, with links to all contributing findings. Analyst notes are append-only, escaped in HTML, bounded, scoped to retained scans and included in JSON exports. Missing source IPs no longer form authentication attack groups. IPv4-mapped IPv6 addresses normalize to IPv4. Windows Security JSON support preserves event IDs, host, domain/user and available process metadata; service/batch/new-credential logons are separated from ordinary login rules. Unsupported or malformed inputs generate parser warnings. Binary EVTX is unsupported.

Historical profile provenance is included in result JSON. Profile counts include matching login identities only; retention and revocation remove derived training observations. Existing analysis results remain snapshots. The dataset evaluator requires source provenance and distinguishes partially labeled data from fully adjudicated event/rule pairs; accepting provenance does not verify it. See DEMO_GUIDE.md.
