# Owner-approved Windows monitoring

Start the application with `python serve.py --open`. Open **Local monitoring** in the sidebar, choose a retention window (1, 6, or 24 hours) and polling interval (15, 30, or 60 seconds), check the authorization box, and click Start. Stop prevents another poll; an in-flight read has a 25-second timeout. The application must remain running. Restarting the application leaves monitoring stopped and requires fresh consent.

## Access and scope

Only the local Windows Security channel is read. Supported event IDs are 4624, 4625, and 4688. Windows must already be configured to audit logon failures/successes and process creation. Process command lines require the corresponding Windows audit setting. An authorized Event Log Readers account or administrator permissions may be needed; the tool does not change policy or elevate itself. Permission errors appear on the monitoring page and are retried at the selected interval.

First start defaults to the current Security record ID and subsequent events. An explicit last-10-minutes option includes recent events on an uninitialized checkpoint. Existing checkpoints take priority on resume. Resume uses a durable SQLite checkpoint. Collection reads up to 1,000 channel records per poll in ascending order, including unsupported IDs for checkpoint progression, so bursts can create a backlog. Unsupported event IDs are outside detection coverage, not evidence of safety. On a detectable record sequence reset or overwritten backlog, a gap notice is shown. Clearing and refilling a log beyond the previous ID between polls may evade the reset check; this is a prototype, not a guaranteed-lossless agent.

## Reports and notifications

New supported events are correlated with retained events using the existing detector. The latest report link updates automatically; report snapshots are immutable and keep the existing notes/review workflow. The monitoring page polls status every five seconds. High/critical findings appear there, and optional browser notifications require a user click and browser permission. Browser notifications work while the monitoring page is open; no email, desktop service, or external notification delivery is installed. Findings indicate review priority, not a confirmed attack.

## Retention and privacy

The active source window expires events outside the chosen duration, with a maximum of 10,000 supported events and 5 MiB of normalized JSON. Capacity truncation is disclosed. Snapshot history retains the latest 20 reports across uploads and monitoring; those snapshots may retain evidence longer than the rolling window. Monitoring state retains 100 recent notifications and 20 gap notices. SQLite stores checkpoints, normalized events, consent time, status, and notifications locally and is excluded from Git. Original Windows XML is not preserved; report original-source export contains the collected JSON snapshot. Stop does not delete saved evidence.

Run exactly one Sentryline server process per database. This collector is a daemon thread owned by that process, not a Windows service. Local Start/Stop routes require loopback access and the app's existing CSRF protection; optional HTTP authentication still applies. Loopback access alone does not prove machine ownership, so use authentication on shared computers. No unattended startup or operating-system changes are installed.

## Validation

Automated tests simulate record batches, failures, restarts, duplicate records, cross-poll brute force, log resets, consent, and CSRF. They validate application behavior, not Windows audit configuration or live event delivery. Validate on an authorized Windows machine by starting monitoring, generating known test login/process activity, and checking the report against Event Viewer. Real collection remains dependent on that machine's audit settings and permissions.

## If monitoring appears inactive

Check the consent box and select **Check access**. The diagnostic tests Security log readability and reports supported event counts from the last 10 minutes (up to 500 events), including observed process command-line availability. It does not advance the monitoring checkpoint or start collection. Zero recent events does not establish that Windows audit policy is enabled. A successful diagnostic does not guarantee future collection.

If access is denied, use an authorized account with Security log read permission, or an administrator PowerShell terminal if you have authority to do so. Start the server from that terminal using the project virtual environment. This tool never grants itself privileges or changes Windows audit policy or PowerShell execution policy. The development execution environment denied a live Security read during validation; live delivery has not been demonstrated here.

The status API stays responsive during Windows reads. It distinguishes collecting, waiting for new supported events, stopped, and collection error. The page shows the last successful collection, batch counts, and backlog measured in channel record IDs (not selected-event count). Unsupported channel records are consumed to advance the checkpoint. A backlog can undercount recent activity until it is drained. Existing reports are snapshots; use the updated latest-report link for the newest analysis.

## Authentication rate and rule interpretation

Live metrics count normalized login events in the last 60 seconds using Windows event timestamps, not their arrival time. Attempts per second and failures per second are averages over that fixed 60-second window. Peak attempts uses a sliding one-second window within the last minute; the 60 bars use one-second age bins. Polling is periodic, so these are observed rates with collection delay, not a per-packet real-time sensor. Stopped/failed collection and backlog are explicitly disclosed. Future-dated events are excluded from current rates and counted as a clock caveat.

The source table groups failures by host and normalized source address over the configured brute-force rule window (currently 10 minutes). Three failures meet the existing critical-review threshold; six meet escalation. A threshold match is a suspicious signal, not proof of an attack. Rate alone does not establish brute force. Missing-address failures are counted but cannot meet the address-based rule, and service logon types 4, 5, and 9 are excluded to match the existing parser/detector behavior. Sources are capped at the top 20 displayed rows with a total-source count. Existing report logic also checks account takeover and other supported patterns.

Validation now includes real PowerShell execution against mocked Windows records, rate-window boundaries, source/host isolation, service exclusions, clock caveats, timeout/error messages, and status responsiveness during a slow read. These tests do not generate real login failures or change machine settings.
