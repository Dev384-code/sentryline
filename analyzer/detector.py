from collections import defaultdict, deque
from datetime import datetime, timedelta
import re
from statistics import median
from bisect import bisect_right
import shlex
from hashlib import sha256

from config import (
    ACCOUNT_TAKEOVER_THRESHOLD,
    ACCOUNT_TAKEOVER_WINDOW_MINUTES,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    CORRELATION_WINDOW_SECONDS,
    POST_AUTH_COMMAND_WINDOW_SECONDS,
    SUSPICIOUS_IPS,
)

ATTACK_MAP = {
    "brute_force": {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
    "brute_force_escalated": {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
    "account_takeover": {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
    "suspicious_ip": {"technique_id": "—", "technique": "Configured IP indicator (context only)", "tactic": "Unclassified"},
    "unusual_time": {"technique_id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access"},
    "country_change": {"technique_id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access"},
    "privilege_escalation": {"technique_id": "T1548", "technique": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "suspicious_powershell": {"technique_id": "T1059.001", "technique": "PowerShell", "tactic": "Execution"},
    "lolbin_execution": {"technique_id": "T1218", "technique": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "c2_beaconing": {"technique_id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control"},
    "data_exfiltration": {"technique_id": "T1041", "technique": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "network_scan": {"technique_id": "T1046", "technique": "Network Service Scanning", "tactic": "Discovery"},
    "web_attack": {"technique_id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "post_auth_download_execute": {"technique_id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command and Control"},
}
from analyzer.context_rules import RULES, web_signature, contextual
ATTACK_MAP.update({key: dict(technique_id=value[0], technique=value[1], tactic=value[2]) for key,value in RULES.items()})



def _finding(alert_type, severity, event, message, confidence="medium"):
    return {
        "type": alert_type,
        "severity": severity,
        "user": event["user"],
        "ip": event["ip"],
        "timestamp": event["timestamp"],
        "line": event.get("line"),
        "message": message,
        "confidence": confidence,
        "mitre": ATTACK_MAP[alert_type],
        "host": event.get("host"),
        "evidence_lines": [event.get("line")],
    }


def circular_hour_diff(h1: float, h2: float) -> float:
    diff = abs(h1 - h2) % 24.0
    return min(diff, 24.0 - diff)


def _timestamp(event):
    return datetime.fromisoformat(event["timestamp"])


def _correlate(findings):
    groups = defaultdict(list)
    for finding in findings:
        key = (finding.get("host"), finding["user"], finding["ip"])
        if finding["user"] == "unknown" and finding["ip"] == "UNKNOWN":
            continue
        groups[key].append(finding)
    for key, related in groups.items():
        related.sort(key=lambda f: f["timestamp"])
        episodes = []
        for finding in related:
            if not episodes or datetime.fromisoformat(finding["timestamp"]) - datetime.fromisoformat(episodes[-1][0]["timestamp"]) > timedelta(minutes=30):
                episodes.append([])
            episodes[-1].append(finding)
        for episode in episodes:
            types = sorted({f["type"] for f in episode})
            if len(types) < 2:
                continue
            identity = sha256(repr(key).encode()).hexdigest()[:10]
            incident_id = f"INC-{identity}-{min(f.get('line') or 0 for f in episode):04d}"
            for finding in episode:
                finding["correlation"] = {"incident_id": incident_id, "related_detection_types": types, "window_minutes": 30}


def archive_output(command):
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None
    tool = tokens[0].rsplit("/", 1)[-1]
    if tool == "tar":
        if not any(t == "--create" or (t.startswith("-") and "c" in t[1:] and not t.startswith("--")) for t in tokens[1:]):
            return None
        for i, token in enumerate(tokens[1:], 1):
            if token.startswith("--file="):
                return token.split("=", 1)[1]
            if token == "--file" or (token.startswith("-") and "f" in token[1:]):
                return tokens[i+1] if i+1 < len(tokens) else None
    if tool == "zip":
        return next((t for t in tokens[1:] if not t.startswith("-")), None)
    return None

def upload_input(command):
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None
    tool = tokens[0].rsplit("/", 1)[-1]
    if tool == "curl":
        for i, token in enumerate(tokens):
            if token in {"-T", "--upload-file"}:
                return tokens[i+1] if i+1 < len(tokens) else None
    if tool in {"scp", "rsync"}:
        if any(t.startswith("-") for t in tokens[1:]):
            return None  # Ambiguous options need a dedicated adapter.
        return tokens[1] if len(tokens) >= 3 else None
    return None


def detect(events: list[dict], historical_baselines: dict | None = None) -> list[dict]:
    historical_baselines = historical_baselines or {}
    findings = []
    failed_by_ip = defaultdict(list)
    events_by_user = defaultdict(list)
    user_countries = defaultdict(set)
    user_hours = defaultdict(list)
    privilege_events = []

    for event in events:
        timestamp = _timestamp(event)
        is_login = event["action"].lower() == "login"
        if is_login and event["user"] != "unknown":
            if event["status"] == "success":
                user_hours[(event.get("host"), event["user"])].append(timestamp.hour + timestamp.minute / 60)
            events_by_user[(event.get("host"), event["user"])].append(event)
        if is_login and event["status"].lower() == "failed" and event["ip"] != "UNKNOWN":
            failed_by_ip[(event.get("host"), event["ip"])].append(event)
        if is_login and event["user"] != "unknown" and event["status"] == "success" and event["country"].upper() not in {"UNKNOWN", "UN", "N/A", "-"}:
            user_countries[(event.get("host"), event["user"])].add(event["country"])
        if event["ip"] in SUSPICIOUS_IPS:
            findings.append(_finding("suspicious_ip", "high", event,
                                     f"Source matches configured review indicator {event['ip']}", "high"))
        content = f"{event.get('request', '')} {event.get('raw', '')}"
        action = event["action"].lower()
        web_content = event.get("request", "") or (content if action in {"get", "post", "put", "delete", "patch", "web", "web_access"} else "")
        web_attack = web_signature(web_content)
        if web_attack:
            findings.append(_finding("web_attack", "high", event,
                                     f"{web_attack} observed in request; exploitation outcome is unknown", "medium"))
        action = event["action"].lower()
        if action == "process":
            process_content = content + " " + event.get("command", "")
            powershell = re.search(r"\b(?:powershell|pwsh)(?:\.exe)?\b", process_content, re.IGNORECASE)
            encoded = re.search(r"-(?:enc|encodedcommand)\b|frombase64string", process_content, re.IGNORECASE)
            proxy_execution = re.search(r"(?:certutil(?:\.exe)?\b.*(?:-urlcache|-decode)|mshta(?:\.exe)?\b.*https?://|regsvr32(?:\.exe)?\b.*(?:/i:https?://|scrobj\.dll))", process_content, re.IGNORECASE)
            if powershell and encoded:
                findings.append(_finding("suspicious_powershell", "medium", event,
                                         "Encoded PowerShell observed; review command context before deciding whether it is malicious", "medium"))
            if proxy_execution:
                findings.append(_finding("lolbin_execution", "high", event,
                                         "System binary download, decode, or remote proxy-execution pattern observed", "medium"))
        elif action == "privilege" and event["status"] == "alert":
            privilege_events.append(event)
        elif action == "data_transfer" and event["status"] == "alert":
            if not event.get("command"):
                findings.append(_finding("data_exfiltration", "high", event,
                                         "Potential large outbound transfer or external network connection", "medium"))
        elif action == "c2" and event["status"] == "alert":
            if event.get("event_type") != "beacon":
                findings.append(_finding("c2_beaconing", "medium", event,
                                         "Potential command-and-control beacon or heartbeat", "medium"))
        elif action == "country_change" and event["status"] == "alert":
            findings.append(_finding("country_change", "high", event,
                                     f"GeoIP changed from {event.get('previous_country', 'unknown')} to {event.get('country', 'unknown')} for {event['user']}", "high"))
        # Unclassified security events remain evidence, not assumed C2.

    # A user-specific baseline avoids treating every off-hours event as suspicious.
    for identity in events_by_user:
        profile = historical_baselines.get(identity)
        hours = profile["hours"] if profile else user_hours.get(identity, [])
        user = identity[1]
        if len(hours) < 3:
            continue
        # Unwrap hours around the circular mean before computing a median.
        from math import atan2, sin, cos, pi
        angle = atan2(sum(sin(h * pi / 12) for h in hours), sum(cos(h * pi / 12) for h in hours))
        center = (angle * 12 / pi) % 24
        baseline = median([center + ((h - center + 12) % 24 - 12) for h in hours]) % 24
        absolute_deviations = [circular_hour_diff(hour, baseline) for hour in hours]
        mad = median(absolute_deviations)
        allowed_deviation = max(2.0, mad * 3)
        for event in events_by_user[identity]:
            if event["status"] not in {"success", "failed"}:
                continue
            hour = _timestamp(event).hour + _timestamp(event).minute / 60
            if circular_hour_diff(hour, baseline) > allowed_deviation:
                findings.append(_finding("unusual_time", "medium", event,
                                         f"Login at {hour:04.1f} UTC deviates from {user}'s {baseline:04.1f} UTC reference pattern"))
                findings[-1]["baseline_source"] = "approved_history" if profile else "current_upload"
                findings[-1]["baseline_runs"] = profile["sources"] if profile else []

    for (host, ip), failures in failed_by_ip.items():
        failures.sort(key=_timestamp)
        last_alert_time = None
        for index in range(len(failures) - BRUTE_FORCE_THRESHOLD + 1):
            window = failures[index:index + BRUTE_FORCE_THRESHOLD]
            if _timestamp(window[-1]) - _timestamp(window[0]) <= timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                if last_alert_time is None or _timestamp(window[-1]) - last_alert_time > timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                    findings.append(_finding("brute_force", "critical", window[-1],
                                             f"{len(window)} failed login attempts within {BRUTE_FORCE_WINDOW_MINUTES} minutes", "high"))
                    findings[-1]["evidence_lines"] = [e["line"] for e in window]
                    last_alert_time = _timestamp(window[-1])
        escalation_size = BRUTE_FORCE_THRESHOLD * 2
        last_esc_time = None
        for index in range(len(failures) - escalation_size + 1):
            window = failures[index:index + escalation_size]
            if _timestamp(window[-1]) - _timestamp(window[0]) <= timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                if last_esc_time is None or _timestamp(window[-1]) - last_esc_time > timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES):
                    findings.append(_finding("brute_force_escalated", "critical", window[-1],
                                             f"{len(window)} failed login attempts reached at least 2x the threshold of {BRUTE_FORCE_THRESHOLD}", "high"))
                    findings[-1]["evidence_lines"] = [e["line"] for e in window]
                    last_esc_time = _timestamp(window[-1])

    login_events = [event for event in events if event["action"].lower() == "login" and event["status"].lower() in {"success", "failed"}]
    suspicious_logins = []
    failure_windows = defaultdict(deque)
    for login in sorted(login_events, key=_timestamp):
        if login["ip"] == "UNKNOWN":
            continue
        key = (login.get("host"), login["user"], login["ip"])
        queue = failure_windows[key]
        now = _timestamp(login)
        while queue and now - queue[0][0] > timedelta(minutes=ACCOUNT_TAKEOVER_WINDOW_MINUTES):
            queue.popleft()
        if login["status"] == "failed":
            queue.append((now, login["line"]))
            continue
        if len(queue) >= ACCOUNT_TAKEOVER_THRESHOLD:
            findings.append(_finding("account_takeover", "critical", login,
                                     f"Possible account compromise: successful authentication followed {len(queue)} failed attempts from {login['ip']} for {login['user']}", "high"))
            findings[-1]["evidence_lines"] = [line for _, line in queue] + [login["line"]]
            suspicious_logins.append(login)
        elif login["ip"] in SUSPICIOUS_IPS:
            suspicious_logins.append(login)
        queue.clear()

    download_commands = re.compile(r"\b(?:wget|curl)\b.*?(?:-O|-o)\s+(?P<path>/[^\s;]+)", re.IGNORECASE)
    chmod_commands = re.compile(r"\bchmod\s+\+x\s+(?P<path>/[^\s;]+)", re.IGNORECASE)
    execute_command = re.compile(r"^\s*(?P<path>/[^\s;]+)(?:\s|$)")
    chain_lines = set()

    def session_key(event):
        return (event.get("host"), event.get("session_pid"), event.get("user"), event.get("ip"))

    commands_by_session = defaultdict(list)
    for event in events:
        if event["action"].lower() == "privilege" and event.get("command"):
            commands_by_session[session_key(event)].append(event)
    login_times = defaultdict(list)
    for login in suspicious_logins:
        key = (login.get("host"), login.get("pid"), login.get("user"), login.get("ip"))
        login_times[key].append(_timestamp(login))
    for times in login_times.values():
        times.sort()
    # Scan each command chain once; repeated successful logins must not multiply work or alerts.
    for key, commands in commands_by_session.items():
        commands.sort(key=_timestamp)
        times = login_times.get(key, [])
        if not times:
            continue
        for index, command_event in enumerate(commands):
            download_match = download_commands.search(command_event["command"])
            if not download_match:
                continue
            chain = commands[index + 1:index + 3]
            if len(chain) < 2:
                continue
            chmod_match = chmod_commands.search(chain[0]["command"])
            execute_match = execute_command.match(chain[1]["command"])
            if not chmod_match or not execute_match:
                continue
            if not (download_match.group("path") == chmod_match.group("path") == execute_match.group("path")):
                continue
            login_index = bisect_right(times, _timestamp(command_event)) - 1
            if login_index < 0 or (_timestamp(chain[1]) - times[login_index]).total_seconds() > POST_AUTH_COMMAND_WINDOW_SECONDS:
                continue
            finding = _finding("post_auth_download_execute", "critical", chain[1],
                               "Suspicious post-auth download, chmod, and execution chain", "high")
            finding["mitre_techniques"] = [
                {"technique_id": "T1105", "technique": "Ingress Tool Transfer"},
                {"technique_id": "T1204", "technique": "User Execution"},
            ]
            finding["evidence_lines"] = [command_event["line"], chain[0]["line"], chain[1]["line"]]
            findings.append(finding)
            chain_lines.update(event.get("line") for event in [command_event, *chain])

    beacon_groups = defaultdict(list)
    for event in events:
        if event.get("event_type") == "beacon":
            beacon_groups[(event.get("host"), event["ip"], event.get("destination_port"))].append(event)
    confirmed_endpoints = {}
    for (beacon_host, endpoint, port), beacons in beacon_groups.items():
        beacons.sort(key=_timestamp)
        for index in range(len(beacons) - 2):
            window = beacons[index:index + 3]
            intervals = [(b - a).total_seconds() for a, b in zip(map(_timestamp, window), map(_timestamp, window[1:]))]
            if min(intervals) > 0 and max(intervals) <= 3600 and max(intervals) - min(intervals) <= max(1, min(intervals) * 0.2):
                confirmed_endpoints[(beacon_host, endpoint)] = _timestamp(window[-1])
                findings.append(_finding("c2_beaconing", "medium", window[-1],
                                         f"Periodic outbound check-ins to {endpoint}:{port}; C2 hypothesis requires investigation", "medium"))
                break

    archive_commands = re.compile(r"^\s*(?:/[^\s]*/)?(?:tar|zip|gzip)\b", re.IGNORECASE)
    transfer_commands = re.compile(r"\b(?:curl\b.*\s-T\s|scp\b|ftp\b.*\b(?:put|upload)\b|rsync\b)", re.IGNORECASE)
    external_ip = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    suspicious_endpoints = set(SUSPICIOUS_IPS)

    exfil_lines = set()
    command_sessions = defaultdict(list)
    for event in events:
        if event.get("action") == "privilege" and event.get("command"):
            command_sessions[session_key(event)].append(event)
    for commands in command_sessions.values():
        commands.sort(key=_timestamp)
        latest_archive = None
        archive_path = None
        for command in commands:
            if archive_commands.search(command["command"]):
                latest_archive = command
                archive_path = archive_output(command["command"])
                continue
            if latest_archive is None or (_timestamp(command) - _timestamp(latest_archive)).total_seconds() > CORRELATION_WINDOW_SECONDS:
                continue
            transfer_ips = set(external_ip.findall(command["command"]))
            trusted_match = transfer_ips & suspicious_endpoints or any((command.get("host"), ip) in confirmed_endpoints and confirmed_endpoints[(command.get("host"), ip)] <= _timestamp(command) for ip in transfer_ips)
            if transfer_commands.search(command["command"]) and trusted_match and archive_path and archive_path == upload_input(command["command"]):
                findings.append(_finding("data_exfiltration", "high", command,
                                         "Archive operation followed by outbound transfer to a configured suspicious endpoint", "medium"))
                exfil_lines.update({latest_archive.get("line"), command.get("line")})
                findings[-1]["evidence_lines"] = [latest_archive["line"], command["line"]]
                latest_archive = None

    scan_groups = defaultdict(list)
    for event in events:
        if event.get("event_type") == "firewall_block" and event.get("destination_port") is not None:
            scan_groups[(event.get("host"), event["ip"], event.get("destination_ip"))].append(event)
    for (scan_host, source_ip, destination_ip), blocked in scan_groups.items():
        blocked.sort(key=_timestamp)
        window = deque()
        port_counts = defaultdict(int)
        for probe in blocked:
            while window and (_timestamp(probe) - _timestamp(window[0])).total_seconds() > 10:
                old = window.popleft()
                port_counts[old["destination_port"]] -= 1
                if port_counts[old["destination_port"]] == 0:
                    del port_counts[old["destination_port"]]
            window.append(probe)
            port_counts[probe["destination_port"]] += 1
            if len(port_counts) >= 4:
                findings.append(_finding("network_scan", "medium", probe,
                                         f"{len(port_counts)} destination ports probed on {destination_ip} from {source_ip} within 10 seconds", "medium"))
                findings[-1]["evidence_lines"] = sorted({e["destination_port"]: e["line"] for e in window}.values())
                break

    for event in privilege_events:
        if event.get("line") in chain_lines or event.get("line") in exfil_lines:
            continue
        command = event.get("command") or event.get("raw", "")
        suspicious_elevation = re.search(r"(?:\busermod\b.*(?:sudo|wheel)|\bvisudo\b|(?:tee|echo|sed)\b.*sudoers|\bchmod\b.*(?:u\+s|[2467][0-7]{3}\b))", command, re.IGNORECASE)
        if suspicious_elevation:
            findings.append(_finding("privilege_escalation", "high", event,
                                     "Privilege-policy or setuid change observed; verify administrative authorization", "medium"))

    for identity, countries in user_countries.items():
        user = identity[1]
        if len(countries) > 1:
            user_events = [e for e in events_by_user[identity] if e["status"] == "success" and e["country"].upper() not in {"UNKNOWN", "UN", "N/A", "-"}]
            latest = max(user_events, key=_timestamp)
            findings.append(_finding("country_change", "high", latest,
                                     f"Account accessed from {', '.join(sorted(countries))}", "medium"))
    findings.extend(contextual(events, findings, _finding, archive_output, upload_input))
    _correlate(findings)
    return findings


def calculate_risk(events: list[dict], findings: list[dict]) -> int:
    weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    failed = sum(event["action"].lower() == "login" and event["status"].lower() == "failed" for event in events)
    return min(100, sum(weights.get(item["severity"], 0) for item in findings) + min(10, failed))
