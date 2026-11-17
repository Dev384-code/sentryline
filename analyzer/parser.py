import csv
import base64
from hashlib import sha256
import json
import re
from ipaddress import ip_address
import config
from analyzer.windows import normalize_windows
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

NORMALIZED_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+user=(?P<user>\S+)\s+ip=(?P<ip>\S+)"
    r"\s+country=(?P<country>\S+)\s+action=(?P<action>\S+)\s+status=(?P<status>\S+)$"
)
SSH_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+))\s+"
    r"(?:(?P<host>\S+)\s+)?sshd(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<verb>Failed|Accepted)\s+\S+\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[^\s]+)"
)
SUDO_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+))\s+"
    r"(?:(?P<host>\S+)\s+)?sudo(?:\[(?P<pid>\d+)\])?:\s+(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+)\s*;\s*PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"(?:USER=(?P<target_user>[^;]+)\s*;\s*)?COMMAND=(?P<command>.+)$"
)
SYSLOG_PROCESS_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+))\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
APACHE_PATTERN = re.compile(
    r"^(?P<ip>[^\s]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^]]+)\]\s+"
    r"\"(?P<request>[^\"]+)\"\s+(?P<status>\d{3})"
)
ISO_PREFIX_PATTERN = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<body>.*)$")
IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
WEB_ACTION_PATTERN = re.compile(r"(?:\"(?:GET|POST|PUT|DELETE|PATCH)\s+|/(?:wp-|admin|login|search|product))", re.IGNORECASE)


def _iso_timestamp(value: str, syslog: bool = False) -> str:
    if syslog:
        year = datetime.now(timezone.utc).year
        parsed = datetime.strptime(f"{year} {value}", "%Y %b %d %H:%M:%S")
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _event(timestamp, user, ip, country, action, status, line_number):
    if ip != "UNKNOWN":
        address = ip_address(ip)
        ip = str(getattr(address, "ipv4_mapped", None) or address)
    normalized_status = str(status).lower()
    if normalized_status in {"ok", "allowed", "accepted", "success", "succeeded", "200", "201"}:
        normalized_status = "success"
    elif normalized_status in {"failed", "failure", "denied", "block", "blocked", "error", "401", "403"}:
        normalized_status = "failed"
    event = {"timestamp": _iso_timestamp(timestamp), "user": user or "unknown", "ip": ip,
            "country": country or "UNKNOWN", "action": action or "login",
            "status": normalized_status, "line": line_number}
    if datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is None:
        event["timestamp_assumption"] = "Timestamp lacks a timezone; UTC was assumed"
    return event


def _parse_json(line, line_number):
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    windows = normalize_windows(value)
    if windows is not None:
        event = _event(windows['timestamp'],windows['user'],windows['ip'],windows['country'],windows['action'],windows['status'],line_number)
        event.update({k:v for k,v in windows.items() if k not in {'timestamp','user','ip','country','action','status'}})
        return event
    timestamp = value.get("timestamp") or value.get("time") or value.get("@timestamp")
    ip = value.get("ip") or value.get("source_ip") or value.get("client_ip") or value.get("src_ip")
    user = value.get("user") or value.get("username") or value.get("account")
    status = value.get("status") or value.get("result") or value.get("outcome")
    if isinstance(value.get("success"), bool):
        status = "success" if value["success"] else "failed"
    action = value.get("action") or value.get("event") or "security_event"
    if not isinstance(action,str):
        raise ValueError("JSON action requires an explicit string; vendor objects need an adapter")
    if timestamp and (status or value.get("command") or value.get("host")) and (ip or (action.lower() in {"process", "privilege", "security_event"} and (value.get("command") or value.get("host")))):
        for key,item in (("timestamp",timestamp),("source IP",ip),("user",user),("status",status)):
            if item is not None and not isinstance(item,str):
                raise ValueError(f"JSON {key} must be a string; nested vendor fields need an adapter")
        event = _event(str(timestamp), str(user or "unknown"), str(ip or "UNKNOWN"), str(value.get("country", "UNKNOWN")),
                       action, str(status or "info"), line_number)
        for field in ("host", "pid", "command", "request", "process", "event_type", "destination_ip", "session_pid"):
            if isinstance(value.get(field), str):
                event[field] = value[field]
        code = value.get("http_status")
        if isinstance(code,int) and not isinstance(code,bool) and 100 <= code <= 599:
            event["http_status"] = code
        port = value.get("destination_port")
        if isinstance(port, int) and 0 < port <= 65535:
            event["destination_port"] = port
        return event
    return None


def _parse_csv(line, line_number):
    try:
        fields = next(csv.reader(StringIO(line)))
    except (csv.Error, StopIteration):
        return None
    if len(fields) != 6 or fields[0].lower() in {"timestamp", "time", "date"}:
        return None
    try:
        timestamp, user, ip, country, action, status = [field.strip() for field in fields]
        _iso_timestamp(timestamp)
    except (ValueError, TypeError):
        return None
    return _event(timestamp, user, ip, country, action, status, line_number)


def _parse_generic_security_line(line, line_number):
    match = ISO_PREFIX_PATTERN.match(line)
    if not match:
        return None
    body = match.group("body")
    ip_match = IP_PATTERN.search(body)
    lowered = body.lower()
    supported_without_ip = any(keyword in lowered for keyword in ("sudo", "usermod", "useradd", "powershell", "lolbin"))
    if not ip_match and not supported_without_ip:
        return None
    user_match = re.search(r"(?:for|user|account|host)\s+(?:user\s+)?([A-Za-z0-9_.-]+)", body, re.IGNORECASE)
    if not user_match:
        user_match = re.search(r"\(([A-Za-z0-9_.-]+)\)", body)
    if "failed" in lowered or "block" in lowered or "denied" in lowered:
        status = "failed"
    elif "accepted" in lowered or "success" in lowered:
        status = "success"
    else:
        status = "alert"
    if "sudo" in lowered or "usermod" in lowered or "useradd" in lowered:
        action = "privilege"
    elif "process" in lowered or "powershell" in lowered or "lolbin" in lowered:
        action = "process"
    elif "transfer" in lowered or "outbound" in lowered or "bytes_out" in lowered:
        action = "data_transfer"
    elif "beacon" in lowered or "heartbeat" in lowered or "c2" in lowered:
        action = "c2"
    elif "ufw" in lowered or "firewall" in lowered:
        action = "firewall"
    else:
        action = "security_event"
    return _event(match.group("timestamp"), user_match.group(1) if user_match else "unknown",
                  ip_match.group(0) if ip_match else "UNKNOWN", "UNKNOWN", action, status, line_number)


def _parse_sudo_line(line, line_number):
    match = SUDO_PATTERN.match(line)
    if not match:
        return None
    values = match.groupdict()
    timestamp = values["timestamp"]
    if not timestamp[0].isdigit():
        timestamp = _iso_timestamp(timestamp, syslog=True)
    event = _event(timestamp, values["user"], "UNKNOWN", "UNKNOWN", "privilege", "alert", line_number)
    event.update({
        "host": values.get("host"),
        "pid": values.get("pid"),
        "tty": values["tty"].strip(),
        "pwd": values["pwd"].strip(),
        "command": values["command"].strip(),
        "target_user": (values.get("target_user") or "").strip(),
    })
    return event


def _parse_syslog_process_line(line, line_number):
    match = SYSLOG_PROCESS_PATTERN.match(line)
    if not match:
        return None
    values = match.groupdict()
    timestamp = values["timestamp"]
    if not timestamp[0].isdigit():
        timestamp = _iso_timestamp(timestamp, syslog=True)
    event = _event(timestamp, "unknown", "UNKNOWN", "UNKNOWN", "unclassified", "info", line_number)
    event.update({
        "host": values["host"],
        "process": values["process"],
        "pid": values.get("pid"),
        "message": values["message"],
        "event_type": "unclassified",
    })
    message = values["message"]
    if values["process"].lower() in {"nginx", "apache", "httpd"}:
        access_match = APACHE_PATTERN.match(message)
        if access_match:
            access = access_match.groupdict()
            status_code = int(access["status"])
            event.update({
                "ip": access["ip"],
                "action": access["request"].split()[0],
                "status": "failed" if status_code >= 400 else "success",
                "request": access["request"],
                "http_status": status_code,
                "event_type": "web_access",
            })
    elif values["process"].lower() == "kernel" and "ufw block" in message.lower():
        source_ip = re.search(r"\bSRC=(?P<ip>[^\s]+)", message)
        destination_ip = re.search(r"\bDST=(?P<ip>[^\s]+)", message)
        destination_port = re.search(r"\bDPT=(?P<port>\d+)", message)
        if source_ip and destination_ip and destination_port:
            event.update({
                "ip": source_ip.group("ip"),
                "action": "firewall",
                "status": "failed",
                "destination_ip": destination_ip.group("ip"),
                "destination_port": int(destination_port.group("port")),
                "event_type": "firewall_block",
            })
    elif values["process"].lower() in {"geoip", "geolocation"}:
        geo_match = re.search(
            r"login for user (?P<user>\S+) previously seen from (?P<previous>[A-Za-z]{2,})[, ]+now seen from (?P<current>[A-Za-z]{2,})",
            message,
            re.IGNORECASE,
        )
        if geo_match:
            event.update({
                "user": geo_match.group("user"),
                "action": "country_change",
                "status": "alert",
                "previous_country": geo_match.group("previous").upper(),
                "country": geo_match.group("current").upper(),
                "event_type": "geoip_change",
            })
    elif "beacon" in message.lower() or "check-in" in message.lower():
        endpoint = re.search(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d+)\b", message)
        if endpoint:
            event.update({
                "ip": endpoint.group("ip"),
                "action": "c2",
                "status": "alert",
                "destination_port": int(endpoint.group("port")),
                "event_type": "beacon",
            })
    return event


def _parse_session_line(line, line_number):
    event = _parse_syslog_process_line(line, line_number)
    if not event or event["process"] != "sshd":
        return None
    match = re.search(r"pam_unix\(sshd:session\): session (opened|closed) for user ([^\s(]+)", event["message"])
    if not match:
        return None
    state, user = match.groups()
    event.update({
        "user": user,
        "action": "session",
        "status": "success" if state == "opened" else "info",
        "session_state": state,
        "event_type": "ssh_session",
    })
    return event


def parse_line(line: str, line_number: int) -> dict | None:
    stripped = line.strip()
    match = NORMALIZED_PATTERN.match(stripped)
    if match:
        values = match.groupdict()
        event = _event(values["timestamp"], values["user"], values["ip"], values["country"],
                   values["action"], values["status"], line_number)
        event["raw"] = stripped
        return event

    json_event = _parse_json(stripped, line_number)
    if json_event:
        json_event["raw"] = stripped
        return json_event

    csv_event = _parse_csv(stripped, line_number)
    if csv_event:
        csv_event["raw"] = stripped
        return csv_event

    match = SSH_PATTERN.match(stripped)
    if match:
        values = match.groupdict()
        syslog_timestamp = not values["timestamp"][0].isdigit()
        event = _event(_iso_timestamp(values["timestamp"], syslog=syslog_timestamp), values["user"], values["ip"], "UNKNOWN", "login",
                      "success" if values["verb"].lower() == "accepted" else "failed", line_number)
        event["host"] = values.get("host")
        event["pid"] = values.get("pid")
        event["raw"] = stripped
        return event

    sudo_event = _parse_sudo_line(stripped, line_number)
    if sudo_event:
        sudo_event["raw"] = stripped
        return sudo_event

    session_event = _parse_session_line(stripped, line_number)
    if session_event:
        session_event["raw"] = stripped
        return session_event

    process_event = _parse_syslog_process_line(stripped, line_number)
    if process_event:
        process_event["raw"] = stripped
        return process_event

    match = APACHE_PATTERN.match(stripped)
    if match:
        values = match.groupdict()
        status_code = int(values["status"])
        event = _event(datetime.strptime(values["timestamp"], "%d/%b/%Y:%H:%M:%S %z").isoformat(),
                       "unknown", values["ip"], "UNKNOWN", values["request"].split()[0],
                       "failed" if status_code >= 400 else "success", line_number)
        event["request"] = values["request"]
        event["http_status"] = status_code
        event["raw"] = stripped
        return event

    generic_event = _parse_generic_security_line(stripped, line_number)
    if generic_event:
        generic_event["raw"] = stripped
    return generic_event


class ParseWarnings(list):
    """Backward-compatible warning list carrying an exact input audit."""
    input_audit = None


def parse_log_file(path: Path) -> tuple[list[dict], list[str]]:
    events = []
    errors = ParseWarnings()
    skipped = 0
    if path.stat().st_size > config.MAX_UPLOAD_BYTES:
        raise ValueError("Input exceeds the 5 MiB limit")
    source_bytes = path.read_bytes()
    if len(source_bytes) > config.MAX_UPLOAD_BYTES:
        raise ValueError("Input exceeds the 5 MiB limit")
    source_text = source_bytes.decode("utf-8-sig")
    ledger = []
    blank = 0
    unclassified = 0
    with StringIO(source_text, newline=None) as stream:
        for line_number, line in enumerate(stream, 1):
            if line_number > config.MAX_SOURCE_LINES:
                raise ValueError("Input exceeds the 100,000 physical-line limit; entire upload rejected")
            if not line.strip():
                blank += 1
                ledger.append(dict(line=line_number,state="blank"))
                continue
            try:
                if len(line) > config.MAX_LINE_LENGTH:
                    raise ValueError("line exceeds 64 KiB")
                event = parse_line(line, line_number)
            except (ValueError, TypeError, OverflowError, IndexError, RecursionError) as exc:
                event = None
                reason = str(exc)
            else:
                reason = "unsupported log format; no recognized timestamp or structured fields"
            if event and event["ip"] != "UNKNOWN":
                try:
                    ip_address(event["ip"])
                except ValueError:
                    event = None
                    reason = "invalid source IP address"
            if event:
                is_unclassified = event.get("action", "").lower() not in {"login", "process", "privilege", "data_transfer", "c2", "country_change", "firewall", "get", "post", "put", "delete", "patch", "web", "web_access", "session", "service_logon"}
                unclassified += int(is_unclassified)
                ledger.append(dict(line=line_number,state="parsed_unclassified" if is_unclassified else "parsed"))
                if re.match(r"^[A-Z][a-z]{2}\s+\d+\s+", line):
                    event["timestamp_assumption"] = "Syslog prefix assumes current UTC year/timezone; check original source clock"
                events.append(event)
                if len(events) > config.MAX_EVENTS:
                    raise ValueError("Log exceeds the 50,000 event limit")
            else:
                ledger.append(dict(line=line_number,state="unparsed",reason=reason))
                skipped += 1
                if len(errors) < config.MAX_PARSE_WARNINGS:
                    errors.append(f"Line {line_number}: {reason}")
    if skipped > len(errors):
        errors.append(f"{skipped - len(errors)} additional invalid lines omitted")
    events.sort(key=lambda item: (item["timestamp"], item["line"]))
    auth_contexts = {}
    active_sessions = {}
    sessions_by_identity = {}
    latest_auth = {}
    for event in events:
        host = event.get("host")
        pid = event.get("pid")
        if event.get("action") == "login":
            if event["status"] == "success":
                auth_contexts[(host, pid)] = {
                    "user": event["user"],
                    "ip": event["ip"],
                    "host": host,
                    "pid": pid,
                    "timestamp": event["timestamp"],
                }
                latest_auth[(host, event["user"])] = auth_contexts[(host, pid)]
            continue
        if event.get("event_type") == "ssh_session":
            context = auth_contexts.get((host, pid))
            if context is None:
                context = latest_auth.get((host, event["user"]))
            if context:
                event["ip"] = context["ip"]
                event["session_source_ip"] = context["ip"]
                event["session_pid"] = context["pid"]
            key = (host, pid, event["user"])
            if event["session_state"] == "opened":
                active_sessions[key] = event
                sessions_by_identity.setdefault((host, event["user"]), {})[key] = event
            elif key in active_sessions:
                opened = active_sessions.pop(key)
                sessions_by_identity.get((host, event["user"]), {}).pop(key, None)
                event["session_duration_seconds"] = int(
                    (datetime.fromisoformat(event["timestamp"]) - datetime.fromisoformat(opened["timestamp"])).total_seconds()
                )
                event["session_source_ip"] = opened.get("session_source_ip", event["ip"])
                event["ip"] = event["session_source_ip"]
            continue
        if event.get("user") != "unknown" and host:
            candidates = sessions_by_identity.get((host, event["user"]), {})
            if len(candidates) == 1:
                session = next(iter(candidates.values()))
                event["ip"] = session.get("session_source_ip", session["ip"])
                event["session_source_ip"] = event["ip"]
                event["session_pid"] = session.get("session_pid", session.get("pid"))
    errors.input_audit = dict(total_lines=len(ledger),blank_lines=blank,parsed_lines=len(events),
        unparsed_lines=skipped,parsed_unclassified_lines=unclassified,
        accounting_balanced=len(ledger)==blank+len(events)+skipped,
        input_state="no_events" if not events else ("partial" if skipped or unclassified else "supported_input"),
        bytes=len(source_bytes),sha256=sha256(source_bytes).hexdigest(),source_base64=base64.b64encode(source_bytes).decode("ascii"),
        ledger=ledger,coverage_note="Every physical line is accounted for. Parsing is not proof that all attacks are detectable.")
    return events, errors
