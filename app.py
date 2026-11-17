
import csv
import base64
import json
import os
import secrets
from datetime import datetime, timezone 
from io import StringIO
from time import perf_counter
from uuid import uuid4
from hashlib import sha256
from functools import lru_cache
from pathlib import Path

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for, session, abort
from werkzeug.utils import secure_filename

import config
from analyzer import storage
from analyzer.alerts import build_alerts
from analyzer.detector import ATTACK_MAP, calculate_risk, detect
from analyzer.metrics import evaluate_findings
from analyzer.explanations import explain
from analyzer.coverage import describe
from analyzer.parser import parse_log_file

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("SENTRYLINE_HTTPS") == "1",
                  MAX_FORM_PARTS=10, MAX_FORM_MEMORY_SIZE=65536)
if bool(os.environ.get("SENTRYLINE_AUTH_USER")) != bool(os.environ.get("SENTRYLINE_AUTH_PASSWORD")):
    raise RuntimeError("Configure both authentication variables or neither")
if os.environ.get("SENTRYLINE_PRODUCTION") == "1" and not all(os.environ.get(k) for k in ("SECRET_KEY", "SENTRYLINE_AUTH_USER", "SENTRYLINE_AUTH_PASSWORD")):
    raise RuntimeError("Production requires SECRET_KEY and both authentication variables")

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def require_basic_auth():
    username = os.environ.get("SENTRYLINE_AUTH_USER")
    password = os.environ.get("SENTRYLINE_AUTH_PASSWORD")
    if not username or not password or request.path.startswith("/static/"):
        return None
    auth = request.authorization
    if not auth or not secrets.compare_digest(auth.username or "", username) or not secrets.compare_digest(auth.password or "", password):
        return ("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Sentryline"'})
    return None


@app.before_request
def protect_mutations():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not app.config.get("TESTING"):
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        expected = session.get("csrf_token")
        if not token or not expected or not isinstance(token, str) or not secrets.compare_digest(token, expected):
            abort(400, description="Invalid CSRF token. Reload the page and try again.")

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.errorhandler(413)
def too_large(error):
    return render_template("error.html", message="File too large. The upload limit is 5 MiB."), 413

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify(error=error.description), 404
    return render_template("error.html", message=error.description), 404

@app.errorhandler(400)
def bad_request(error):
    if request.path.startswith("/api/"):
        return jsonify(error=error.description), 400
    return render_template("error.html", message=error.description), 400

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}




def empty_result():
    return {
        "generated_at": None,
        "source": "No file uploaded",
        "events": [],
        "alerts": [],
        "parse_errors": [],
        "risk_score": 0,
        "summary": {
            "total_events": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "open_alerts": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "unique_users": 0,
            "unique_ips": 0,
        },
    }


def analyze_log(path, parsed=None, source=None):
    started = perf_counter()
    events, parse_errors = parsed if parsed is not None else parse_log_file(path)
    cutoff = min((event["timestamp"] for event in events), default=None)
    identities = {(event.get("host", "unknown"), event["user"]) for event in events if event["action"].lower() == "login"}
    historical = {identity: profile for identity, profile in storage.baselines_before(cutoff).items() if identity in identities}
    findings = detect(events, historical_baselines=historical)
    alerts = sorted(
        build_alerts(findings),
        key=lambda alert: SEVERITY_ORDER.get(alert["severity"].lower(), 99),
    )
    counts = {severity: sum(item["severity"] == severity for item in alerts)
              for severity in ("critical", "high", "medium", "low")}
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source or str(path.name),
        "analysis_id": uuid4().hex,
        "ruleset_version": config.RULESET_VERSION,
        "baseline_context": {"historical_profiles": len(historical), "training_runs": sorted({run for p in historical.values() for run in p["sources"]}), "cutoff": cutoff},
        "events": events,
        "alerts": alerts,
        "parse_errors": parse_errors,
        "risk_score": calculate_risk(events, findings) if events else None,
        "analysis_status": "limited_rule_analysis" if events else "not_assessed",
        "summary": {
            "total_events": len(events),
            "failed_logins": sum(event["action"].lower() == "login" and event["status"].lower() == "failed" for event in events),
            "successful_logins": sum(event["action"].lower() == "login" and event["status"].lower() == "success" for event in events),
            "open_alerts": len(alerts),
            "severity_counts": counts,
            "unique_users": len({event["user"] for event in events if event["user"] != "unknown"}),
            "unique_ips": len({event["ip"] for event in events if event["ip"] != "UNKNOWN"}),
        },
    }
    result["input_audit"] = getattr(parse_errors, "input_audit", None)
    result["coverage_assessment"] = describe(events, result["input_audit"])
    result["processing_ms"] = round((perf_counter() - started) * 1000, 1)
    storage.save(result)
    return result


def get_results(analysis_id=None):
    if analysis_id:
        result = storage.get_run(analysis_id)
        if result is None:
            abort(404, description="This analysis was not found or has expired from retention. Open the latest scan.")
        return result
    return storage.latest() or empty_result()


def build_coverage(alerts):
    stages = [
        ("Discovery", "Network scanning", "T1046", {"network_scan"}),
        ("Initial Access", "Web and account signals", "T1190 / T1078", {"web_attack", "unusual_time", "country_change", "success_after_source_failures"}),
        ("Credential Access", "Authentication and credential-file signals", "T1110 / T1003.008", {"brute_force", "brute_force_escalated", "account_takeover", "distributed_authentication", "slow_authentication", "sensitive_file_read"}),
        ("Execution / Privilege", "Command and elevation signals", "T1548 / T1218 / T1059.001 / T1105", {"privilege_escalation", "lolbin_execution", "suspicious_powershell", "post_auth_download_execute"}),
        ("Persistence", "Account, cron and upload context", "T1136.001 / T1053.003 / T1505.003", {"account_creation_context", "cron_change_context", "upload_command_request"}),
        ("Defense Evasion", "Evidence clearing commands", "T1070.002 / T1070.003", {"log_clearing", "history_clearing"}),
        ("Command and Control", "Periodic beaconing", "T1071", {"c2_beaconing"}),
        ("Exfiltration", "Outbound transfer signals", "T1041 / T1048", {"data_exfiltration", "archive_transfer_review"}),
    ]
    tiles = []
    for tactic, title, techniques, types in stages:
        hits = [alert for alert in alerts if alert["type"] in types]
        severity = min((a["severity"] for a in hits), key=lambda s: SEVERITY_ORDER[s], default="low")
        tiles.append(dict(tactic=tactic, title=title, techniques=techniques, count=len(hits), severity=severity))
    return tiles


def template_context():
    result = get_results(request.args.get("run"))
    priority_alerts = sorted(
        [alert for alert in result["alerts"] if alert.get("status", "open") in {"open", "in_progress"}],
        key=lambda alert: SEVERITY_ORDER.get(alert["severity"].lower(), 99),
    )
    alert_counts = {
        alert_type: sum(alert["type"] == alert_type for alert in result["alerts"])
        for alert_type in ATTACK_MAP
    }
    notes_by_alert = {}
    notes = storage.notes(result.get("analysis_id"))
    for note in notes:
        notes_by_alert.setdefault(note["alert_id"], []).append(note)
    return {
        "notes_by_alert": notes_by_alert,
        "result": result,
        "run_id": result.get("analysis_id"),
        "history": storage.history(),
        "audit": storage.audit_trail(result.get("analysis_id")),
        "notes": notes,
        "baseline_status": storage.baseline_status(result.get("analysis_id")),
        "coverage": build_coverage(result["alerts"]),
        "priority_alerts": priority_alerts,
        "detection_types": ATTACK_MAP,
        "alert_counts": alert_counts,
        "evidence_by_line": {event["line"]: event for event in result["events"]},
    }


@app.get("/")
def index():
    return render_template("index.html", **template_context())


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html", **template_context())


@lru_cache(maxsize=1)
def benchmark_metrics():
    eval_log = config.BASE_DIR / "tests" / "fixtures" / "evaluation_logs.txt"
    ground_truth = config.BASE_DIR / "tests" / "fixtures" / "ground_truth.csv"
    if not eval_log.exists() or not ground_truth.exists():
        return None
    events, _ = parse_log_file(eval_log)
    findings = detect(events)
    with ground_truth.open(encoding="utf-8") as f:
        labels = list(csv.DictReader(f))
    return evaluate_findings(findings, labels, total_cases=len(events))


@app.get("/report")
def report():
    context = template_context()
    context["benchmark"] = benchmark_metrics()
    context["explanations"] = {alert["id"]: explain(alert) for alert in context["result"]["alerts"]}
    context["review_open_count"] = sum(a.get("status", "open") in {"open", "in_progress"} for a in context["result"]["alerts"])
    query = request.args.get("q", "").strip().lower()[:200]
    severity = request.args.get("severity", "all")
    status = request.args.get("status", "all")
    matches = [alert for alert in context["result"]["alerts"]
               if (severity == "all" or alert["severity"] == severity)
               and (status == "all" or alert["status"] == status)
               and (not query or query in (" ".join(str(alert.get(k, "")) for k in ("id", "message", "user", "host", "ip", "type", "mitre")) + " " + " ".join(explain(alert).values())).lower())]
    pages = max(1, (len(matches) + 99) // 100)
    page = min(pages, max(1, request.args.get("page", 1, type=int)))
    context.update(report_alerts=matches[(page-1)*100:page*100], page=page, pages=pages,
                   matched_count=len(matches), filters={"q": query, "severity": severity, "status": status, "run": context["run_id"]})
    return render_template("report.html", **context)


@app.post("/upload")
def upload():
    uploaded_file = request.files.get("log_file")
    if not uploaded_file or not uploaded_file.filename:
        flash("Choose a .txt, .log, or .jsonl file before uploading.", "error")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded_file.filename)
    extension = Path(original_name).suffix.lower()
    if extension not in config.ALLOWED_LOG_EXTENSIONS:
        flash("Unsupported file type. Upload a .txt, .log, or .jsonl file.", "error")
        return redirect(url_for("dashboard"))

    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    stored_name = f"uploaded_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}{extension}"
    upload_path = config.UPLOAD_DIR / stored_name
    uploaded_file.save(upload_path)
    try:
        events, parse_errors = parse_log_file(upload_path)
    except (UnicodeDecodeError, ValueError):
        upload_path.unlink(missing_ok=True)
        flash("Upload rejected: use UTF-8 text within 5 MiB, 50,000 events and 100,000 physical lines. The whole upload was rejected.", "error")
        return redirect(url_for("dashboard"))

    try:
        result = analyze_log(upload_path, parsed=(events, parse_errors), source=original_name)
    finally:
        # Delete the temporary upload; exact source bytes and input audit persist with the scan.
        upload_path.unlink(missing_ok=True)
    message = f"Uploaded {original_name} and analyzed {len(events)} events."
    if parse_errors:
        message += " Analysis is incomplete; inspect the input audit and preserved source lines."
    if not events:
        message = "No supported events were detected. Input is preserved for review; this is not a clean security result."
    flash(message, "success" if events and not parse_errors else "error")
    return redirect(url_for("dashboard", run=result["analysis_id"]))


@app.get("/api/results")
def api_results():
    result = get_results(request.args.get("run"))
    if request.args.get("summary") == "1":
        result = {**result, "events": []}
        if result.get("input_audit"):
            result["input_audit"] = {k:v for k,v in result["input_audit"].items() if k not in {"source_base64", "ledger"}}
            result["input_audit"]["source_available"] = True
    return jsonify(result)


@app.post("/api/alert/<alert_id>/status")
def update_alert_status(alert_id):
    data = request.get_json(silent=True) if request.is_json else request.form
    if not hasattr(data, "get") or not isinstance(data.get("status"), str):
        return jsonify(error="Status must be a string"), 400
    new_status = data["status"].strip().lower()
    allowed_statuses = {"open", "in_progress", "resolved", "false_positive"}
    if new_status not in allowed_statuses:
        return jsonify({"error": f"Invalid status. Choose from: {', '.join(sorted(allowed_statuses))}"}), 400

    actor = request.authorization.username if request.authorization else "local-analyst"
    analysis_id = data.get("analysis_id")
    if analysis_id is not None and (not isinstance(analysis_id, str) or not analysis_id):
        return jsonify(error="analysis_id must be a nonempty string"), 400
    if not storage.update_status(alert_id, new_status, actor, analysis_id):
        return jsonify(error="Alert not found in this analysis. Reload the report or choose a retained scan."), 404
    return jsonify({"success": True, "alert_id": alert_id, "status": new_status})


@app.post("/load-sample")
def load_sample():
    sample_path = config.BASE_DIR / "tests" / "fixtures" / "sample_incident.log"
    if not sample_path.exists():
        flash("Sample incident log not found in tests/fixtures/.", "error")
        return redirect(url_for("dashboard"))
    result = analyze_log(sample_path)
    flash(f"Loaded and analyzed sample: {len(result['events'])} events, {len(result['alerts'])} alerts.", "success")
    return redirect(url_for("dashboard", run=result["analysis_id"]))


def csv_cell(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text

def analyst_name():
    return request.authorization.username if request.authorization else "local-analyst"

@app.post("/api/analysis/<run_id>/notes")
def add_investigation_note(run_id):
    data = request.get_json(silent=True) if request.is_json else request.form
    if not hasattr(data, "get") or not isinstance(data.get("alert_id"), str) or not isinstance(data.get("disposition", "investigating"), str):
        return jsonify(error="Provide an alert ID, note, and disposition"), 400
    try:
        note_id = storage.add_note(run_id,data["alert_id"],data.get("body"),data.get("disposition","investigating"),analyst_name())
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if note_id is None:
        abort(404, description="Alert not found in this retained scan")
    if request.is_json:
        return jsonify(success=True,note_id=note_id), 201
    flash("Investigation note saved.", "success")
    return redirect(url_for('report',run=run_id,q=data['alert_id'])+'#'+data['alert_id'])

@app.post("/baseline/<run_id>/approve")
def approve_training(run_id):
    if request.form.get("trusted") != "yes":
        abort(400, description="Review the scan and acknowledge that its successful logins are trusted before training")
    try:
        count = storage.approve_baseline(run_id,analyst_name())
    except ValueError as exc:
        abort(400, description=str(exc))
    if count is None:
        abort(404, description="Training scan was not found")
    flash(f"Approved {count} successful logins for future historical baselines. Profiles need 10 distinct timestamps across 3 days.", "success")
    return redirect(url_for('dashboard',run=run_id))

@app.post("/baseline/<run_id>/revoke")
def revoke_training(run_id):
    get_results(run_id)
    storage.revoke_baseline(run_id)
    flash("Training approval revoked for future scans. Existing analysis results remain unchanged.", "success")
    return redirect(url_for('dashboard',run=run_id))

@app.get("/timeline")
def timeline():
    context = template_context()
    query = request.args.get('q','').strip().lower()[:200]
    action = request.args.get('action','all')
    alert_only = request.args.get('alerts') == '1'
    alerts_by_line = {}
    for alert in context['result']['alerts']:
        for line in alert.get('evidence_lines',[alert['line']]):
            alerts_by_line.setdefault(line,[]).append(alert)
    matches = [event for event in context['result']['events']
               if (action == 'all' or event['action'].lower() == action.lower())
               and (not alert_only or event['line'] in alerts_by_line)
               and (not query or query in ' '.join(str(event.get(k,'')) for k in ('raw','user','host','ip','action')).lower())]
    matches.sort(key=lambda e:(e['timestamp'],e['line']))
    pages = max(1,(len(matches)+99)//100)
    page = min(pages,max(1,request.args.get('page',1,type=int)))
    context.update(timeline_events=matches[(page-1)*100:page*100],alerts_by_line=alerts_by_line,
                   page=page,pages=pages,matched_count=len(matches),
                   filters=dict(run=context['run_id'],q=query,action=action,alerts='1' if alert_only else ''),
                   actions=sorted({e['action'] for e in context['result']['events']}))
    return render_template('timeline.html',**context)

@app.get("/export/json")
def export_json():
    result = get_results(request.args.get('run'))
    payload = dict(result,investigation_notes=storage.notes(result.get('analysis_id')),triage_activity_recent_50=storage.audit_trail(result.get('analysis_id')))
    return Response(json.dumps(payload,indent=2),mimetype='application/json',headers={'Content-Disposition':'attachment; filename=sentryline-investigation.json'})

@app.get("/health")
def health():
    with storage.connection() as db:
        db.execute("SELECT 1")
    return jsonify(status="ok")

@app.get("/export/csv")
def export_csv():
    result = get_results(request.args.get("run"))
    alerts = result.get("alerts", [])
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Alert ID", "Severity", "Triage Status", "ATT&CK ID", "ATT&CK Technique", "Tactic", "User", "Source IP", "Timestamp", "Message", "Source Line"])
    for alert in alerts:
        mitre = alert.get("mitre", {})
        writer.writerow([csv_cell(value) for value in [
            alert.get("id", ""),
            alert.get("severity", ""),
            alert.get("status", "open"),
            mitre.get("technique_id", ""),
            mitre.get("technique", ""),
            mitre.get("tactic", ""),
            alert.get("user", ""),
            alert.get("ip", ""),
            alert.get("timestamp", ""),
            alert.get("message", ""),
            alert.get("line", ""),
        ]])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=sentryline_alerts_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.csv"}
    )



@app.get("/input-audit")
def input_audit():
    result=get_results(request.args.get("run"))
    audit=result.get("input_audit")
    if not audit:
        abort(404, description="This scan has no preserved input audit. Re-upload the original file.")
    state=request.args.get("state","all")
    matches=[row for row in audit["ledger"] if state=="all" or row["state"]==state]
    pages=max(1,(len(matches)+99)//100)
    page=min(pages,max(1,request.args.get("page",1,type=int)))
    text=verified_source(audit).decode("utf-8-sig")
    # StringIO matches parser physical-line handling (universal CR/LF, no extra Unicode splits).
    from io import StringIO as SourceStream
    lines=list(SourceStream(text,newline=None))
    rows=[dict(row,raw=lines[row["line"]-1].rstrip("\r\n")) for row in matches[(page-1)*100:page*100]]
    return render_template("input_audit.html",result=result,run_id=result["analysis_id"],audit=audit,
                           rows=rows,page=page,pages=pages,state=state,matched=len(matches))

@app.get("/export/source")
def export_source():
    result=get_results(request.args.get("run"))
    audit=result.get("input_audit")
    if not audit:
        abort(404,description="Original input is unavailable for this older scan. Re-upload the file.")
    return Response(verified_source(audit),mimetype="application/octet-stream",
                    headers={"Content-Disposition":"attachment; filename=sentryline-original.log"})


def verified_source(audit):
    try:
        raw=base64.b64decode(audit["source_base64"],validate=True)
        if len(raw)!=audit["bytes"] or sha256(raw).hexdigest()!=audit["sha256"]:
            raise ValueError("Source checksum mismatch")
    except (ValueError,KeyError,TypeError):
        abort(409,description="Stored source integrity check failed. Use the original file and re-upload; this copy cannot be trusted.")
    return raw


from analyzer.monitor import Monitor
monitor = Monitor(analyze_log)

@app.get('/monitor')
def monitoring():
    return render_template('monitor.html', **template_context(), monitor=monitor.status())

@app.get('/api/monitor')
def monitor_status():
    return jsonify(monitor.status())

@app.post('/monitor/start')
def monitor_start():
    # Local server control only. Consent must be submitted explicitly each start.
    if request.remote_addr not in {'127.0.0.1', '::1'}:
        abort(403)
    try:
        monitor.start(request.form.get('consent') == 'yes', int(request.form.get('window_hours','24')), int(request.form.get('interval_seconds','30')), int(request.form.get('lookback_minutes','0')))
    except ValueError as exc:
        abort(400,description=str(exc))
    return redirect(url_for('monitoring'))

@app.post('/monitor/check')
def monitor_check():
    if request.remote_addr not in {'127.0.0.1','::1'}:
        abort(403)
    try:
        monitor.diagnose(request.form.get('consent') == 'yes')
    except ValueError as exc:
        abort(400,description=str(exc))
    return redirect(url_for('monitoring'))

@app.post('/monitor/stop')
def monitor_stop():
    if request.remote_addr not in {'127.0.0.1', '::1'}:
        abort(403)
    monitor.stop()
    return redirect(url_for('monitoring'))

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
