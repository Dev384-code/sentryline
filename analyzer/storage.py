"""Transactional local persistence. Keep bounded history and analyst audit events."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
import config

@contextmanager
def connection():
    config.DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(config.DATABASE_FILE, timeout=15)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, created TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS runs_created ON runs(created DESC);
            CREATE TABLE IF NOT EXISTS run_summary (
                id TEXT PRIMARY KEY, source TEXT, events INTEGER, alerts INTEGER, risk INTEGER);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, run_id TEXT, alert_id TEXT,
                old_status TEXT, new_status TEXT, actor TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, alert_id TEXT NOT NULL,
                body TEXT NOT NULL, disposition TEXT NOT NULL, actor TEXT NOT NULL, created TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS notes_run ON notes(run_id, id DESC);
            CREATE TABLE IF NOT EXISTS baseline_sources (
                run_id TEXT PRIMARY KEY, actor TEXT NOT NULL, approved TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS baseline_observations (
                run_id TEXT NOT NULL, line INTEGER NOT NULL, host TEXT NOT NULL, user TEXT NOT NULL,
                event_time TEXT NOT NULL, hour REAL NOT NULL, PRIMARY KEY(run_id, line));
            CREATE INDEX IF NOT EXISTS baseline_identity ON baseline_observations(host, user, event_time);
            CREATE INDEX IF NOT EXISTS audit_run ON audit(run_id, id DESC);
        """)
        with db:
            yield db
    finally:
        db.close()

def save(result):
    with connection() as db:
        db.execute("INSERT INTO runs VALUES (?, ?, ?)",
                   (result['analysis_id'], result['generated_at'], json.dumps(result)))
        db.execute("INSERT INTO run_summary VALUES (?, ?, ?, ?, ?)",
                   (result['analysis_id'], result['source'], len(result['events']), len(result['alerts']), result['risk_score']))
        db.execute("DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY created DESC LIMIT ?)",
                   (config.HISTORY_LIMIT,))
        db.execute("DELETE FROM run_summary WHERE id NOT IN (SELECT id FROM runs)")
        db.execute("DELETE FROM audit WHERE run_id NOT IN (SELECT id FROM runs)")
        for table in ("notes", "baseline_sources", "baseline_observations"):
            db.execute(f"DELETE FROM {table} WHERE run_id NOT IN (SELECT id FROM runs)")

def latest():
    with connection() as db:
        row = db.execute("SELECT payload FROM runs ORDER BY created DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None

def update_status(alert_id, status, actor, analysis_id=None):
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        if analysis_id is not None:
            row = db.execute("SELECT id, payload FROM runs WHERE id=?", (analysis_id,)).fetchone()
        else:
            row = db.execute("SELECT id, payload FROM runs ORDER BY created DESC LIMIT 1").fetchone()
        if not row:
            return False
        result = json.loads(row[1])
        alert = next((a for a in result['alerts'] if a['id'] == alert_id), None)
        if alert is None:
            return False
        if alert["status"] == status:
            return True
        now = datetime.now(timezone.utc).isoformat()
        db.execute("INSERT INTO audit (run_id, alert_id, old_status, new_status, actor, created) VALUES (?, ?, ?, ?, ?, ?)",
                   (row[0], alert_id, alert['status'], status, actor, now))
        alert.update(status=status, triage_updated_at=now)
        result['summary']['open_alerts'] = sum(a['status'] in {'open', 'in_progress'} for a in result['alerts'])
        db.execute("UPDATE runs SET payload=? WHERE id=?", (json.dumps(result), row[0]))
        return True

def get_run(analysis_id):
    with connection() as db:
        row = db.execute("SELECT payload FROM runs WHERE id=?", (analysis_id,)).fetchone()
    return json.loads(row[0]) if row else None

def history():
    with connection() as db:
        # Backfill metadata for analyses created before history browsing was introduced.
        missing = db.execute("SELECT id, payload FROM runs WHERE id NOT IN (SELECT id FROM run_summary)").fetchall()
        for run_id, payload in missing:
            result = json.loads(payload)
            db.execute("INSERT OR IGNORE INTO run_summary VALUES (?, ?, ?, ?, ?)",
                       (run_id, result['source'], len(result['events']), len(result['alerts']), result['risk_score']))
        rows = db.execute("SELECT r.id, r.created, s.source, s.events, s.alerts, s.risk FROM runs r JOIN run_summary s ON r.id=s.id ORDER BY r.created DESC LIMIT ?", (config.HISTORY_LIMIT,)).fetchall()
    return [dict(zip(('analysis_id','generated_at','source','events','alerts','risk_score'), row)) for row in rows]

def audit_trail(analysis_id):
    with connection() as db:
        rows = db.execute("SELECT alert_id, old_status, new_status, actor, created FROM audit WHERE run_id=? ORDER BY id DESC LIMIT 50", (analysis_id,)).fetchall()
    return [dict(zip(('alert_id','old_status','new_status','actor','created'), row)) for row in rows]

DISPOSITIONS = {"investigating", "benign", "suspicious", "needs_context"}

def add_note(run_id, alert_id, body, disposition, actor):
    if not isinstance(body, str) or not body.strip() or len(body) > 5000 or disposition not in DISPOSITIONS:
        raise ValueError("Use a note of 1–5,000 characters and a valid disposition")
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT payload FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None or not any(a['id'] == alert_id for a in json.loads(row[0])['alerts']):
            return None
        count = db.execute("SELECT COUNT(*) FROM notes WHERE run_id=?", (run_id,)).fetchone()[0]
        if count >= 500:
            raise ValueError("This scan has reached its 500-note limit")
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute("INSERT INTO notes (run_id, alert_id, body, disposition, actor, created) VALUES (?, ?, ?, ?, ?, ?)",
                            (run_id, alert_id, body.strip(), disposition, actor, now))
        return cursor.lastrowid

def notes(run_id):
    with connection() as db:
        rows = db.execute("SELECT id, alert_id, body, disposition, actor, created FROM notes WHERE run_id=? ORDER BY id DESC LIMIT 500", (run_id,)).fetchall()
    return [dict(zip(('id','alert_id','body','disposition','actor','created'), row)) for row in rows]

def approve_baseline(run_id, actor):
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT payload FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            return None
        result = json.loads(row[0])
        observations = []
        for event in result['events']:
            if event['action'].lower() == 'login' and event['status'] == 'success' and event['user'] != 'unknown' and event.get('host'):
                moment = datetime.fromisoformat(event['timestamp'])
                observations.append((run_id,event['line'],event['host'],event['user'],event['timestamp'],moment.hour+moment.minute/60))
        if not observations:
            raise ValueError("Training needs successful login events with explicit host and user fields")
        db.execute("INSERT OR IGNORE INTO baseline_sources VALUES (?, ?, ?)", (run_id,actor,datetime.now(timezone.utc).isoformat()))
        db.executemany("INSERT OR IGNORE INTO baseline_observations VALUES (?, ?, ?, ?, ?, ?)", observations)
        return len(observations)

def baseline_status(run_id):
    with connection() as db:
        row = db.execute("SELECT actor, approved FROM baseline_sources WHERE run_id=?", (run_id,)).fetchone()
    return dict(actor=row[0],approved=row[1]) if row else None

def baselines_before(cutoff):
    if not cutoff:
        return {}
    with connection() as db:
        rows = db.execute("""SELECT host, user, event_time, hour, run_id FROM (
            SELECT *, ROW_NUMBER() OVER (PARTITION BY host,user ORDER BY event_time DESC,run_id,line) AS rank
            FROM (SELECT host,user,event_time,MIN(hour) AS hour,MIN(run_id) AS run_id,MIN(line) AS line
                  FROM baseline_observations WHERE event_time < ? GROUP BY host,user,event_time))
            WHERE rank <= 200 ORDER BY host,user,event_time""", (cutoff,)).fetchall()
    profiles = {}
    seen = set()
    for host,user,event_time,hour,run_id in rows:
        # Reuploading identical events must not multiply training support.
        fingerprint = (host,user,event_time)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        profile = profiles.setdefault((host,user),dict(hours=[],days=set(),sources=set(),latest_event=event_time))
        profile['hours'].append(hour)
        profile['days'].add(event_time[:10])
        profile['sources'].add(run_id)
        profile['latest_event'] = event_time
    return {key:dict(hours=p['hours'],sources=sorted(p['sources']),latest_event=p['latest_event'])
            for key,p in profiles.items() if len(p['hours']) >= 10 and len(p['days']) >= 3}

def revoke_baseline(run_id):
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM baseline_observations WHERE run_id=?", (run_id,))
        cursor = db.execute("DELETE FROM baseline_sources WHERE run_id=?", (run_id,))
    return cursor.rowcount > 0
