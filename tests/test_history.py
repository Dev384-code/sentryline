import config
from app import app, analyze_log, get_results
from analyzer import storage

def scan():
    return analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')

def test_history_scans_open_independently():
    first, second=scan(), scan()
    client=app.test_client()
    assert client.get('/api/results?run='+first['analysis_id']).get_json()['analysis_id']==first['analysis_id']
    assert client.get('/api/results').get_json()['analysis_id']==second['analysis_id']
    page=client.get('/dashboard?run='+first['analysis_id'])
    assert page.status_code==200 and b'Analysis history' in page.data

def test_explicit_historical_triage_does_not_change_latest():
    first,second=scan(),scan()
    alert=first['alerts'][0]['id']
    response=app.test_client().post(f'/api/alert/{alert}/status',json={'status':'resolved','analysis_id':first['analysis_id']})
    assert response.status_code==200
    assert storage.get_run(first['analysis_id'])['summary']['open_alerts']==len(first['alerts'])-1
    assert get_results()['summary']['open_alerts']==len(second['alerts'])
    assert storage.audit_trail(first['analysis_id'])[0]['new_status']=='resolved'

def test_cross_run_alert_id_rejected():
    first,second=scan(),scan()
    response=app.test_client().post(f"/api/alert/{first['alerts'][0]['id']}/status",json={'status':'resolved','analysis_id':second['analysis_id']})
    assert response.status_code==404
    assert storage.audit_trail(second['analysis_id'])==[]

def test_history_retention_and_expired_links(monkeypatch):
    monkeypatch.setattr(config,'HISTORY_LIMIT',2)
    first=scan()
    scan();scan()
    assert len(storage.history())==2
    client=app.test_client()
    assert client.get('/dashboard?run='+first['analysis_id']).status_code==404
    assert client.get('/api/results?run='+first['analysis_id']).status_code==404

def test_history_backfills_existing_database():
    result=scan()
    with storage.connection() as db:
        db.execute('DELETE FROM run_summary')
    assert storage.history()[0]['analysis_id']==result['analysis_id']

def test_noop_triage_does_not_add_audit_noise():
    result=scan()
    assert storage.update_status(result['alerts'][0]['id'],'open','tester',result['analysis_id'])
    assert storage.audit_trail(result['analysis_id'])==[]

def test_selected_report_links_preserve_run():
    result=scan()
    page=app.test_client().get('/report?run='+result['analysis_id'])
    assert b'Triage activity' in page.data
    assert ('name="run" value="'+result['analysis_id']+'"').encode() in page.data
    assert ('/export/csv?run='+result['analysis_id']).encode() in page.data

def test_server_rendered_coverage_does_not_require_javascript():
    scan()
    page=app.test_client().get('/dashboard')
    assert b'Periodic beaconing' in page.data
    assert b'Loading tactic coverage' not in page.data

def test_upload_redirect_selects_its_new_scan():
    response=app.test_client().post('/load-sample')
    assert 'run='+get_results()['analysis_id'] in response.headers['Location']

def test_invalid_analysis_id_payload():
    client=app.test_client()
    for run in [3, [], '']:
        assert client.post('/api/alert/any/status',json={'status':'open','analysis_id':run}).status_code==400
