from datetime import datetime,timedelta,timezone
from io import BytesIO
import json
import config
from app import app,analyze_log,get_results
from analyzer import storage
from analyzer.parser import parse_line,parse_log_file
from analyzer.detector import detect

def sample():
    return analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')

def training_file(tmp_path,name='train.log',host='srv',user='alice'):
    values=[]
    for day in range(3):
        for minute in range(4):
            values.append(dict(timestamp=f'2026-09-{day+1:02d}T09:{minute:02d}:00Z',user=user,host=host,ip='192.0.2.10',country='UNKNOWN',action='login',status='success'))
    path=tmp_path/name
    path.write_text('\n'.join(json.dumps(v) for v in values),encoding='utf-8')
    return path

def test_note_roundtrip_scope_and_export():
    first,second=sample(),sample()
    alert_id=first['alerts'][0]['id']
    client=app.test_client()
    response=client.post(f"/api/analysis/{first['analysis_id']}/notes",json=dict(alert_id=alert_id,body='Reviewed failures and subsequent success',disposition='needs_context'))
    assert response.status_code==201
    assert storage.notes(second['analysis_id'])==[]
    payload=client.get('/export/json?run='+first['analysis_id']).get_json()
    assert payload['investigation_notes'][0]['body']=='Reviewed failures and subsequent success'
    assert payload['ruleset_version']==config.RULESET_VERSION

def test_note_cannot_target_different_scan():
    first,second=sample(),sample()
    assert app.test_client().post(f"/api/analysis/{second['analysis_id']}/notes",json=dict(alert_id=first['alerts'][0]['id'],body='x')).status_code==404

def test_notes_validate_and_escape():
    result=sample(); client=app.test_client(); route=f"/api/analysis/{result['analysis_id']}/notes"; aid=result['alerts'][0]['id']
    for body in ['',None,[], 'x'*5001]:
        assert client.post(route,json=dict(alert_id=aid,body=body)).status_code==400
    assert client.post(route,json=dict(alert_id=aid,body='x',disposition='confirmed')).status_code==400
    assert client.post(route,json=dict(alert_id=aid,body='<script>evil()</script>',disposition='benign')).status_code==201
    page=client.get('/report?run='+result['analysis_id']).data
    assert b'&lt;script&gt;evil()&lt;/script&gt;' in page and b'<script>evil()</script>' not in page

def test_timeline_links_all_contributing_lines():
    result=sample(); client=app.test_client()
    page=client.get('/timeline?run='+result['analysis_id']+'&alerts=1')
    assert page.status_code==200 and b'Evidence timeline' in page.data
    assert b'Line 1' in page.data and b'Line 3' in page.data
    assert b'q=ALT-' in page.data
    assert client.get('/timeline?q=nonexistent').data.count(b'No evidence matches')==1

def test_note_and_training_csrf(monkeypatch):
    result=sample(); monkeypatch.setitem(app.config,'TESTING',False); client=app.test_client()
    assert client.post(f"/api/analysis/{result['analysis_id']}/notes",json={'alert_id':result['alerts'][0]['id'],'body':'x'}).status_code==400
    assert client.post(f"/baseline/{result['analysis_id']}/approve",data={'trusted':'yes'}).status_code==400

def test_historical_baseline_is_prior_and_opt_in(tmp_path):
    trained=analyze_log(training_file(tmp_path))
    assert storage.baselines_before('2026-09-04T00:00:00+00:00')=={}
    assert storage.approve_baseline(trained['analysis_id'],'tester')==12
    profiles=storage.baselines_before('2026-09-04T00:00:00+00:00')
    assert len(profiles[('srv','alice')]['hours'])==12
    assert storage.baselines_before('2026-09-01T00:00:00+00:00')=={}
    path=tmp_path/'new.log'
    path.write_text(json.dumps(dict(timestamp='2026-09-05T23:00:00Z',host='srv',user='alice',ip='192.0.2.10',country='UNKNOWN',action='login',status='success')))
    result=analyze_log(path)
    anomaly=next(a for a in result['alerts'] if a['type']=='unusual_time')
    assert anomaly['baseline_source']=='approved_history'
    assert anomaly['baseline_runs']==[trained['analysis_id']]
    assert storage.baseline_status(result['analysis_id']) is None

def test_training_support_days_duplicates_revoke(tmp_path):
    first=analyze_log(training_file(tmp_path));second=analyze_log(training_file(tmp_path,'duplicate.log'))
    storage.approve_baseline(first['analysis_id'],'tester');storage.approve_baseline(second['analysis_id'],'tester')
    assert len(storage.baselines_before('2026-09-04T00:00:00+00:00')[('srv','alice')]['hours'])==12
    storage.revoke_baseline(first['analysis_id']);storage.revoke_baseline(second['analysis_id'])
    assert storage.baselines_before('2026-09-04T00:00:00+00:00')=={}

def test_training_requires_host_and_trust_acknowledgment(tmp_path):
    result=sample();client=app.test_client()
    assert client.post(f"/baseline/{result['analysis_id']}/approve").status_code==400
    path=tmp_path/'missing.log'
    path.write_text('2026-09-01T10:00:00Z user=a ip=192.0.2.1 country=US action=login status=success')
    scan=analyze_log(path)
    assert client.post(f"/baseline/{scan['analysis_id']}/approve",data={'trusted':'yes'}).status_code==400

def test_retention_cleans_notes_and_training(tmp_path,monkeypatch):
    trained=analyze_log(training_file(tmp_path));storage.approve_baseline(trained['analysis_id'],'tester')
    annotated=sample();storage.add_note(annotated['analysis_id'],annotated['alerts'][0]['id'],'reason','benign','tester')
    monkeypatch.setattr(config,'HISTORY_LIMIT',1);sample()
    assert storage.notes(annotated['analysis_id'])==[]
    assert storage.baselines_before('2026-10-01T00:00:00+00:00')=={}

def windows(event_id,fields=None,**kwargs):
    return dict(System=dict(EventID=event_id,Computer='WKS-01',TimeCreated=dict(SystemTime='2026-09-01T10:00:00Z')),EventData=fields or {},**kwargs)

def test_windows_authentication_fields_and_ipv4_mapping():
    failed=parse_line(json.dumps(windows(4625,dict(TargetUserName='alice',TargetDomainName='CORP',IpAddress='::ffff:192.0.2.10',LogonType='3'))),1)
    assert failed['status']=='failed' and failed['host']=='WKS-01' and failed['ip']=='192.0.2.10'
    assert failed['user']=='CORP'+chr(92)+'alice'
    success=parse_line(json.dumps(windows(4624,dict(TargetUserName='alice',IpAddress='192.0.2.10',LogonType='10'))),2)
    assert success['status']=='success' and success['action']=='login'

def test_windows_process_and_service_logons():
    value=parse_line(json.dumps(windows(4688,dict(SubjectUserName='alice',CommandLine='powershell.exe -EncodedCommand SQBFAFgA',NewProcessName='powershell.exe'))),1)
    assert value['ip']=='UNKNOWN' and value['windows_event_id']==4688
    assert {f['type'] for f in detect([value])}=={'suspicious_powershell'}
    local=[parse_line(json.dumps(windows(4625,dict(TargetUserName='local',IpAddress='-',LogonType='2'))),i) for i in range(1,5)]
    assert detect(local)==[]
    service=parse_line(json.dumps(windows(4624,dict(TargetUserName='svc',IpAddress='-',LogonType='5'))),1)
    assert service['action']=='service_logon'

def test_winlogbeat_adapter_and_invalid_windows(tmp_path):
    value=parse_line(json.dumps({'@timestamp':'2026-09-01T10:00:00Z','winlog':{'event_id':4625,'computer_name':'dc','event_data':{'TargetUserName':'alice','IpAddress':'192.0.2.1'}}}),1)
    assert value['host']=='dc' and value['status']=='failed'
    path=tmp_path/'bad.log';path.write_text(json.dumps({'EventID':4625,'EventData':[]}))
    events,errors=parse_log_file(path)
    assert events==[] and errors

def test_jsonl_upload_and_timeline():
    client=app.test_client()
    payload=json.dumps(windows(4624,dict(TargetUserName='alice',IpAddress='192.0.2.10',LogonType='3'))).encode()
    assert client.post('/upload',data={'log_file':(BytesIO(payload),'security.jsonl')}).status_code==302
    assert b'Windows Security 4624' in client.get('/timeline').data
