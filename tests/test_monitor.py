from datetime import datetime, timezone
import pytest
from analyzer.monitor import Monitor, state
from app import app, analyze_log

def row(record, status=4625):
    return dict(record_id=record,event=dict(System=dict(EventID=status,Computer='TEST-HOST',TimeCreated=dict(SystemTime=datetime.now(timezone.utc).isoformat())),EventData=dict(TargetUserName='alice',IpAddress='192.0.2.20',LogonType='3')))

def test_consent_and_options():
    monitor=Monitor(analyze_log)
    with pytest.raises(ValueError):monitor.start(False)
    with pytest.raises(ValueError):monitor.start(True,2,30)
    assert not monitor.status()['running']

def test_checkpoints_dedup_and_cross_poll_detection():
    batches=iter([dict(rows=[row(1),row(2)],checkpoint=2),dict(rows=[row(2),row(3),row(4)],checkpoint=4)])
    cursors=[]
    def reader(checkpoint):
        cursors.append(checkpoint);return next(batches)
    monitor=Monitor(analyze_log,reader)
    monitor.poll();monitor.poll()
    value=state()
    assert cursors==[None,2]
    assert len(value['rows'])==4
    assert value['checkpoint']==4
    assert value['latest_run']
    from analyzer import storage
    result=storage.get_run(value['latest_run'])
    assert any(a['type']=='brute_force' for a in result['alerts'])
    assert value['notifications']
    # Reconstructing collector retains checkpoint, but does not auto-start.
    assert Monitor(analyze_log,reader).status()['checkpoint']==4
    assert not Monitor(analyze_log,reader).status()['running']

def test_failure_preserves_checkpoint():
    monitor=Monitor(lambda *a,**kw: (_ for _ in ()).throw(RuntimeError('analysis failed')),lambda cp:dict(rows=[row(1)],checkpoint=1))
    with pytest.raises(RuntimeError):monitor.poll()
    assert state()['checkpoint'] is None

def test_reset_and_gap():
    batches=iter([dict(rows=[row(20)],checkpoint=20),dict(rows=[],checkpoint=2,reset=True,gap='Log reset')])
    monitor=Monitor(analyze_log,lambda cp:next(batches))
    monitor.poll();monitor.poll()
    assert state()['checkpoint']==2
    assert state()['rows']==[]
    assert state()['gaps'][0]['message']=='Log reset'

def test_no_new_records_do_not_create_snapshots():
    monitor=Monitor(analyze_log,lambda cp:dict(rows=[],checkpoint=5))
    monitor.poll();monitor.poll()
    assert state()['latest_run'] is None

def test_monitor_routes_and_csrf(monkeypatch):
    client=app.test_client()
    assert client.get('/monitor').status_code==200
    assert client.get('/api/monitor').json['running'] is False
    assert client.post('/monitor/start').status_code==400
    assert client.post('/monitor/start',data={'consent':'yes'},environ_overrides={'REMOTE_ADDR':'192.0.2.1'}).status_code==403
    monkeypatch.setitem(app.config,'TESTING',False)
    assert client.post('/monitor/stop').status_code==400

def test_stopped_does_not_ingest():
    monitor=Monitor(analyze_log,lambda cp:dict(rows=[row(1)],checkpoint=1))
    monitor.stop();monitor.poll()
    assert state()['checkpoint'] is None

def test_backwards_checkpoint_rejected():
    batches=iter([dict(rows=[],checkpoint=10),dict(rows=[],checkpoint=2)])
    monitor=Monitor(analyze_log,lambda cp:next(batches));monitor.poll()
    with pytest.raises(ValueError):monitor.poll()
    assert state()['checkpoint']==10


def test_notification_deduplication():
    records=[row(i) for i in range(1,5)]
    monitor=Monitor(analyze_log,lambda cp:dict(rows=records,checkpoint=4))
    monitor.poll();keys=[n['key'] for n in state()['notifications']]
    monitor.poll()
    assert [n['key'] for n in state()['notifications']]==keys

def test_expired_events_removed():
    from datetime import timedelta
    from analyzer.monitor import persist
    old=row(1);old['event']['System']['TimeCreated']['SystemTime']=(datetime.now(timezone.utc)-timedelta(hours=25)).isoformat()
    value=state();value.update(rows=[old],checkpoint=1);persist(value)
    monitor=Monitor(analyze_log,lambda cp:dict(rows=[],checkpoint=1));monitor.poll()
    assert not state()['rows']
    assert state()['latest_run']

def test_source_capacity_is_disclosed(monkeypatch):
    import config
    monkeypatch.setattr(config,'MAX_UPLOAD_BYTES',1)
    monitor=Monitor(analyze_log,lambda cp:dict(rows=[row(1)],checkpoint=1));monitor.poll()
    assert not state()['rows']
    assert 'capacity' in state()['gaps'][0]['message']

def test_worker_records_permission_error():
    def denied(cp):raise RuntimeError('Permission denied')
    monitor=Monitor(analyze_log,denied)
    def finish(seconds):monitor.stop();return True
    monitor.stop_event.wait=finish
    monitor.loop()
    assert state()['error']=='Permission denied'
    assert state()['checkpoint'] is None
