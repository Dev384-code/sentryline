from datetime import datetime,timezone,timedelta
import pytest
from analyzer.monitor_metrics import summarize
from analyzer.monitor import Monitor,WindowsReader


BASE=datetime(2026,10,11,12,0,tzinfo=timezone.utc)
def row(record,age=0,event_id=4625,ip='192.0.2.1',host='HOST',logon_type='3'):
    return dict(record_id=record,event=dict(System=dict(EventID=event_id,Computer=host,TimeCreated=dict(SystemTime=(BASE-timedelta(seconds=age)).isoformat())),EventData=dict(TargetUserName='alice',IpAddress=ip,LogonType=logon_type)))

def test_rates_counts_and_sliding_peak():
    result=summarize([row(1,0.3),row(2,0.7),row(3,1.1),row(4,10,4624)],BASE)
    assert result['attempts_last_60s']==4
    assert result['failures_last_60s']==3
    assert result['successes_last_60s']==1
    assert result['attempts_per_second_60']==0.067
    assert result['peak_attempts_in_one_second']==3
    assert sum(result['seconds'])==4
    assert result['sources'][0]['signal']=='threshold_met'

def test_window_expiration_and_future_timestamps():
    result=summarize([row(1,60),row(2,600),row(3,601),row(4,-1)],BASE)
    assert result['attempts_last_60s']==0
    assert result['sources'][0]['failures']==2
    assert result['future_events']==1

def test_source_host_isolation_and_unknown_address():
    records=[row(1),row(2,host='OTHER'),row(3,ip='192.0.2.2'),row(4,ip='-')]
    result=summarize(records,BASE)
    assert result['source_count']==4
    assert all(s['signal'] in {'below_threshold','source_unavailable'} for s in result['sources'])
    assert result['unknown_source_failures']==1

def test_service_logons_excluded_and_malformed_events_counted():
    result=summarize([row(1,logon_type='5'),row(2,event_id=4688),{'record_id':3,'event':{}},row(4,ip='bad-ip')],BASE)
    assert result['attempts_last_60s']==0
    assert result['service_logons_excluded']==1
    assert result['invalid_events']==2

def test_escalation_threshold():
    result=summarize([row(i) for i in range(1,7)],BASE)
    assert result['sources'][0]['signal']=='escalated'

def test_status_does_not_wait_for_windows_reader():
    import threading,time
    from analyzer import storage
    entered=threading.Event();release=threading.Event();errors=[]
    def reader(cp):
        entered.set();release.wait(3);return dict(rows=[],checkpoint=5)
    monitor=Monitor(lambda *a,**kw:None,reader)
    def poll():
        try:monitor.poll()
        except Exception as exc:errors.append(exc)
    worker=threading.Thread(target=poll);worker.start()
    try:
        assert entered.wait(2)
        start=time.monotonic();status=monitor.status()
        assert time.monotonic()-start<1
        assert status['collecting']
        monitor.stop()
    finally:release.set();worker.join(3)
    assert not errors

def test_reader_permission_error_classification(monkeypatch):
    from types import SimpleNamespace
    import analyzer.monitor as module
    monkeypatch.setattr(module,'IS_WINDOWS',True)
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=1,stderr='SENTRYLINE_ACCESS_DENIED',stdout=''))
    with pytest.raises(RuntimeError,match='Security log access denied'):WindowsReader()(None)

def test_reader_timeout_is_actionable(monkeypatch):
    import analyzer.monitor as module
    monkeypatch.setattr(module,'IS_WINDOWS',True)
    def fail(*a,**kw):raise module.subprocess.TimeoutExpired('powershell',25)
    monkeypatch.setattr(module.subprocess,'run',fail)
    with pytest.raises(RuntimeError,match='timed out'):WindowsReader()(None)

def test_diagnostic_requires_consent_and_does_not_advance_checkpoint(monkeypatch):
    from analyzer.monitor import state
    monkeypatch.setattr(WindowsReader,'__call__',lambda *a,**kw:dict(rows=[],checkpoint=42,diagnostic={'security_log_readable':True}))
    monitor=Monitor(lambda *a,**kw:None)
    with pytest.raises(ValueError):monitor.diagnose(False)
    assert monitor.diagnose(True)['ok']
    assert state()['checkpoint'] is None

def test_diagnostic_route_and_rate_fields(monkeypatch):
    from app import app
    client=app.test_client()
    assert client.post('/monitor/check').status_code==400
    assert client.post('/monitor/check',data={'consent':'yes'},environ_overrides={'REMOTE_ADDR':'192.0.2.1'}).status_code==403
    assert 'attempts_per_second_60' in client.get('/api/monitor').json['metrics']
    assert b'Attempts / second' in client.get('/monitor').data

def test_reader_reports_unsupported_platform(monkeypatch):
    import analyzer.monitor as module
    monkeypatch.setattr(module,'IS_WINDOWS',False)
    with pytest.raises(RuntimeError,match='requires Windows'):WindowsReader()(None)
