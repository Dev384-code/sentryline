from pathlib import Path
from io import BytesIO
import base64,hashlib
import pytest
import config
from analyzer.parser import parse_log_file
from analyzer.coverage import describe
from app import app,analyze_log
from scripts.evaluate_dataset import evaluate

GOOD='2026-10-09T01:00:00Z user=a ip=192.0.2.1 country=US action=login status=success'

def test_all_lines_and_original_bytes_retained(tmp_path):
    raw=b'\xef\xbb\xbf'+(GOOD+'\r\n\r\nunsupported <script>x</script>\r\n').encode()
    p=tmp_path/'mixed.log';p.write_bytes(raw)
    events,warnings=parse_log_file(p);audit=warnings.input_audit
    assert len(events)==1 and audit['total_lines']==3
    assert audit['parsed_lines']==1 and audit['blank_lines']==1 and audit['unparsed_lines']==1
    assert audit['accounting_balanced'] and audit['input_state']=='partial'
    assert base64.b64decode(audit['source_base64'])==raw
    assert audit['sha256']==hashlib.sha256(raw).hexdigest()
    scan=analyze_log(p);client=app.test_client()
    assert client.get('/export/source?run='+scan['analysis_id']).data==raw
    page=client.get('/input-audit?run='+scan['analysis_id']+'&state=unparsed')
    assert page.status_code==200 and b'Line 3' in page.data
    assert b'&lt;script&gt;x&lt;/script&gt;' in page.data and b'<script>x</script>' not in page.data

def test_warning_cap_does_not_drop_line_audit(tmp_path):
    p=tmp_path/'unsupported.log';p.write_text('unrecognized event\n'*250)
    _,warnings=parse_log_file(p)
    assert len(warnings)==201
    assert warnings.input_audit['unparsed_lines']==250 and len(warnings.input_audit['ledger'])==250

def test_no_supported_events_saved_as_not_assessed():
    client=app.test_client()
    response=client.post('/upload',data={'log_file':(BytesIO(b'vendor unsupported event\n'),'vendor.log')},follow_redirects=True)
    assert response.status_code==200 and b'Not assessed' in response.data
    scan=client.get('/export/json').json
    assert scan['alerts']==[] and scan['input_audit']['input_state']=='no_events'
    assert scan['risk_score'] is None and scan['analysis_status']=='not_assessed'
    assert client.get('/export/source?run='+scan['analysis_id']).data==b'vendor unsupported event\n'
    assert b'Not assessed' in client.get('/report').data

def test_unclassified_events_are_not_complete_coverage(tmp_path):
    p=tmp_path/'unknown.log';p.write_text('Oct 09 01:00:00 h unknownservice: opaque message\n')
    scan=analyze_log(p)
    assert scan['input_audit']['parsed_unclassified_lines']==1
    assert scan['input_audit']['input_state']=='partial'
    assert scan['coverage_assessment']['unsupported_action_events']==1
    assert scan['coverage_assessment']['assumed_timestamp_events']==1

def test_unsupported_labeled_event_is_a_false_negative(tmp_path):
    p=tmp_path/'unknown.log';p.write_text('vendor says login burst\n')
    labels=tmp_path/'labels.csv';labels.write_text('line,type\n1,brute_force\n')
    result=evaluate(p,labels,'external test','operator labels',True)
    assert result['events']==0 and result['source_lines_scored']==1
    assert result['metrics']['false_negative']==1 and result['metrics']['recall']==0

def test_line_limit_rejects_entire_file(tmp_path,monkeypatch):
    monkeypatch.setattr(config,'MAX_SOURCE_LINES',2)
    p=tmp_path/'lines.log';p.write_text('\n\n\n')
    with pytest.raises(ValueError,match='entire upload rejected'):parse_log_file(p)

def test_size_limit_rejects_without_partial_result(tmp_path,monkeypatch):
    monkeypatch.setattr(config,'MAX_UPLOAD_BYTES',5)
    p=tmp_path/'size.log';p.write_bytes(b'123456')
    with pytest.raises(ValueError,match='5 MiB'):parse_log_file(p)

def test_legacy_source_export_is_explicitly_unavailable(tmp_path):
    from analyzer import storage
    scan=analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    scan['analysis_id']='old-run';scan.pop('input_audit');scan.pop('coverage_assessment');storage.save(scan)
    client=app.test_client()
    assert client.get('/export/source?run=old-run').status_code==404
    assert b'Input coverage unavailable' in client.get('/report?run=old-run').data

def test_ledger_pagination_keeps_selection(tmp_path):
    p=tmp_path/'many.log';p.write_text('unrecognized\n'*205)
    scan=analyze_log(p);page=app.test_client().get('/input-audit?run='+scan['analysis_id']+'&page=3&state=unparsed')
    assert b'Line 205' in page.data and b'Line 100' not in page.data
    assert ('run='+scan['analysis_id']).encode() in page.data

def test_invalid_utf8_upload_is_not_silently_analyzed():
    client=app.test_client();response=client.post('/upload',data={'log_file':(BytesIO(b'\xffbad'),'bad.log')},follow_redirects=True)
    assert response.status_code==200 and b'Upload rejected' in response.data
    from analyzer import storage
    assert storage.latest() is None

def test_arbitrary_action_reports_limited_coverage(tmp_path):
    p=tmp_path/'opaque.log';p.write_text(GOOD.replace('action=login','action=opaque_vendor_action'))
    scan=analyze_log(p)
    assert scan['input_audit']['parsed_unclassified_lines']==1 and scan['input_audit']['input_state']=='partial'
    assert scan['coverage_assessment']['universal_detection'] is False


def test_stored_source_checksum_is_verified(tmp_path):
    from analyzer import storage
    p=tmp_path/'source.log';p.write_text(GOOD)
    scan=analyze_log(p);scan['analysis_id']='damaged';scan['input_audit']['sha256']='wrong';storage.save(scan)
    client=app.test_client()
    assert client.get('/export/source?run=damaged').status_code==409
    assert client.get('/input-audit?run=damaged').status_code==409

def test_summary_does_not_transfer_complete_source(tmp_path):
    p=tmp_path/'summary.log';p.write_text(GOOD)
    scan=analyze_log(p);summary=app.test_client().get('/api/results?run='+scan['analysis_id']+'&summary=1').json
    assert summary['input_audit']['source_available']
    assert 'source_base64' not in summary['input_audit'] and 'ledger' not in summary['input_audit']
    assert summary['input_audit']['total_lines']==1


def test_json_unknown_vendor_is_not_assumed_to_be_login(tmp_path):
    import json
    p=tmp_path/'vendor.jsonl';p.write_text(json.dumps(dict(timestamp='2026-10-09T01:00:00Z',user='a',ip='192.0.2.1',status='failed')))
    events,warnings=parse_log_file(p)
    assert events[0]['action']=='security_event' and warnings.input_audit['parsed_unclassified_lines']==1

def test_local_process_json_without_address_can_be_assessed(tmp_path):
    import json
    p=tmp_path/'process.jsonl';p.write_text(json.dumps(dict(timestamp='2026-10-09T01:00:00Z',host='h',action='process',command='powershell -EncodedCommand AAA=')))
    scan=analyze_log(p)
    assert scan['events'][0]['ip']=='UNKNOWN'
    assert any(a['type']=='suspicious_powershell' for a in scan['alerts'])

def test_nested_vendor_fields_are_not_stringified_as_identities(tmp_path):
    import json
    p=tmp_path/'vendor.jsonl';p.write_text(json.dumps(dict(timestamp='2026-10-09T01:00:00Z',user={'name':'a'},ip='192.0.2.1',status='failed',action='login')))
    events,warnings=parse_log_file(p)
    assert not events and warnings.input_audit['unparsed_lines']==1
    assert 'nested vendor fields' in warnings[0]


def test_naive_timestamp_assumption_is_visible(tmp_path):
    p=tmp_path/'naive.log';p.write_text(GOOD.replace('00Z','00'))
    scan=analyze_log(p)
    assert scan['coverage_assessment']['assumed_timestamp_events']==1
    assert 'UTC was assumed' in scan['events'][0]['timestamp_assumption']

def test_deeply_nested_json_is_preserved_not_server_failure(tmp_path):
    p=tmp_path/'deep.jsonl';p.write_text('['*2000+'0'+']'*2000)
    events,warnings=parse_log_file(p)
    assert not events and warnings.input_audit['unparsed_lines']==1
    assert len(warnings.input_audit['ledger'])==1
