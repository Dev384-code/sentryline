import json
from pathlib import Path
import pytest
from analyzer.detector import detect

CASES=json.loads((Path(__file__).parent/'fixtures/scenarios.json').read_text(encoding='utf-8'))

@pytest.mark.parametrize('case',CASES,ids=[c['name'] for c in CASES])
def test_reviewed_scenario(case):
    findings=detect(case['events'])
    assert {f['type'] for f in findings}==set(case['expected_types'])
    lines={e['line'] for e in case['events']}
    assert all(f['line'] in lines and set(f['evidence_lines'])<=lines for f in findings)
    if case['name']=='successful_auth_resets_failure_sequence':
        assert sum(f['type']=='account_takeover' for f in findings)==1
    if case['name']=='country_change_then_failed_login':
        assert next(f for f in findings if f['type']=='country_change')['line']==2

@pytest.mark.parametrize('case',CASES,ids=[c['name'] for c in CASES])
def test_scenario_through_file_parser(case,tmp_path):
    from analyzer.parser import parse_log_file
    path=tmp_path/'scenario.log'
    path.write_text('\n'.join(e['raw'] for e in case['events']),encoding='utf-8')
    events,errors=parse_log_file(path)
    assert errors==[]
    assert {f['type'] for f in detect(events)}==set(case['expected_types'])
