from analyzer.explanations import GUIDES,explain
from analyzer.detector import ATTACK_MAP
from app import app,analyze_log
import config

def test_all_rules_have_review_guidance():
    assert set(ATTACK_MAP)<=set(GUIDES)
    for kind in ATTACK_MAP:
        guide=explain({'type':kind,'severity':'high'})
        assert all(guide.get(k) for k in ('title','why','uncertainty','next_step','priority'))

def test_report_keeps_evidence_and_triage_with_plain_guidance():
    scan=analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    client=app.test_client();page=client.get('/report?run='+scan['analysis_id'])
    assert page.status_code==200
    for text in ['Why this needs attention','What we cannot conclude yet','What to check next','Technical details for analysts','Open source evidence','Your review status']:
        assert text in page.text
    for alert in scan['alerts']:
        assert alert['id'] in page.text and alert['message'] in page.text
    assert 'A login succeeded after repeated failures' in page.text
    assert 'not attack probability' in page.text
    assert 'Developer test-fixture metrics' in page.text

def test_plain_language_search_finds_technical_rule():
    scan=analyze_log(config.BASE_DIR/'tests/fixtures/sample_incident.log')
    page=app.test_client().get('/report?run='+scan['analysis_id']+'&q=A+login+succeeded+after+repeated+failures')
    assert '1 matching alerts' in page.text
    assert 'A login succeeded after repeated failures' in page.text

def test_legacy_rule_explanation_is_honest():
    guide=explain({'type':'old_unknown_rule','severity':'high'})
    assert 'no specific beginner explanation' in guide['uncertainty']
