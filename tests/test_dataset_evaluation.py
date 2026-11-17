from pathlib import Path
import pytest
from scripts.evaluate_dataset import evaluate
import config

def test_incomplete_labels_do_not_claim_false_positives(tmp_path):
    labels=tmp_path/'labels.csv';labels.write_text('line,type\n')
    result=evaluate(config.BASE_DIR/'tests/fixtures/sample_incident.log',labels,'review','operator-provided',False)
    assert result['metrics']['precision'] is None
    assert result['metrics']['false_positive_rate'] is None
    assert result['predictions_needing_adjudication']
    assert result['provenance_verified'] is False

def test_complete_dataset_scores_known_fixture():
    result=evaluate(config.BASE_DIR/'tests/fixtures/evaluation_logs.txt',config.BASE_DIR/'tests/fixtures/ground_truth.csv','bundled','synthetic reviewed fixture',True)
    assert result['metrics']['precision']==1 and result['metrics']['recall']==1

@pytest.mark.parametrize('text',['line,type\n999,brute_force\n','line,type\n1,not_a_rule\n','line,type\n1,brute_force\n1,brute_force\n','wrong,columns\n'])
def test_invalid_labels_rejected(text,tmp_path):
    labels=tmp_path/'labels.csv';labels.write_text(text)
    with pytest.raises(ValueError):
        evaluate(config.BASE_DIR/'tests/fixtures/sample_incident.log',labels,'x','x')
