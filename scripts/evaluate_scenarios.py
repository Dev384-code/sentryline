"""Print expected vs observed rule signals for reviewed synthetic scenarios."""
import sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyzer.detector import detect

def evaluate():
    cases=json.loads((Path(__file__).resolve().parents[1]/'tests/fixtures/scenarios.json').read_text(encoding='utf-8'))
    results=[]
    for case in cases:
        findings=detect(case['events'])
        expected=set(case['expected_types'])
        actual={f['type'] for f in findings}
        results.append(dict(name=case['name'],passed=expected==actual,expected=sorted(expected),observed=sorted(actual),unexpected=sorted(actual-expected),missing=sorted(expected-actual),note=case['note']))
    return results

if __name__=='__main__':
    results=evaluate()
    for row in results:
        print(('PASS' if row['passed'] else 'FAIL')+' '+row['name']+' expected='+str(row['expected'])+' observed='+str(row['observed']))
    print(f"{sum(r['passed'] for r in results)}/{len(results)} scenarios passed. Synthetic regression coverage, not independent field validation.")
    raise SystemExit(0 if all(r['passed'] for r in results) else 1)
