"""Evaluate a local labeled corpus with explicit provenance and label completeness."""
import argparse,csv,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyzer.parser import parse_log_file
from analyzer.detector import detect,ATTACK_MAP
from analyzer.metrics import evaluate_findings

def evaluate(log_path,label_path,dataset_name,provenance,complete_labels=False):
    events,warnings=parse_log_file(Path(log_path))
    audit=getattr(warnings,'input_audit',None)
    if not audit or audit['total_lines']==0:
        raise ValueError('No source lines were found')
    with Path(label_path).open(encoding='utf-8-sig',newline='') as stream:
        reader=csv.DictReader(stream)
        if not {'line','type'} <= set(reader.fieldnames or []):
            raise ValueError('Labels require line,type columns; lines refer to physical input lines')
        labels=list(reader)
    valid_lines={row['line'] for row in audit['ledger'] if row['state']!='blank'}
    seen=set()
    for label in labels:
        try:
            line=int(label['line'])
        except (TypeError,ValueError):
            raise ValueError('Each label needs an integer source line')
        key=(line,label['type'])
        if line not in valid_lines or label['type'] not in ATTACK_MAP or key in seen:
            raise ValueError('Labels must refer to nonblank source lines and enabled rule types without duplicate pairs')
        seen.add(key)
    findings=detect(events)
    metrics=evaluate_findings(findings,labels,total_cases=len(valid_lines))
    # Complete labels adjudicate every event/enabled-rule pair.
    negative_pairs = len(valid_lines) * len(ATTACK_MAP) - len(seen)
    metrics['false_positive_rate'] = round(metrics['false_positive'] / negative_pairs, 3) if negative_pairs else 0.0
    metrics['evaluated_rule_types'] = sorted(ATTACK_MAP)
    predicted={(f['line'],f['type']) for f in findings}
    uncovered=sorted(predicted-seen)
    if not complete_labels:
        metrics.pop('false_positive',None)
        metrics['precision']=None
        metrics['false_positive_rate']=None
        for values in metrics['by_type'].values():
            values.pop('false_positive',None)
            values['precision']=None
            values['false_positive_rate']=None
    return dict(dataset_name=dataset_name,provenance=provenance,provenance_verified=False,
                validation_kind='operator-supplied corpus; independence not established by this program',
                complete_labels_declared=complete_labels,events=len(events),source_lines_scored=len(valid_lines),unparsed_lines=audit['unparsed_lines'],parser_warnings=warnings,
                metrics=metrics,missing_labels=sorted(seen-predicted),
                unexpected_predictions=uncovered if complete_labels else None,
                predictions_needing_adjudication=uncovered if not complete_labels else None)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log');parser.add_argument('labels')
    parser.add_argument('--dataset-name',required=True);parser.add_argument('--provenance',required=True)
    parser.add_argument('--complete-labels',action='store_true',help='Declare all event/rule pairs are adjudicated; absent pairs are negative')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        result=evaluate(args.log,args.labels,args.dataset_name,args.provenance,args.complete_labels)
    except (OSError,ValueError) as exc:
        parser.error(str(exc))
    payload=json.dumps(result,indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(payload,encoding='utf-8')
    print(payload)
