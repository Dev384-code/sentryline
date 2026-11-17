"""Check input accounting without writing a scan or exposing complete source contents."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyzer.parser import parse_log_file
from analyzer.coverage import describe

def inspect(path):
    events,warnings=parse_log_file(path)
    audit=warnings.input_audit
    return dict(input_audit={k:v for k,v in audit.items() if k not in {'source_base64','ledger'}},
                coverage=describe(events,audit),parser_warning_examples=list(warnings))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file',type=Path)
    args=parser.parse_args()
    try:result=inspect(args.file)
    except (OSError,UnicodeError,ValueError) as exc:
        print(json.dumps({'accepted':False,'reason':str(exc)}));raise SystemExit(2)
    print(json.dumps(result,indent=2))
    # Zero means source input was parsed into supported categories, not that it is safe.
    raise SystemExit(0 if result['input_audit']['input_state']=='supported_input' else 1)
