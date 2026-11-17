"""Reproducible synthetic detector timing; no private logs or database writes."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
from datetime import datetime, timedelta, timezone
from time import perf_counter
from analyzer.detector import detect

def run(count, users):
    start = datetime(2026, 9, 1, 9, tzinfo=timezone.utc)
    events = [dict(line=i+1, timestamp=(start+timedelta(seconds=i)).isoformat(), user=f'user{i%users}', ip='192.0.2.1', country='UNKNOWN', action='login', status='success', raw='') for i in range(count)]
    before = perf_counter()
    findings = detect(events)
    seconds = perf_counter()-before
    print(f'{count} events, {users} users: {seconds:.3f}s, {count/max(seconds,0.000001):.0f} events/s, {len(findings)} alerts')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--events',type=int,default=10000)
    parser.add_argument('--users',type=int,default=1000)
    args = parser.parse_args()
    run(args.events,args.users)
