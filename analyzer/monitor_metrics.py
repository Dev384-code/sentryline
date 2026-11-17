"""Observed authentication rates. No inference of attempts absent from collected logs."""
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from analyzer.parser import parse_line
import config
import json

def peak(times):
    queue=deque(); highest=0
    for timestamp in sorted(times):
        while queue and timestamp-queue[0]>=timedelta(seconds=1):queue.popleft()
        queue.append(timestamp);highest=max(highest,len(queue))
    return highest

def summarize(rows, reference=None):
    reference=reference or datetime.now(timezone.utc)
    recent=[];groups=defaultdict(list);unknown=0;service=0;invalid=0;future=0
    seconds=[0]*60
    for row in rows:
        try:
            event=parse_line(json.dumps(row['event']),row['record_id'])
            if event is None:invalid+=1;continue
            timestamp=datetime.fromisoformat(event['timestamp'])
        except (ValueError,TypeError,KeyError):invalid+=1;continue
        age=(reference-timestamp).total_seconds()
        if age<0:future+=1;continue
        if age>config.BRUTE_FORCE_WINDOW_MINUTES*60:continue
        if event['action']=='service_logon':service+=1;continue
        if event['action']!='login':continue
        if event['status'] not in {'success','failed'}:continue
        if age<60:
            recent.append((timestamp,event));seconds[59-int(age)]+=1
        if event['status']=='failed':
            if event['ip']=='UNKNOWN':unknown+=1
            groups[(event.get('host','unknown'),event['ip'])].append((timestamp,event))
    failures=sum(e['status']=='failed' for _,e in recent)
    sources=[]
    for (host,ip),items in groups.items():
        count=len(items);matched=ip!='UNKNOWN' and count>=config.BRUTE_FORCE_THRESHOLD
        sources.append(dict(host=host,ip=ip,failures=count,users=sorted({e['user'] for _,e in items})[:10],
                            failures_per_second_60=round(sum((reference-t).total_seconds()<60 for t,_ in items)/60,3),
                            peak_failures_in_one_second=peak([t for t,_ in items]),
                            signal='source_unavailable' if ip=='UNKNOWN' else ('escalated' if count>=config.BRUTE_FORCE_THRESHOLD*2 else 'threshold_met' if matched else 'below_threshold')))
    sources.sort(key=lambda x:(x['ip']=='UNKNOWN',-x['failures'],x['host'],x['ip']))
    return dict(as_of=reference.isoformat(),attempts_last_60s=len(recent),failures_last_60s=failures,
                successes_last_60s=len(recent)-failures,attempts_per_second_60=round(len(recent)/60,3),
                failures_per_second_60=round(failures/60,3),peak_attempts_in_one_second=peak([t for t,_ in recent]),
                seconds=seconds,sources=sources[:20],source_count=len(sources),unknown_source_failures=unknown,
                service_logons_excluded=service,invalid_events=invalid,future_events=future,
                threshold=config.BRUTE_FORCE_THRESHOLD,window_minutes=config.BRUTE_FORCE_WINDOW_MINUTES)
