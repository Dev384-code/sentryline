"""Describe observed input gaps without claiming universal attack coverage."""
from collections import Counter

def describe(events,audit):
    actions=Counter(e.get('action','unknown').lower() for e in events)
    missing_host=sum(not e.get('host') for e in events)
    unknown_ip=sum(e.get('ip')=='UNKNOWN' for e in events)
    assumptions=sum(bool(e.get('timestamp_assumption')) for e in events)
    unsupported_actions=sum(e.get('action','').lower() not in {'login','process','privilege','data_transfer','c2','country_change','firewall','get','post','put','delete','patch','web','web_access','session','service_logon'} for e in events)
    unknown_status=sum(e.get('action','').lower()=='login' and e.get('status') not in {'success','failed'} for e in events)
    notes=[]
    if unknown_status:notes.append(f'{unknown_status} login events lack recognized success/failure outcomes; authentication sequence rules cannot fully assess them.')
    if not audit:notes.append('This stored scan has no complete input audit; re-upload to obtain line accounting.')
    if audit and audit['unparsed_lines']:notes.append(f"{audit['unparsed_lines']} nonblank lines were not parsed. Their source evidence is preserved; these lines did not enter the detection engine.")
    if unsupported_actions:notes.append(f'{unsupported_actions} parsed events have unclassified/unsupported action categories; no complete detection interpretation is available.')
    if missing_host:notes.append(f'{missing_host} events lack a computer name; host-specific correlations and historical training can be limited.')
    if unknown_ip:notes.append(f'{unknown_ip} events lack a source address; address-based authentication correlations can be limited.')
    if assumptions:notes.append(f'{assumptions} events use an assumed year or timezone; confirm the source clock before relying on sequence timing.')
    notes.append('Request bodies, actual process outcomes, transferred bytes and unrecorded events cannot be inferred from missing telemetry.')
    return dict(actions=dict(actions),notes=notes,unsupported_action_events=unsupported_actions,
        missing_host_events=missing_host,unknown_ip_events=unknown_ip,assumed_timestamp_events=assumptions,unknown_login_status_events=unknown_status,
        conclusion='Not assessed' if not events else 'Limited to supported rules and available evidence',
        universal_detection=False,independent_accuracy_verified=False)
