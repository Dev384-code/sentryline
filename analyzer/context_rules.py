"""Contextual review signals; none establishes successful exploitation or intent."""
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
from urllib.parse import unquote_plus, urlsplit, parse_qs
from ipaddress import ip_address, ip_network
import re
import config
from bisect import bisect_right

RULES = {
 'distributed_authentication': ('T1110','Brute Force','Credential Access'),
 'slow_authentication': ('T1110','Brute Force','Credential Access'),
 'success_after_source_failures': ('T1078','Valid Accounts','Initial Access'),
 'upload_command_request': ('T1505.003','Web Shell','Persistence'),
 'sensitive_file_read': ('T1003.008','/etc/passwd and /etc/shadow','Credential Access'),
 'account_creation_context': ('T1136.001','Local Account','Persistence'),
 'cron_change_context': ('T1053.003','Cron','Persistence'),
 'history_clearing': ('T1070.003','Clear Command History','Defense Evasion'),
 'log_clearing': ('T1070.002','Clear Linux or Mac System Logs','Defense Evasion'),
 'archive_transfer_review': ('T1048','Exfiltration Over Alternative Protocol','Exfiltration'),
}

def web_signature(request):
    text = unquote_plus(unquote_plus(request))
    text = re.sub(r'/\*[^*]*(?:\*(?!/)[^*]*)*\*/', ' ', text)
    text = re.sub(r'\bUNION(?:/|\s)+SELECT\b', 'UNION SELECT', text, flags=re.I)
    signatures = [
      ('SQL-like payload', r"(?:'\s*OR\s*'?\d+['\"]?\s*=|\bUNION\s+SELECT\b|;\s*DROP\s+TABLE\b)"),
      ('HTML script or event-handler payload', r'<script\b|<[^>]{0,4096}\bon(?:error|load|click)\s*=|javascript\s*:'),
      ('parent-directory traversal payload', r'\.\./'),
    ]
    for name, pattern in signatures:
        if re.search(pattern,text,re.I): return name
    return None

def contextual(events, findings, make, archive_output, upload_input):
    output=[]
    def emit(kind,event,message,evidence=None,severity='medium'):
        f=make(kind,severity,event,message,'medium')
        f['evidence_lines']=sorted({e['line'] for e in (evidence or [event])})
        if len(evidence or []) >= 100:
            f['evidence_note']='Supporting lines are bounded; the reported window count can exceed displayed evidence'
        f['evidence_basis']='Observed pattern; authorization and outcome require review'
        output.append(f)
    ordered=sorted(events,key=lambda e:(e['timestamp'],e['line']))
    def time(e):return datetime.fromisoformat(e['timestamp'])
    # Rolling host and source windows: counters avoid rescanning accumulated failures.
    host_windows=defaultdict(deque); source_windows=defaultdict(deque)
    host_ips=defaultdict(Counter);host_users=defaultdict(Counter)
    source_users=defaultdict(Counter);last_distributed={};last_slow={}
    for e in ordered:
        if e['action'].lower()!='login' or not e.get('host') or e['ip']=='UNKNOWN':continue
        now=time(e);host=e['host'];key=(host,e['ip']);sq=source_windows[key];su=source_users[key]
        while sq and now-time(sq[0])>timedelta(minutes=120):
            old=sq.popleft();su[old['user']]-=1
            if not su[old['user']]:del su[old['user']]
        if e['status']=='success':
            if len(sq)>=8 and len(su)>=4 and now-time(sq[0])>=timedelta(minutes=20):
                emit('success_after_source_failures',e,'Successful login after a prolonged multi-account failure pattern from the same source; verify authorization',list(sq)[-100:]+[e], 'high')
            sq.clear();su.clear();continue
        if e['status']!='failed':continue
        sq.append(e);su[e['user']]+=1
        if len(sq)>=8 and len(su)>=4 and now-time(sq[0])>=timedelta(minutes=20) and (key not in last_slow or now-last_slow[key]>=timedelta(minutes=120)):
            emit('slow_authentication',e,f'{len(sq)} failures across {len(su)} accounts in a 120-minute source window',list(sq)[-100:]);last_slow[key]=now
        hq=host_windows[host];ips=host_ips[host];users=host_users[host]
        while hq and now-time(hq[0])>timedelta(minutes=10):
            old=hq.popleft()
            for counter,field in ((ips,'ip'),(users,'user')):
                counter[old[field]]-=1
                if not counter[old[field]]:del counter[old[field]]
        hq.append(e);ips[e['ip']]+=1;users[e['user']]+=1
        if len(hq)>=12 and len(ips)>=6 and len(users)>=2 and (host not in last_distributed or now-last_distributed[host]>=timedelta(minutes=10)):
            emit('distributed_authentication',e,f'{len(hq)} failures from {len(ips)} sources across {len(users)} accounts within 10 minutes',list(hq)[-100:]);last_distributed[host]=now
    uploads={}
    for e in ordered:
        request=e.get('request','');parts=request.split(' ',1)
        if len(parts)!=2 or not e.get('host') or e['ip']=='UNKNOWN':continue
        method,target=parts;target=target.rsplit(' HTTP/',1)[0]
        try:parsed=urlsplit(unquote_plus(unquote_plus(target)))
        except ValueError:continue
        key=(e['host'],e['ip'])
        code=e.get('http_status')
        if method.upper()=='POST' and re.search(r'/(?:upload|uploads)(?:/|$)',parsed.path,re.I) and isinstance(code,int) and 200<=code<300:
            uploads[key]=e;continue
        prior=uploads.get(key)
        if prior and 0<=(time(e)-time(prior)).total_seconds()<=600 and re.search(r'/uploads/[^/]+\.(?:php|jsp|aspx?)$',parsed.path,re.I) and any(k.lower() in {'cmd','command','exec'} for k in parse_qs(parsed.query)):
            emit('upload_command_request',e,'Accepted upload followed by a command-parameter request to an uploaded script; execution is unverified',[prior,e],'high');uploads.pop(key,None)
    # Command findings are restricted to actual command fields, never raw quoted prose.
    risky=defaultdict(list)
    for f in findings:
        if f['type'] in {'account_takeover','post_auth_download_execute'}:
            risky[(f.get('host'),f['user'])].append(f)
    line_index={e["line"]:e for e in events}
    risk_times={}
    for key,items in risky.items():
        items.sort(key=lambda f:f["timestamp"])
        risk_times[key]=[datetime.fromisoformat(f["timestamp"]) for f in items]
    sessions=defaultdict(list)
    for e in ordered:
        command=e.get('command','')
        if not command or e['action'].lower() not in {'privilege','process'}:continue
        host=e.get('host');user=e['user'];key=(host,user);index=bisect_right(risk_times.get(key,[]),time(e))-1
        context=[risky[key][index]] if index>=0 and (time(e)-risk_times[key][index]).total_seconds()<=600 else []
        if re.search(r'^\s*(?:/\S*/)?(?:cat|head|tail|less|more|cp)\b.*(?:^|\s)/etc/shadow(?:\s|$)',command):
            emit('sensitive_file_read',e,'Command requests reading or copying /etc/shadow; command outcome and authorization are unknown')
        if context and re.search(r'^\s*(?:/\S*/)?(?:useradd|adduser)\b',command):
            emit('account_creation_context',e,'Account creation command follows suspicious authentication/execution context', [e]+[line_index[n] for n in context[-1]['evidence_lines'] if n in line_index],'high')
        if context and re.search(r'\bcrontab\s+-e\b',command):
            emit('cron_change_context',e,'Cron editor invoked after suspicious authentication/execution; no job contents observed',[e]+[line_index[n] for n in context[-1]['evidence_lines'] if n in line_index])
        if re.search(r'^\s*(?:/\S*/)?history\s+-c\b',command):emit('history_clearing',e,'Command requests shell history clearing; review authorization')
        if re.search(r'^\s*(?:/\S*/)?(?:rm|truncate|shred)\b.*(?:/var/log/|/var/log\b)',command) or re.search(r'\bjournalctl\b.*--vacuum-time=(?:1s|0)\b',command):
            emit('log_clearing',e,'Command requests log removal or aggressive journal pruning; review maintenance policy')
        if host:sessions[(host,user,e.get('tty'),e.get('session_pid'),e['ip'])].append(e)
    approved=[ip_network(n) for n in config.TRUSTED_TRANSFER_NETWORKS]
    private=[ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','fc00::/7','fe80::/10','::1/128')]
    already={f['line'] for f in findings if f['type']=='data_exfiltration'}
    for commands in sessions.values():
        archive=None;path=None
        for e in commands:
            candidate=archive_output(e['command'])
            if candidate:archive=e;path=candidate;continue
            if not archive or e['line'] in already or time(e)-time(archive)>timedelta(seconds=600) or upload_input(e['command'])!=path:continue
            # Only simple outbound scp/rsync and curl upload destinations are supported.
            match=re.search(r'(?:@|https?://)((?:\d{1,3}\.){3}\d{1,3})(?=[:/\s]|$)',e['command'])
            if not match:continue
            try:ip=ip_address(match.group(1))
            except ValueError:continue
            if ip.is_unspecified or ip.is_multicast or any(ip in network for network in private+approved if network.version==ip.version):continue
            emit('archive_transfer_review',e,'Archive followed by transfer command to a non-local IP; destination reputation and transferred bytes are unknown',[archive,e]);archive=None
    return output
