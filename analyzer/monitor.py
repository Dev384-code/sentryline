"""Explicit-consent, single-process Windows Security collector. No automatic startup."""
import json
import os
import subprocess
import tempfile
import threading
import time
from analyzer.monitor_metrics import summarize
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import Path
from analyzer import storage
import config

def now():
    return datetime.now(timezone.utc).isoformat()

def state():
    with storage.connection() as db:
        db.execute("CREATE TABLE IF NOT EXISTS monitor_state (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        row = db.execute("SELECT payload FROM monitor_state WHERE id=1").fetchone()
    return json.loads(row[0]) if row else dict(checkpoint=None, rows=[], notifications=[], last_poll=None, latest_run=None, error=None, gaps=[])

def persist(value):
    with storage.connection() as db:
        db.execute("CREATE TABLE IF NOT EXISTS monitor_state (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        db.execute("INSERT OR REPLACE INTO monitor_state VALUES (1,?)", (json.dumps(value),))

class WindowsReader:
    def __call__(self, checkpoint, lookback_minutes=0, diagnostic=False):
        if os.name != 'nt':
            raise RuntimeError('Local monitoring requires Windows. File uploads still work on this platform.')
        command = ['powershell.exe','-NoProfile','-NonInteractive','-File',str(config.BASE_DIR/'scripts/collect_windows.ps1')]
        if diagnostic:
            command += ['-Diagnostic']
        if lookback_minutes:
            command += ['-InitialLookbackMinutes',str(int(lookback_minutes))]
        if checkpoint is not None:
            command += ['-Checkpoint',str(int(checkpoint))]
        try:
            result = subprocess.run(command,capture_output=True,timeout=25,encoding='utf-8-sig',errors='replace',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError('Windows read timed out after 25 seconds. Collection is delayed; check Event Log service health.') from exc
        except FileNotFoundError as exc:
            raise RuntimeError('Windows PowerShell was not found. This collector requires powershell.exe.') from exc
        if result.returncode:
            detail=result.stderr[-800:]
            if 'SENTRYLINE_ACCESS_DENIED' in detail:
                message='Security log access denied. Run the server with an authorized Event Log Readers account or, if you are authorized, from an administrator terminal.'
            elif 'PSSecurityException' in detail or 'UnauthorizedAccess' in detail or 'running scripts is disabled' in detail:
                message='PowerShell blocked the collector script. Review your organization execution policy; this tool does not change it.'
            else:
                message='Windows collector failed. Review the diagnostic details and Windows Event Log service.'
            raise RuntimeError(message+' '+detail)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError('Windows collector did not return valid JSON. Check PowerShell startup and script output.') from exc
        if not isinstance(value,dict) or not isinstance(value.get('rows'),list):
            raise ValueError('Collector returned invalid data')
        return value

class Monitor:
    def __init__(self, analyze, reader=None):
        self.analyze=analyze
        self.reader=reader or WindowsReader()
        self.lock=threading.RLock()
        self.poll_lock=threading.Lock()
        self.poll_started=None
        self.stop_event=threading.Event()
        self.thread=None
    def status(self):
        with self.lock:
            value=state()
            value['metrics']=summarize(value.pop('rows',[]))
            value['running']=bool(self.thread and self.thread.is_alive() and not self.stop_event.is_set())
            value['window_hours']=value.get('window_hours',24)
            value['event_limit']=10000
            value['interval_seconds']=value.get('interval_seconds',30)
            value['collecting']=self.poll_started is not None
            value['poll_elapsed_seconds']=round(time.monotonic()-self.poll_started,1) if self.poll_started is not None else 0
            value['health']='error' if value.get('error') else ('collecting' if value['collecting'] else 'waiting_for_events' if value['running'] and not value.get('retained_events') else 'running' if value['running'] else 'stopped')
            return value
    def start(self, consent, window_hours=24, interval_seconds=30, lookback_minutes=0):
        if consent is not True:
            raise ValueError('Explicit owner authorization is required')
        if lookback_minutes not in {0,10}:
            raise ValueError('Choose start now or the last 10 minutes')
        if window_hours not in {1,6,24} or interval_seconds not in {15,30,60}:
            raise ValueError('Choose an allowed retention window and poll interval')
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError('Collector already running or stopping')
            value=state(); value['consent_at']=now(); value['error']=None;value['window_hours']=window_hours;value['interval_seconds']=interval_seconds;value['lookback_minutes']=lookback_minutes;persist(value)
            self.stop_event.clear()
            self.thread=threading.Thread(target=self.loop,name='sentryline-monitor',daemon=True)
            self.thread.start()
    def stop(self):
        self.stop_event.set()
        # Finish the current bounded poll; no further reads are scheduled.
    def loop(self):
        while not self.stop_event.is_set():
            try:
                self.poll()
            except Exception as exc:
                with self.lock:
                    value=state();value['error']=str(exc)[:1200];value['last_poll']=now();persist(value)
            self.stop_event.wait(state().get('interval_seconds',30))
    def poll(self):
        with self.poll_lock:
            self.poll_started=time.monotonic()
            try:
                return self._poll()
            finally:
                self.poll_started=None

    def diagnose(self,consent):
        if consent is not True:
            raise ValueError('Explicit owner authorization is required')
        try:
            result=WindowsReader()(None,diagnostic=True)
            diagnostic=dict(at=now(),ok=True,details=result.get('diagnostic',{}))
        except (RuntimeError,ValueError) as exc:
            diagnostic=dict(at=now(),ok=False,error=str(exc))
        with self.lock:
            value=state();value['diagnostic']=diagnostic;persist(value)
        return diagnostic

    def _poll(self):
        value=state()
        batch=self.reader(value['checkpoint'],value.get('lookback_minutes',0)) if isinstance(self.reader,WindowsReader) else self.reader(value['checkpoint'])
        if self.stop_event.is_set():
            return
        if not isinstance(batch.get('checkpoint'),int) or batch['checkpoint'] < 0:
            raise ValueError('Invalid collector checkpoint')
        if value['checkpoint'] is not None and batch['checkpoint']<value['checkpoint'] and not batch.get('reset'):
            raise ValueError('Collector checkpoint moved backwards without a reset')
        rows=batch['rows']
        if batch.get('gap'):
            value['gaps']=(value.get('gaps',[])+[dict(at=now(),message=batch['gap'])])[-20:]
        previous=[] if batch.get('reset') else value['rows']
        merged={row['record_id']:row for row in previous}
        for row in rows:
            if not isinstance(row.get('record_id'),int) or not isinstance(row.get('event'),dict):
                raise ValueError('Invalid event record')
            merged[row['record_id']]=row
        cutoff=datetime.now(timezone.utc)-timedelta(hours=value.get('window_hours',24))
        retained=[row for row in merged.values() if datetime.fromisoformat(row['event']['System']['TimeCreated']['SystemTime'].replace('Z','+00:00'))>=cutoff]
        retained.sort(key=lambda row:row['record_id'])
        # Bound source bytes as well as count; explicitly disclose all pruning.
        removed=len(merged)-len(retained)
        removed+=max(0,len(retained)-10000)
        retained=retained[-10000:]
        encoded=[json.dumps(row['event'],ensure_ascii=True) for row in retained]
        total=sum(len(line.encode())+1 for line in encoded)
        while encoded and total>config.MAX_UPLOAD_BYTES:
            total-=len(encoded.pop(0).encode())+1; retained.pop(0);removed+=1
        value['retention_note']=f"Rolling {value.get('window_hours',24)} hours, at most 10,000 events and 5 MiB; older/excess evidence expires."
        value['retained_events']=len(retained)
        retained_ids={row['record_id'] for row in retained}
        if removed and any(datetime.fromisoformat(row['event']['System']['TimeCreated']['SystemTime'].replace('Z','+00:00'))>=cutoff and row['record_id'] not in retained_ids for row in merged.values()):
            value['gaps']=(value['gaps']+[dict(at=now(),message='Rolling event capacity exceeded; oldest events removed.')])[-20:]
        if rows or batch.get('reset') or retained != previous:
            with tempfile.TemporaryDirectory(prefix='sentryline-monitor-',dir=config.DATABASE_FILE.parent) as directory:
                path=Path(directory)/'windows-live.jsonl';path.write_text('\n'.join(encoded)+('\n' if encoded else ''),encoding='utf-8')
                result=self.analyze(path,source='Windows Security - rolling local monitor')
            value['latest_run']=result['analysis_id']
            known={n['key'] for n in value['notifications']}
            for alert in result['alerts']:
                if alert['severity'] not in {'high','critical'}:continue
                identity={k:v for k,v in alert.items() if k not in {'id','created_at','status','line','evidence_lines'}}
                key=sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
                if key not in known:
                    value['notifications'].append(dict(key=key,at=now(),severity=alert['severity'],message=alert.get('message',alert['type']),run=result['analysis_id']))
                    known.add(key)
            value['notifications']=value['notifications'][-100:]
        value.update(rows=retained,checkpoint=batch['checkpoint'],last_poll=now(),last_success=now(),error=None,
                     last_batch_events=len(rows),channel_head=batch.get('head',batch['checkpoint']),
                     backlog_records=max(0,batch.get('head',batch['checkpoint'])-batch['checkpoint']),
                     records_scanned=batch.get('scanned',len(rows)))
        with self.lock:
            current=state()
            if current.get('diagnostic'):value['diagnostic']=current['diagnostic']
            persist(value)
