"""Exercise the real PowerShell collector against in-process mocked Windows records."""
import json,shutil,subprocess
from pathlib import Path
import pytest
POWER_SHELL=shutil.which('powershell.exe')
pytestmark=pytest.mark.skipif(not POWER_SHELL,reason='Windows PowerShell unavailable')
HARNESS=Path(__file__).parent/'fixtures/collector_harness.ps1'
def run(mode):
    result=subprocess.run([POWER_SHELL,'-NoProfile','-NonInteractive','-File',str(HARNESS),'-Mode',mode],capture_output=True,encoding='utf-8-sig',timeout=20)
    assert result.returncode==0,result.stderr
    return json.loads(result.stdout)
def test_first_start_checkpoints_without_replaying():
    result=run('initial');assert result['checkpoint']==4;assert result['rows']==[]
def test_resume_reads_ascending_without_skipping():
    result=run('resume');assert [r['record_id'] for r in result['rows']]==[3,4];assert result['checkpoint']==4
    assert result['scanned']==2
def test_recent_backfill_contains_supported_records():
    result=run('recent');assert [r['record_id'] for r in result['rows']]==[2,3,4];assert result['scanned']==4
def test_diagnostic_and_empty_channel():
    result=run('diagnostic');assert result['diagnostic']['recent_counts']['4625']==2
    assert result['diagnostic']['recent_counts']['4624']==1
    result=run('empty');assert result['checkpoint']==0;assert result['rows']==[]
