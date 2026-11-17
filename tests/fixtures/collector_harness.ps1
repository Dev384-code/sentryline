param([ValidateSet('initial','resume','recent','diagnostic','empty')][string]$Mode)
# Override Get-WinEvent in this process only. This harness never reads machine logs.
function Get-WinEvent {
 [CmdletBinding()]
 param([string]$ListLog,[string]$LogName,[string]$FilterXPath,[switch]$Oldest,[int]$MaxEvents)
 if ($ListLog) { return [pscustomobject]@{IsEnabled=$true;RecordCount=4} }
 if ($Mode -eq 'empty') { return }
 $rows = @()
 foreach ($i in 1..4) {
  $id = if ($i -eq 1) { 9999 } elseif ($i -eq 4) { 4624 } else { 4625 }
  $event = [pscustomobject]@{RecordId=[long]$i;Id=$id;MachineName='TEST';TimeCreated=[datetime]::UtcNow.AddSeconds(-5)}
  $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.1</Data><Data Name="LogonType">3</Data></EventData></Event>' }
  $rows += $event
 }
 if ($FilterXPath -match 'EventRecordID > (\d+)') { $cursor=[long]$Matches[1];$rows=@($rows | Where-Object RecordId -gt $cursor) }
 if ($FilterXPath -match 'EventRecordID <= (\d+)') { $head=[long]$Matches[1];$rows=@($rows | Where-Object RecordId -le $head) }
 if ($FilterXPath -match 'EventID=4624') { $rows=@($rows | Where-Object Id -in @(4624,4625,4688)) }
 if (-not $Oldest) { $rows=@($rows | Sort-Object RecordId -Descending) }
 return @($rows | Select-Object -First $MaxEvents)
}
$collector = Join-Path $PSScriptRoot '../../scripts/collect_windows.ps1'
if ($Mode -eq 'diagnostic') { & $collector -Diagnostic }
elseif ($Mode -eq 'resume') { & $collector -Checkpoint 2 }
elseif ($Mode -eq 'recent') { & $collector -InitialLookbackMinutes 10 }
else { & $collector }
