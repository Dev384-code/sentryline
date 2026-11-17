param(
 [long]$Checkpoint = -1,
 [ValidateSet(0,10)][int]$InitialLookbackMinutes = 0,
 [switch]$Diagnostic
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
function Read-Events([string]$Query, [int]$Limit, [bool]$Ascending) {
 try {
  if ($Ascending) { return @(Get-WinEvent -LogName Security -FilterXPath $Query -Oldest -MaxEvents $Limit) }
  return @(Get-WinEvent -LogName Security -FilterXPath $Query -MaxEvents $Limit)
 } catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
  throw
 }
}
try {
 $log = Get-WinEvent -ListLog Security
 $latest = @(Read-Events '*' 1 $false)
} catch {
 if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match 'unauthorized|denied') {
  throw 'SENTRYLINE_ACCESS_DENIED: The server account cannot read the Windows Security log.'
 }
 throw
}
$head = if ($latest.Count) { [long]$latest[0].RecordId } else { 0 }
if ($Diagnostic) {
 $recent = @(Read-Events '*[System[(EventID=4624 or EventID=4625 or EventID=4688) and TimeCreated[timediff(@SystemTime) <= 600000]]]' 500 $false)
 $counts = @{ '4624'=0; '4625'=0; '4688'=0 }
 $commandLines = 0
 foreach ($event in $recent) {
  $counts[[string]$event.Id]++
  if ($event.Id -eq 4688) {
   [xml]$xml = $event.ToXml()
   foreach ($entry in $xml.Event.EventData.Data) { if ($entry.Name -eq 'CommandLine' -and [string]$entry.'#text') { $commandLines++ } }
  }
 }
 @{rows=@();checkpoint=$head;diagnostic=@{security_log_readable=$true;enabled=[bool]$log.IsEnabled;channel_records=$log.RecordCount;head=$head;recent_supported_events=$recent.Count;recent_counts=$counts;recent_scan_capped=($recent.Count -eq 500);process_events_with_command_line=$commandLines;note='Counts cover up to 500 supported events from the last 10 minutes. Zero events does not prove that audit policy is enabled.'}} | ConvertTo-Json -Depth 8 -Compress
 exit
}
$reset = $Checkpoint -gt $head
$gap = $null
if ($reset) { $gap = 'Security log record sequence reset. Evidence may have been cleared; collection restarted.'; $Checkpoint = -1 }
if ($Checkpoint -lt 0) {
 if ($InitialLookbackMinutes -eq 10 -and $head -gt 0) {
  $first = @(Read-Events '*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]' 1 $true)
  $Checkpoint = if ($first.Count) { [long]$first[0].RecordId - 1 } else { $head }
 } else { $Checkpoint = $head }
}
if ($head -eq 0) { @{rows=@();checkpoint=0;head=0;scanned=0;reset=$reset;gap=$gap} | ConvertTo-Json -Depth 8 -Compress; exit }
$oldest = @(Read-Events '*' 1 $true)
if ($oldest.Count -and $Checkpoint -lt ([long]$oldest[0].RecordId - 1)) { $gap = 'Security log retention removed records before the saved checkpoint. Some evidence is unavailable.' }
$xpath = "*[System[EventRecordID > $Checkpoint and EventRecordID <= $head]]"
$events = @(Read-Events $xpath 1000 $true)
$rows = [System.Collections.Generic.List[object]]::new()
$cursor = $Checkpoint
foreach ($event in $events) {
 $cursor = [long]$event.RecordId
 if ($event.Id -notin @(4624,4625,4688)) { continue }
 [xml]$xml = $event.ToXml()
 $fields = @{}
 foreach ($entry in $xml.Event.EventData.Data) { $fields[[string]$entry.Name] = [string]$entry.'#text' }
 $rows.Add(@{record_id=$cursor;event=@{System=@{EventID=[int]$event.Id;Computer=[string]$event.MachineName;TimeCreated=@{SystemTime=$event.TimeCreated.ToUniversalTime().ToString('o')}};EventData=$fields}})
}
@{rows=@($rows.ToArray());checkpoint=$cursor;head=$head;scanned=$events.Count;reset=$reset;gap=$gap} | ConvertTo-Json -Depth 8 -Compress
