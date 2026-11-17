param(
    [Parameter(Mandatory=$true)][string]$Path,
    [ValidateRange(1,50000)][int]$MaxEvents = 1000
)
# Run manually on a machine where you are authorized to read Security events.
# Event data can contain accounts, addresses, and command lines; keep the export private.
$ErrorActionPreference = 'Stop'
$rows = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624,4625,4688 } -MaxEvents $MaxEvents | ForEach-Object {
    [xml]$eventXml = $_.ToXml()
    $fields = @{}
    foreach ($entry in $eventXml.Event.EventData.Data) { $fields[[string]$entry.Name] = [string]$entry.'#text' }
    @{
        System = @{ EventID=[int]$_.Id; Computer=[string]$_.MachineName; TimeCreated=@{SystemTime=$_.TimeCreated.ToUniversalTime().ToString('o')} }
        EventData = $fields
    } | ConvertTo-Json -Depth 6 -Compress
}
$rows | Set-Content -LiteralPath $Path -Encoding utf8
Write-Output "Exported $($rows.Count) events to $Path"
