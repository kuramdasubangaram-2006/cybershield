# CyberShield Windows event agent (foreground MVP).
# Collects only a fixed set of Windows Security and Defender event IDs.
# It never sends usernames or complete event messages and accepts no remote commands.

[CmdletBinding()]
param(
    [ValidateSet('https://cybershield-kb.onrender.com/api/agent/events')]
    [string]$Endpoint = 'https://cybershield-kb.onrender.com/api/agent/events',
    [ValidateRange(5, 300)]
    [int]$IntervalSeconds = 15
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$AgentVersion = '1.1.0'

Write-Host 'CyberShield Windows monitoring agent' -ForegroundColor Cyan
Write-Host 'This agent sends only selected Windows event metadata over HTTPS.'
Write-Host 'It does not send usernames, full event messages, or accept remote commands.'
Write-Host 'Run this window as Administrator. Press Ctrl+C to stop.'
try {
    [void](Read-Host 'In CyberShield click Copy token, then press Enter here')
    $agentToken = ([string](Get-Clipboard -Raw)).Trim()
}
catch {
    throw 'Could not read the clipboard. Copy the device token in CyberShield and try again.'
}
if ($agentToken -notmatch '^[A-Za-z0-9_-]{32,128}$') {
    throw 'The clipboard does not contain a valid device token. Copy it with the CyberShield Copy token button and try again.'
}

$stateDirectory = Join-Path $env:LOCALAPPDATA 'CyberShield'
$statePath = Join-Path $stateDirectory 'windows-agent-state.json'
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$state = @{ Cursors = @{} }
if (Test-Path -LiteralPath $statePath) {
    try {
        $loaded = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($loaded -and $loaded.Cursors) {
            foreach ($key in @('Security', 'Defender')) {
                $savedCursor = $loaded.Cursors.$key
                if ($null -ne $savedCursor) { $state.Cursors[$key] = [long]$savedCursor }
            }
        }
    }
    catch { Write-Warning 'Saved event cursor could not be read; it will be initialized again.' }
}

$channels = @(
    @{ Name = 'Security'; Key = 'Security'; Ids = @(4624, 4625, 1102, 5156, 5157); IdExpression = 'EventID=4624 or EventID=4625 or EventID=1102 or EventID=5156 or EventID=5157' },
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; Key = 'Defender'; Ids = @(1116, 1117); IdExpression = 'EventID=1116 or EventID=1117' }
)
$headers = @{ Authorization = "Bearer $agentToken" }

function Save-AgentState {
    $temporaryPath = "$statePath.tmp"
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporaryPath -Encoding utf8
    Move-Item -LiteralPath $temporaryPath -Destination $statePath -Force
}

function Get-SourceIp {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record)
    try {
        [xml]$eventXml = $Record.ToXml()
        $ipNode = $eventXml.Event.EventData.Data | Where-Object { $_.GetAttribute('Name') -eq 'IpAddress' } | Select-Object -First 1
        if ($ipNode) {
            $value = ([string]$ipNode.InnerText).Trim()
            if ($value -and $value -ne '-') { return $value }
        }
    }
    catch { }
    return $null
}

function Get-EventField {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record, [string]$FieldName)
    try {
        [xml]$eventXml = $Record.ToXml()
        $field = $eventXml.Event.EventData.Data | Where-Object { $_.GetAttribute('Name') -eq $FieldName } | Select-Object -First 1
        if ($field) { return ([string]$field.InnerText).Trim() }
    }
    catch { }
    return $null
}

function Send-AgentBatch {
    param([object[]]$Events, [string[]]$WarningChannels)
    $body = @{ agent_version = $AgentVersion; warning_channels = @($WarningChannels); events = @($Events) } | ConvertTo-Json -Depth 5 -Compress
    Invoke-RestMethod -Method Post -Uri $Endpoint -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 20 | Out-Null
}

foreach ($channel in $channels) {
    if (-not $state.Cursors.ContainsKey($channel.Key)) {
        try {
            $latest = Get-WinEvent -LogName $channel.Name -MaxEvents 1 -ErrorAction Stop
            $state.Cursors[$channel.Key] = [long]$latest.RecordId
        }
        catch {
            $state.Cursors[$channel.Key] = 0
            Write-Warning "Cannot read '$($channel.Name)'. Run PowerShell as Administrator and confirm the log exists."
        }
    }
}
Save-AgentState

while ($true) {
    $batch = [System.Collections.Generic.List[object]]::new()
    $warningChannels = [System.Collections.Generic.List[string]]::new()
    $nextCursors = @{}
    foreach ($channel in $channels) {
        $cursor = [long]$state.Cursors[$channel.Key]
        $nextCursors[$channel.Key] = $cursor
        try {
            $xpath = "*[System[($($channel.IdExpression)) and (EventRecordID > $cursor)]]"
            $records = @(Get-WinEvent -LogName $channel.Name -FilterXPath $xpath -MaxEvents 100 -ErrorAction Stop | Sort-Object RecordId)
            foreach ($record in $records) {
                $networkEvent = $record.Id -in @(5156, 5157)
                $directionValue = if ($networkEvent) { Get-EventField -Record $record -FieldName 'Direction' } else { $null }
                $direction = switch ($directionValue) {
                    '%%14592' { 'Inbound'; break }
                    '%%14593' { 'Outbound'; break }
                    default { $null }
                }
                $protocolValue = if ($networkEvent) { Get-EventField -Record $record -FieldName 'Protocol' } else { $null }
                $sourcePortValue = if ($networkEvent) { Get-EventField -Record $record -FieldName 'SourcePort' } else { $null }
                $destinationPortValue = if ($networkEvent) { Get-EventField -Record $record -FieldName 'DestPort' } else { $null }
                $batch.Add(@{
                    channel = $channel.Name
                    event_id = [int]$record.Id
                    record_id = [string]$record.RecordId
                    event_time = $record.TimeCreated.ToUniversalTime().ToString('o')
                    source_ip = if ($record.Id -in @(4624, 4625)) { Get-SourceIp -Record $record } elseif ($networkEvent) { Get-EventField -Record $record -FieldName 'SourceAddress' } else { $null }
                    source_port = if ($networkEvent -and $sourcePortValue -match '^\d{1,5}$') { [int]$sourcePortValue } else { $null }
                    destination_ip = if ($networkEvent) { Get-EventField -Record $record -FieldName 'DestAddress' } else { $null }
                    destination_port = if ($networkEvent -and $destinationPortValue -match '^\d{1,5}$') { [int]$destinationPortValue } else { $null }
                    network_protocol = if ($networkEvent -and $protocolValue -match '^\d{1,3}$') { $protocolValue } else { $null }
                    network_direction = $direction
                })
                $nextCursors[$channel.Key] = [long]$record.RecordId
            }
        }
        catch {
            $noMatchingEvents = $_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or
                $_.Exception.Message -match 'No events were found that match'
            if (-not $noMatchingEvents) {
                $warningChannels.Add($channel.Key)
                Write-Warning "Could not read new events from '$($channel.Name)': $($_.Exception.Message)"
            }
        }
    }

    try {
        # Empty batches are heartbeats, allowing the dashboard to show the device as online.
        Send-AgentBatch -Events $batch.ToArray() -WarningChannels $warningChannels.ToArray()
        foreach ($key in $nextCursors.Keys) { $state.Cursors[$key] = $nextCursors[$key] }
        Save-AgentState
        if ($batch.Count -gt 0) { Write-Host "Sent $($batch.Count) selected event(s) at $(Get-Date -Format 'HH:mm:ss')." -ForegroundColor Green }
        else { Write-Host "Connected; no new selected events. $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor DarkGray }
    }
    catch {
        Write-Warning "CyberShield could not be reached; event cursors were not advanced: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $IntervalSeconds
}
