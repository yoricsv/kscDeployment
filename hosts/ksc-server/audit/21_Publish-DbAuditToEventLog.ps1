<#
.SYNOPSIS
    Forwards MariaDB audit file records into the Windows event log.

.DESCRIPTION
    Worker script of the forwarder: reads new lines of server_audit.log,
    parses them into fields and writes them into the Windows event log, from
    which MP 10 Collector picks the events up.

    It is deployed and registered in the Task Scheduler by
    20_Install-AuditForwarder.ps1; a manual run is only needed for diagnostics.

    Details:
      * the read position is kept in a state file, so records are never
        forwarded twice;
      * file rotation by the plugin is detected by a decrease in file size:
        the remainder is read from server_audit.log.1, after which reading
        continues from the beginning of the new file;
      * parallel runs are blocked by a mutex;
      * every AuditHeartbeatMin minutes a service record (event id 1100) is
        written so that the SIEM can monitor source availability.

    Plugin record format:
        timestamp,serverhost,username,host,connectionid,queryid,operation,database,object,retcode

.PARAMETER StateFile
    State file (read position). Default:
    C:\ProgramData\KscDeployment\audit-forwarder-state.json.

.PARAMETER MaxBytesPerRun
    Maximum amount of the audit file processed in a single run (burst
    protection). The remainder is read by the next run. Default 64 MB.

.EXAMPLE
    .\21_Publish-DbAuditToEventLog.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$StateFile = 'C:\ProgramData\KscDeployment\audit-forwarder-state.json',
    [int]$MaxBytesPerRun = 64MB
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"

$auditFile = Join-Path $KSC.AuditLogDir $KSC.AuditFileName
$logName = $KSC.AuditWinLogName
$source = $KSC.AuditWinLogSource

# Maximum Windows event message size is 31 839 characters.
$messageLimit = 30000

# Event ids: sessions 1001-1003, statements 1010-1013, objects 1020,
# service events 1100 (health check) and 1101 (forwarder error).
$eventIds = @{
    CONNECT             = 1001
    DISCONNECT          = 1002
    FAILED_CONNECT      = 1003
    QUERY               = 1010
    QUERY_DDL           = 1011
    QUERY_DML           = 1012
    QUERY_DML_NO_SELECT = 1012
    QUERY_DCL           = 1013
    TABLE               = 1020
    READ                = 1020
    WRITE               = 1020
    CREATE              = 1011
    ALTER               = 1011
    DROP                = 1011
    RENAME              = 1011
}

$recordPattern = [regex]'^(?<ts>\d{8}\s\d{2}:\d{2}:\d{2}),(?<srvhost>[^,]*),(?<user>[^,]*),(?<host>[^,]*),(?<connid>\d*),(?<queryid>\d*),(?<op>[A-Z_]+),(?<db>[^,]*),(?<obj>.*),(?<ret>-?\d+)\s*$'

# ------------------------------------------------------------------ State

function Read-ForwarderState {
    if (Test-Path $StateFile) {
        try { return Get-Content $StateFile -Raw | ConvertFrom-Json }
        catch { Write-Verbose 'State file is corrupted, reading will start at the end of the audit file.' }
    }
    $size = if (Test-Path $auditFile) { (Get-Item $auditFile).Length } else { 0 }
    [pscustomobject]@{ Position = $size; LastHeartbeat = '1970-01-01T00:00:00'; Forwarded = 0 }
}

function Save-ForwarderState {
    param($State)
    $dir = Split-Path $StateFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $State | ConvertTo-Json -Depth 3 | Set-Content $StateFile -Encoding UTF8
}

# ------------------------------------------------------------------ Parsing and writing

function ConvertTo-AuditEvent {
    <# Audit file line -> object with security event fields (Order No. 130, item 2). #>
    param([string]$Line)

    $m = $recordPattern.Match($Line)
    if (-not $m.Success) { return $null }

    $ts = $m.Groups['ts'].Value
    $parsed = [datetime]::MinValue
    [void][datetime]::TryParseExact($ts, 'yyyyMMdd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$parsed)

    $op = $m.Groups['op'].Value
    $ret = [int]$m.Groups['ret'].Value
    $srcHost = $m.Groups['host'].Value

    $id = if ($eventIds.ContainsKey($op)) { $eventIds[$op] } else { 1099 }
    if ($op -eq 'CONNECT' -and $ret -ne 0) { $id = $eventIds['FAILED_CONNECT'] }

    # The plugin marks every statement as QUERY: the class is derived from the
    # statement text, otherwise privilege changes and schema operations are
    # indistinguishable from selects. The text is only classified, never executed.
    if ($id -eq $eventIds['QUERY']) {
        $sql = $m.Groups['obj'].Value.TrimStart("'", ' ', "`t")
        switch -Regex ($sql) {
            '^(?i)(GRANT|REVOKE|CREATE\s+USER|DROP\s+USER|ALTER\s+USER|RENAME\s+USER|SET\s+PASSWORD|CREATE\s+ROLE|DROP\s+ROLE)' { $id = $eventIds['QUERY_DCL']; break }
            '^(?i)(CREATE|ALTER|DROP|TRUNCATE|RENAME)\b' { $id = $eventIds['QUERY_DDL']; break }
            '^(?i)(INSERT|UPDATE|DELETE|REPLACE|LOAD\s+DATA|CALL|LOCK|UNLOCK)\b' { $id = $eventIds['QUERY_DML']; break }
        }
    }

    $type = if ($id -eq 1003 -or $ret -ne 0) { 'Warning' } else { 'Information' }

    $message = @(
        "MariaDB audit: $op"
        "event_time=$(if ($parsed -ne [datetime]::MinValue) { $parsed.ToString('yyyy-MM-dd HH:mm:ss') } else { $ts })"
        "db_user=$($m.Groups['user'].Value)"
        "src_host=$srcHost"
        "server_host=$($m.Groups['srvhost'].Value)"
        "db_host=$($KSC.AuditDbHost)"
        "database=$($m.Groups['db'].Value)"
        "object=$($m.Groups['obj'].Value)"
        "operation=$op"
        "connection_id=$($m.Groups['connid'].Value)"
        "query_id=$($m.Groups['queryid'].Value)"
        "return_code=$ret"
        "raw=$Line"
    ) -join "`r`n"

    if ($message.Length -gt $messageLimit) { $message = $message.Substring(0, $messageLimit) + '...[truncated]' }

    [pscustomobject]@{ EventId = $id; EntryType = $type; Message = $message }
}

function Write-AuditEvent {
    param([int]$EventId, [string]$EntryType, [string]$Message)
    Write-EventLog -LogName $logName -Source $source -EventId $EventId -EntryType $EntryType -Message $Message
}

function Read-AuditTail {
    <#
        Reads complete lines of the file starting at byte position $From.
        Returns the lines and the new position - the end of the last line
        break, so a line still being written by the plugin is read on the
        next run.
    #>
    param([string]$Path, [long]$From)

    $empty = [pscustomobject]@{ Lines = @(); Position = $From }
    if (-not (Test-Path $Path)) { return $empty }

    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $start = if ($From -gt $fs.Length) { 0 } else { $From }
        $available = $fs.Length - $start
        if ($available -le 0) { return [pscustomobject]@{ Lines = @(); Position = $start } }

        # Per-run volume limit: the remainder is read by the next run.
        $toRead = [int][Math]::Min($available, $MaxBytesPerRun)
        [void]$fs.Seek($start, 'Begin')
        $buffer = New-Object byte[] $toRead
        $read = $fs.Read($buffer, 0, $toRead)

        $lastLf = [Array]::LastIndexOf($buffer, [byte]10, $read - 1)
        if ($lastLf -lt 0) { return [pscustomobject]@{ Lines = @(); Position = $start } }

        $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $lastLf + 1)
        $lines = $text -split "`r?`n" | Where-Object { $_ -ne '' }
        [pscustomobject]@{ Lines = $lines; Position = $start + $lastLf + 1 }
    }
    finally { $fs.Dispose() }
}

# ------------------------------------------------------------------ Main loop

$mutex = New-Object Threading.Mutex($false, 'Global\KscDbAuditForwarder')
if (-not $mutex.WaitOne(0)) {
    Write-Verbose 'Previous run is still in progress - exiting.'
    return
}

try {
    if (-not [Diagnostics.EventLog]::SourceExists($source)) {
        throw "Event source '$source' is not registered. Run 20_Install-AuditForwarder.ps1."
    }

    $state = Read-ForwarderState
    $sent = 0
    $skipped = 0

    # Rotation: the file is shorter than the stored position - the remainder is in .1
    if ((Test-Path $auditFile) -and (Get-Item $auditFile).Length -lt $state.Position) {
        $rotated = "$auditFile.1"
        if (Test-Path $rotated) {
            $tail = Read-AuditTail -Path $rotated -From $state.Position
            foreach ($line in $tail.Lines) {
                $ev = ConvertTo-AuditEvent -Line $line
                if ($ev) { Write-AuditEvent -EventId $ev.EventId -EntryType $ev.EntryType -Message $ev.Message; $sent++ }
                elseif ($line) { $skipped++ }
            }
        }
        $state.Position = 0
    }

    $batch = Read-AuditTail -Path $auditFile -From $state.Position
    foreach ($line in $batch.Lines) {
        $ev = ConvertTo-AuditEvent -Line $line
        if ($ev) { Write-AuditEvent -EventId $ev.EventId -EntryType $ev.EntryType -Message $ev.Message; $sent++ }
        elseif ($line) { $skipped++ }
    }
    $state.Position = $batch.Position
    $state.Forwarded = [int]$state.Forwarded + $sent

    $lastHb = [datetime]::Parse($state.LastHeartbeat)
    if ((Get-Date) -gt $lastHb.AddMinutes($KSC.AuditHeartbeatMin)) {
        $hb = @(
            'MariaDB audit: source health check'
            "db_host=$($KSC.AuditDbHost)"
            "audit_file=$auditFile"
            "position=$($state.Position)"
            "forwarded_total=$($state.Forwarded)"
            "forwarded_now=$sent"
            "unparsed_now=$skipped"
        ) -join "`r`n"
        Write-AuditEvent -EventId 1100 -EntryType 'Information' -Message $hb
        $state.LastHeartbeat = (Get-Date).ToString('s')
    }

    Save-ForwarderState -State $state
    Write-Verbose "Records forwarded: $sent, unparsed lines: $skipped, position: $($state.Position)."
}
catch {
    if ([Diagnostics.EventLog]::SourceExists($source)) {
        Write-EventLog -LogName $logName -Source $source -EventId 1101 -EntryType 'Error' `
            -Message "Database audit forwarder error: $($_.Exception.Message)"
    }
    throw
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
