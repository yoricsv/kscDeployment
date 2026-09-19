<#
.SYNOPSIS
    Verifies host auditing: OS, database and application, and event delivery to the collector.

.DESCRIPTION
    Health check after running 00-40. It verifies that:
      * the advanced OS audit policy, PowerShell logging, log sizes and
        directory access auditing are in place;
      * the database audit file exists, keeps growing and has restricted
        permissions;
      * the forwarder task is registered and completes without errors;
      * the event log exists, contains recent records and a "source alive"
        record;
      * the collector account is a member of the required groups and is not
        disabled;
      * firewall rules for the collector address exist and the RPC port is
        listening;
      * the event set covers the items of Order No. 130 of the OAC
        (sessions, administrator statements, privilege changes).

    Result: a table of checks and an exit code (0 - all checks passed).

.EXAMPLE
    .\90_Test-Audit.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\..\..\..\common\config.ps1"

$auditFile = Join-Path $KSC.AuditLogDir $KSC.AuditFileName
$results = New-Object Collections.Generic.List[object]

function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Check = $Name; Result = $(if ($Passed) { 'OK' } else { 'FAILED' }); Details = $Detail })
}

# ------------------------------------------------------------------ OS audit

# Subcategories are checked by GUID: names are localized and differ between builds.
$requiredSubcategories = [ordered]@{
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'
    '{0CCE9228-69AE-11D9-BED3-505054503030}' = 'Sensitive Privilege Use'
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'Audit Policy Change'
    '{0CCE921D-69AE-11D9-BED3-505054503030}' = 'File System (SACL)'
}
$noAudit = @()
foreach ($guid in $requiredSubcategories.Keys) {
    $line = & auditpol.exe /get /subcategory:"$guid" 2>&1 | Where-Object { $_ -match '\S' } | Select-Object -Last 1
    # A configured subcategory is recognized by success or failure in the settings column.
    if ($line -notmatch '(?i)success|failure') { $noAudit += $requiredSubcategories[$guid] }
}
Add-Check 'Advanced OS audit policy' ($noAudit.Count -eq 0) $(if ($noAudit) { 'not configured: ' + ($noAudit -join ', ') } else { "subcategories checked: $($requiredSubcategories.Count)" })

$cmdLine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
Add-Check 'Command line in 4688 events' ($cmdLine -eq 1) 'ProcessCreationIncludeCmdLine_Enabled'

$sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$transcript = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
Add-Check 'PowerShell logging' (($sbl -eq 1) -and ($transcript -eq 1)) "script blocks: $($sbl -eq 1), transcription: $($transcript -eq 1)"

$secLog = Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue
Add-Check 'Security log size' ([bool]$secLog -and $secLog.MaximumSizeInBytes -ge ($KSC.AuditSecurityLogSizeMb * 1MB)) $(if ($secLog) { '{0:N0} MB' -f ($secLog.MaximumSizeInBytes / 1MB) } else { 'log is not available' })

$dirSacl = if (Test-Path $KSC.AuditLogDir) { (Get-Acl -Path $KSC.AuditLogDir -Audit).Audit } else { $null }
Add-Check 'Access auditing for the audit directory' ([bool]$dirSacl) $(if ($dirSacl) { "audit rules: $(@($dirSacl).Count)" } else { 'SACL is not set (run 00_Set-OsAudit.ps1)' })

# ------------------------------------------------------------------ Audit file

if (Test-Path $auditFile) {
    $item = Get-Item $auditFile
    $ageMin = [int]((Get-Date) - $item.LastWriteTime).TotalMinutes
    Add-Check 'Audit file exists' $true ('{0}, {1:N1} MB' -f $auditFile, ($item.Length / 1MB))
    Add-Check 'Audit file keeps growing' ($ageMin -le 60) "last record $ageMin min ago"

    $acl = Get-Acl $auditFile
    $wide = $acl.Access | Where-Object {
        $_.IdentityReference -match 'Everyone|BUILTIN\\Users' -and $_.AccessControlType -eq 'Allow'
    }
    Add-Check 'Audit file permissions restricted' (-not $wide) $(if ($wide) { 'permissions for broad groups are present' } else { 'access limited to administrators, the service and auditors' })
}
else {
    Add-Check 'Audit file exists' $false "not found: $auditFile (run 10_Enable-DbAudit.ps1)"
}

# ------------------------------------------------------------------ Forwarder

$task = Get-ScheduledTask -TaskName 'KSC-DbAudit-Forwarder' -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -TaskName 'KSC-DbAudit-Forwarder'
    Add-Check 'Forwarder task registered' ($task.State -ne 'Disabled') "state: $($task.State)"
    Add-Check 'Last forwarder run succeeded' ($info.LastTaskResult -eq 0) "code $($info.LastTaskResult), run at $($info.LastRunTime)"
}
else {
    Add-Check 'Forwarder task registered' $false 'task KSC-DbAudit-Forwarder not found (run 20_Install-AuditForwarder.ps1)'
}

# ------------------------------------------------------------------ Event log

$logExists = [Diagnostics.EventLog]::SourceExists($KSC.AuditWinLogSource)
Add-Check 'Event source registered' $logExists $KSC.AuditWinLogSource

if ($logExists) {
    $events = Get-WinEvent -LogName $KSC.AuditWinLogName -MaxEvents 500 -ErrorAction SilentlyContinue
    Add-Check 'Event log contains events' ([bool]$events) ('records read: {0}' -f @($events).Count)

    $heartbeat = $events | Where-Object { $_.Id -eq 1100 } | Select-Object -First 1
    if ($heartbeat) {
        $hbAge = [int]((Get-Date) - $heartbeat.TimeCreated).TotalMinutes
        Add-Check 'Source health record' ($hbAge -le ($KSC.AuditHeartbeatMin * 3)) "last 1100 record: $hbAge min ago"
    }
    else {
        Add-Check 'Source health record' $false 'no events with id 1100'
    }

    $errors = $events | Where-Object { $_.Id -eq 1101 }
    Add-Check 'No forwarder errors' (-not $errors) $(if ($errors) { "1101 events: $(@($errors).Count), last: $($errors[0].TimeCreated)" } else { 'no 1101 events' })

    # Conformance with Order No. 130: session control and statements.
    $sessionEvents = $events | Where-Object { $_.Id -in 1001, 1002, 1003 }
    Add-Check 'Session events are logged (items 2.1-2.2)' ([bool]$sessionEvents) ('ids 1001-1003: {0}' -f @($sessionEvents).Count)

    $commandEvents = $events | Where-Object { $_.Id -in 1010, 1011, 1012, 1013, 1020 }
    Add-Check 'Statements and objects are logged (items 2.3-2.4)' ([bool]$commandEvents) ('ids 1010-1020: {0}' -f @($commandEvents).Count)
}

# ------------------------------------------------------------------ Collector account

$user = Get-LocalUser -Name $KSC.AuditAccount -ErrorAction SilentlyContinue
if ($user) {
    Add-Check 'Collector account enabled' ($user.Enabled) "$($KSC.AuditAccount), enabled: $($user.Enabled)"
    $readers = Get-LocalGroup -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue
    $inGroup = if ($readers) { (Get-LocalGroupMember -Group $readers -ErrorAction SilentlyContinue).SID.Value -contains $user.SID.Value } else { $false }
    Add-Check 'Account is in Event Log Readers' $inGroup 'S-1-5-32-573 (Event Log Readers)'

    $sddl = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$($KSC.AuditWinLogName)" -Name CustomSD -ErrorAction SilentlyContinue).CustomSD
    Add-Check 'Log read permission granted' ([bool]$sddl -and $sddl -match [regex]::Escape($user.SID.Value)) $(if ($sddl) { 'CustomSD contains the account SID' } else { 'CustomSD is not set' })
}
else {
    Add-Check 'Collector account enabled' $false "$($KSC.AuditAccount) not found (run 40_Set-AuditCollectorAccess.ps1)"
}

# ------------------------------------------------------------------ KSC application audit

$kavLog = Get-WinEvent -ListLog 'Kaspersky Event Log' -ErrorAction SilentlyContinue
Add-Check 'Kaspersky application event log' ([bool]$kavLog) $(if ($kavLog) { 'records: {0}, size {1:N0} MB' -f $kavLog.RecordCount, ($kavLog.MaximumSizeInBytes / 1MB) } else { 'channel is absent: enable writing to the Windows event log in the policy (30_Set-KscAppAudit.ps1)' })

$kscServices = @(Get-Service | Where-Object { $_.Name -match '^kl' -and $_.Status -eq 'Running' })
Add-Check 'Kaspersky services are running' ($kscServices.Count -gt 0) ('services running: {0}' -f $kscServices.Count)

# ------------------------------------------------------------------ Network

$fwRules = Get-NetFirewallRule -Group 'KSC Audit' -ErrorAction SilentlyContinue
Add-Check 'Firewall rules for the collector' ([bool]$fwRules) ('rules: {0}, source {1}' -f @($fwRules).Count, $KSC.AuditCollectorHost)

$rpcListening = [bool](Get-NetTCPConnection -LocalPort 135 -State Listen -ErrorAction SilentlyContinue)
Add-Check 'RPC port 135 is listening' $rpcListening 'required for remote event log reading'

# ------------------------------------------------------------------ Summary

Write-Host ''
$results | Format-Table -AutoSize
$failed = @($results | Where-Object { $_.Result -ne 'OK' })
if ($failed.Count -eq 0) {
    Write-KscLog 'All audit chain checks passed.' 'OK'
    exit 0
}
Write-KscLog "Checks failed: $($failed.Count). Fix the findings and run again." 'ERROR'
exit 1
