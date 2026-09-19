<#
.SYNOPSIS
    Installs the forwarder that converts MariaDB audit records into the Windows event log.

.DESCRIPTION
    On Windows the server_audit plugin can only write to a file
    (MDEV-19851: the SYSLOG value has no effect on this platform), while in the
    chosen design MP 10 Collector reads the Windows event log remotely. The
    link between them is a forwarder that copies new audit file records into a
    dedicated event log.

    The script:
      1. Creates the event log $KSC.AuditWinLogName and the source
         $KSC.AuditWinLogSource, sets the log size and overwrite-as-needed mode.
      2. Copies the worker script and common/config.ps1 into
         C:\ProgramData\KscDeployment\bin (write access: administrators and
         SYSTEM only) so that the forwarder does not depend on the repository
         location.
      3. Registers the scheduled task "KSC-DbAudit-Forwarder": runs as SYSTEM
         at system start and then every $KSC.AuditForwardPeriodMin minutes,
         parallel runs are not allowed.
      4. Runs the task and shows the last forwarded events.

.PARAMETER Rollback
    Remove the scheduled task and the working files. The event log is kept
    (deleting a log with collected events is a manual operation).

.EXAMPLE
    .\20_Install-AuditForwarder.ps1
    .\20_Install-AuditForwarder.ps1 -Rollback
#>
[CmdletBinding()]
param([switch]$Rollback)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

$taskName = 'KSC-DbAudit-Forwarder'
$binRoot = 'C:\ProgramData\KscDeployment\bin'
$workerRel = 'hosts\ksc-server\audit\21_Publish-DbAuditToEventLog.ps1'
$workerPath = Join-Path $binRoot $workerRel

# ------------------------------------------------------------------ Rollback

if ($Rollback) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-KscLog "Scheduled task '$taskName' removed." 'OK'
    }
    if (Test-Path $binRoot) {
        Remove-Item $binRoot -Recurse -Force
        Write-KscLog "Working files removed: $binRoot" 'OK'
    }
    Write-KscLog "Event log '$($KSC.AuditWinLogName)' kept. To delete: Remove-EventLog -LogName '$($KSC.AuditWinLogName)'" 'WARN'
    return
}

# ------------------------------------------------------------------ 1. Event log

if ([Diagnostics.EventLog]::SourceExists($KSC.AuditWinLogSource)) {
    $existingLog = [Diagnostics.EventLog]::LogNameFromSourceName($KSC.AuditWinLogSource, '.')
    if ($existingLog -ne $KSC.AuditWinLogName) {
        throw "Source '$($KSC.AuditWinLogSource)' is already registered in log '$existingLog'. Remove it: Remove-EventLog -Source '$($KSC.AuditWinLogSource)'"
    }
    Write-KscLog "Event log '$($KSC.AuditWinLogName)' and source '$($KSC.AuditWinLogSource)' already exist." 'WARN'
}
else {
    New-EventLog -LogName $KSC.AuditWinLogName -Source $KSC.AuditWinLogSource
    Write-KscLog "Created event log '$($KSC.AuditWinLogName)' with source '$($KSC.AuditWinLogSource)'." 'OK'
}

# The log is a local delivery buffer for the SIEM: overwrite as needed is
# acceptable, long-term retention is provided by the collector.
Limit-EventLog -LogName $KSC.AuditWinLogName `
    -MaximumSize ($KSC.AuditWinLogSizeMb * 1MB) `
    -OverflowAction OverwriteAsNeeded
Write-KscLog "Log size: $($KSC.AuditWinLogSizeMb) MB, mode: overwrite as needed." 'OK'

# ------------------------------------------------------------------ 2. Working files

foreach ($dir in @($binRoot, (Join-Path $binRoot 'common'), (Join-Path $binRoot 'hosts\ksc-server\audit'))) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Copy-Item (Join-Path $PSScriptRoot '21_Publish-DbAuditToEventLog.ps1') $workerPath -Force
Copy-Item "$PSScriptRoot\..\..\..\common\config.ps1" (Join-Path $binRoot 'common\config.ps1') -Force
Write-KscLog "Working files deployed: $binRoot" 'OK'

# Only administrators and SYSTEM may modify the forwarder script.
$acl = Get-Acl $binRoot
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
foreach ($id in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    'BUILTIN\Users', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -Path $binRoot -AclObject $acl
Write-KscLog 'Permissions on the forwarder directory restricted.' 'OK'

# ------------------------------------------------------------------ 3. Scheduled task

$interval = 'PT{0}M' -f $KSC.AuditForwardPeriodMin
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $workerPath

# The task is defined in XML: this is the only way to set an indefinite
# repetition with a one-minute interval (New-ScheduledTaskTrigger requires
# a finite repetition duration).
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Forwards MariaDB audit records (server_audit) into the Windows event log for collection by MP 10 Collector.</Description>
    <URI>\$taskName</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
      <Repetition>
        <Interval>$interval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </BootTrigger>
    <TimeTrigger>
      <StartBoundary>2000-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>$interval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>6</Priority>
    <RestartOnFailure>
      <Interval>PT5M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$arguments</Arguments>
    </Exec>
  </Actions>
</Task>
"@

Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null
Write-KscLog "Task '$taskName' registered: runs as SYSTEM every $($KSC.AuditForwardPeriodMin) min." 'OK'

# ------------------------------------------------------------------ 4. First run

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 10
$info = Get-ScheduledTaskInfo -TaskName $taskName
Write-KscLog "Last run exit code: $($info.LastTaskResult) (0 - success)." $(if ($info.LastTaskResult -eq 0) { 'OK' } else { 'WARN' })

$events = Get-WinEvent -LogName $KSC.AuditWinLogName -MaxEvents 5 -ErrorAction SilentlyContinue
if ($events) {
    Write-KscLog 'Last events in the database audit log:' 'OK'
    $events | ForEach-Object { Write-Host ('    {0}  id={1}  {2}' -f $_.TimeCreated, $_.Id, ($_.Message -split "`r?`n")[0]) -ForegroundColor Gray }
}
else {
    Write-KscLog 'No events forwarded yet: check that auditing is enabled (10_Enable-DbAudit.ps1) and the audit file is growing.' 'WARN'
}

Write-KscLog '=== Forwarder installed. Next step: 40_Set-AuditCollectorAccess.ps1 ===' 'OK'
