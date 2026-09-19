<#
.SYNOPSIS
    Application audit: Kaspersky Security Center and Network Agent.

.DESCRIPTION
    Order No. 130 of the OAC requires logging the actions of security tool
    administrators. For KSC there are two independent streams:

      * events of the Administration Server itself (console logon, changes to
        policies, tasks, rights, licence) - stored in the KSC database and
        exported either to a SIEM over Syslog/CEF or to the Windows event log;
      * protection events from managed devices - delivered by Network Agents
        into the same database.

    The script performs what is configured on the OS side and verifies the rest:

      1. Detects the Administration Server installation directory and the
         Kaspersky services.
      2. Enables and sizes the Windows event logs used by Kaspersky software
         ("Kaspersky Event Log", Application).
      3. Grants the collector account (kscaudit) read access to those logs.
      4. Enables access auditing (SACL) for the installation directory and the
         shared folder if it has not been set by 00_Set-OsAudit.ps1.
      5. Prints a checklist of the settings that can only be made in the
         console (SIEM export, retention, auditor role) with the site values
         substituted.

    SIEM export parameters are taken from common/config.ps1
    (SiemHost/SiemPort/SiemProtocol/SiemFormat); when SiemHost is empty the
    audit collector address is used.

.PARAMETER SkipSacl
    Do not change access auditing for the KSC directories.

.EXAMPLE
    .\30_Set-KscAppAudit.ps1 -WhatIf
    .\30_Set-KscAppAudit.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$SkipSacl)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

Write-KscLog '=== Application audit (Kaspersky Security Center) ==='

# ------------------------------------------------------------------ 1. Installed software

$services = Get-Service | Where-Object { $_.Name -match '^kl' -or $_.Name -match 'KSCWebConsole' }
if (-not $services) {
    Write-KscLog 'Kaspersky services not found: this script is intended for the Administration Server host.' 'WARN'
}
else {
    foreach ($s in $services) {
        Write-KscLog ('  service {0,-28} {1}' -f $s.Name, $s.Status) $(if ($s.Status -eq 'Running') { 'OK' } else { 'WARN' })
    }
}

$installDir = $null
$srvService = Get-CimInstance Win32_Service -Filter "Name='klserver'" -ErrorAction SilentlyContinue
if ($srvService -and $srvService.PathName) {
    $exe = ($srvService.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+).*$', '$1'
    if (Test-Path $exe) { $installDir = Split-Path (Split-Path $exe -Parent) -Parent }
}
if ($installDir) { Write-KscLog "Administration Server installation directory: $installDir" 'OK' }
else { Write-KscLog 'Could not determine the Administration Server directory (service klserver not found).' 'WARN' }

# ------------------------------------------------------------------ 2. Windows logs used by Kaspersky software

Write-KscLog '--- Windows logs used by Kaspersky software ---'

# "Kaspersky Event Log" is created when writing events to the Windows event
# log is enabled in the Network Agent/KES policy; before that the channel
# does not exist.
$kasperskyLogs = @('Kaspersky Event Log', 'Application')
$presentLogs = @()
foreach ($name in $kasperskyLogs) {
    $log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
    if (-not $log) {
        Write-KscLog "  ! log '$name' is absent: enable writing events to the Windows event log in the policy (see checklist)." 'WARN'
        continue
    }
    $presentLogs += $name
    if (-not $PSCmdlet.ShouldProcess("Log $name", "Size $($KSC.AuditChannelSizeMb) MB")) { continue }
    $sizeBytes = $KSC.AuditChannelSizeMb * 1MB
    $out = & wevtutil.exe sl "$name" /e:true /ms:$sizeBytes /rt:false 2>&1
    if ($LASTEXITCODE -eq 0) { Write-KscLog "  + $name : $($KSC.AuditChannelSizeMb) MB, overwrite as needed" 'OK' }
    else { Write-KscLog "  ! failed to change '$name': $out" 'WARN' }
}

# ------------------------------------------------------------------ 3. Collector account access

Write-KscLog '--- Collector account access to the application logs ---'

$collectorUser = Get-LocalUser -Name $KSC.AuditAccount -ErrorAction SilentlyContinue
if (-not $collectorUser) {
    Write-KscLog "Account $($KSC.AuditAccount) does not exist: run 40_Set-AuditCollectorAccess.ps1." 'WARN'
}
else {
    # Membership in Event Log Readers (S-1-5-32-573) grants read access to the
    # modern channels; for classic logs with their own descriptor the right is
    # granted explicitly through CustomSD.
    foreach ($name in $presentLogs) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$name"
        if (-not (Test-Path $key)) {
            Write-KscLog "  = $name : modern channel, access is granted by Event Log Readers membership."
            continue
        }
        $sddl = (Get-ItemProperty -Path $key -Name CustomSD -ErrorAction SilentlyContinue).CustomSD
        $ace = "(A;;0x1;;;$($collectorUser.SID.Value))"
        if ($sddl -and $sddl.Contains($collectorUser.SID.Value)) {
            Write-KscLog "  = $name : read access already granted."
            continue
        }
        $newSddl = if ($sddl) { $sddl + $ace } else { 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;ER)' + $ace }
        if ($PSCmdlet.ShouldProcess($name, 'Grant read access to the collector account')) {
            New-ItemProperty -Path $key -Name CustomSD -Value $newSddl -PropertyType String -Force | Out-Null
            Write-KscLog "  + $name : read access granted to $($KSC.AuditAccount)" 'OK'
        }
    }
}

# ------------------------------------------------------------------ 4. Access auditing for KSC directories

if (-not $SkipSacl) {
    Write-KscLog '--- Access auditing for KSC files ---'
    $paths = @($installDir, $KSC.KlShareDir, $KSC.BackupDir) | Where-Object { $_ -and (Test-Path $_) }
    $rights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'

    foreach ($path in $paths) {
        if (-not $PSCmdlet.ShouldProcess($path, 'Enable change auditing')) { continue }
        try {
            $acl = Get-Acl -Path $path -Audit
            $exists = $acl.Audit | Where-Object { $_.IdentityReference -match 'Everyone' }
            if ($exists) { Write-KscLog "  = $path : auditing already configured."; continue }
            $acl.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule(
                'Everyone', $rights, 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')))
            Set-Acl -Path $path -AclObject $acl
            Write-KscLog "  + $path" 'OK'
        }
        catch {
            Write-KscLog "  ! $path : $($_.Exception.Message)" 'WARN'
        }
    }
}

# ------------------------------------------------------------------ 5. Console checklist

$siemHost = if ($KSC.SiemHost) { $KSC.SiemHost } else { $KSC.AuditCollectorHost }

Write-KscLog '--- Configured in the administration console only ---'
$checklist = @(
    @{ Title = 'Event export to SIEM (main delivery channel for KSC events)'
       Steps = @(
         'Console -> Administration Server properties -> Event export -> Configure export to SIEM system.'
         "SIEM system address: $siemHost, port: $($KSC.SiemPort), protocol: $($KSC.SiemProtocol)."
         "Format: $($KSC.SiemFormat)."
         'Select the event types to export: administrator action audit, protection status, detections, device status.'
         'After enabling, verify that events arrive at the collector.'
       ) }
    @{ Title = 'Writing events to the Windows event log (fallback channel)'
       Steps = @(
         'Network Agent policy -> Event configuration: enable "Store in the Windows event log" for the selected event types.'
         'Do the same in the Kaspersky Endpoint Security policy for critical events.'
         "Once the policy is applied the 'Kaspersky Event Log' appears; re-run this script to grant access to $($KSC.AuditAccount)."
       ) }
    @{ Title = 'Event storage in the KSC database'
       Steps = @(
         'Administration Server properties -> Event repository.'
         "Retention period: $($KSC.RetentionDays) days; maximum number of records: $($KSC.EventsLimit)."
         'Check that the database size fits into the allocated volume.'
       ) }
    @{ Title = 'Logging of KSC administrator actions'
       Steps = @(
         'Administration Server properties -> Event configuration -> "Audit" category: enable logging of all events in the category.'
         'Check that "Object modified", "Object status changed" and "User logged in" are enabled and exported.'
         "Read-only role (group $($KSC.AuditorsGroup)) - for the staff controlling the audit; administrators must not be allowed to clear the logs."
       ) }
)

$n = 0
foreach ($item in $checklist) {
    $n++
    Write-Host ''
    Write-Host ("  {0}. {1}" -f $n, $item.Title) -ForegroundColor Cyan
    foreach ($step in $item.Steps) { Write-Host "     - $step" -ForegroundColor Gray }
}

Write-Host ''
Write-KscLog '=== Application audit configured on the OS side. Complete the checklist, then run 90_Test-Audit.ps1 ===' 'OK'
