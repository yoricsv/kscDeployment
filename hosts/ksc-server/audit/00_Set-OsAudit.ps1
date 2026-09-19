<#
.SYNOPSIS
    Extended operating system audit on the KSC host (Windows Server 2022).

.DESCRIPTION
    Order No. 130 of the OAC defines the minimum set of events to be logged.
    This script enables that minimum and extends it with the events required
    for incident response and investigation:

      1. Advanced audit policy subcategories are set by GUID, not by name:
         subcategory names are localized, and calling auditpol with an English
         name on a localized Windows build fails.
      2. Command line in process creation events (4688); advanced audit policy
         takes precedence over the legacy one.
      3. PowerShell logging: script blocks, modules and transcription into a
         protected directory.
      4. Size and retention mode of the Security/System/Application logs and
         activation of additional channels (PowerShell, Task Scheduler, WinRM,
         Firewall, RDP, SMB, Defender).
      5. Access auditing (SACL) for the KSC, DBMS and backup directories:
         modification and deletion of files, permission changes, denied attempts.
      6. Auditing of changes in the KasperskyLab registry branch.

    Local settings are overridden by domain group policy: if the host is a
    domain member, the same set must be defined in a GPO, otherwise the values
    are reverted at the next policy refresh.

    The script supports -WhatIf: run a trial pass before applying.

.PARAMETER SkipSacl
    Do not change access auditing for directories and registry (policy and
    event logs only).

.EXAMPLE
    .\00_Set-OsAudit.ps1 -WhatIf
    .\00_Set-OsAudit.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$SkipSacl)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

Write-KscLog '=== Extended operating system audit ==='

# ------------------------------------------------------------------ 1. Audit subcategories

# Subcategory GUIDs do not depend on the system language (docs.microsoft.com,
# "Advanced security audit policy settings"). S - success, F - failure.
$subcategories = @(
    # Logon and sessions (Order No. 130, session control)
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon';                              S = $true; F = $true }
    @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Logoff';                             S = $true; F = $false }
    @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Account Lockout';                    S = $true; F = $true }
    @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special Logon (privileges)';         S = $true; F = $false }
    @{ Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Name = 'Other Logon/Logoff Events (RDP)';    S = $true; F = $true }
    @{ Guid = '{0CCE9249-69AE-11D9-BED3-505054503030}'; Name = 'Group Membership';                   S = $true; F = $false }

    # Credential validation
    @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation';              S = $true; F = $true }
    @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Authentication Service';    S = $true; F = $true }
    @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Service Ticket Operations'; S = $true; F = $true }
    @{ Guid = '{0CCE9241-69AE-11D9-BED3-505054503030}'; Name = 'Other Account Logon Events';         S = $true; F = $true }

    # Account and privilege management
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management';            S = $true; F = $true }
    @{ Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Name = 'Computer Account Management';        S = $true; F = $true }
    @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management';          S = $true; F = $true }
    @{ Guid = '{0CCE9239-69AE-11D9-BED3-505054503030}'; Name = 'Application Group Management';       S = $true; F = $true }
    @{ Guid = '{0CCE923A-69AE-11D9-BED3-505054503030}'; Name = 'Other Account Management Events';    S = $true; F = $true }

    # Privilege use
    @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Sensitive Privilege Use';            S = $true; F = $true }
    @{ Guid = '{0CCE922A-69AE-11D9-BED3-505054503030}'; Name = 'Other Privilege Use Events';         S = $false; F = $true }
    @{ Guid = '{0CCE924A-69AE-11D9-BED3-505054503030}'; Name = 'Token Right Adjusted';               S = $true; F = $false }

    # Processes (incident investigation)
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation';                   S = $true; F = $true }
    @{ Guid = '{0CCE922C-69AE-11D9-BED3-505054503030}'; Name = 'Process Termination';                S = $true; F = $false }
    @{ Guid = '{0CCE9248-69AE-11D9-BED3-505054503030}'; Name = 'Plug and Play Events';               S = $true; F = $false }
    @{ Guid = '{0CCE922E-69AE-11D9-BED3-505054503030}'; Name = 'RPC Events';                         S = $false; F = $true }

    # Object access
    @{ Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Name = 'File System (by SACL)';              S = $true; F = $true }
    @{ Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}'; Name = 'Registry (by SACL)';                 S = $true; F = $true }
    @{ Guid = '{0CCE9220-69AE-11D9-BED3-505054503030}'; Name = 'SAM Access';                         S = $false; F = $true }
    @{ Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Name = 'File Share';                         S = $true; F = $true }
    @{ Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Name = 'Detailed File Share';                S = $false; F = $true }
    @{ Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Name = 'Removable Storage';                  S = $true; F = $true }
    @{ Guid = '{0CCE9222-69AE-11D9-BED3-505054503030}'; Name = 'Application Generated (KSC)';        S = $true; F = $true }
    @{ Guid = '{0CCE9223-69AE-11D9-BED3-505054503030}'; Name = 'Handle Manipulation';                S = $false; F = $true }
    @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Name = 'Other Object Access Events';         S = $true; F = $true }

    # Policy change
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change';                S = $true; F = $true }
    @{ Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Name = 'Authentication Policy Change';       S = $true; F = $true }
    @{ Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Name = 'Authorization Policy Change';        S = $true; F = $true }
    @{ Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Name = 'MPSSVC Rule-Level Policy Change';    S = $true; F = $true }
    @{ Guid = '{0CCE9234-69AE-11D9-BED3-505054503030}'; Name = 'Other Policy Change Events';         S = $false; F = $true }

    # System
    @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Name = 'Security State Change';              S = $true; F = $true }
    @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Security System Extension';          S = $true; F = $true }
    @{ Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Name = 'System Integrity';                   S = $true; F = $true }
    @{ Guid = '{0CCE9214-69AE-11D9-BED3-505054503030}'; Name = 'Other System Events';                S = $false; F = $true }
)

Write-KscLog '--- Advanced audit policy subcategories ---'
$applied = 0
foreach ($s in $subcategories) {
    if (-not $PSCmdlet.ShouldProcess($s.Name, 'Configure audit')) { continue }
    $success = if ($s.S) { 'enable' } else { 'disable' }
    $failure = if ($s.F) { 'enable' } else { 'disable' }
    $out = & auditpol.exe /set /subcategory:"$($s.Guid)" /success:$success /failure:$failure 2>&1
    if ($LASTEXITCODE -eq 0) {
        $applied++
        Write-KscLog ('  + {0}: success={1}, failure={2}' -f $s.Name, $success, $failure)
    }
    else {
        Write-KscLog "  ! failed to configure '$($s.Name)' ($($s.Guid)): $out" 'WARN'
    }
}
Write-KscLog "Subcategories configured: $applied of $($subcategories.Count)." $(if ($applied -eq $subcategories.Count) { 'OK' } else { 'WARN' })

# Advanced audit policy takes precedence over the legacy category-based one
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -PropertyType DWord -Force | Out-Null

# ------------------------------------------------------------------ 2. Event detail

Write-KscLog '--- Event detail level ---'

$auditPolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $auditPolicyKey)) { New-Item -Path $auditPolicyKey -Force | Out-Null }
New-ItemProperty -Path $auditPolicyKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
Write-KscLog '  + command line included in 4688 events' 'OK'

# ------------------------------------------------------------------ 3. PowerShell logging

Write-KscLog '--- PowerShell logging ---'

$transcriptDir = $KSC.AuditTranscriptDir
if (-not (Test-Path $transcriptDir)) { New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null }

# Transcripts contain administrator command output: only administrators and
# SYSTEM may read them, the collector account is granted read access separately.
$acl = Get-Acl $transcriptDir
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
foreach ($id in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
if ($PSCmdlet.ShouldProcess($transcriptDir, 'Restrict permissions')) { Set-Acl -Path $transcriptDir -AclObject $acl }

$psPolicies = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';      Name = 'EnableModuleLogging';      Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*';                 Value = '*'; Type = 'String' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Name = 'EnableTranscripting';      Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Name = 'EnableInvocationHeader';   Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Name = 'OutputDirectory';          Value = $transcriptDir; Type = 'String' }
)
foreach ($p in $psPolicies) {
    if (-not $PSCmdlet.ShouldProcess("$($p.Path)\$($p.Name)", 'Set value')) { continue }
    if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
    New-ItemProperty -Path $p.Path -Name $p.Name -Value $p.Value -PropertyType $p.Type -Force | Out-Null
}
Write-KscLog "  + script blocks, modules, transcription -> $transcriptDir" 'OK'

# ------------------------------------------------------------------ 4. Event logs

Write-KscLog '--- Event logs ---'

# The Security log is the main source; the other channels provide context for
# investigations. Local capacity covers a few days of standalone operation:
# long-term retention (one year) is provided by the collector.
$logs = [ordered]@{
    'Security'                                                      = $KSC.AuditSecurityLogSizeMb
    'System'                                                        = 256
    'Application'                                                   = 256
    'Microsoft-Windows-PowerShell/Operational'                      = $KSC.AuditChannelSizeMb
    'Windows PowerShell'                                            = $KSC.AuditChannelSizeMb
    'Microsoft-Windows-TaskScheduler/Operational'                   = 64
    'Microsoft-Windows-WinRM/Operational'                           = 64
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' = 64
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 64
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 64
    'Microsoft-Windows-SMBServer/Security'                          = 64
    'Microsoft-Windows-Windows Defender/Operational'                = 64
}
foreach ($name in $logs.Keys) {
    $sizeBytes = $logs[$name] * 1MB
    if (-not $PSCmdlet.ShouldProcess("Log $name", "Enable, size $($logs[$name]) MB")) { continue }
    $out = & wevtutil.exe sl "$name" /e:true /ms:$sizeBytes /rt:false 2>&1
    if ($LASTEXITCODE -eq 0) { Write-KscLog ('  + {0}: {1} MB' -f $name, $logs[$name]) }
    else { Write-KscLog "  ! channel '$name' is not available: $out" 'WARN' }
}

# ------------------------------------------------------------------ 5. Directory access auditing

if (-not $SkipSacl) {
    Write-KscLog '--- Directory access auditing (SACL) ---'

    # Modification, deletion, permission and ownership changes are logged.
    # Read access is not logged: the event volume outweighs its value.
    $auditRights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $saclPaths = @(
        $KSC.AuditLogDir
        $KSC.MariaDbDataDir
        $KSC.BackupDir
        $KSC.KlShareDir
        $KSC.KscInstallDir
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($path in $saclPaths) {
        if (-not $PSCmdlet.ShouldProcess($path, 'Enable change auditing')) { continue }
        try {
            $dirAcl = Get-Acl -Path $path -Audit
            $rule = New-Object Security.AccessControl.FileSystemAuditRule(
                'Everyone', $auditRights, 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')
            $dirAcl.AddAuditRule($rule)
            Set-Acl -Path $path -AclObject $dirAcl
            Write-KscLog "  + $path : modification, deletion, permission change (success and failure)" 'OK'
        }
        catch {
            Write-KscLog "  ! $path : failed to set auditing - $($_.Exception.Message)" 'WARN'
        }
    }

    # ---------------------------------------------------------- 6. Registry auditing

    Write-KscLog '--- Auditing of the KasperskyLab registry branch ---'
    $regPaths = @('HKLM:\SOFTWARE\KasperskyLab', 'HKLM:\SOFTWARE\WOW6432Node\KasperskyLab') |
        Where-Object { Test-Path $_ }

    foreach ($path in $regPaths) {
        if (-not $PSCmdlet.ShouldProcess($path, 'Enable change auditing')) { continue }
        try {
            $regAcl = Get-Acl -Path $path -Audit
            $rule = New-Object Security.AccessControl.RegistryAuditRule(
                'Everyone',
                [Security.AccessControl.RegistryRights]'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership',
                'ContainerInherit', 'None', 'Success,Failure')
            $regAcl.AddAuditRule($rule)
            Set-Acl -Path $path -AclObject $regAcl
            Write-KscLog "  + $path" 'OK'
        }
        catch {
            Write-KscLog "  ! $path : failed to set auditing - $($_.Exception.Message)" 'WARN'
        }
    }
}
else {
    Write-KscLog 'Directory and registry access auditing skipped (-SkipSacl).' 'WARN'
}

# ------------------------------------------------------------------ Summary

Write-KscLog '--- Effective audit policy (summary) ---'
& auditpol.exe /get /category:* | Select-Object -Skip 1 | Where-Object { $_ -match '\S' } | ForEach-Object {
    Write-Host "    $_" -ForegroundColor DarkGray
}

if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-KscLog 'Host is domain-joined: define the same audit settings in a GPO, otherwise local values will be overwritten at the next policy refresh.' 'WARN'
}
Write-KscLog '=== OS audit configured. Next step: 10_Enable-DbAudit.ps1 ===' 'OK'
