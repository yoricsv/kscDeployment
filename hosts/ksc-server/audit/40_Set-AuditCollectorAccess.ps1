<#
.SYNOPSIS
    MP 10 Collector access to the database audit log: account, rights, firewall.

.DESCRIPTION
    Prepares the database host for remote event collection by the MaxPatrol
    collector ($KSC.AuditCollectorHost). Windows event sources require an OS
    account that belongs to the Event Log Readers group, has the right to
    access the computer from the network and is allowed to connect to WMI
    remotely; TCP 135 and the dynamic RPC range are used.

    The script:
      1. Creates the local account $KSC.AuditAccount (password is prompted for)
         or updates the settings of an existing one.
      2. Adds it to the Event Log Readers and Distributed COM Users groups.
      3. Grants the "Access this computer from the network" right and
         explicitly denies interactive, remote interactive, batch and service
         logon.
      4. Allows reading the $KSC.AuditWinLogName log (CustomSD descriptor) and
         remote access to the root\cimv2 WMI namespace.
      5. Creates firewall rules that allow connections from the collector
         address only (rule group "KSC Audit").

    The account is a service account: interactive logon is denied, the
    password is kept in a password vault and entered in MaxPatrol when the
    account is added.

    KSC data is not affected: the script changes Windows accounts, rights and
    firewall rules only.

.PARAMETER Rollback
    Remove the "KSC Audit" firewall rules and take the account out of the
    access groups. The account itself is not deleted.

.PARAMETER WhatIf
    Show the planned account, rights, event log and firewall changes without
    applying them or requesting a password.

.EXAMPLE
    .\40_Set-AuditCollectorAccess.ps1
    .\40_Set-AuditCollectorAccess.ps1 -Rollback
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Rollback)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

$account = $KSC.AuditAccount
$collector = $KSC.AuditCollectorHost
$fwGroup = 'KSC Audit'

# Groups are referenced by SID: their names are localized.
$groupSids = @{
    'S-1-5-32-573' = 'Event Log Readers'
    'S-1-5-32-562' = 'Distributed COM Users'
}

if ($WhatIfPreference) {
    Write-KscLog "WhatIf: configure local account '$account' for MP 10 Collector access." 'OK'
    Write-KscLog 'WhatIf: add the account to Event Log Readers and Distributed COM Users.' 'OK'
    Write-KscLog 'WhatIf: grant required network and WMI rights, configure event log access, and create restricted RPC firewall rules.' 'OK'
    if ($Rollback) {
        Write-KscLog "WhatIf: remove '$fwGroup' firewall rules and group memberships; keep the account." 'OK'
    }
    return
}

# ------------------------------------------------------------------ Rollback

if ($Rollback) {
    Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($sid in $groupSids.Keys) {
        $group = Get-LocalGroup -SID $sid -ErrorAction SilentlyContinue
        if ($group) { Remove-LocalGroupMember -Group $group -Member $account -ErrorAction SilentlyContinue }
    }
    Write-KscLog "Rules of group '$fwGroup' removed, account $account excluded from the access groups." 'OK'
    return
}

# ------------------------------------------------------------------ 1. Account

$user = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
if (-not $user) {
    $pwdSec = Read-Host "Set the password for account $account (used by MP 10 Collector)" -AsSecureString
    $user = New-LocalUser -Name $account -Password $pwdSec `
        -FullName 'MP 10 Collector: database audit log reader' `
        -Description 'Service account for security event collection. Interactive logon denied.' `
        -PasswordNeverExpires -UserMayNotChangePassword
    Write-KscLog "Local account $account created." 'OK'
}
else {
    # The password of an existing account is not changed.
    Write-KscLog "Account $account already exists - its settings will be updated, the password is left unchanged." 'WARN'
    Set-LocalUser -Name $account -PasswordNeverExpires $true -UserMayChangePassword $false
}
Enable-LocalUser -Name $account
$userSid = (Get-LocalUser -Name $account).SID.Value

# ------------------------------------------------------------------ 2. Access groups

foreach ($sid in $groupSids.Keys) {
    $group = Get-LocalGroup -SID $sid -ErrorAction SilentlyContinue
    if (-not $group) {
        Write-KscLog "  group $($groupSids[$sid]) not found - skipped." 'WARN'
        continue
    }
    $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
    if ($members.SID.Value -contains $userSid) {
        Write-KscLog "  $account is already a member of $($groupSids[$sid])."
    }
    else {
        Add-LocalGroupMember -Group $group -Member $account
        Write-KscLog "  $account added to group $($groupSids[$sid])." 'OK'
    }
}

# ------------------------------------------------------------------ 3. Logon rights

function Grant-KscUserRight {
    <# Adds the SID to the given user right, keeping the existing holders. #>
    param(
        [Parameter(Mandatory)][string]$Right,
        [Parameter(Mandatory)][string]$Sid
    )

    $exportFile = Join-Path $env:TEMP ('secpol-{0}.inf' -f ([guid]::NewGuid()))
    $importFile = Join-Path $env:TEMP ('secpol-{0}-new.inf' -f ([guid]::NewGuid()))
    $seceditDb = Join-Path $env:TEMP ('secpol-{0}.sdb' -f ([guid]::NewGuid()))
    try {
        secedit /export /areas USER_RIGHTS /cfg $exportFile | Out-Null
        $current = (Select-String -Path $exportFile -Pattern "^$Right\s*=" -ErrorAction SilentlyContinue).Line
        $values = if ($current) { ($current -split '=', 2)[1].Trim() -split ',' | ForEach-Object { $_.Trim() } } else { @() }
        if ($values -contains "*$Sid") {
            Write-KscLog "  right $Right is already granted."
            return
        }
        $values = @($values | Where-Object { $_ }) + "*$Sid"

        @(
            '[Unicode]'
            'Unicode=yes'
            '[Version]'
            'signature="$CHICAGO$"'
            'Revision=1'
            '[Privilege Rights]'
            "$Right = $($values -join ',')"
        ) | Set-Content -Path $importFile -Encoding Unicode

        secedit /configure /db $seceditDb /cfg $importFile /areas USER_RIGHTS | Out-Null
        Write-KscLog "  right $Right granted." 'OK'
    }
    finally {
        # Temporary secedit files only.
        Remove-Item $exportFile, $importFile, $seceditDb -Force -ErrorAction SilentlyContinue
    }
}

Write-KscLog '--- Logon rights of the service account ---'
Grant-KscUserRight -Right 'SeNetworkLogonRight' -Sid $userSid
foreach ($deny in @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
        'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight')) {
    Grant-KscUserRight -Right $deny -Sid $userSid
}

# ------------------------------------------------------------------ 4. Event log and WMI access

# Classic log: permissions are defined by the CustomSD descriptor.
# 0x1 - read, 0x2 - write, 0x4 - clear.
$logKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$($KSC.AuditWinLogName)"
if (-not (Test-Path $logKey)) {
    throw "Log '$($KSC.AuditWinLogName)' does not exist. Run 20_Install-AuditForwarder.ps1 first."
}
$sddl = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)' + "(A;;0x1;;;$userSid)"
Set-ItemProperty -Path $logKey -Name 'CustomSD' -Value $sddl
Write-KscLog "Permissions on log '$($KSC.AuditWinLogName)': read - $account and Event Log Readers." 'OK'

# Remote log polling goes through WMI: Enable Account, Execute Methods and
# Remote Enable are required in the root\cimv2 namespace.
function Grant-KscWmiAccess {
    # The namespace security descriptor is changed through the methods of the
    # __systemsecurity class: CIM cmdlets provide no equivalent access.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    param([string]$Namespace = 'root/cimv2', [Parameter(Mandatory)][string]$Sid)

    $wmiEnable = 0x1
    $wmiMethodExecute = 0x2
    $wmiRemoteEnable = 0x20
    $containerInherit = 0x2

    $sd = Invoke-WmiMethod -Namespace $Namespace -Path '__systemsecurity=@' -Name GetSecurityDescriptor
    if ($sd.ReturnValue -ne 0) { throw "Failed to read the WMI security descriptor (code $($sd.ReturnValue))." }

    $descriptor = $sd.Descriptor
    if ($descriptor.DACL.Trustee.SIDString -contains $Sid) {
        Write-KscLog "  WMI access to $Namespace is already granted."
        return
    }

    $trustee = ([wmiclass]"\\.\${Namespace}:Win32_Trustee").CreateInstance()
    $trustee.SidString = $Sid
    $ace = ([wmiclass]"\\.\${Namespace}:Win32_Ace").CreateInstance()
    $ace.AccessMask = $wmiEnable -bor $wmiMethodExecute -bor $wmiRemoteEnable
    $ace.AceFlags = $containerInherit
    $ace.AceType = 0
    $ace.Trustee = $trustee

    $descriptor.DACL += $ace
    $result = Invoke-WmiMethod -Namespace $Namespace -Path '__systemsecurity=@' -Name SetSecurityDescriptor -ArgumentList $descriptor
    if ($result.ReturnValue -ne 0) { throw "Failed to apply the WMI security descriptor (code $($result.ReturnValue))." }
    Write-KscLog "  WMI access to $Namespace granted (Enable, Method Execute, Remote Enable)." 'OK'
}

Write-KscLog '--- WMI access ---'
Grant-KscWmiAccess -Sid $userSid

# ------------------------------------------------------------------ 5. Firewall

Write-KscLog '--- Firewall rules for the collector ---'
Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName 'KSC Audit: RPC endpoint mapper 135 (MP 10 Collector)' -Group $fwGroup `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135 -RemoteAddress $collector -Profile Any `
    -Description 'RPC endpoint mapper for remote event log reading' | Out-Null
Write-KscLog "  + TCP 135 <- $collector"

New-NetFirewallRule -DisplayName 'KSC Audit: dynamic RPC ports (MP 10 Collector)' -Group $fwGroup `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 49152-65535 -RemoteAddress $collector -Profile Any `
    -Description 'Dynamic RPC/DCOM range for WMI' | Out-Null
Write-KscLog "  + TCP 49152-65535 <- $collector"

# The collector address must also be present in the common list of security tools
if ($KSC.SecurityToolsHosts -notcontains $collector) {
    Write-KscLog "Add $collector to SecurityToolsHosts (common/config.ps1) and re-run 10_Set-Firewall.ps1, otherwise the management rules will diverge." 'WARN'
}

# ------------------------------------------------------------------ Summary

Write-Host ''
Write-Host '============ SOURCE PARAMETERS FOR MaxPatrol ============' -ForegroundColor Cyan
Write-Host "  Source host (asset):    $($KSC.AuditDbHost)" -ForegroundColor Gray
Write-Host "  OS account:             $env:COMPUTERNAME\$account (local)" -ForegroundColor Gray
Write-Host "  Event log:              $($KSC.AuditWinLogName)" -ForegroundColor Gray
Write-Host "  Event source:           $($KSC.AuditWinLogSource)" -ForegroundColor Gray
Write-Host "  Collector:              $collector" -ForegroundColor Gray
Write-Host "  Ports:                  TCP 135 + 49152-65535" -ForegroundColor Gray
Write-Host '=========================================================' -ForegroundColor Cyan

Write-KscLog 'Store the account password in a password vault: it is required when adding the account in MaxPatrol.' 'WARN'
Write-KscLog '=== Collector access configured. Next step: 90_Test-Audit.ps1 ===' 'OK'
