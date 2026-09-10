<#
.SYNOPSIS
    Проверка защищённости контроллера домена (по умолчанию — только аудит, без изменений).

.DESCRIPTION
    Контроллер домена — критичный узел: неосторожное применение параметров
    (RunAsPPL, отключение NTLM, подпись LDAP) способно нарушить аутентификацию
    во всём домене. Поэтому скрипт работает в двух режимах:

      * -Mode Audit  (по умолчанию) — только проверка и отчёт;
      * -Mode Apply  — применение безопасного подмножества параметров,
                       не затрагивающего протоколы аутентификации домена.

    Параметры, которые скрипт НИКОГДА не меняет автоматически на КД
    (только выдаёт рекомендацию):
      * требование подписи LDAP и привязки каналов;
      * ограничение исходящего/входящего NTLM;
      * членство в группе Protected Users;
      * отключение печати (Spooler) — влияет на сценарии домена.

.PARAMETER Mode
    Audit | Apply

.EXAMPLE
    .\Invoke-Hardening.ps1
    .\Invoke-Hardening.ps1 -Mode Apply -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('Audit', 'Apply')][string]$Mode = 'Audit')

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Import-Module "$PSScriptRoot\..\..\..\common\WindowsBaseline.psm1" -Force
Assert-Elevated

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param($Check, $Expected, $Actual, [bool]$Pass, $Recommendation = '')
    $findings.Add([pscustomobject]@{
        Проверка = $Check; Ожидание = $Expected; Факт = $Actual
        Результат = if ($Pass) { 'СООТВ.' } else { 'НЕ СООТВ.' }; Рекомендация = $Recommendation
    })
}
function Get-Reg { param($Path, $Name) (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name }
# Отображение значения, отсутствующего в реестре (без операторов PowerShell 7).
function Show-Val { param($Value, $Default = 'не задано') if ($null -eq $Value -or "$Value" -eq '') { $Default } else { $Value } }

Write-KscLog "=== Контроллер домена: режим $Mode ==="

# ---------------------------------------------------------------- Аудит

# 1. Подпись LDAP
$ldapSign = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
Add-Finding 'Требование подписи LDAP (LDAPServerIntegrity)' '2 (обязательно)' (Show-Val $ldapSign) ($ldapSign -eq 2) `
    'Включать только после проверки, что все клиенты (включая Linux и СЗИ) используют LDAPS или подпись.'

# 2. Привязка каналов LDAP
$cbt = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
Add-Finding 'Привязка каналов LDAP (LdapEnforceChannelBinding)' '2' (Show-Val $cbt) ($cbt -eq 2) `
    'Требует поддержки со стороны клиентов; вводить поэтапно (сначала значение 1 — аудит).'

# 3. SMBv1
$smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
Add-Finding 'Компонент SMBv1' 'Disabled' (Show-Val $smb1 'н/д') ($smb1 -eq 'Disabled') 'Отключить, перезагрузка обязательна.'

# 4. Подпись SMB
$smbSign = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
Add-Finding 'Обязательная подпись SMB' '1' (Show-Val $smbSign) ($smbSign -eq 1) 'На КД включено по умолчанию политикой контроллеров домена.'

# 5. NTLM
$lm = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
Add-Finding 'Уровень совместимости LM' '5 (только NTLMv2)' (Show-Val $lm) ($lm -eq 5) ''

# 6. Аудит
$auditPol = auditpol /get /category:* 2>&1 | Out-String
foreach ($sub in @('Logon', 'User Account Management', 'Security Group Management', 'Directory Service Changes', 'Kerberos Authentication Service')) {
    $enabled = $auditPol -match [regex]::Escape($sub) + '.*(Success|Успех)'
    Add-Finding "Аудит: $sub" 'включён (успех)' $(if ($enabled) { 'включён' } else { 'выключен' }) $enabled 'Требуется для расследования инцидентов.'
}

# 7. Размер журнала безопасности
$secLog = Get-WinEvent -ListLog Security
$sizeMb = [math]::Round($secLog.MaximumSizeInBytes / 1MB)
Add-Finding 'Размер журнала безопасности, МБ' '>= 1024' $sizeMb ($sizeMb -ge 1024) 'При выгрузке в SIEM допускается меньший размер.'

# 8. Учётные записи KSC
foreach ($acc in @($KSC.SvcAccount, $KSC.DeployAccount)) {
    $u = Get-ADUser -Filter "SamAccountName -eq '$acc'" -Properties AccountNotDelegated, PasswordNeverExpires -ErrorAction SilentlyContinue
    if (-not $u) { Add-Finding "Учётная запись $acc" 'существует' 'отсутствует' $false 'Создать скриптом 00_New-KscAccounts.ps1.'; continue }
    Add-Finding "Учётная запись ${acc}: запрет делегирования" 'True' $u.AccountNotDelegated ($u.AccountNotDelegated -eq $true) `
        "Set-ADAccountControl -Identity $acc -AccountNotDelegated `$true"
}

# 9. Административные учётные записи с SPN (Kerberoasting)
$spnUsers = Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, MemberOf -ErrorAction SilentlyContinue |
    Where-Object { $_.MemberOf -match 'Domain Admins|Enterprise Admins' }
Add-Finding 'Административные учётные записи с SPN' 'отсутствуют' $(if ($spnUsers) { ($spnUsers.SamAccountName -join ', ') } else { 'нет' }) (-not $spnUsers) `
    'Учётные записи с SPN уязвимы к Kerberoasting: вывести из групп администраторов.'

# 10. Устаревшая криптография Kerberos
$krbEnc = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes'
Add-Finding 'Типы шифрования Kerberos' 'только AES (24)' (Show-Val $krbEnc 'по умолчанию') ($krbEnc -eq 24) `
    'Отключение RC4 выполнять после проверки совместимости всех служб.'

# ---------------------------------------------------------------- Применение

if ($Mode -eq 'Apply') {
    Write-KscLog '--- Применение безопасного подмножества параметров ---'
    Write-KscLog 'Параметры аутентификации домена (LDAP signing, NTLM, Kerberos enc) НЕ изменяются автоматически.' 'WARN'

    Set-AuditPolicy -SecurityLogSizeKb 1048576
    Set-AutorunHardening
    Set-UacHardening
    Set-RdpHardening -IdleTimeoutMinutes 15

    # SMBv1 отключается — на КД безопасно при отсутствии клиентов старше Windows 7
    $smb1state = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State
    if ($smb1state -eq 'Enabled' -and $PSCmdlet.ShouldProcess('SMB1Protocol', 'Отключить')) {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
        Write-KscLog '  + SMBv1 отключён (перезагрузка обязательна)' 'OK'
    }

    Write-KscLog 'Службы на КД не отключаются автоматически: состав ролей уникален для каждой площадки.' 'WARN'
}

# ---------------------------------------------------------------- Отчёт

Write-Host ''
$findings | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host

$bad = @($findings | Where-Object Результат -eq 'НЕ СООТВ.')
Write-Host ''
Write-Host "Соответствует: $($findings.Count - $bad.Count) из $($findings.Count)" -ForegroundColor Cyan
if ($bad) {
    Write-Host 'Требуют внимания:' -ForegroundColor Yellow
    $bad | ForEach-Object { Write-Host "  - $($_.Проверка): $($_.Рекомендация)" -ForegroundColor Yellow }
}

$reportDir = 'C:\ProgramData\KscDeployment\reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$csv = Join-Path $reportDir ("dc-hardening-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$findings | Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Host "Отчёт: $csv" -ForegroundColor Green
