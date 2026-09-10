<#
.SYNOPSIS
    Харденинг АРМ администратора (терминальный сервер RDS, 10.20.30.15).

.DESCRIPTION
    АРМ администратора — привилегированный узел: с него выполняется управление
    системой антивирусной защиты. Компрометация этого узла равнозначна
    компрометации всей системы защиты, поэтому профиль строже базового:

      * запрет проброса буфера обмена, дисков, принтеров в сеансах RDP;
      * обязательная блокировка сеанса при простое;
      * запрет хранения учётных данных (Credential Delegation);
      * ограничение состава локальных администраторов;
      * запрет запуска неподписанных сценариев;
      * усиленный аудит запуска процессов;
      * контроль состава установленного ПО (вывод перечня для сверки).

    Скрипт поддерживает -WhatIf.

.EXAMPLE
    .\Invoke-Hardening.ps1 -WhatIf
    .\Invoke-Hardening.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([int]$IdleLockMinutes = 10)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Import-Module "$PSScriptRoot\..\..\..\common\WindowsBaseline.psm1" -Force
Assert-Elevated

Write-KscLog '=== Харденинг: АРМ администратора (RDS) ==='

# ---------------------------------------------------------------- Базовый профиль

Disable-LegacyProtocols
Set-TlsHardening
Set-AuthenticationHardening -CachedLogons 0     # кеширование доменных входов запрещено
Set-UacHardening
Set-AutorunHardening
Set-AuditPolicy -SecurityLogSizeKb 524288
Set-DefenderBaseline

# ---------------------------------------------------------------- RDP: усиленный профиль

Write-KscLog '--- Параметры терминальных сеансов ---'
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
Set-RegValue -Path $ts -Name 'fDenyTSConnections' -Value 0
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'UserAuthentication' -Value 1 -Comment '(NLA обязательна)'
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'SecurityLayer' -Value 2
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'MinEncryptionLevel' -Value 3
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisableClip' -Value 1 -Comment '(буфер обмена)'
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisableCdm' -Value 1 -Comment '(диски)'
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisableCpm' -Value 1 -Comment '(принтеры)'
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisableCcm' -Value 1 -Comment '(COM-порты)'
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisableLPT' -Value 1 -Comment '(LPT-порты)'
Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisablePNPRedir' -Value 1 -Comment '(PnP-устройства)'

$idleMs = $IdleLockMinutes * 60000
Set-RegValue -Path $ts -Name 'MaxIdleTime' -Value $idleMs -Comment "(разрыв сеанса при простое $IdleLockMinutes мин)"
Set-RegValue -Path $ts -Name 'MaxDisconnectionTime' -Value 60000
Set-RegValue -Path $ts -Name 'fResetBroken' -Value 1
Set-RegValue -Path $ts -Name 'fPromptForPassword' -Value 1 -Comment '(всегда запрашивать пароль)'

# Блокировка рабочего стола при простое
Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value ($IdleLockMinutes * 60)

# ---------------------------------------------------------------- Делегирование учётных данных

Write-KscLog '--- Защита учётных данных ---'
$cd = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
Set-RegValue -Path $cd -Name 'AllowProtectedCreds' -Value 1 -Comment '(Restricted Admin / Remote Credential Guard)'
Set-RegValue -Path $cd -Name 'RestrictedRemoteAdministration' -Value 1
Set-RegValue -Path $cd -Name 'RestrictedRemoteAdministrationType' -Value 3 -Comment '(Restricted Admin либо Remote Credential Guard)'

# Запрет сохранения паролей в диспетчере учётных данных
Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Value 1

# ---------------------------------------------------------------- PowerShell

Write-KscLog '--- PowerShell ---'
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'EnableScripts' -Value 1
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -Value 'AllSigned' -Type String `
    -Comment '(запуск только подписанных сценариев)'
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value 'C:\ProgramData\PSTranscripts' -Type String
Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Value 1
Write-KscLog '  ! Политика AllSigned требует подписи скриптов этого репозитория корпоративным сертификатом.' 'WARN'
Write-KscLog '    До внедрения подписи используйте RemoteSigned, иначе скрипты развёртывания не запустятся.' 'WARN'

# ---------------------------------------------------------------- Службы

Disable-UnneededServices

# ---------------------------------------------------------------- Локальные администраторы

Write-KscLog '--- Состав локальных администраторов ---'
$admins = Get-LocalGroupMember -Group 'Администраторы' -ErrorAction SilentlyContinue
if (-not $admins) { $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue }
$admins | ForEach-Object { Write-KscLog "  $($_.Name) [$($_.ObjectClass)]" }
Write-KscLog "Ожидаемый состав: встроенный администратор, $($KSC.DomainNetBios)\$($KSC.AdminsGroup)." 'WARN'
Write-KscLog 'Лишние учётные записи удалить: Remove-LocalGroupMember -Group Администраторы -Member <имя>' 'WARN'

# ---------------------------------------------------------------- Установленное ПО

Write-KscLog '--- Установленное программное обеспечение (для сверки с перечнем разрешённого) ---'
$soft = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                         'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
$soft | Format-Table -AutoSize | Out-String -Width 160 | Write-Host

$reportDir = 'C:\ProgramData\KscDeployment\reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$soft | Export-Csv (Join-Path $reportDir ("rds-software-{0}.csv" -f (Get-Date -Format 'yyyyMMdd'))) -NoTypeInformation -Encoding UTF8

Write-HardeningSummary -Role 'Admin Workstation (RDS)'
