<#
.SYNOPSIS
    Харденинг АРМ администратора (RDS 10.20.30.15) — единственной точки управления KSC.

.DESCRIPTION
    Профиль строже, чем у остальных узлов: узел даёт доступ к управлению всей
    системой защиты, поэтому его компрометация равнозначна компрометации KSC.

    Отличия от профиля рядового узла:

      * кеширование доменных входов запрещено полностью;
      * перенаправление в сеансах запрещено целиком (буфер обмена, диски,
        принтеры, COM/LPT, PnP) — канал переноса данных из контура;
      * делегирование учётных данных ограничено режимами Restricted Admin
        и Remote Credential Guard: пароль администратора не попадает
        на управляемый узел;
      * съёмные носители запрещены полностью, а не только на запись;
      * управление запуском программ включается для всех, кроме администраторов;
      * PowerShell — только подписанные сценарии, с ведением стенограмм.

    Скрипт поддерживает -WhatIf.

.PARAMETER Level
    Strict (по умолчанию) либо Baseline.

.PARAMETER IdleLockMinutes
    Простой до разрыва сеанса и блокировки рабочего стола.

.PARAMETER SkipCredentialGuard
    Не включать защиту на основе виртуализации.

.PARAMETER EnforceAppLocker
    Режим блокировки вместо режима наблюдения.

.EXAMPLE
    .\Invoke-Hardening.ps1 -WhatIf
    .\Invoke-Hardening.ps1 -IdleLockMinutes 10
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Strict', 'Baseline')][string]$Level = 'Strict',
    [int]$IdleLockMinutes = 15,
    [switch]$SkipCredentialGuard,
    [switch]$EnforceAppLocker
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Import-Module "$PSScriptRoot\..\..\..\common\WindowsBaseline.psm1" -Force
Assert-Elevated

Write-KscLog "=== Харденинг: АРМ администратора (RDS), профиль $Level ==="

# ---------------------------------------------------------------- Общая часть

Disable-LegacyProtocols
Set-TlsHardening
Set-AuthenticationHardening -CachedLogons 0     # кеширование доменных входов запрещено
Set-UacHardening
Set-AutorunHardening

if ($Level -eq 'Strict') {
    Set-AuditPolicy -SecurityLogSizeKb 1048576 -Strict
    # Пароли администраторов: строже, чем на рядовых узлах.
    Set-PasswordPolicy -MinLength 16 -MaxAgeDays 45 -LockoutThreshold 3 -LockoutDurationMin 60
    Set-UserRightsHardening
    Set-CredentialProtection -SkipCredentialGuard:$SkipCredentialGuard
    Set-NetworkStackHardening
    Set-TelemetryHardening
    Set-UpdateHardening
    Set-ScriptHostHardening
    Set-PowerShellHardening -ExecutionPolicy AllSigned
    Set-LegalNotice
    Set-DefenderStrict
    # Полный запрет съёмных носителей: узел управления не должен служить
    # каналом переноса сведений из контура.
    Set-RemovableStorageHardening -Mode DenyAll
    Set-AppLockerBaseline -Enforce:$EnforceAppLocker -AllowedPaths @(
        'C:\Program Files (x86)\Kaspersky Lab\'
        'C:\Program Files\Kaspersky Lab\'
    )
} else {
    Set-AuditPolicy -SecurityLogSizeKb 524288
    Set-DefenderBaseline
    Set-PowerShellHardening -ExecutionPolicy AllSigned
}

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
Set-RegValue -Path $ts -Name 'fSingleSessionPerUser' -Value 1 -Comment '(один сеанс на пользователя)'

if ($Level -eq 'Strict') {
    # Ограничение количества и длительности сеансов
    Set-RegValue -Path $ts -Name 'MaxConnectionTime' -Value 43200000 -Comment '(предельная длительность сеанса 12 ч)'
    Set-RegValue -Path $ts -Name 'fDisableAutoReconnect' -Value 1
    # Запись сеансов средствами узла не ведётся: контроль действий
    # обеспечивается журналом действий администраторов KSC и стенограммами PowerShell.
}

Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value ($IdleLockMinutes * 60)

# ---------------------------------------------------------------- Делегирование учётных данных

Write-KscLog '--- Делегирование учётных данных ---'
$cd = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
Set-RegValue -Path $cd -Name 'AllowProtectedCreds' -Value 1 -Comment '(Restricted Admin / Remote Credential Guard)'
Set-RegValue -Path $cd -Name 'RestrictedRemoteAdministration' -Value 1
Set-RegValue -Path $cd -Name 'RestrictedRemoteAdministrationType' -Value 3 -Comment '(Restricted Admin либо Remote Credential Guard)'
Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Value 1

if ($Level -eq 'Strict') {
    # Запрет сохранения паролей в браузере и диспетчере учётных данных
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'PasswordManagerEnabled' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'AutofillCreditCardEnabled' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'BackgroundModeEnabled' -Value 0
    Write-KscLog '  + сохранение паролей в браузере запрещено (Web Console открывается без сохранения учётных данных)' 'OK'
}

# ---------------------------------------------------------------- Службы

$keepServices = @(
    'TermService'    # узел принимает подключения администраторов
    'SessionEnv'
    'UmRdpService'
)
Disable-UnneededServices -Keep $keepServices -Strict:($Level -eq 'Strict')

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

Write-KscLog 'Проверьте доступность консолей после перезагрузки: 00_Install-KscConsole.ps1 выполняет проверку портов.' 'WARN'
Write-HardeningSummary -Role "Admin Workstation (RDS, $Level)"
