<#
.SYNOPSIS
    Харденинг рабочей станции / рядового сервера Windows в аттестованном контуре.

.DESCRIPTION
    Расширенный (строгий) профиль для узлов, которыми управляет KSC:

      * входящие подключения запрещены, кроме служебных портов Агента
        с адреса Сервера;
      * RDP отключён (при необходимости включается -AllowRdp с ограничением
        источника адресом АРМ администратора);
      * локальным учётным записям запрещён сетевой и удалённый вход:
        прекращается боковое перемещение по сети с одинаковым локальным паролем;
      * PowerShell переводится в режим ограниченного языка, сервер сценариев
        Windows отключается: на рабочем месте пользователя интерпретаторы
        применяются главным образом вредоносным кодом;
      * управление запуском программ включается в режиме наблюдения;
      * съёмные носители — запрет записи (основной механизм контроля
        устройств обеспечивает политика Kaspersky Endpoint Security).

    Скрипт сохраняет прежние значения реестра и выгрузку локальной политики
    безопасности для отката (common\Restore-Baseline.ps1).

.PARAMETER Level
    Strict (по умолчанию) либо Baseline.

.PARAMETER AllowRdp
    Оставить RDP включённым, ограничив источник адресом АРМ администратора.

.PARAMETER RemovableStorage
    DenyWrite (по умолчанию) либо DenyAll.

.PARAMETER AllowRemoteDeploy
    Сохранить доступ к SMB, RPC и удалённому реестру с адреса Сервера:
    требуется для удалённой установки и обновления Агента средствами KSC.

.PARAMETER AllowScriptHost
    Не отключать сервер сценариев Windows (если сценарии входа используют wscript).

.PARAMETER EnforceAppLocker
    Режим блокировки вместо режима наблюдения.

.EXAMPLE
    .\Invoke-Hardening.ps1 -WhatIf
    .\Invoke-Hardening.ps1
    .\Invoke-Hardening.ps1 -Level Baseline -AllowRdp
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Strict', 'Baseline')][string]$Level = 'Strict',
    [switch]$AllowRdp,
    [ValidateSet('DenyWrite', 'DenyAll')][string]$RemovableStorage = 'DenyWrite',
    [switch]$AllowRemoteDeploy,
    [switch]$AllowScriptHost,
    [switch]$EnforceAppLocker
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Import-Module "$PSScriptRoot\..\..\..\common\WindowsBaseline.psm1" -Force
Assert-Elevated

Write-KscLog "=== Харденинг: рабочая станция / рядовой сервер (профиль $Level) ==="

# ---------------------------------------------------------------- Общая часть

Disable-LegacyProtocols
Set-TlsHardening
Set-AuthenticationHardening -CachedLogons 2   # кеш нужен при недоступности контроллера домена
Set-UacHardening
Set-AutorunHardening

if ($Level -eq 'Strict') {
    # События выгружаются в KSC и систему мониторинга, локально держим буфер
    # на случай потери связи с Сервером.
    Set-AuditPolicy -SecurityLogSizeKb 524288 -Strict
    Set-PasswordPolicy -MinLength 14 -MaxAgeDays 90 -LockoutThreshold 5 -LockoutDurationMin 15
    Set-UserRightsHardening -DenyRemoteInteractiveForAll:(-not $AllowRdp)
    Set-CredentialProtection
    Set-NetworkStackHardening
    Set-TelemetryHardening
    Set-UpdateHardening
    Set-ScriptHostHardening -KeepWindowsScriptHost:$AllowScriptHost
    # На рабочем месте пользователя ограниченный язык допустим: средства
    # администрирования запускаются с АРМ, а не локально.
    Set-PowerShellHardening -ExecutionPolicy AllSigned -ConstrainedLanguage
    Set-LegalNotice
    Set-DefenderStrict
    Set-RemovableStorageHardening -Mode $RemovableStorage
    Set-AppLockerBaseline -Enforce:$EnforceAppLocker -AllowedPaths @(
        'C:\Program Files (x86)\Kaspersky Lab\'
        'C:\ProgramData\KasperskyLab\'
    )
} else {
    Set-AuditPolicy -SecurityLogSizeKb 262144
    Set-DefenderBaseline
    Set-RemovableStorageHardening -Mode DenyWrite
}

# ---------------------------------------------------------------- Удалённый доступ

if ($AllowRdp) {
    Set-RdpHardening -IdleTimeoutMinutes 15
    Get-NetFirewallRule -DisplayName 'KSC Endpoint RDP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'KSC Endpoint RDP' -Group 'KSC Deployment' -Direction Inbound `
        -Protocol TCP -LocalPort 3389 -RemoteAddress (Get-KscManagementHosts) -Action Allow | Out-Null
    Write-KscLog "  + RDP разрешён только с $((Get-KscManagementHosts) -join ', ')" 'OK'
} else {
    Set-RdpHardening -DisableRdp
    Write-KscLog '  + RDP отключён (параметр -AllowRdp включает его с ограничением по адресу)' 'OK'
}

# ---------------------------------------------------------------- Брандмауэр узла

Write-KscLog '--- Брандмауэр узла ---'
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False

if ($Level -eq 'Strict' -and $PSCmdlet.ShouldProcess('Брандмауэр', 'Включить регистрацию отклонённых пакетов')) {
    Set-NetFirewallProfile -Profile Domain, Private, Public `
        -LogBlocked True -LogMaxSizeKilobytes 16384 `
        -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'
    Write-KscLog '  + регистрация отклонённых подключений включена' 'OK'
}

foreach ($rule in @(
    @{ N = 'KSC Agent 15000/udp'; P = 'UDP'; Port = $KSC.PortServerToAgent }
    @{ N = 'KSC Agent 15001/udp'; P = 'UDP'; Port = 15001 }
)) {
    Get-NetFirewallRule -DisplayName $rule.N -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $rule.N -Group 'KSC Deployment' -Direction Inbound `
        -Protocol $rule.P -LocalPort $rule.Port -RemoteAddress $KSC.KscIp -Action Allow | Out-Null
    Write-KscLog "  + $($rule.N) (только с Сервера $($KSC.KscIp))" 'OK'
}

# Удалённая установка средствами KSC требует доступа к admin$ и удалённому
# реестру с адреса Сервера. Правила создаются точечно, а не для всей подсети.
if ($AllowRemoteDeploy) {
    foreach ($rule in @(
        @{ N = 'KSC Remote deploy SMB'; Port = 445 }
        @{ N = 'KSC Remote deploy RPC'; Port = 135 }
    )) {
        Get-NetFirewallRule -DisplayName $rule.N -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $rule.N -Group 'KSC Deployment' -Direction Inbound `
            -Protocol TCP -LocalPort $rule.Port -RemoteAddress $KSC.KscIp -Action Allow | Out-Null
        Write-KscLog "  + $($rule.N) (только с Сервера $($KSC.KscIp))" 'OK'
    }
} else {
    foreach ($n in @('KSC Remote deploy SMB', 'KSC Remote deploy RPC')) {
        Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    Write-KscLog '  + доступ к SMB и RPC закрыт полностью' 'OK'
    Write-KscLog '    Удалённая установка и переустановка Агента средствами KSC на этом узле работать не будет:' 'WARN'
    Write-KscLog '    применяйте групповую политику либо запускайте -AllowRemoteDeploy на время развёртывания.' 'WARN'
}

# ---------------------------------------------------------------- Службы

$keep = @()
if ($AllowRemoteDeploy) { $keep += 'RemoteRegistry' }
if ($AllowRdp) { $keep += @('TermService', 'SessionEnv', 'UmRdpService') }
Disable-UnneededServices -Keep $keep -Strict:($Level -eq 'Strict')

if ($AllowRemoteDeploy) {
    $rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
    if ($rr -and $PSCmdlet.ShouldProcess('RemoteRegistry', 'Режим запуска: вручную')) {
        Set-Service RemoteRegistry -StartupType Manual
        Write-KscLog '  + RemoteRegistry: запуск вручную (задачи удалённой установки KSC)' 'OK'
    }
}

# ---------------------------------------------------------------- Проверка Агента

$svc = Get-Service -Name 'klnagent' -ErrorAction SilentlyContinue
if ($svc) {
    Write-KscLog "Агент администрирования: служба $($svc.Status)" $(if ($svc.Status -eq 'Running') { 'OK' } else { 'WARN' })
} else {
    Write-KscLog 'Агент администрирования не установлен: узел не контролируется системой защиты.' 'ERROR'
    Write-KscLog 'Установка: hosts\win-endpoint\00_Install-NetworkAgent.ps1 либо групповая политика.' 'ERROR'
}

if ($Level -eq 'Strict') {
    Write-KscLog 'Строгий профиль изменил политику паролей и назначение прав: проверьте вход пользователя' 'WARN'
    Write-KscLog 'и работу прикладного ПО до применения профиля на остальных узлах.' 'WARN'
}

Write-HardeningSummary -Role "Windows Endpoint ($Level)"
