<#
.SYNOPSIS
    Харденинг рабочей станции / рядового сервера Windows в аттестованном контуре.

.DESCRIPTION
    Профиль рассчитан на узлы, которыми управляет KSC. Отличия от профиля Сервера KSC:

      * входящие подключения запрещены, кроме служебных портов Агента с адреса Сервера;
      * RDP отключён (управление узлами выполняется только через средства KSC
        и с АРМ администратора; при необходимости включается параметром -AllowRdp);
      * съёмные носители блокируются на запись (параметр -BlockRemovableWrite).

    Скрипт сохраняет прежние значения реестра для отката
    (common\Restore-Baseline.ps1).

.PARAMETER AllowRdp
    Оставить RDP включённым, ограничив источник адресом АРМ администратора.

.PARAMETER BlockRemovableWrite
    Запретить запись на съёмные носители.

.EXAMPLE
    .\Invoke-Hardening.ps1 -WhatIf
    .\Invoke-Hardening.ps1 -BlockRemovableWrite
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AllowRdp,
    [switch]$BlockRemovableWrite
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Import-Module "$PSScriptRoot\..\..\..\common\WindowsBaseline.psm1" -Force
Assert-Elevated

Write-KscLog '=== Харденинг: рабочая станция / рядовой сервер ==='

# ---------------------------------------------------------------- Базовый профиль

Disable-LegacyProtocols
Set-TlsHardening
Set-AuthenticationHardening -CachedLogons 2   # кеш нужен при недоступности КД
Set-UacHardening
Set-AutorunHardening
Set-AuditPolicy -SecurityLogSizeKb 262144     # события выгружаются в KSC/SIEM
Set-DefenderBaseline

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

# ---------------------------------------------------------------- Съёмные носители

if ($BlockRemovableWrite) {
    Write-KscLog '--- Съёмные носители ---'
    $rs = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
    Set-RegValue -Path $rs -Name 'Deny_Write' -Value 1 -Comment '(запрет записи на съёмные диски)'
    Write-KscLog '  Контроль устройств KSC (модуль Device Control) даёт более гибкие правила — используйте его как основной механизм.' 'WARN'
}

# ---------------------------------------------------------------- Брандмауэр узла

Write-KscLog '--- Брандмауэр узла ---'
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False

foreach ($rule in @(
    @{ N = 'KSC Agent 15000/udp'; P = 'UDP'; Port = $KSC.PortServerToAgent }
    @{ N = 'KSC Agent 15001/udp'; P = 'UDP'; Port = 15001 }
)) {
    Get-NetFirewallRule -DisplayName $rule.N -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $rule.N -Group 'KSC Deployment' -Direction Inbound `
        -Protocol $rule.P -LocalPort $rule.Port -RemoteAddress $KSC.KscIp -Action Allow | Out-Null
    Write-KscLog "  + $($rule.N) (только с Сервера $($KSC.KscIp))" 'OK'
}

# Удалённая установка средствами KSC требует доступа к admin$ и удалённому реестру
# с адреса Сервера. Правила создаются точечно, а не для всей подсети.
foreach ($rule in @(
    @{ N = 'KSC Remote deploy SMB'; Port = 445 }
    @{ N = 'KSC Remote deploy RPC'; Port = 135 }
)) {
    Get-NetFirewallRule -DisplayName $rule.N -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $rule.N -Group 'KSC Deployment' -Direction Inbound `
        -Protocol TCP -LocalPort $rule.Port -RemoteAddress $KSC.KscIp -Action Allow | Out-Null
    Write-KscLog "  + $($rule.N) (только с Сервера $($KSC.KscIp))" 'OK'
}

# ---------------------------------------------------------------- Службы

Disable-UnneededServices -Keep @('RemoteRegistry')
Write-KscLog 'Служба удалённого реестра оставлена в режиме "Вручную": используется задачами удалённой установки KSC.' 'WARN'

# ---------------------------------------------------------------- Проверка Агента

$svc = Get-Service -Name 'klnagent' -ErrorAction SilentlyContinue
if ($svc) {
    Write-KscLog "Агент администрирования: служба $($svc.Status)" $(if ($svc.Status -eq 'Running') { 'OK' } else { 'WARN' })
} else {
    Write-KscLog 'Агент администрирования не установлен: узел не контролируется системой защиты.' 'ERROR'
    Write-KscLog 'Установка: hosts\win-endpoint\00_Install-NetworkAgent.ps1 либо групповая политика.' 'ERROR'
}

Write-HardeningSummary -Role 'Windows Endpoint'
