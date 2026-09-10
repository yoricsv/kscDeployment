<#
.SYNOPSIS
    Правила брандмауэра Windows на сервере администрирования KSC.

.DESCRIPTION
    Модель доступа для аттестованной сети (ДСП):

      * Управление (RDP, MMC-консоль, Web Console, OpenAPI) — ТОЛЬКО с АРМ администратора
        (RDS, 10.20.30.15) и с явно перечисленных хостов смежных СЗИ.
      * Служебное взаимодействие с Агентами администрирования — вся подсеть 10.20.30.0/24.
      * СУБД MariaDB — только петлевой интерфейс.
      * Всё остальное входящее — запрещено (политика по умолчанию Block).

    Все создаваемые правила помечены группой "KSC Deployment", что позволяет
    просмотреть и откатить их одной командой:
        Get-NetFirewallRule -Group 'KSC Deployment'
        Remove-NetFirewallRule -Group 'KSC Deployment'

.PARAMETER Rollback
    Удалить все правила группы "KSC Deployment" и выйти.

.EXAMPLE
    .\10_Set-Firewall.ps1
    .\10_Set-Firewall.ps1 -Rollback
#>
[CmdletBinding()]
param([switch]$Rollback)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$group = 'KSC Deployment'

if ($Rollback) {
    Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-KscLog "Правила группы '$group' удалены." 'OK'
    return
}

# ------------------------------------------------------------------ Профили

Set-NetFirewallProfile -Profile Domain, Private, Public `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -NotifyOnListen False `
    -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' `
    -LogMaxSizeKilobytes 32767 `
    -LogAllowed False `
    -LogBlocked True
Write-KscLog 'Профили брандмауэра: входящие по умолчанию — запрет, журналирование блокировок включено.' 'OK'

# ------------------------------------------------------------------ Списки адресов

$mgmtHosts = Get-KscManagementHosts          # RDS + смежные СЗИ
$subnet = $KSC.Subnet
$dc = $KSC.DomainController

Write-KscLog "Управляющие хосты: $($mgmtHosts -join ', ')"
Write-KscLog "Подсеть агентов: $subnet"

# Очистка ранее созданных правил группы (идемпотентность)
Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule

function New-KscRule {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('TCP', 'UDP')][string]$Protocol,
        [Parameter(Mandatory)][string[]]$Port,
        [Parameter(Mandatory)][string[]]$Remote,
        [string]$Direction = 'Inbound',
        [string]$Description = ''
    )
    New-NetFirewallRule -DisplayName $Name -Group $group -Direction $Direction -Action Allow `
        -Protocol $Protocol -LocalPort $Port -RemoteAddress $Remote -Profile Any `
        -Description $Description | Out-Null
    Write-KscLog "  + $Name ($Protocol/$($Port -join ',')) <- $($Remote -join ', ')"
}

# ------------------------------------------------------------------ 1. Управление: только RDS и смежные СЗИ

Write-KscLog '--- Правила управления (ограниченный список источников) ---'
New-KscRule -Name 'KSC: RDP (управление)'          -Protocol TCP -Port 3389                  -Remote $mgmtHosts -Description 'Удалённый рабочий стол администратора'
New-KscRule -Name 'KSC: MMC-консоль 13291'          -Protocol TCP -Port $KSC.PortMmc          -Remote $mgmtHosts -Description 'Консоль администрирования MMC'
New-KscRule -Name 'KSC: Web Console 8080'           -Protocol TCP -Port $KSC.PortWebConsole   -Remote $mgmtHosts -Description 'Веб-консоль KSC'
New-KscRule -Name 'KSC: OpenAPI 13299'              -Protocol TCP -Port $KSC.PortOpenApi      -Remote $mgmtHosts -Description 'OpenAPI: Web Console и интеграция со смежными СЗИ'
New-KscRule -Name 'KSC: WinRM (управление)'         -Protocol TCP -Port 5985, 5986            -Remote $mgmtHosts -Description 'Удалённое администрирование PowerShell'
New-KscRule -Name 'KSC: SMB (управление)'           -Protocol TCP -Port 445                   -Remote (@($mgmtHosts) + @($dc)) -Description 'Административные ресурсы, групповые политики'

if ($KSC.SecurityToolsHosts.Count -gt 0) {
    New-KscRule -Name 'KSC: SNMP мониторинг'        -Protocol UDP -Port 161                   -Remote $KSC.SecurityToolsHosts -Description 'Опрос состояния хоста смежными СЗИ'
} else {
    Write-KscLog 'Список SecurityToolsHosts пуст — правила для смежных СЗИ не создавались. Заполните config.ps1.' 'WARN'
}

# ------------------------------------------------------------------ 2. Агенты администрирования: вся подсеть

Write-KscLog '--- Правила взаимодействия с Агентами администрирования ---'
New-KscRule -Name 'KSC: Агенты 13000/tcp (SSL)'     -Protocol TCP -Port $KSC.PortAgentSsl     -Remote $subnet -Description 'Подключение Агентов по SSL'
New-KscRule -Name 'KSC: Агенты 13000/udp'           -Protocol UDP -Port $KSC.PortAgentSsl     -Remote $subnet -Description 'Служебный UDP Агентов'
New-KscRule -Name 'KSC: Агенты 14000/tcp'           -Protocol TCP -Port $KSC.PortAgentNoSsl   -Remote $subnet -Description 'Подключение Агентов без SSL (совместимость)'
New-KscRule -Name 'KSC: Веб-сервер 8060/8061'       -Protocol TCP -Port $KSC.PortWebSrvHttp, $KSC.PortWebSrvHttps -Remote $subnet -Description 'Раздача автономных пакетов установки'
New-KscRule -Name 'KSC: ICMP эхо (диагностика)'     -Protocol TCP -Port 135                   -Remote $subnet -Description 'RPC для удалённой установки Агентов'

New-NetFirewallRule -DisplayName 'KSC: ICMPv4 эхо-запрос' -Group $group -Direction Inbound -Action Allow `
    -Protocol ICMPv4 -IcmpType 8 -RemoteAddress $subnet -Profile Any | Out-Null
Write-KscLog '  + KSC: ICMPv4 эхо-запрос'

# ------------------------------------------------------------------ 3. СУБД: только локально

Write-KscLog '--- Правила СУБД ---'
New-NetFirewallRule -DisplayName 'KSC: MariaDB 3306 (только localhost)' -Group $group -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $KSC.PortMariaDb -RemoteAddress 127.0.0.1 -Profile Any | Out-Null
Write-KscLog "  + MariaDB $($KSC.PortMariaDb)/tcp <- 127.0.0.1"

New-NetFirewallRule -DisplayName 'KSC: MariaDB 3306 (запрет извне)' -Group $group -Direction Inbound -Action Block `
    -Protocol TCP -LocalPort $KSC.PortMariaDb -RemoteAddress Any -Profile Any | Out-Null
Write-KscLog "  + Явный запрет MariaDB извне"

# ------------------------------------------------------------------ 4. Исходящие

Write-KscLog '--- Исходящие правила ---'
New-KscRule -Name 'KSC: Сервер -> Агенты 15000/udp' -Protocol UDP -Port $KSC.PortServerToAgent -Remote $subnet -Direction Outbound -Description 'Команда синхронизации Агентам'

# ------------------------------------------------------------------ Итог

Write-KscLog '--- Итоговый набор правил ---'
Get-NetFirewallRule -Group $group | ForEach-Object {
    $pf = $_ | Get-NetFirewallPortFilter
    $af = $_ | Get-NetFirewallAddressFilter
    '{0,-45} {1,-8} {2,-14} {3,-8} {4}' -f $_.DisplayName, $_.Direction, ($pf.LocalPort -join ','), $_.Action, ($af.RemoteAddress -join ',')
} | Out-String | Write-Host

Write-KscLog '=== Настройка брандмауэра завершена. Следующий шаг: 20_Install-MariaDB.ps1 ===' 'OK'
