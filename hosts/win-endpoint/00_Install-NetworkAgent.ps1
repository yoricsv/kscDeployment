<#
.SYNOPSIS
    Установка Агента администрирования KSC на узел Windows (ручной сценарий).

.DESCRIPTION
    Основной способ развёртывания на доменных узлах — групповая политика
    (hosts/dc-gpo/10_New-AgentGpo.ps1). Этот скрипт применяется, когда GPO
    неприменима или не сработала:

      * узлы вне домена;
      * узлы, не перезагружавшиеся длительное время;
      * повторная установка после сбоя;
      * серверы, на которых установка выполняется в согласованное окно.

    Скрипт выполняет установку MSI в тихом режиме с параметрами подключения
    к Серверу, добавляет правила брандмауэра и проверяет связь с Сервером.

.PARAMETER MsiPath
    Путь к klnagent64.msi (локальный или UNC: \\ksc\KLSHARE\Packages\NetAgent\).

.PARAMETER UseAgentPassword
    Задать пароль удаления/изменения Агента. Обязательно для узлов вне домена,
    где отсутствует доменная аутентификация администратора.

.EXAMPLE
    .\00_Install-NetworkAgent.ps1
    .\00_Install-NetworkAgent.ps1 -MsiPath D:\distr\klnagent64.msi -UseAgentPassword
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$MsiPath,
    [switch]$UseAgentPassword,
    [switch]$SkipFirewall
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$fqdn = "$($KSC.KscHostName).$($KSC.DomainFqdn)"
$logDir = 'C:\ProgramData\KscDeployment\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# ---------------------------------------------------------------- 1. Предварительные проверки

Write-KscLog '=== Установка Агента администрирования ==='

$existing = Get-Service -Name 'klnagent' -ErrorAction SilentlyContinue
if ($existing) {
    Write-KscLog "Агент уже установлен (служба: $($existing.Status))." 'WARN'
    Write-KscLog 'Для смены Сервера используйте klmover, для переустановки — сначала удалите текущий Агент.' 'WARN'
    Write-KscLog "  `"C:\Program Files (x86)\Kaspersky Lab\NetworkAgent\klmover.exe`" -address $fqdn"
    if (-not $PSCmdlet.ShouldProcess('Агент администрирования', 'Переустановить поверх существующего')) { return }
}

# Разрешение имени Сервера обязательно: адрес Сервера в сертификате указан как FQDN
try {
    $resolved = [System.Net.Dns]::GetHostAddresses($fqdn) | Where-Object AddressFamily -eq 'InterNetwork'
    Write-KscLog "Сервер $fqdn разрешается в $($resolved.IPAddressToString -join ', ')" 'OK'
} catch {
    Write-KscLog "Имя $fqdn не разрешается. Для узлов вне домена добавьте запись в C:\Windows\System32\drivers\etc\hosts:" 'ERROR'
    Write-KscLog "  $($KSC.KscIp)`t$fqdn`t$($KSC.KscHostName)" 'ERROR'
    throw 'Сервер администрирования не разрешается по имени.'
}

if (-not (Test-KscPort -ComputerName $fqdn -Port $KSC.PortAgentSsl)) {
    Write-KscLog "Порт $($KSC.PortAgentSsl)/TCP на Сервере недоступен — Агент не сможет подключиться." 'ERROR'
    throw 'Нет связи с Сервером администрирования.'
}
Write-KscLog "Порт $($KSC.PortAgentSsl)/TCP доступен." 'OK'

# ---------------------------------------------------------------- 2. Поиск дистрибутива

if (-not $MsiPath) {
    $MsiPath = "\\$fqdn\KLSHARE\Packages\NetAgent\klnagent64.msi"
    Write-KscLog "Путь к дистрибутиву не указан, используется общий ресурс: $MsiPath"
}
if (-not (Test-Path $MsiPath)) {
    throw "Не найден дистрибутив Агента: $MsiPath. Укажите путь параметром -MsiPath или скопируйте пакет локально."
}

# ---------------------------------------------------------------- 3. Установка

$msiLog = Join-Path $logDir ("klnagent-install-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

$props = @(
    "SERVERADDRESS=$fqdn"
    "SERVERPORT=$($KSC.PortAgentSsl)"
    "SERVERSSLPORT=$($KSC.PortAgentSsl)"
    'USESSL=1'
    'EULA=1'
    'PRIVACYPOLICY=1'
)

$agentPwd = $null
if ($UseAgentPassword) {
    $agentPwd = Read-Host 'Пароль защиты Агента от удаления' -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($agentPwd))
    $props += "UNINSTALLPASSWORD=$plain"
    $props += 'USEUNINSTALLPASSWORD=1'
}

$argList = @('/i', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', "`"$msiLog`"") + $props

if ($PSCmdlet.ShouldProcess($MsiPath, 'Установить Агент администрирования')) {
    try {
        # Пароль передаётся только в аргументах процесса и не попадает в журнал скрипта
        Write-KscLog "Установка... (журнал MSI: $msiLog)"
        $p = Start-Process msiexec.exe -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
        switch ($p.ExitCode) {
            0     { Write-KscLog 'Установка завершена успешно.' 'OK' }
            3010  { Write-KscLog 'Установка завершена, требуется перезагрузка.' 'WARN' }
            1618  { throw 'Другая установка MSI уже выполняется. Повторите позже.' }
            1603  { throw "Критическая ошибка установки. Разбор: $msiLog" }
            default { throw "msiexec завершился с кодом $($p.ExitCode). Журнал: $msiLog" }
        }
    } finally {
        $plain = $null
        $argList = $null
        [GC]::Collect()
    }
}

# ---------------------------------------------------------------- 4. Правила брандмауэра

if (-not $SkipFirewall) {
    Write-KscLog '--- Правила брандмауэра для Агента ---'
    $rules = @(
        @{ Name = 'KSC Agent 15000/udp (сервер -> агент)'; Protocol = 'UDP'; Port = $KSC.PortServerToAgent }
        @{ Name = 'KSC Agent 15001/udp (многоадресная рассылка)'; Protocol = 'UDP'; Port = 15001 }
    )
    foreach ($r in $rules) {
        $existingRule = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
        if ($existingRule) { Remove-NetFirewallRule -DisplayName $r.Name }
        New-NetFirewallRule -DisplayName $r.Name -Group 'KSC Deployment' -Direction Inbound `
            -Protocol $r.Protocol -LocalPort $r.Port -RemoteAddress $KSC.KscIp -Action Allow | Out-Null
        Write-KscLog "  + $($r.Name) (только с $($KSC.KscIp))" 'OK'
    }
}

# ---------------------------------------------------------------- 5. Проверка связи

Start-Sleep -Seconds 10
$chk = 'C:\Program Files (x86)\Kaspersky Lab\NetworkAgent\klnagchk.exe'
if (Test-Path $chk) {
    Write-KscLog '--- Проверка подключения к Серверу (klnagchk) ---'
    & $chk -sendhb -nowait 2>&1 | ForEach-Object { Write-Host "  $_" }
} else {
    Write-KscLog "klnagchk.exe не найден по пути $chk — проверьте установку." 'WARN'
}

$svc = Get-Service -Name 'klnagent' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Running') { Start-Service klnagent }
Write-KscLog "Служба Агента: $((Get-Service klnagent -ErrorAction SilentlyContinue).Status)" 'OK'
Write-KscLog 'Убедитесь, что узел появился в консоли KSC (Обнаружение устройств → Нераспределённые устройства).'
