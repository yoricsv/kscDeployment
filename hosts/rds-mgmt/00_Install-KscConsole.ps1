<#
.SYNOPSIS
    Подготовка АРМ администратора (RDS, 10.20.30.15) к управлению KSC.

.DESCRIPTION
    АРМ администратора — единственная точка управления Сервером KSC:
    на Сервере разрешены подключения к портам управления только с этого адреса.

    Скрипт:
      1. проверяет сетевую доступность Сервера по портам управления;
      2. устанавливает консоль администрирования MMC (если указан дистрибутив);
      3. импортирует корневой сертификат УЦ в доверенные (для Web Console);
      4. создаёт ярлыки для консоли MMC и Web Console;
      5. проверяет, что с других узлов управление недоступно (по журналу правил).

.PARAMETER ConsoleSetupPath
    Путь к инсталлятору консоли администрирования MMC.

.PARAMETER RootCaCertPath
    Путь к файлу корневого сертификата корпоративного УЦ (.cer).

.EXAMPLE
    .\00_Install-KscConsole.ps1
    .\00_Install-KscConsole.ps1 -ConsoleSetupPath D:\distr\console.exe -RootCaCertPath D:\distr\rootca.cer
#>
[CmdletBinding()]
param(
    [string]$ConsoleSetupPath,
    [string]$RootCaCertPath
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$fqdn = "$($KSC.KscHostName).$($KSC.DomainFqdn)"

# ---------------------------------------------------------------- 1. Доступность Сервера

Write-KscLog "=== Проверка доступности Сервера администрирования $fqdn ==="

$myIp = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway }).IPv4Address.IPAddress | Select-Object -First 1
Write-KscLog "Адрес АРМ: $myIp"
if ($myIp -ne $KSC.RdsHost) {
    Write-KscLog "Внимание: адрес АРМ ($myIp) не совпадает с разрешённым в правилах Сервера ($($KSC.RdsHost)). Управление будет заблокировано." 'WARN'
}

$mgmtPorts = [ordered]@{
    $KSC.PortMmc        = 'Консоль MMC'
    $KSC.PortOpenApi    = 'OpenAPI'
    $KSC.PortWebConsole = 'Web Console'
    3389                = 'RDP'
}
$allOk = $true
foreach ($p in $mgmtPorts.Keys) {
    $ok = Test-KscPort -ComputerName $fqdn -Port $p
    if (-not $ok) { $allOk = $false }
    Write-KscLog ('  {0,-6} {1,-14} {2}' -f $p, $mgmtPorts[$p], $(if ($ok) { 'доступен' } else { 'НЕ доступен' })) $(if ($ok) { 'OK' } else { 'ERROR' })
}
if (-not $allOk) {
    Write-KscLog 'Часть портов недоступна. Проверьте правила брандмауэра на Сервере (10_Set-Firewall.ps1) и список управляющих хостов в config.ps1.' 'WARN'
}

# ---------------------------------------------------------------- 2. Консоль MMC

if ($ConsoleSetupPath) {
    if (-not (Test-Path $ConsoleSetupPath)) { throw "Не найден инсталлятор консоли: $ConsoleSetupPath" }
    Write-KscLog 'Запуск установки консоли администрирования...'
    Start-Process $ConsoleSetupPath -Wait
    Write-KscLog 'Установка завершена.' 'OK'
} else {
    Write-KscLog 'Путь к инсталлятору консоли не указан — шаг пропущен.' 'WARN'
    Write-KscLog "Дистрибутив консоли входит в полный пакет KSC (каталог Console) либо доступен по адресу http://$fqdn`:$($KSC.PortWebSrvHttp)."
}

# ---------------------------------------------------------------- 3. Сертификат УЦ

if ($RootCaCertPath) {
    if (-not (Test-Path $RootCaCertPath)) { throw "Не найден сертификат: $RootCaCertPath" }
    $cert = Import-Certificate -FilePath $RootCaCertPath -CertStoreLocation 'Cert:\LocalMachine\Root'
    Write-KscLog "Корневой сертификат импортирован: $($cert.Subject)" 'OK'
} else {
    Write-KscLog 'Сертификат УЦ не указан. Без него браузер будет предупреждать о недоверенном соединении с Web Console.' 'WARN'
}

# ---------------------------------------------------------------- 4. Ярлыки

$desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$shell = New-Object -ComObject WScript.Shell

$webUrl = "https://$fqdn`:$($KSC.PortWebConsole)"
$lnk = $shell.CreateShortcut((Join-Path $desktop 'KSC Web Console.url'))
$lnk.TargetPath = $webUrl
$lnk.Save()
Write-KscLog "Создан ярлык Web Console: $webUrl" 'OK'

$rdpFile = Join-Path $desktop 'KSC Server (RDP).rdp'
@"
full address:s:$fqdn
username:s:$($KSC.DomainNetBios)\
authentication level:i:2
enablecredsspsupport:i:1
redirectclipboard:i:0
redirectdrives:i:0
redirectprinters:i:0
audiomode:i:2
screen mode id:i:2
"@ | Set-Content $rdpFile -Encoding Unicode
Write-KscLog "Создан файл подключения RDP: $rdpFile" 'OK'

# ---------------------------------------------------------------- 5. Итог

Write-Host ''
Write-Host 'ТОЧКИ ВХОДА:' -ForegroundColor Cyan
@"
  Web Console ............ $webUrl
  Консоль MMC ............ подключение к $fqdn, порт $($KSC.PortMmc)
  RDP .................... $fqdn (только с $($KSC.RdsHost))

  Учётные записи: члены группы $($KSC.DomainNetBios)\$($KSC.AdminsGroup).
  Управление с любых других узлов заблокировано правилами брандмауэра Сервера.
"@ | Write-Host

Write-KscLog '=== АРМ администратора подготовлен ===' 'OK'
