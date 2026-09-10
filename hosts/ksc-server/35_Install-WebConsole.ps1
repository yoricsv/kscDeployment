<#
.SYNOPSIS
    Установка Kaspersky Security Center Web Console и настройка доступа только с АРМ администратора.

.DESCRIPTION
    Web Console ставится отдельным инсталлятором. Скрипт:
      1. проверяет доступность Сервера администрирования по порту OpenAPI;
      2. печатает значения для мастера установки;
      3. запускает инсталлятор;
      4. проверяет, что служба поднялась и порт слушается;
      5. напоминает о замене самоподписанного сертификата на выданный
         корпоративным удостоверяющим центром.

    Доступ к порту Web Console уже ограничен списком управляющих хостов
    правилом брандмауэра из 10_Set-Firewall.ps1.

.PARAMETER SetupPath
    Путь к инсталлятору Web Console (ksc-web-console-<ver>.x86_64.exe).

.EXAMPLE
    .\35_Install-WebConsole.ps1 -SetupPath D:\distr\ksc-web-console-15.1.exe
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SetupPath)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$fqdn = "$($KSC.KscHostName).$($KSC.DomainFqdn)"

if (-not (Test-Path $SetupPath)) { throw "Не найден инсталлятор: $SetupPath" }

# ------------------------------------------------------------------ Проверки

if (-not (Test-KscPort -ComputerName 'localhost' -Port $KSC.PortOpenApi)) {
    throw "Порт OpenAPI $($KSC.PortOpenApi) не отвечает. Сервер администрирования должен быть установлен и запущен."
}
Write-KscLog "Сервер администрирования доступен по OpenAPI ($($KSC.PortOpenApi))." 'OK'

$listening = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).LocalPort
if ($listening -contains $KSC.PortWebConsole) {
    throw "Порт $($KSC.PortWebConsole) уже занят. Освободите его или измените PortWebConsole в config.ps1."
}

# ------------------------------------------------------------------ Значения мастера

Write-Host ''
Write-Host '=========== ЗНАЧЕНИЯ ДЛЯ МАСТЕРА WEB CONSOLE ===========' -ForegroundColor Cyan
@"
Адрес Сервера администрирования .... $fqdn
Порт Сервера (OpenAPI) ............. $($KSC.PortOpenApi)
Адрес Web Console .................. $fqdn
Порт Web Console ................... $($KSC.PortWebConsole)
Сертификат ......................... на этапе установки — самоподписанный,
                                     после установки заменить на выданный
                                     корпоративным УЦ (см. ниже)
Доверенные Серверы администрирования только $fqdn
"@ | Write-Host
Write-Host '========================================================' -ForegroundColor Cyan
Write-Host ''

Start-Process $SetupPath -Wait

# ------------------------------------------------------------------ Постпроверка

Start-Sleep -Seconds 10
$ok = Test-KscPort -ComputerName 'localhost' -Port $KSC.PortWebConsole
if ($ok) {
    Write-KscLog "Web Console отвечает: https://$fqdn`:$($KSC.PortWebConsole)" 'OK'
} else {
    Write-KscLog "Порт $($KSC.PortWebConsole) не слушается. Проверьте службу KSCWebConsole и журнал установки." 'ERROR'
}

Write-KscLog "Доступ к Web Console разрешён только с: $((Get-KscManagementHosts) -join ', ')" 'OK'

Write-Host ''
Write-Host 'ЗАМЕНА СЕРТИФИКАТА (выполнить до ввода в эксплуатацию):' -ForegroundColor Yellow
@"
  1. Выпустить сертификат в корпоративном УЦ на имя $fqdn
     (шаблон Web Server, SAN: DNS=$fqdn, DNS=$($KSC.KscHostName), IP=$($KSC.KscIp)).
  2. Экспортировать в PEM: сертификат + закрытый ключ.
  3. Указать их в мастере переустановки Web Console либо в файле конфигурации
     службы Web Console, после чего перезапустить службу.
  4. Проверить с АРМ администратора ($($KSC.RdsHost)), что предупреждение
     браузера о недоверенном сертификате исчезло.
"@ | Write-Host

Write-KscLog '=== Следующий шаг: 40_Set-PostInstall.ps1 ===' 'OK'
