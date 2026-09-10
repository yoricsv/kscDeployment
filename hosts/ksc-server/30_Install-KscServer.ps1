<#
.SYNOPSIS
    Предустановочная проверка и запуск установки Сервера администрирования KSC.

.DESCRIPTION
    Скрипт выполняет полный набор предустановочных проверок (СУБД, порты,
    учётные записи, DNS, каталоги, свободное место) и затем запускает
    инсталлятор Kaspersky Security Center.

    Режимы:
      * по умолчанию — интерактивная установка (мастер), скрипт печатает
        точный перечень значений, которые нужно ввести в каждом окне мастера;
      * -Silent — тихая установка с параметрами из 31_ksc_setup_params.txt.

    ВАЖНО: набор ключей тихой установки различается между версиями KSC
    (14.2 / 15.x). Перед использованием -Silent сверьте состав параметров
    в файле 31_ksc_setup_params.txt с документацией на вашу версию
    ("Установка Сервера администрирования в тихом режиме"). Скрипт
    не изобретает ключи: он передаёт инсталлятору ровно то, что записано
    в файле параметров.

.PARAMETER SetupPath
    Путь к setup.exe из дистрибутива KSC (полный пакет ksc_<ver>_full_ru).

.PARAMETER Silent
    Запустить установку в тихом режиме с параметрами из файла.

.PARAMETER ChecksOnly
    Выполнить только проверки, установку не запускать.

.EXAMPLE
    .\30_Install-KscServer.ps1 -ChecksOnly
    .\30_Install-KscServer.ps1 -SetupPath D:\distr\ksc\setup.exe
#>
[CmdletBinding()]
param(
    [string]$SetupPath,
    [switch]$Silent,
    [switch]$ChecksOnly
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$fqdn = "$($KSC.KscHostName).$($KSC.DomainFqdn)"
$errors = @()
$warnings = @()

function Add-Problem { param($Text, $Level = 'ERROR')
    if ($Level -eq 'ERROR') { $script:errors += $Text; Write-KscLog $Text 'ERROR' }
    else { $script:warnings += $Text; Write-KscLog $Text 'WARN' }
}

Write-KscLog '=== Предустановочная проверка Сервера администрирования ==='

# ------------------------------------------------------------------ 1. Домен и имя

$cs = Get-CimInstance Win32_ComputerSystem
if (-not $cs.PartOfDomain) { Add-Problem 'Хост не введён в домен.' }
try { Resolve-DnsName $fqdn -Type A -ErrorAction Stop | Out-Null; Write-KscLog "DNS: $fqdn разрешается." 'OK' }
catch { Add-Problem "Не разрешается FQDN $fqdn — Агенты не смогут подключиться." }

# ------------------------------------------------------------------ 2. СУБД

$svc = Get-Service 'MariaDB' -ErrorAction SilentlyContinue
if (-not $svc) { Add-Problem 'Служба MariaDB не найдена. Выполните 20_Install-MariaDB.ps1.' }
elseif ($svc.Status -ne 'Running') { Add-Problem "Служба MariaDB в состоянии $($svc.Status)." }
else { Write-KscLog 'Служба MariaDB запущена.' 'OK' }

$mysqlExe = Join-Path $KSC.MariaDbInstallDir 'bin\mysql.exe'
if (Test-Path $mysqlExe) {
    Write-KscLog "Проверка параметров СУБД под учётной записью $($KSC.DbUser)..."
    $dbPwd = Read-Host "Пароль учётной записи $($KSC.DbUser) (Enter — пропустить проверку)" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbPwd))
    if ($plain) {
        $cnf = Join-Path $env:TEMP ('chk-{0}.ini' -f [guid]::NewGuid())
        try {
            Set-Content $cnf "[client]`nuser=$($KSC.DbUser)`npassword=$plain`nhost=127.0.0.1`nport=$($KSC.PortMariaDb)" -Encoding ASCII
            icacls $cnf /inheritance:r /grant:r "$env:USERNAME:(R)" | Out-Null

            $checks = @{
                'innodb_buffer_pool_size'        = $null
                'max_allowed_packet'             = 33554432
                'innodb_flush_log_at_trx_commit' = 0
                'innodb_lock_wait_timeout'       = 300
                'optimizer_search_depth'         = 8
            }
            foreach ($var in $checks.Keys) {
                $val = (& $mysqlExe "--defaults-file=$cnf" -N -B -e "SHOW VARIABLES LIKE '$var'" 2>&1) -split "`t" | Select-Object -Last 1
                $expected = $checks[$var]
                if ($null -ne $expected -and "$val" -ne "$expected") {
                    Add-Problem "Параметр СУБД $var = $val, ожидается $expected. Проверьте my.ini." 'WARN'
                } else {
                    Write-KscLog "  $var = $val" 'OK'
                }
            }
            $dbExists = & $mysqlExe "--defaults-file=$cnf" -N -B -e "SHOW DATABASES LIKE '$($KSC.DbName)'" 2>&1
            if ("$dbExists" -notmatch $KSC.DbName) { Add-Problem "База $($KSC.DbName) не найдена или недоступна учётной записи." }
            else { Write-KscLog "База $($KSC.DbName) доступна." 'OK' }
        }
        finally { Remove-Item $cnf -Force -ErrorAction SilentlyContinue; Remove-Variable plain -ErrorAction SilentlyContinue }
    } else {
        Add-Problem 'Проверка параметров СУБД пропущена оператором.' 'WARN'
    }
}

# ------------------------------------------------------------------ 3. Порты

$ports = @{
    $KSC.PortAgentSsl    = 'Агенты (SSL)'
    $KSC.PortAgentNoSsl  = 'Агенты (без SSL)'
    $KSC.PortMmc         = 'Консоль MMC'
    $KSC.PortOpenApi     = 'OpenAPI'
    $KSC.PortWebSrvHttp  = 'Веб-сервер HTTP'
    $KSC.PortWebSrvHttps = 'Веб-сервер HTTPS'
}
$listening = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).LocalPort
foreach ($p in $ports.Keys) {
    if ($listening -contains $p) { Add-Problem "Порт $p ($($ports[$p])) уже занят другим процессом." }
}
if ($errors.Count -eq 0) { Write-KscLog 'Требуемые порты свободны.' 'OK' }

# ------------------------------------------------------------------ 4. Учётные записи AD

if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
    foreach ($acc in @($KSC.SvcAccount, $KSC.DeployAccount)) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$acc'" -ErrorAction SilentlyContinue)) {
            Add-Problem "Учётная запись $($KSC.DomainNetBios)\$acc не найдена в AD. Создайте её скриптом hosts/dc-gpo/00_New-KscAccounts.ps1." 'WARN'
        } else { Write-KscLog "Учётная запись $acc найдена." 'OK' }
    }
} else {
    Add-Problem 'Модуль ActiveDirectory недоступен — проверка учётных записей пропущена (RSAT не установлен).' 'WARN'
}

# ------------------------------------------------------------------ 5. Диски

foreach ($drv in @($KSC.DiskSystem, $KSC.DiskDatabase, $KSC.DiskData) | Select-Object -Unique) {
    $vol = Get-Volume -DriveLetter $drv.TrimEnd(':') -ErrorAction SilentlyContinue
    if (-not $vol) { Add-Problem "Том $drv отсутствует."; continue }
    $freeGb = [math]::Round($vol.SizeRemaining / 1GB)
    Write-KscLog "Том $drv свободно $freeGb ГБ"
    if ($freeGb -lt 40) { Add-Problem "На томе $drv менее 40 ГБ свободно." }
}

# ------------------------------------------------------------------ 6. Итог проверок

Write-KscLog '--- Результат проверок ---'
Write-KscLog "Ошибок: $($errors.Count), предупреждений: $($warnings.Count)"
if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-KscLog "  ОШИБКА: $_" 'ERROR' }
    throw 'Установка не начата: устраните ошибки и повторите.'
}
if ($ChecksOnly) { Write-KscLog 'Режим ChecksOnly — установка не запускается.' 'OK'; return }

# ------------------------------------------------------------------ 7. Установка

if (-not $SetupPath -or -not (Test-Path $SetupPath)) {
    throw 'Укажите -SetupPath <путь к setup.exe из дистрибутива KSC>.'
}

Write-Host ''
Write-Host '=========== ЗНАЧЕНИЯ ДЛЯ МАСТЕРА УСТАНОВКИ ===========' -ForegroundColor Cyan
@"
Тип установки .................. Выборочная
Размер сети .................... от 1000 до 5000 устройств
Учётная запись службы .......... $($KSC.DomainNetBios)\$($KSC.SvcAccount) (учётная запись домена)
СУБД ........................... MySQL / MariaDB
   Имя сервера ................. $($KSC.DbHost)
   Порт ........................ $($KSC.PortMariaDb)
   Имя базы данных ............. $($KSC.DbName)
   Учётная запись .............. $($KSC.DbUser)
Общая папка .................... $($KSC.KlShareDir)
Порт подключения Агентов ....... $($KSC.PortAgentSsl)  (SSL)
Порт без SSL ................... $($KSC.PortAgentNoSsl)
Порт консоли (MMC) ............. $($KSC.PortMmc)
Порт OpenAPI ................... $($KSC.PortOpenApi)
Адрес Сервера администрирования  $fqdn      <-- ИМЕННО FQDN, НЕ IP-адрес
Плагины ........................ KES for Windows, KESL (Linux), KSWS (при наличии файловых серверов)
"@ | Write-Host
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''

if ($Silent) {
    $paramsFile = "$PSScriptRoot\31_ksc_setup_params.txt"
    if (-not (Test-Path $paramsFile)) { throw "Не найден файл параметров $paramsFile" }
    $params = (Get-Content $paramsFile | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }) -join ' '
    Write-KscLog "Тихая установка. Параметры: $params" 'WARN'
    Write-KscLog 'Убедитесь, что состав ключей соответствует документации на вашу версию KSC.' 'WARN'
    $proc = Start-Process $SetupPath -ArgumentList $params -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) { throw "Инсталлятор вернул код $($proc.ExitCode)." }
} else {
    Write-KscLog 'Запуск мастера установки. Введите значения из таблицы выше.'
    Start-Process $SetupPath -Wait
}

# ------------------------------------------------------------------ 8. Постпроверка

$srvSvc = Get-Service 'kladminserver*' -ErrorAction SilentlyContinue
if ($srvSvc -and $srvSvc.Status -eq 'Running') {
    Write-KscLog "Служба Сервера администрирования запущена: $($srvSvc.Name)" 'OK'
} else {
    Add-Problem 'Служба Сервера администрирования не запущена — проверьте журнал установки.' 'WARN'
}

Write-KscLog '=== Следующий шаг: 35_Install-WebConsole.ps1, затем 40_Set-PostInstall.ps1 ===' 'OK'
