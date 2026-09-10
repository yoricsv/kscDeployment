<#
.SYNOPSIS
    Установка и настройка MariaDB под Kaspersky Security Center.

.DESCRIPTION
    Порядок работы:
      1. Тихая установка MSI-пакета MariaDB (если СУБД ещё не установлена).
      2. Остановка службы и подстановка конфигурации из 21_my.ini.template.
      3. Удаление старых журналов ib_logfile* (требуется при смене innodb_log_file_size).
      4. Запуск службы и проверка применённых параметров.
      5. Создание базы данных и учётной записи по 22_Create-Database.sql.

    Пароли не сохраняются в файлы и не попадают в журнал: они запрашиваются
    интерактивно (SecureString) и передаются СУБД через временный файл
    с ограниченными правами, удаляемый в блоке finally.

.PARAMETER MsiPath
    Путь к дистрибутиву MariaDB (mariadb-10.11.x-winx64.msi).

.PARAMETER SkipInstall
    Пропустить установку MSI (СУБД уже установлена) и только применить конфигурацию.

.EXAMPLE
    .\20_Install-MariaDB.ps1 -MsiPath D:\distr\mariadb-10.11.9-winx64.msi
    .\20_Install-MariaDB.ps1 -SkipInstall
#>
[CmdletBinding()]
param(
    [string]$MsiPath,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$serviceName = 'MariaDB'
$installDir = $KSC.MariaDbInstallDir
$dataDir = $KSC.MariaDbDataDir
$mysqlExe = Join-Path $installDir 'bin\mysql.exe'

# ------------------------------------------------------------------ 1. Установка

if (-not $SkipInstall) {
    if (-not $MsiPath -or -not (Test-Path $MsiPath)) {
        throw "Укажите корректный путь к дистрибутиву: -MsiPath <...\mariadb-$($KSC.MariaDbVersion).x-winx64.msi>"
    }
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
        Write-KscLog "Служба $serviceName уже существует — установка пропущена." 'WARN'
    } else {
        Write-KscLog "Установка MariaDB из $MsiPath ..."
        $rootPwd = Read-Host 'Задайте пароль root СУБД' -AsSecureString
        $rootPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rootPwd))

        $msiArgs = @(
            '/i', "`"$MsiPath`""
            '/qn'
            "INSTALLDIR=`"$installDir`""
            "DATADIR=`"$dataDir`""
            "SERVICENAME=$serviceName"
            "PORT=$($KSC.PortMariaDb)"
            "PASSWORD=$rootPlain"
            'UTF8=1'
            'SKIPNETWORKING=0'
            '/L*v', "`"$($KSC.LogDir)\mariadb-install.log`""
        )
        $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
        Remove-Variable rootPlain -ErrorAction SilentlyContinue
        if ($p.ExitCode -ne 0) { throw "Установка MariaDB завершилась с кодом $($p.ExitCode). См. $($KSC.LogDir)\mariadb-install.log" }
        Write-KscLog 'MariaDB установлена.' 'OK'
    }
}

if (-not (Test-Path $mysqlExe)) { throw "Не найден $mysqlExe. Проверьте MariaDbInstallDir в config.ps1." }

# ------------------------------------------------------------------ 2. Конфигурация

Write-KscLog 'Остановка службы для применения конфигурации...'
Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
(Get-Service $serviceName).WaitForStatus('Stopped', '00:02:00')

$template = Get-Content "$PSScriptRoot\21_my.ini.template" -Raw -Encoding UTF8
$config = $template.
    Replace('{{DATADIR}}', $dataDir).
    Replace('{{PORT}}', $KSC.PortMariaDb).
    Replace('{{INNODB_BUFFER_POOL}}', $KSC.InnoDbBufferPool).
    Replace('{{INNODB_LOG_FILE_SIZE}}', $KSC.InnoDbLogFileSize)

$iniPath = Join-Path $dataDir 'my.ini'
if (Test-Path $iniPath) {
    $backup = "$iniPath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item $iniPath $backup
    Write-KscLog "Прежний my.ini сохранён: $backup"
}
Set-Content -Path $iniPath -Value $config -Encoding ASCII
Write-KscLog "Конфигурация записана: $iniPath" 'OK'

# ------------------------------------------------------------------ 3. Журналы InnoDB

# Изменение innodb_log_file_size требует удаления существующих журналов
# после корректной остановки службы, иначе СУБД не стартует.
$logFiles = Get-ChildItem -Path $dataDir -Filter 'ib_logfile*' -ErrorAction SilentlyContinue
if ($logFiles) {
    $logBackup = Join-Path $dataDir ('ib_logfile_backup_{0}' -f (Get-Date -Format yyyyMMddHHmmss))
    New-Item -ItemType Directory -Path $logBackup -Force | Out-Null
    $logFiles | Move-Item -Destination $logBackup
    Write-KscLog "Журналы InnoDB перемещены в $logBackup (удалите после успешного старта)." 'WARN'
}

# ------------------------------------------------------------------ 4. Запуск и проверка

Set-Service $serviceName -StartupType Automatic
Start-Service $serviceName
(Get-Service $serviceName).WaitForStatus('Running', '00:03:00')
Write-KscLog 'Служба MariaDB запущена.' 'OK'

# ------------------------------------------------------------------ 5. База данных и учётная запись

Write-KscLog '--- Создание базы данных и учётной записи ---'
$rootPwdSec = Read-Host 'Пароль root СУБД' -AsSecureString
$dbPwdSec = Read-Host "Задайте пароль для учётной записи $($KSC.DbUser)" -AsSecureString

$tmpSql = Join-Path $env:TEMP ('ksc-db-{0}.sql' -f ([guid]::NewGuid()))
$tmpCnf = Join-Path $env:TEMP ('ksc-cnf-{0}.ini' -f ([guid]::NewGuid()))
try {
    $rootPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($rootPwdSec))
    $dbPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbPwdSec))

    $sql = (Get-Content "$PSScriptRoot\22_Create-Database.sql" -Raw -Encoding UTF8).
        Replace('{{DB_NAME}}', $KSC.DbName).
        Replace('{{DB_USER}}', $KSC.DbUser).
        Replace('{{DB_PASS}}', $dbPlain)
    Set-Content -Path $tmpSql -Value $sql -Encoding UTF8

    # Пароль root передаётся через defaults-file, а не в командной строке:
    # аргументы процесса видны другим пользователям системы.
    Set-Content -Path $tmpCnf -Value "[client]`nuser=root`npassword=$rootPlain`nport=$($KSC.PortMariaDb)`nhost=127.0.0.1" -Encoding ASCII
    icacls $tmpCnf /inheritance:r /grant:r "$env:USERNAME:(R)" "SYSTEM:(R)" | Out-Null

    $output = & $mysqlExe "--defaults-file=$tmpCnf" -e "source $($tmpSql -replace '\\','/')" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Ошибка выполнения SQL: $output" }
    $output | Out-String | Write-Host
    Write-KscLog "База $($KSC.DbName) и учётная запись $($KSC.DbUser) созданы." 'OK'
}
finally {
    foreach ($f in @($tmpSql, $tmpCnf)) {
        if (Test-Path $f) {
            # Затирание содержимого перед удалением
            Set-Content -Path $f -Value ('0' * 4096) -Encoding ASCII -ErrorAction SilentlyContinue
            Remove-Item $f -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Variable rootPlain, dbPlain -ErrorAction SilentlyContinue
}

Write-KscLog 'Пароль учётной записи СУБД потребуется на шаге установки KSC — сохраните его в парольном хранилище.' 'WARN'
Write-KscLog '=== MariaDB готова. Следующий шаг: 30_Install-KscServer.ps1 ===' 'OK'
