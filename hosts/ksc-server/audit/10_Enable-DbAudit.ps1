<#
.SYNOPSIS
    Включение аудита СУБД MariaDB (плагин server_audit) по требованиям Приказа ОАЦ № 130.

.DESCRIPTION
    Скрипт выполняется на узле СУБД (по умолчанию $KSC.AuditDbHost) и:

      1. Проверяет наличие библиотеки плагина server_audit.dll в каталоге плагинов.
      2. Создаёт каталог файла аудита и назначает на него ограничительные права
         (SYSTEM, администраторы, учётная запись службы СУБД, группа аудиторов).
      3. Подставляет блок параметров из 11_server_audit.ini.template в my.ini
         между маркерами KSC-AUDIT BEGIN / KSC-AUDIT END (идемпотентно).
      4. Перезапускает службу СУБД и проверяет фактические значения переменных
         server_audit_* и наличие записей в файле аудита.

    Состав регистрируемых событий задаётся в common/config.ps1
    ($KSC.AuditEvents, $KSC.AuditExclUsers) — см. docs/06_db_audit/README.md.

    Проверка (шаг 4) требует пароль root СУБД; при -SkipVerify выполняется
    только настройка, а команды для ручной проверки выводятся на экран.

.PARAMETER IniPath
    Путь к my.ini. По умолчанию определяется автоматически: <DataDir>\my.ini,
    затем <InstallDir>\data\my.ini.

.PARAMETER ServiceName
    Имя службы СУБД. По умолчанию определяется автоматически (MariaDB, MySQL).

.PARAMETER SkipVerify
    Не подключаться к СУБД для проверки применённых параметров.

.PARAMETER NoRestart
    Не перезапускать службу: параметры вступят в силу при следующем запуске.

.PARAMETER Rollback
    Удалить блок параметров аудита из my.ini (плагин перестанет загружаться
    после перезапуска службы). Файлы аудита не удаляются.

.EXAMPLE
    .\10_Enable-DbAudit.ps1
    .\10_Enable-DbAudit.ps1 -IniPath 'C:\Program Files\MariaDB 10.5\data\my.ini'
    .\10_Enable-DbAudit.ps1 -Rollback
#>
[CmdletBinding()]
param(
    [string]$IniPath,
    [string]$ServiceName,
    [switch]$SkipVerify,
    [switch]$NoRestart,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

# Маркеры только из символов ASCII: my.ini сохраняется в однобайтовой кодировке,
# и кириллица в маркере нарушила бы повторный поиск блока.
$markerBegin = '# >>> KSC-AUDIT BEGIN (managed by 10_Enable-DbAudit.ps1, do not edit manually)'
$markerEnd = '# <<< KSC-AUDIT END'

# ------------------------------------------------------------------ Служба и пути

if (-not $ServiceName) {
    $svc = Get-Service | Where-Object { $_.Name -in @('MariaDB', 'MySQL') -or $_.DisplayName -match 'MariaDB' } | Select-Object -First 1
    if (-not $svc) { throw 'Служба СУБД не найдена. Укажите её имя параметром -ServiceName.' }
    $ServiceName = $svc.Name
}
Write-KscLog "Служба СУБД: $ServiceName"

$svcCim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
$svcAccount = $svcCim.StartName
# Путь к mysqld в командной строке службы: "C:\...\bin\mysqld.exe" --defaults-file=...
$binPath = ([regex]'"?(?<p>[^"]+mysqld\.exe)"?').Match($svcCim.PathName).Groups['p'].Value
$installDir = if ($binPath) { Split-Path (Split-Path $binPath -Parent) -Parent } else { $KSC.MariaDbInstallDir }
$defaultsFile = ([regex]'--defaults-file="?(?<f>[^"]+\.ini)"?').Match($svcCim.PathName).Groups['f'].Value

Write-KscLog "Каталог установки: $installDir"
Write-KscLog "Учётная запись службы: $svcAccount"

if (-not $IniPath) {
    $IniPath = @($defaultsFile, (Join-Path $KSC.MariaDbDataDir 'my.ini'), (Join-Path $installDir 'data\my.ini')) |
        Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $IniPath -or -not (Test-Path $IniPath)) {
    throw 'Не найден my.ini. Укажите путь параметром -IniPath.'
}
Write-KscLog "Файл конфигурации: $IniPath"

# ------------------------------------------------------------------ Откат

if ($Rollback) {
    $text = Get-Content $IniPath -Raw
    if ($text -notmatch [regex]::Escape($markerBegin)) {
        Write-KscLog 'Блок параметров аудита в my.ini отсутствует — откат не требуется.' 'WARN'
        return
    }
    Copy-Item $IniPath "$IniPath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    $pattern = '(?s)\r?\n?' + [regex]::Escape($markerBegin) + '.*?' + [regex]::Escape($markerEnd) + '\r?\n?'
    Set-Content -Path $IniPath -Value ([regex]::Replace($text, $pattern, "`r`n")) -Encoding ASCII
    Write-KscLog 'Блок параметров аудита удалён из my.ini. Перезапустите службу для применения.' 'OK'
    return
}

# ------------------------------------------------------------------ 1. Плагин

$pluginDll = Join-Path $installDir 'lib\plugin\server_audit.dll'
if (-not (Test-Path $pluginDll)) {
    throw "Не найдена библиотека плагина: $pluginDll. Проверьте комплектность установки MariaDB."
}
Write-KscLog "Библиотека плагина найдена: $pluginDll" 'OK'

# ------------------------------------------------------------------ 2. Каталог аудита и права

$auditDir = $KSC.AuditLogDir
$auditFile = Join-Path $auditDir $KSC.AuditFileName
if (-not (Test-Path $auditDir)) {
    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
    Write-KscLog "Создан каталог аудита: $auditDir" 'OK'
}

# Доступ к файлу аудита: запись — только служба СУБД и система, чтение — аудиторы.
$acl = Get-Acl $auditDir
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

function Add-AuditDirRule {
    param([string]$Identity, [string]$Rights)
    try {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $Identity, $Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Write-KscLog "  права на каталог аудита: $Identity -> $Rights"
    }
    catch {
        Write-KscLog "  не удалось назначить права для '$Identity': $($_.Exception.Message)" 'WARN'
    }
}

Add-AuditDirRule -Identity 'NT AUTHORITY\SYSTEM' -Rights 'FullControl'
Add-AuditDirRule -Identity 'BUILTIN\Administrators' -Rights 'FullControl'
if ($svcAccount -and $svcAccount -notmatch '^(LocalSystem|NT AUTHORITY\\SYSTEM)$') {
    Add-AuditDirRule -Identity $svcAccount -Rights 'Modify'
}
$auditorsGroup = "$($KSC.DomainNetBios)\$($KSC.AuditorsGroup)"
Add-AuditDirRule -Identity $auditorsGroup -Rights 'ReadAndExecute'
Set-Acl -Path $auditDir -AclObject $acl
Write-KscLog "Права на $auditDir ограничены (наследование отключено)." 'OK'

# ------------------------------------------------------------------ 3. Параметры в my.ini

$templatePath = Join-Path $PSScriptRoot '11_server_audit.ini.template'
$block = (Get-Content $templatePath -Encoding UTF8 |
    Where-Object { $_ -notmatch '^\s*//' }) -join "`r`n"
$block = $block.
    Replace('{{AUDIT_FILE}}', $auditFile).
    Replace('{{ROTATE_SIZE}}', ($KSC.AuditRotateSizeMb * 1MB)).
    Replace('{{ROTATIONS}}', $KSC.AuditRotations).
    Replace('{{EVENTS}}', $KSC.AuditEvents).
    Replace('{{EXCL_USERS}}', $KSC.AuditExclUsers).
    Replace('{{QUERY_LOG_LIMIT}}', $KSC.AuditQueryLogLimit)
$block = "$markerBegin`r`n$($block.Trim())`r`n$markerEnd"

$ini = Get-Content $IniPath -Raw
Copy-Item $IniPath "$IniPath.bak-$(Get-Date -Format yyyyMMddHHmmss)"

if ($ini -match [regex]::Escape($markerBegin)) {
    $pattern = '(?s)' + [regex]::Escape($markerBegin) + '.*?' + [regex]::Escape($markerEnd)
    # Удвоение '$' защищает текст замены от толкования как ссылки на группу.
    $ini = [regex]::Replace($ini, $pattern, $block.Replace('$', '$$'))
    Write-KscLog 'Блок параметров аудита в my.ini обновлён.' 'OK'
}
else {
    $ini = $ini.TrimEnd() + "`r`n`r`n" + $block + "`r`n"
    Write-KscLog 'Блок параметров аудита добавлен в my.ini.' 'OK'
}
Set-Content -Path $IniPath -Value $ini -Encoding ASCII

# ------------------------------------------------------------------ 4. Перезапуск и проверка

if ($NoRestart) {
    Write-KscLog 'Перезапуск службы пропущен (-NoRestart): параметры применятся при следующем старте.' 'WARN'
    return
}

Write-KscLog 'Перезапуск службы СУБД...'
Restart-Service $ServiceName -Force
(Get-Service $ServiceName).WaitForStatus('Running', '00:03:00')
Write-KscLog 'Служба запущена.' 'OK'

if ($SkipVerify) {
    Write-KscLog "Проверка пропущена. Выполните вручную: SHOW GLOBAL VARIABLES LIKE 'server_audit%';" 'WARN'
    return
}

$mysqlExe = Join-Path $installDir 'bin\mysql.exe'
if (-not (Test-Path $mysqlExe)) { $mysqlExe = Join-Path $installDir 'bin\mariadb.exe' }
if (-not (Test-Path $mysqlExe)) {
    Write-KscLog 'Клиент mysql.exe не найден — проверка пропущена.' 'WARN'
    return
}

$rootPwdSec = Read-Host 'Пароль root СУБД (для проверки параметров)' -AsSecureString
$tmpCnf = Join-Path $env:TEMP ('ksc-audit-{0}.ini' -f ([guid]::NewGuid()))
try {
    $rootPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rootPwdSec))
    Set-Content -Path $tmpCnf -Value "[client]`nuser=root`npassword=$rootPlain`nport=$($KSC.PortMariaDb)`nhost=127.0.0.1" -Encoding ASCII
    icacls $tmpCnf /inheritance:r /grant:r "$env:USERNAME:(R)" 'SYSTEM:(R)' | Out-Null

    $vars = & $mysqlExe "--defaults-file=$tmpCnf" -N -B -e "SHOW GLOBAL VARIABLES LIKE 'server_audit%'" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Ошибка подключения к СУБД: $vars" }
    $vars | Out-String | Write-Host

    $logging = ($vars | Where-Object { $_ -match '^server_audit_logging' }) -replace '.*\s'
    if ($logging -ne 'ON') { throw 'server_audit_logging не равен ON — аудит не включён.' }

    # Контрольное событие: неуспешная попытка обращения к несуществующей таблице
    & $mysqlExe "--defaults-file=$tmpCnf" -e 'SELECT 1 FROM information_schema.tables LIMIT 1' | Out-Null
}
finally {
    if (Test-Path $tmpCnf) {
        Set-Content -Path $tmpCnf -Value ('0' * 4096) -Encoding ASCII -ErrorAction SilentlyContinue
        Remove-Item $tmpCnf -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable rootPlain -ErrorAction SilentlyContinue
}

if (Test-Path $auditFile) {
    $last = Get-Content $auditFile -Tail 3
    Write-KscLog "Последние записи файла аудита ($auditFile):" 'OK'
    $last | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
}
else {
    Write-KscLog "Файл аудита $auditFile ещё не создан — проверьте права службы на каталог." 'WARN'
}

Write-KscLog '=== Аудит СУБД включён. Следующий шаг: 20_Install-AuditForwarder.ps1 ===' 'OK'
