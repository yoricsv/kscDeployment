<#
.SYNOPSIS
    Резервное копирование данных Сервера администрирования KSC (klbackup) с ротацией.

.DESCRIPTION
    Создаёт резервную копию средствами штатной утилиты klbackup.exe:
    база данных, сертификат Сервера, параметры. Копия сертификата критична:
    без неё восстановление требует ручного перенаправления всех Агентов.

    Дополнительно:
      * ротация копий по числу дней хранения (BackupKeepCopies);
      * контроль свободного места перед запуском;
      * копирование последней резервной копии на внешний ресурс (-RemotePath);
      * регистрация задания планировщика (-Register).

    Требования: скрипт запускается от учётной записи с правами локального
    администратора; служба Сервера администрирования должна быть запущена.

.PARAMETER RemotePath
    UNC-путь для выноса копии за пределы хоста (например \\backup\ksc$).

.PARAMETER Register
    Зарегистрировать ежедневное задание в планировщике и выйти.

.PARAMETER Time
    Время запуска задания при -Register (по умолчанию 01:30).

.EXAMPLE
    .\50_Backup-KscServer.ps1
    .\50_Backup-KscServer.ps1 -RemotePath \\10.20.30.11\ksc-backup$
    .\50_Backup-KscServer.ps1 -Register -Time 01:30
#>
[CmdletBinding()]
param(
    [string]$RemotePath,
    [switch]$Register,
    [string]$Time = '01:30'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

# ------------------------------------------------------------------ Регистрация задания

if ($Register) {
    $taskName = 'KSC - Резервное копирование Сервера администрирования'
    $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($RemotePath) { $taskArgs += " -RemotePath `"$RemotePath`"" }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgs
    $trigger = New-ScheduledTaskTrigger -Daily -At $Time
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 4)

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-KscLog "Задание '$taskName' зарегистрировано на $Time ежедневно." 'OK'
    return
}

# ------------------------------------------------------------------ Поиск klbackup

$candidates = @(
    'C:\Program Files (x86)\Kaspersky Lab\Kaspersky Security Center\klbackup.exe'
    'C:\Program Files\Kaspersky Lab\Kaspersky Security Center\klbackup.exe'
)
$klbackup = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $klbackup) { throw "Не найден klbackup.exe. Проверьте каталог установки KSC." }

# ------------------------------------------------------------------ Проверки

$svc = Get-Service 'kladminserver*' -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-KscLog 'Служба Сервера администрирования не запущена — резервная копия может быть неполной.' 'WARN'
}

$backupRoot = $KSC.BackupDir
if (-not (Test-Path $backupRoot)) { New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null }

$vol = Get-Volume -DriveLetter (Split-Path -Qualifier $backupRoot).TrimEnd(':')
$freeGb = [math]::Round($vol.SizeRemaining / 1GB)
Write-KscLog "Свободно на томе резервных копий: $freeGb ГБ"
if ($freeGb -lt 20) { throw "Недостаточно места для резервной копии ($freeGb ГБ). Освободите том." }

# ------------------------------------------------------------------ Копирование

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$target = Join-Path $backupRoot $stamp
New-Item -ItemType Directory -Path $target -Force | Out-Null

Write-KscLog "Запуск klbackup -> $target"
# -savecert  сохранить сертификат Сервера администрирования
# -logfile   журнал операции
# -path      каталог назначения
$logFile = Join-Path $KSC.LogDir "klbackup-$stamp.log"
$proc = Start-Process $klbackup -ArgumentList @('-path', "`"$target`"", '-logfile', "`"$logFile`"", '-savecert') `
    -Wait -PassThru -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-KscLog "klbackup завершился с кодом $($proc.ExitCode). Журнал: $logFile" 'ERROR'
    throw 'Резервное копирование не выполнено.'
}

$sizeGb = [math]::Round(((Get-ChildItem $target -Recurse -File | Measure-Object Length -Sum).Sum / 1GB), 2)
Write-KscLog "Резервная копия создана: $target ($sizeGb ГБ)" 'OK'

# ------------------------------------------------------------------ Вынос копии

if ($RemotePath) {
    if (Test-Path $RemotePath) {
        $dest = Join-Path $RemotePath $stamp
        Copy-Item $target $dest -Recurse -Force
        Write-KscLog "Копия перенесена на внешний ресурс: $dest" 'OK'
    } else {
        Write-KscLog "Внешний ресурс $RemotePath недоступен — копия осталась только на хосте KSC." 'ERROR'
    }
}

# ------------------------------------------------------------------ Ротация

$keep = $KSC.BackupKeepCopies
$old = Get-ChildItem $backupRoot -Directory |
    Where-Object { $_.Name -match '^\d{8}-\d{6}$' } |
    Sort-Object Name -Descending |
    Select-Object -Skip $keep
foreach ($dir in $old) {
    Remove-Item $dir.FullName -Recurse -Force
    Write-KscLog "Удалена устаревшая копия: $($dir.Name)"
}
Write-KscLog "Хранится копий: $((Get-ChildItem $backupRoot -Directory).Count) (лимит $keep)." 'OK'

# ------------------------------------------------------------------ Контроль восстановления

Write-KscLog 'Напоминание: не реже одного раза в квартал выполняйте тестовое восстановление на изолированном стенде.' 'WARN'
Write-KscLog "Восстановление: klrestore.exe -path `"<каталог копии>`" (служба Сервера должна быть остановлена)."
