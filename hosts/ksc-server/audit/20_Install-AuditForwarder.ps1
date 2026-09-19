<#
.SYNOPSIS
    Установка конвертера записей аудита MariaDB в журнал событий Windows.

.DESCRIPTION
    Плагин server_audit на Windows умеет писать только в файл
    (MDEV-19851: значение SYSLOG на этой платформе не действует), а MP 10 Collector
    в выбранной схеме читает журнал Windows удалённо. Связующее звено — конвертер,
    который переносит новые записи файла аудита в отдельный журнал событий.

    Скрипт:
      1. Создаёт журнал событий $KSC.AuditWinLogName и источник $KSC.AuditWinLogSource,
         задаёт размер журнала и перезапись по мере заполнения.
      2. Копирует рабочий сценарий и common/config.ps1 в
         C:\ProgramData\KscDeployment\bin (права: запись — только администраторы
         и SYSTEM), чтобы работа конвертера не зависела от носителя с репозиторием.
      3. Регистрирует задачу планировщика "KSC-DbAudit-Forwarder": запуск от SYSTEM
         при старте системы и далее каждые $KSC.AuditForwardPeriodMin минут,
         параллельные запуски запрещены.
      4. Выполняет задачу и показывает последние перенесённые события.

.PARAMETER Rollback
    Удалить задачу планировщика и рабочие файлы. Журнал событий сохраняется
    (удаление журнала с накопленными событиями выполняется только вручную).

.EXAMPLE
    .\20_Install-AuditForwarder.ps1
    .\20_Install-AuditForwarder.ps1 -Rollback
#>
[CmdletBinding()]
param([switch]$Rollback)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

$taskName = 'KSC-DbAudit-Forwarder'
$binRoot = 'C:\ProgramData\KscDeployment\bin'
$workerRel = 'hosts\ksc-server\audit\21_Publish-DbAuditToEventLog.ps1'
$workerPath = Join-Path $binRoot $workerRel

# ------------------------------------------------------------------ Откат

if ($Rollback) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-KscLog "Задача планировщика '$taskName' удалена." 'OK'
    }
    if (Test-Path $binRoot) {
        Remove-Item $binRoot -Recurse -Force
        Write-KscLog "Рабочие файлы удалены: $binRoot" 'OK'
    }
    Write-KscLog "Журнал '$($KSC.AuditWinLogName)' сохранён. Удаление: Remove-EventLog -LogName '$($KSC.AuditWinLogName)'" 'WARN'
    return
}

# ------------------------------------------------------------------ 1. Журнал событий

if ([Diagnostics.EventLog]::SourceExists($KSC.AuditWinLogSource)) {
    $existingLog = [Diagnostics.EventLog]::LogNameFromSourceName($KSC.AuditWinLogSource, '.')
    if ($existingLog -ne $KSC.AuditWinLogName) {
        throw "Источник '$($KSC.AuditWinLogSource)' уже зарегистрирован в журнале '$existingLog'. Удалите его: Remove-EventLog -Source '$($KSC.AuditWinLogSource)'"
    }
    Write-KscLog "Журнал '$($KSC.AuditWinLogName)' и источник '$($KSC.AuditWinLogSource)' уже существуют." 'WARN'
}
else {
    New-EventLog -LogName $KSC.AuditWinLogName -Source $KSC.AuditWinLogSource
    Write-KscLog "Создан журнал '$($KSC.AuditWinLogName)' с источником '$($KSC.AuditWinLogSource)'." 'OK'
}

# Журнал — локальный буфер доставки в SIEM: перезапись по мере заполнения
# допустима, долговременное хранение обеспечивает коллектор.
Limit-EventLog -LogName $KSC.AuditWinLogName `
    -MaximumSize ($KSC.AuditWinLogSizeMb * 1MB) `
    -OverflowAction OverwriteAsNeeded
Write-KscLog "Размер журнала: $($KSC.AuditWinLogSizeMb) МБ, режим — перезапись по мере заполнения." 'OK'

# ------------------------------------------------------------------ 2. Рабочие файлы

foreach ($dir in @($binRoot, (Join-Path $binRoot 'common'), (Join-Path $binRoot 'hosts\ksc-server\audit'))) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Copy-Item (Join-Path $PSScriptRoot '21_Publish-DbAuditToEventLog.ps1') $workerPath -Force
Copy-Item "$PSScriptRoot\..\..\..\common\config.ps1" (Join-Path $binRoot 'common\config.ps1') -Force
Write-KscLog "Рабочие файлы размещены: $binRoot" 'OK'

# Изменять сценарий конвертера вправе только администраторы и система.
$acl = Get-Acl $binRoot
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
foreach ($id in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    'BUILTIN\Users', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -Path $binRoot -AclObject $acl
Write-KscLog 'Права на каталог конвертера ограничены.' 'OK'

# ------------------------------------------------------------------ 3. Задача планировщика

$interval = 'PT{0}M' -f $KSC.AuditForwardPeriodMin
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $workerPath

# Задача описывается XML: только так задаётся бессрочное повторение
# с интервалом в минуту (командлеты New-ScheduledTaskTrigger требуют
# конечной длительности повторения).
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Перенос записей аудита MariaDB (server_audit) в журнал событий Windows для сбора MP 10 Collector.</Description>
    <URI>\$taskName</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
      <Repetition>
        <Interval>$interval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </BootTrigger>
    <TimeTrigger>
      <StartBoundary>2000-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>$interval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>6</Priority>
    <RestartOnFailure>
      <Interval>PT5M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$arguments</Arguments>
    </Exec>
  </Actions>
</Task>
"@

Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force | Out-Null
Write-KscLog "Задача '$taskName' зарегистрирована: запуск от SYSTEM каждые $($KSC.AuditForwardPeriodMin) мин." 'OK'

# ------------------------------------------------------------------ 4. Первый запуск

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 10
$info = Get-ScheduledTaskInfo -TaskName $taskName
Write-KscLog "Код завершения последнего запуска: $($info.LastTaskResult) (0 — успешно)." $(if ($info.LastTaskResult -eq 0) { 'OK' } else { 'WARN' })

$events = Get-WinEvent -LogName $KSC.AuditWinLogName -MaxEvents 5 -ErrorAction SilentlyContinue
if ($events) {
    Write-KscLog 'Последние события журнала аудита СУБД:' 'OK'
    $events | ForEach-Object { Write-Host ('    {0}  id={1}  {2}' -f $_.TimeCreated, $_.Id, ($_.Message -split "`r?`n")[0]) -ForegroundColor Gray }
}
else {
    Write-KscLog 'События пока не перенесены: проверьте, что аудит включён (10_Enable-DbAudit.ps1) и файл аудита пополняется.' 'WARN'
}

Write-KscLog '=== Конвертер установлен. Следующий шаг: 40_Set-AuditCollectorAccess.ps1 ===' 'OK'
