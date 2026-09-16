<#
.SYNOPSIS
    Проверка цепочки аудита СУБД: плагин -> файл -> журнал Windows -> доступ коллектора.

.DESCRIPTION
    Контроль работоспособности после выполнения 25-27. Проверяются:
      * файл аудита существует, пополняется, права ограничены;
      * задача конвертера зарегистрирована и завершается без ошибок;
      * журнал событий создан, содержит свежие записи и запись "источник жив";
      * учётная запись коллектора состоит в требуемых группах и не заблокирована;
      * правила брандмауэра для адреса коллектора созданы, порт RPC прослушивается;
      * состав событий покрывает пункты перечня Приказа ОАЦ № 130
        (сессии, команды администраторов, изменение полномочий).

    Результат: таблица проверок и итоговый код возврата (0 — все проверки пройдены).

.EXAMPLE
    .\28_Test-DbAudit.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\..\..\common\config.ps1"

$auditFile = Join-Path $KSC.AuditLogDir $KSC.AuditFileName
$results = New-Object Collections.Generic.List[object]

function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Проверка = $Name; Результат = $(if ($Passed) { 'OK' } else { 'ОШИБКА' }); Подробности = $Detail })
}

# ------------------------------------------------------------------ Файл аудита

if (Test-Path $auditFile) {
    $item = Get-Item $auditFile
    $ageMin = [int]((Get-Date) - $item.LastWriteTime).TotalMinutes
    Add-Check 'Файл аудита существует' $true ('{0}, {1:N1} МБ' -f $auditFile, ($item.Length / 1MB))
    Add-Check 'Файл аудита пополняется' ($ageMin -le 60) "последняя запись $ageMin мин назад"

    $acl = Get-Acl $auditFile
    $wide = $acl.Access | Where-Object {
        $_.IdentityReference -match 'Everyone|Все|BUILTIN\\Users|Пользователи' -and $_.AccessControlType -eq 'Allow'
    }
    Add-Check 'Права на файл аудита ограничены' (-not $wide) $(if ($wide) { 'есть разрешения для широких групп' } else { 'доступ только у администраторов, службы и аудиторов' })
}
else {
    Add-Check 'Файл аудита существует' $false "не найден: $auditFile (выполните 25_Enable-DbAudit.ps1)"
}

# ------------------------------------------------------------------ Конвертер

$task = Get-ScheduledTask -TaskName 'KSC-DbAudit-Forwarder' -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -TaskName 'KSC-DbAudit-Forwarder'
    Add-Check 'Задача конвертера зарегистрирована' ($task.State -ne 'Disabled') "состояние: $($task.State)"
    Add-Check 'Последний запуск конвертера успешен' ($info.LastTaskResult -eq 0) "код $($info.LastTaskResult), запуск $($info.LastRunTime)"
}
else {
    Add-Check 'Задача конвертера зарегистрирована' $false 'задача KSC-DbAudit-Forwarder не найдена (выполните 26_Install-AuditForwarder.ps1)'
}

# ------------------------------------------------------------------ Журнал событий

$logExists = [Diagnostics.EventLog]::SourceExists($KSC.AuditWinLogSource)
Add-Check 'Источник журнала зарегистрирован' $logExists $KSC.AuditWinLogSource

if ($logExists) {
    $events = Get-WinEvent -LogName $KSC.AuditWinLogName -MaxEvents 500 -ErrorAction SilentlyContinue
    Add-Check 'В журнале есть события' ([bool]$events) ('получено записей: {0}' -f @($events).Count)

    $heartbeat = $events | Where-Object { $_.Id -eq 1100 } | Select-Object -First 1
    if ($heartbeat) {
        $hbAge = [int]((Get-Date) - $heartbeat.TimeCreated).TotalMinutes
        Add-Check 'Признак работоспособности источника' ($hbAge -le ($KSC.AuditHeartbeatMin * 3)) "последняя запись 1100: $hbAge мин назад"
    }
    else {
        Add-Check 'Признак работоспособности источника' $false 'события с кодом 1100 отсутствуют'
    }

    $errors = $events | Where-Object { $_.Id -eq 1101 }
    Add-Check 'Ошибки конвертера отсутствуют' (-not $errors) $(if ($errors) { "событий 1101: $(@($errors).Count), последнее: $($errors[0].TimeCreated)" } else { 'событий 1101 нет' })

    # Соответствие перечню Приказа ОАЦ № 130: контроль сессий и команды.
    $sessionEvents = $events | Where-Object { $_.Id -in 1001, 1002, 1003 }
    Add-Check 'Регистрируются события сессий (п. 2.1-2.2)' ([bool]$sessionEvents) ('коды 1001-1003: {0}' -f @($sessionEvents).Count)

    $commandEvents = $events | Where-Object { $_.Id -in 1010, 1011, 1012, 1013, 1020 }
    Add-Check 'Регистрируются команды и объекты (п. 2.3-2.4)' ([bool]$commandEvents) ('коды 1010-1020: {0}' -f @($commandEvents).Count)
}

# ------------------------------------------------------------------ Учётная запись коллектора

$user = Get-LocalUser -Name $KSC.AuditAccount -ErrorAction SilentlyContinue
if ($user) {
    Add-Check 'Учётная запись коллектора активна' ($user.Enabled) "$($KSC.AuditAccount), включена: $($user.Enabled)"
    $readers = Get-LocalGroup -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue
    $inGroup = if ($readers) { (Get-LocalGroupMember -Group $readers -ErrorAction SilentlyContinue).SID.Value -contains $user.SID.Value } else { $false }
    Add-Check 'Учётная запись в группе читателей журнала' $inGroup 'S-1-5-32-573 (Event Log Readers)'

    $sddl = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$($KSC.AuditWinLogName)" -Name CustomSD -ErrorAction SilentlyContinue).CustomSD
    Add-Check 'Права чтения журнала выданы' ([bool]$sddl -and $sddl -match [regex]::Escape($user.SID.Value)) $(if ($sddl) { 'CustomSD содержит SID учётной записи' } else { 'CustomSD не задан' })
}
else {
    Add-Check 'Учётная запись коллектора активна' $false "$($KSC.AuditAccount) не найдена (выполните 27_Set-AuditCollectorAccess.ps1)"
}

# ------------------------------------------------------------------ Сеть

$fwRules = Get-NetFirewallRule -Group 'KSC Audit' -ErrorAction SilentlyContinue
Add-Check 'Правила брандмауэра для коллектора' ([bool]$fwRules) ('правил: {0}, источник {1}' -f @($fwRules).Count, $KSC.AuditCollectorHost)

$rpcListening = [bool](Get-NetTCPConnection -LocalPort 135 -State Listen -ErrorAction SilentlyContinue)
Add-Check 'Порт RPC 135 прослушивается' $rpcListening 'требуется для удалённого чтения журнала'

# ------------------------------------------------------------------ Итог

Write-Host ''
$results | Format-Table -AutoSize
$failed = @($results | Where-Object { $_.Результат -ne 'OK' })
if ($failed.Count -eq 0) {
    Write-KscLog 'Все проверки цепочки аудита пройдены.' 'OK'
    exit 0
}
Write-KscLog "Не пройдено проверок: $($failed.Count). Устраните замечания и повторите." 'ERROR'
exit 1
