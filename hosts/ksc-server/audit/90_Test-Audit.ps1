<#
.SYNOPSIS
    Проверка аудита узла: ОС, СУБД и прикладное ПО, доставка событий коллектору.

.DESCRIPTION
    Контроль работоспособности после выполнения 00-40. Проверяются:
      * расширенная политика аудита ОС, журналирование PowerShell,
        размеры журналов и аудит доступа к каталогам;
      * файл аудита СУБД существует, пополняется, права ограничены;
      * задача конвертера зарегистрирована и завершается без ошибок;
      * журнал событий создан, содержит свежие записи и запись "источник жив";
      * учётная запись коллектора состоит в требуемых группах и не заблокирована;
      * правила брандмауэра для адреса коллектора созданы, порт RPC прослушивается;
      * состав событий покрывает пункты перечня Приказа ОАЦ № 130
        (сессии, команды администраторов, изменение полномочий).

    Результат: таблица проверок и итоговый код возврата (0 — все проверки пройдены).

.EXAMPLE
    .\90_Test-Audit.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\..\..\..\common\config.ps1"

$auditFile = Join-Path $KSC.AuditLogDir $KSC.AuditFileName
$results = New-Object Collections.Generic.List[object]

function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ Проверка = $Name; Результат = $(if ($Passed) { 'OK' } else { 'ОШИБКА' }); Подробности = $Detail })
}

# ------------------------------------------------------------------ Аудит ОС

# Подкатегории проверяются по GUID: названия локализованы и различаются между сборками.
$requiredSubcategories = [ordered]@{
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Вход в систему'
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'Управление учётными записями'
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Управление группами безопасности'
    '{0CCE9228-69AE-11D9-BED3-505054503030}' = 'Использование особых прав'
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Создание процесса'
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'Изменение политики аудита'
    '{0CCE921D-69AE-11D9-BED3-505054503030}' = 'Файловая система (SACL)'
}
$noAudit = @()
foreach ($guid in $requiredSubcategories.Keys) {
    $line = & auditpol.exe /get /subcategory:"$guid" 2>&1 | Where-Object { $_ -match '\S' } | Select-Object -Last 1
    # Признак настроенной подкатегории — упоминание успеха или отказа в колонке параметров.
    if ($line -notmatch '(?i)success|failure|успех|отказ') { $noAudit += $requiredSubcategories[$guid] }
}
Add-Check 'Расширенная политика аудита ОС' ($noAudit.Count -eq 0) $(if ($noAudit) { 'не настроены: ' + ($noAudit -join ', ') } else { "проверено подкатегорий: $($requiredSubcategories.Count)" })

$cmdLine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
Add-Check 'Командная строка в событиях 4688' ($cmdLine -eq 1) 'ProcessCreationIncludeCmdLine_Enabled'

$sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$transcript = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
Add-Check 'Журналирование PowerShell' (($sbl -eq 1) -and ($transcript -eq 1)) "блоки сценариев: $($sbl -eq 1), транскрипция: $($transcript -eq 1)"

$secLog = Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue
Add-Check 'Размер журнала безопасности' ([bool]$secLog -and $secLog.MaximumSizeInBytes -ge ($KSC.AuditSecurityLogSizeMb * 1MB)) $(if ($secLog) { '{0:N0} МБ' -f ($secLog.MaximumSizeInBytes / 1MB) } else { 'журнал недоступен' })

$dirSacl = if (Test-Path $KSC.AuditLogDir) { (Get-Acl -Path $KSC.AuditLogDir -Audit).Audit } else { $null }
Add-Check 'Аудит доступа к каталогу аудита' ([bool]$dirSacl) $(if ($dirSacl) { "правил аудита: $(@($dirSacl).Count)" } else { 'SACL не задан (выполните 00_Set-OsAudit.ps1)' })

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
    Add-Check 'Файл аудита существует' $false "не найден: $auditFile (выполните 10_Enable-DbAudit.ps1)"
}

# ------------------------------------------------------------------ Конвертер

$task = Get-ScheduledTask -TaskName 'KSC-DbAudit-Forwarder' -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -TaskName 'KSC-DbAudit-Forwarder'
    Add-Check 'Задача конвертера зарегистрирована' ($task.State -ne 'Disabled') "состояние: $($task.State)"
    Add-Check 'Последний запуск конвертера успешен' ($info.LastTaskResult -eq 0) "код $($info.LastTaskResult), запуск $($info.LastRunTime)"
}
else {
    Add-Check 'Задача конвертера зарегистрирована' $false 'задача KSC-DbAudit-Forwarder не найдена (выполните 20_Install-AuditForwarder.ps1)'
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
    Add-Check 'Учётная запись коллектора активна' $false "$($KSC.AuditAccount) не найдена (выполните 40_Set-AuditCollectorAccess.ps1)"
}

# ------------------------------------------------------------------ Аудит ПО KSC

$kavLog = Get-WinEvent -ListLog 'Kaspersky Event Log' -ErrorAction SilentlyContinue
Add-Check 'Журнал событий ПО Kaspersky' ([bool]$kavLog) $(if ($kavLog) { 'записей: {0}, размер {1:N0} МБ' -f $kavLog.RecordCount, ($kavLog.MaximumSizeInBytes / 1MB) } else { 'канал отсутствует: включите запись в журнал Windows в политике (30_Set-KscAppAudit.ps1)' })

$kscServices = @(Get-Service | Where-Object { $_.Name -match '^kl' -and $_.Status -eq 'Running' })
Add-Check 'Службы Kaspersky работают' ($kscServices.Count -gt 0) ('запущено служб: {0}' -f $kscServices.Count)

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
