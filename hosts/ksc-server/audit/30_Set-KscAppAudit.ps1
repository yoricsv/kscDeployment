<#
.SYNOPSIS
    Аудит прикладного ПО: Kaspersky Security Center и Агент администрирования.

.DESCRIPTION
    Приказ ОАЦ № 130 требует регистрировать действия администраторов средств
    защиты информации. Для KSC это два независимых потока:

      * события самого Сервера администрирования (вход в консоль, изменение
        политик, задач, прав, лицензии) — хранятся в базе KSC и выгружаются
        либо экспортом в SIEM по Syslog/CEF, либо записью в журнал Windows;
      * события защиты с управляемых устройств — приходят от Агентов
        и попадают в ту же базу.

    Сценарий выполняет то, что задаётся на стороне ОС, и проверяет остальное:

      1. Определяет каталог установки Сервера и состав служб Kaspersky.
      2. Включает и задаёт размер журналов Windows, в которые пишет ПО
         Kaspersky ("Kaspersky Event Log", Application).
      3. Выдаёт учётной записи сбора (kscaudit) право чтения этих журналов.
      4. Включает аудит доступа (SACL) к каталогу установки и общей папке,
         если он ещё не задан сценарием 00_Set-OsAudit.ps1.
      5. Печатает чек-лист параметров, которые задаются только в консоли
         (экспорт в SIEM, сроки хранения, роль аудитора), с подставленными
         значениями площадки.

    Параметры экспорта в SIEM берутся из common/config.ps1:
    SiemHost/SiemPort/SiemProtocol/SiemFormat, при пустом SiemHost
    используется адрес коллектора аудита.

.PARAMETER SkipSacl
    Не изменять аудит доступа к каталогам KSC.

.EXAMPLE
    .\30_Set-KscAppAudit.ps1 -WhatIf
    .\30_Set-KscAppAudit.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$SkipSacl)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

Write-KscLog '=== Аудит прикладного ПО (Kaspersky Security Center) ==='

# ------------------------------------------------------------------ 1. Состав ПО

$services = Get-Service | Where-Object { $_.Name -match '^kl' -or $_.Name -match 'KSCWebConsole' }
if (-not $services) {
    Write-KscLog 'Службы Kaspersky не найдены: сценарий предназначен для узла Сервера администрирования.' 'WARN'
}
else {
    foreach ($s in $services) {
        Write-KscLog ('  служба {0,-28} {1}' -f $s.Name, $s.Status) $(if ($s.Status -eq 'Running') { 'OK' } else { 'WARN' })
    }
}

$installDir = $null
$srvService = Get-CimInstance Win32_Service -Filter "Name='klserver'" -ErrorAction SilentlyContinue
if ($srvService -and $srvService.PathName) {
    $exe = ($srvService.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+).*$', '$1'
    if (Test-Path $exe) { $installDir = Split-Path (Split-Path $exe -Parent) -Parent }
}
if ($installDir) { Write-KscLog "Каталог установки Сервера: $installDir" 'OK' }
else { Write-KscLog 'Каталог установки Сервера определить не удалось (служба klserver не найдена).' 'WARN' }

# ------------------------------------------------------------------ 2. Журналы Windows для событий Kaspersky

Write-KscLog '--- Журналы Windows, используемые ПО Kaspersky ---'

# "Kaspersky Event Log" создаётся при включении записи событий в журнал
# Windows в политике Агента/KES; до этого канал отсутствует.
$kasperskyLogs = @('Kaspersky Event Log', 'Application')
$presentLogs = @()
foreach ($name in $kasperskyLogs) {
    $log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
    if (-not $log) {
        Write-KscLog "  ! журнал '$name' отсутствует: включите запись событий в журнал Windows в политике (см. чек-лист)." 'WARN'
        continue
    }
    $presentLogs += $name
    if (-not $PSCmdlet.ShouldProcess("Журнал $name", "Размер $($KSC.AuditChannelSizeMb) МБ")) { continue }
    $sizeBytes = $KSC.AuditChannelSizeMb * 1MB
    $out = & wevtutil.exe sl "$name" /e:true /ms:$sizeBytes /rt:false 2>&1
    if ($LASTEXITCODE -eq 0) { Write-KscLog "  + $name : $($KSC.AuditChannelSizeMb) МБ, перезапись по мере заполнения" 'OK' }
    else { Write-KscLog "  ! не удалось изменить '$name': $out" 'WARN' }
}

# ------------------------------------------------------------------ 3. Доступ учётной записи сбора

Write-KscLog '--- Доступ учётной записи сбора к журналам ПО ---'

$collectorUser = Get-LocalUser -Name $KSC.AuditAccount -ErrorAction SilentlyContinue
if (-not $collectorUser) {
    Write-KscLog "Учётная запись $($KSC.AuditAccount) не создана: выполните 40_Set-AuditCollectorAccess.ps1." 'WARN'
}
else {
    # Членство в группе "Читатели журнала событий" (S-1-5-32-573) даёт чтение
    # стандартных каналов; для классических журналов с собственным дескриптором
    # право выдаётся явно через CustomSD.
    foreach ($name in $presentLogs) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$name"
        if (-not (Test-Path $key)) {
            Write-KscLog "  = $name : современный канал, доступ обеспечивается членством в группе читателей журнала."
            continue
        }
        $sddl = (Get-ItemProperty -Path $key -Name CustomSD -ErrorAction SilentlyContinue).CustomSD
        $ace = "(A;;0x1;;;$($collectorUser.SID.Value))"
        if ($sddl -and $sddl.Contains($collectorUser.SID.Value)) {
            Write-KscLog "  = $name : право чтения уже выдано."
            continue
        }
        $newSddl = if ($sddl) { $sddl + $ace } else { 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;ER)' + $ace }
        if ($PSCmdlet.ShouldProcess($name, 'Выдать право чтения учётной записи сбора')) {
            New-ItemProperty -Path $key -Name CustomSD -Value $newSddl -PropertyType String -Force | Out-Null
            Write-KscLog "  + $name : чтение разрешено $($KSC.AuditAccount)" 'OK'
        }
    }
}

# ------------------------------------------------------------------ 4. Аудит доступа к каталогам KSC

if (-not $SkipSacl) {
    Write-KscLog '--- Аудит доступа к файлам KSC ---'
    $paths = @($installDir, $KSC.KlShareDir, $KSC.BackupDir) | Where-Object { $_ -and (Test-Path $_) }
    $rights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'

    foreach ($path in $paths) {
        if (-not $PSCmdlet.ShouldProcess($path, 'Включить аудит изменений')) { continue }
        try {
            $acl = Get-Acl -Path $path -Audit
            $exists = $acl.Audit | Where-Object { $_.IdentityReference -match 'Everyone|Все' }
            if ($exists) { Write-KscLog "  = $path : аудит уже задан."; continue }
            $acl.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule(
                'Everyone', $rights, 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')))
            Set-Acl -Path $path -AclObject $acl
            Write-KscLog "  + $path" 'OK'
        }
        catch {
            Write-KscLog "  ! $path : $($_.Exception.Message)" 'WARN'
        }
    }
}

# ------------------------------------------------------------------ 5. Чек-лист консоли

$siemHost = if ($KSC.SiemHost) { $KSC.SiemHost } else { $KSC.AuditCollectorHost }

Write-KscLog '--- Задаётся только в консоли администрирования ---'
$checklist = @(
    @{ Title = 'Экспорт событий в SIEM (основной канал доставки событий KSC)'
       Steps = @(
         'Консоль -> Свойства Сервера администрирования -> Экспорт событий -> Настроить экспорт в SIEM-систему.'
         "Адрес SIEM-системы: $siemHost, порт: $($KSC.SiemPort), протокол: $($KSC.SiemProtocol)."
         "Формат: $($KSC.SiemFormat)."
         'Отметить типы событий для экспорта: аудит действий администраторов, состояние защиты, обнаружения, состояние устройств.'
         'После включения проверить приём событий на коллекторе.'
       ) }
    @{ Title = 'Запись событий в журнал событий Windows (резервный канал)'
       Steps = @(
         'Политика Агента администрирования -> Настройка событий: для отобранных типов включить "Записывать в журнал событий Windows".'
         'То же — в политике Kaspersky Endpoint Security для событий критической важности.'
         "После применения политики появится журнал 'Kaspersky Event Log'; повторно выполнить этот сценарий для выдачи прав $($KSC.AuditAccount)."
       ) }
    @{ Title = 'Хранение событий в базе KSC'
       Steps = @(
         'Свойства Сервера администрирования -> Хранилище событий.'
         "Срок хранения: $($KSC.RetentionDays) дней; предельное число записей: $($KSC.EventsLimit)."
         'Проверить, что объём базы укладывается в выделенный том.'
       ) }
    @{ Title = 'Регистрация действий администраторов KSC'
       Steps = @(
         'Свойства Сервера администрирования -> Настройка событий -> категория "Аудит": включить регистрацию всех событий категории.'
         'Проверить, что события "Изменён объект", "Изменено состояние объекта", "Вход пользователя" включены и экспортируются.'
         "Роль только для чтения (группа $($KSC.AuditorsGroup)) — для лиц, контролирующих аудит; администраторы не должны иметь права очистки журналов."
       ) }
)

$n = 0
foreach ($item in $checklist) {
    $n++
    Write-Host ''
    Write-Host ("  {0}. {1}" -f $n, $item.Title) -ForegroundColor Cyan
    foreach ($step in $item.Steps) { Write-Host "     - $step" -ForegroundColor Gray }
}

Write-Host ''
Write-KscLog '=== Аудит ПО настроен в части ОС. Выполните пункты чек-листа, затем 90_Test-Audit.ps1 ===' 'OK'
