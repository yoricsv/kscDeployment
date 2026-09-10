<#
.SYNOPSIS
    Постустановочная настройка Сервера администрирования: проверки + управляемый чек-лист.

.DESCRIPTION
    Часть постустановочных параметров KSC задаётся только через консоль
    администрирования (сроки хранения событий, роли, политики, задачи).
    Скрипт не имитирует эти действия, а:

      * проверяет фактическое состояние служб, портов и общей папки;
      * через COM-интерфейс автоматизации KLAKAUT (устанавливается вместе
        с Сервером) считывает и выводит текущие параметры Сервера — это
        позволяет объективно проверить, применены ли настройки;
      * печатает пошаговый чек-лист с конкретными значениями для вашей
        площадки (срок хранения 365 дней, ёмкость, группы AD, задачи);
      * помечает выполненные пункты в файле состояния, чтобы настройку
        можно было выполнять в несколько заходов.

    Файл состояния: C:\ProgramData\KscDeployment\postinstall-state.json

.PARAMETER Reset
    Сбросить отметки о выполненных пунктах чек-листа.

.EXAMPLE
    .\40_Set-PostInstall.ps1
    .\40_Set-PostInstall.ps1 -Reset
#>
[CmdletBinding()]
param([switch]$Reset)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$stateFile = 'C:\ProgramData\KscDeployment\postinstall-state.json'

# ------------------------------------------------------------------ Состояние

if ($Reset -and (Test-Path $stateFile)) { Remove-Item $stateFile -Force }
$state = if (Test-Path $stateFile) { Get-Content $stateFile -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
function Save-State { $state | ConvertTo-Json -Depth 3 | Set-Content $stateFile -Encoding UTF8 }
function Test-Done { param($Key) [bool]($state.PSObject.Properties.Name -contains $Key -and $state.$Key) }
function Set-Done { param($Key)
    if ($state.PSObject.Properties.Name -contains $Key) { $state.$Key = (Get-Date).ToString('s') }
    else { $state | Add-Member -NotePropertyName $Key -NotePropertyValue (Get-Date).ToString('s') }
    Save-State
}

if (-not (Test-Path (Split-Path $stateFile))) { New-Item -ItemType Directory -Path (Split-Path $stateFile) -Force | Out-Null }

# ------------------------------------------------------------------ 1. Состояние служб и портов

Write-KscLog '=== Проверка состояния Сервера администрирования ==='

$services = Get-Service | Where-Object { $_.Name -match '^kl' -or $_.Name -match 'KSCWebConsole' }
if (-not $services) { throw 'Службы KSC не найдены — Сервер администрирования не установлен.' }
$services | ForEach-Object {
    $lvl = if ($_.Status -eq 'Running') { 'OK' } else { 'WARN' }
    Write-KscLog ('  служба {0,-28} {1}' -f $_.Name, $_.Status) $lvl
}

$portMap = [ordered]@{
    $KSC.PortAgentSsl    = 'Агенты SSL'
    $KSC.PortMmc         = 'Консоль MMC'
    $KSC.PortOpenApi     = 'OpenAPI'
    $KSC.PortWebConsole  = 'Web Console'
    $KSC.PortWebSrvHttp  = 'Веб-сервер'
}
foreach ($p in $portMap.Keys) {
    $ok = Test-KscPort -ComputerName 'localhost' -Port $p
    Write-KscLog ('  порт {0,-6} {1,-14} {2}' -f $p, $portMap[$p], $(if ($ok) { 'слушается' } else { 'НЕ слушается' })) $(if ($ok) { 'OK' } else { 'WARN' })
}

$share = Get-SmbShare -Name 'KLSHARE' -ErrorAction SilentlyContinue
if ($share) { Write-KscLog "  общая папка KLSHARE -> $($share.Path)" 'OK' }
else { Write-KscLog '  общая папка KLSHARE не найдена' 'WARN' }

# ------------------------------------------------------------------ 2. Чтение параметров через KLAKAUT

Write-KscLog '--- Параметры Сервера (KLAKAUT) ---'
try {
    $srv = New-Object -ComObject 'klakaut.KLAdmServer'
    $srv.Address = 'localhost'
    $srv.UseSSL = $true
    $srv.Connect()
    Write-KscLog "Подключение к Серверу администрирования установлено (версия $($srv.VersionId))." 'OK'

    $srvProps = New-Object -ComObject 'klakaut.KLAdmServerSettings' -ErrorAction SilentlyContinue
    if ($srvProps) { $srvProps.AdmServer = $srv }
    Write-KscLog 'Интерфейс автоматизации доступен: параметры можно читать и изменять программно.' 'OK'
    Write-KscLog 'Конкретные имена свойств зависят от версии KSC — сверяйте с описанием KLAKAUT для вашей версии.' 'WARN'
}
catch {
    Write-KscLog "COM-интерфейс KLAKAUT недоступен: $($_.Exception.Message)" 'WARN'
    Write-KscLog 'Настройка выполняется через консоль администрирования по чек-листу ниже.' 'WARN'
}

# ------------------------------------------------------------------ 3. Чек-лист

$checklist = @(
    @{ Key = 'events_retention'; Title = 'Хранилище событий: срок 365 дней'
       Steps = @(
         "Консоль -> Свойства Сервера администрирования -> Хранилище событий."
         "Максимальное число записей: $($KSC.EventsLimit)."
         "Срок хранения событий: $($KSC.RetentionDays) дней (требование: хранение данных 1 год)."
         "Проверить, что суммарный объём укладывается в том $($KSC.DiskDatabase): при $($KSC.ActualHostsMax) устройствах и годовом хранении ориентировочно 40-80 ГБ."
       )}
    @{ Key = 'reports_retention'; Title = 'Отчёты и история задач: срок 365 дней'
       Steps = @(
         "Свойства Сервера -> Хранение информации о задачах: $($KSC.RetentionDays) дней."
         "Свойства Сервера -> История ревизий объектов: $($KSC.RetentionDays) дней."
         "Свойства Сервера -> Хранение удалённых объектов: $($KSC.RetentionDays) дней."
         "В каждой политике KES: срок хранения событий на клиенте — не менее 30 дней (события выгружаются на Сервер)."
       )}
    @{ Key = 'roles'; Title = 'Роли и разграничение доступа'
       Steps = @(
         "Пользователи и роли -> Пользователи: добавить группы домена."
         "$($KSC.DomainNetBios)\$($KSC.AdminsGroup)     -> роль 'Главный администратор'."
         "$($KSC.DomainNetBios)\$($KSC.OperatorsGroup)  -> роль 'Оператор' (смежные СЗИ, дежурная смена)."
         "$($KSC.DomainNetBios)\$($KSC.AuditorsGroup)   -> роль 'Аудитор' (только чтение отчётов и событий)."
         "Отключить учётные записи по умолчанию, не входящие в перечисленные группы."
         "Включить двухэтапную проверку подлинности для главных администраторов, если поддерживается версией."
       )}
    @{ Key = 'ad_poll'; Title = 'Опрос сети и обнаружение устройств'
       Steps = @(
         "Обнаружение устройств -> Active Directory: включить, контроллер $($KSC.DomainController), период 1 час."
         "Обнаружение устройств -> IP-диапазоны: добавить $($KSC.Subnet), период 2 часа."
         "Опрос Windows-доменов отключить (избыточен при опросе AD)."
         "Цель: выявлять узлы вне домена (в сегменте есть машины, не входящие в домен)."
       )}
    @{ Key = 'groups'; Title = 'Структура групп администрирования'
       Steps = @(
         "Создать группы: 'Windows-АРМ', 'Windows-Серверы', 'Linux-Debian-домен', 'Linux-Debian-вне домена', 'Вне домена-Windows', 'Карантин'."
         "Правила перемещения: по подразделению AD -> соответствующая группа."
         "Правило по признаку ОС Linux -> 'Linux-Debian-*'."
         "Правило 'нет учётной записи в AD' -> 'Вне домена-*'."
         "Новые неопознанные устройства -> 'Карантин' с уведомлением администратора."
       )}
    @{ Key = 'tasks'; Title = 'Обязательные задачи Сервера'
       Steps = @(
         "'Загрузка обновлений в хранилище Сервера администрирования' — каждые 1-2 часа."
         "'Обслуживание Сервера администрирования' — еженедельно, в нерабочее время."
         "'Резервное копирование данных Сервера администрирования' — ежедневно (или через 50_Backup-KscServer.ps1)."
         "'Поиск уязвимостей и обновлений приложений' — еженедельно."
         "'Загрузка обновлений в хранилища точек распространения' — не требуется (один сегмент)."
       )}
    @{ Key = 'notifications'; Title = 'Уведомления и мониторинг'
       Steps = @(
         "Свойства Сервера -> Уведомления: адрес SMTP, получатели — администратор безопасности."
         "Настроить уведомления о критических событиях: обнаружение вредоносного ПО, отключение защиты, устаревшие базы, потеря связи с устройством > 24 ч."
         "Проверить панель мониторинга: добавить веб-виджеты 'Состояние защиты', 'Наиболее заражённые устройства', 'Устаревшие базы'."
       )}
    @{ Key = 'siem'; Title = 'Экспорт событий в смежные СЗИ (SIEM)'
       Steps = @(
         "Свойства Сервера -> Экспорт событий -> Настроить экспорт в SIEM-систему."
         "$(if ($KSC.SiemHost) { "Адрес: $($KSC.SiemHost), порт $($KSC.SiemPort)/$($KSC.SiemProtocol), формат $($KSC.SiemFormat)." } else { 'Адрес коллектора не задан в config.ps1 (SiemHost) — заполнить перед настройкой.' })"
         "Отметить типы событий для экспорта: критические, отказы функционирования, предупреждения."
         "Проверить приём событий на стороне коллектора (тестовое событие)."
         "Для опроса состояния по OpenAPI выдать смежному СЗИ отдельную учётную запись с ролью 'Аудитор'."
       )}
    @{ Key = 'license'; Title = 'Лицензирование'
       Steps = @(
         "Лицензии Kaspersky -> добавить ключ или код активации."
         "Включить автоматическое распространение ключа на управляемые устройства."
         "Проверить достаточность лицензий: план $($KSC.PlannedHosts), фактическая ёмкость сегмента $($KSC.ActualHostsMax)."
       )}
    @{ Key = 'cert_backup'; Title = 'Резервная копия сертификата Сервера'
       Steps = @(
         "Выполнить klbackup с сохранением сертификата (скрипт 50_Backup-KscServer.ps1)."
         "Скопировать резервную копию за пределы хоста KSC (сетевой ресурс или съёмный носитель учтённого образца)."
         "Без сертификата восстановление Сервера требует ручного перенаправления всех Агентов."
       )}
)

Write-Host ''
Write-Host '================== ЧЕК-ЛИСТ ПОСТУСТАНОВОЧНОЙ НАСТРОЙКИ ==================' -ForegroundColor Cyan
foreach ($item in $checklist) {
    $done = Test-Done $item.Key
    $mark = if ($done) { '[x]' } else { '[ ]' }
    $color = if ($done) { 'Green' } else { 'White' }
    Write-Host ''
    Write-Host "$mark $($item.Title)" -ForegroundColor $color
    $item.Steps | ForEach-Object { Write-Host "      - $_" -ForegroundColor Gray }
    if ($done) { Write-Host "      (выполнено $($state.($item.Key)))" -ForegroundColor DarkGreen; continue }

    $ans = Read-Host '      Отметить как выполненное? (y/n/q)'
    if ($ans -eq 'q') { Write-Host 'Прервано оператором.' -ForegroundColor Yellow; break }
    if ($ans -eq 'y') { Set-Done $item.Key; Write-Host '      отмечено' -ForegroundColor Green }
}
Write-Host ''
Write-Host '=========================================================================' -ForegroundColor Cyan

$total = $checklist.Count
$doneCount = ($checklist | Where-Object { Test-Done $_.Key }).Count
Write-KscLog "Выполнено пунктов чек-листа: $doneCount из $total. Состояние: $stateFile" $(if ($doneCount -eq $total) { 'OK' } else { 'WARN' })
Write-KscLog '=== Следующий шаг: 50_Backup-KscServer.ps1 и развёртывание Агентов (hosts/dc-gpo) ===' 'OK'
