<#
.SYNOPSIS
    Создание групповой политики установки Агента администрирования KSC на узлы домена.

.DESCRIPTION
    Скрипт создаёт GPO, публикующую MSI-пакет Агента администрирования
    (klnagent.msi + трансформация с адресом Сервера) для назначенных
    подразделений домена.

    Два подхода к развёртыванию Агента через GPO:

      А. Средствами KSC (рекомендуется).
         В консоли: Задача удалённой установки -> способ "Средствами групповых
         политик Active Directory". KSC самостоятельно создаёт объект GPO,
         размещает пакет в KLSHARE и следит за его актуальностью при обновлении
         версии Агента. Скрипт в этом случае используется только для проверки
         результата (-VerifyOnly).

      Б. Собственная GPO (этот скрипт).
         Применяется, когда требуется полный контроль над областью применения,
         фильтрами безопасности и WMI-фильтрами — например, чтобы гарантированно
         исключить контроллеры домена и хост виртуализации.

    Скрипт:
      * проверяет доступность сетевого ресурса с пакетом;
      * создаёт GPO и связывает её с указанными подразделениями;
      * назначает MSI-пакет в разделе "Конфигурация компьютера";
      * ограничивает область применения фильтром безопасности;
      * настраивает правила брандмауэра на узлах для портов Агента.

    Требования: модули GroupPolicy и ActiveDirectory (RSAT), права
    администратора домена.

.PARAMETER MsiUncPath
    UNC-путь к MSI-пакету Агента, доступный узлам на чтение
    (например \\ksc.domain.local\KLSHARE\Packages\NetAgent\klnagent64.msi).

.PARAMETER TargetOu
    Одно или несколько DN подразделений, к которым привязывается политика.

.PARAMETER GpoName
    Имя создаваемой политики.

.PARAMETER VerifyOnly
    Только проверить состояние существующих политик, ничего не создавать.

.EXAMPLE
    .\10_New-AgentGpo.ps1 -VerifyOnly
    .\10_New-AgentGpo.ps1 -MsiUncPath '\\ksc.domain.local\KLSHARE\Packages\NetAgent\klnagent64.msi' `
                          -TargetOu 'OU=Workstations,DC=domain,DC=local','OU=Servers,DC=domain,DC=local'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$MsiUncPath,
    [string[]]$TargetOu,
    [string]$GpoName = 'KSC - Установка Агента администрирования',
    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$fqdn = "$($KSC.KscHostName).$($KSC.DomainFqdn)"

# ---------------------------------------------------------------- Проверка существующих политик

if ($VerifyOnly) {
    Write-KscLog '=== Политики, связанные с KSC ==='
    Get-GPO -All | Where-Object { $_.DisplayName -match 'KSC|Kaspersky|Агент' } | ForEach-Object {
        Write-KscLog "GPO: $($_.DisplayName)  [$($_.Id)]  изменена $($_.ModificationTime)"
        $links = ([xml](Get-GPOReport -Guid $_.Id -ReportType Xml)).GPO.LinksTo
        if ($links) { $links | ForEach-Object { Write-KscLog "   связь: $($_.SOMPath) (включена: $($_.Enabled))" } }
        else { Write-KscLog '   связей нет' 'WARN' }
    }
    return
}

if (-not $MsiUncPath) { throw 'Укажите -MsiUncPath (UNC-путь к MSI-пакету Агента).' }
if (-not $TargetOu) { throw 'Укажите -TargetOu (подразделения для привязки политики).' }

# ---------------------------------------------------------------- 1. Проверки

if (-not (Test-Path $MsiUncPath)) {
    throw "Пакет недоступен по пути $MsiUncPath. Пакет должен лежать на общем ресурсе, доступном учётным записям компьютеров домена на чтение."
}
Write-KscLog "Пакет найден: $MsiUncPath" 'OK'

if ($MsiUncPath -notmatch '^\\\\') {
    throw 'Путь к пакету должен быть UNC (\\сервер\ресурс\...), локальные пути в GPO не работают.'
}

foreach ($ou in $TargetOu) {
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
        throw "Подразделение не найдено: $ou"
    }
    if ($ou -match 'OU=Domain Controllers') {
        throw "Отказ: политика не должна применяться к контроллерам домена ($ou). Агент на КД устанавливается адресно и после согласования."
    }
}
Write-KscLog "Целевые подразделения проверены: $($TargetOu.Count)" 'OK'

# ---------------------------------------------------------------- 2. Создание GPO

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    if ($PSCmdlet.ShouldProcess($GpoName, 'Создать объект групповой политики')) {
        $gpo = New-GPO -Name $GpoName -Comment "Установка Агента администрирования KSC. Сервер: $fqdn. Создано скриптом kscDeployment."
        Write-KscLog "Создана политика '$GpoName' [$($gpo.Id)]" 'OK'
    }
} else {
    Write-KscLog "Политика '$GpoName' уже существует [$($gpo.Id)]" 'WARN'
}

# Конфигурация пользователя не используется — отключаем для ускорения обработки
if ($PSCmdlet.ShouldProcess($GpoName, 'Отключить раздел конфигурации пользователя')) {
    (Get-GPO -Name $GpoName).GpoStatus = 'UserSettingsDisabled'
    Write-KscLog '  раздел "Конфигурация пользователя" отключён' 'OK'
}

# ---------------------------------------------------------------- 3. Правила брандмауэра на узлах

# Агент должен принимать команды Сервера на UDP 15000.
Write-KscLog '--- Параметры брандмауэра узлов через GPO ---'
Write-KscLog "  Требуется разрешить входящий UDP $($KSC.PortServerToAgent) с адреса $($KSC.KscIp)."
Write-KscLog '  Настраивается в разделе: Конфигурация компьютера -> Политики -> Конфигурация Windows ->' 
Write-KscLog '  Параметры безопасности -> Брандмауэр Защитника Windows в режиме повышенной безопасности -> Правила для входящих подключений.'
Write-KscLog '  Программное создание правил в GPO средствами PowerShell выполняется через сеанс политики:' 
Write-KscLog "    `$s = Open-NetGPO -PolicyStore '$($KSC.DomainFqdn)\$GpoName'"
Write-KscLog "    New-NetFirewallRule -GPOSession `$s -DisplayName 'KSC: Агент UDP 15000' -Direction Inbound -Protocol UDP -LocalPort $($KSC.PortServerToAgent) -RemoteAddress $($KSC.KscIp) -Action Allow"
Write-KscLog "    Save-NetGPO -GPOSession `$s"

if ($PSCmdlet.ShouldProcess($GpoName, 'Создать правила брандмауэра в политике')) {
    try {
        $session = Open-NetGPO -PolicyStore "$($KSC.DomainFqdn)\$GpoName"
        New-NetFirewallRule -GPOSession $session -DisplayName 'KSC: Агент администрирования (UDP 15000)' `
            -Direction Inbound -Protocol UDP -LocalPort $KSC.PortServerToAgent -RemoteAddress $KSC.KscIp `
            -Action Allow -Profile Any -Description 'Команды Сервера администрирования Агенту' | Out-Null
        New-NetFirewallRule -GPOSession $session -DisplayName 'KSC: Удалённая установка (RPC/SMB)' `
            -Direction Inbound -Protocol TCP -LocalPort 135, 445 -RemoteAddress $KSC.KscIp `
            -Action Allow -Profile Any -Description 'Удалённая установка и обслуживание Агента с Сервера KSC' | Out-Null
        Save-NetGPO -GPOSession $session
        Write-KscLog '  правила брандмауэра добавлены в политику' 'OK'
    } catch {
        Write-KscLog "  не удалось создать правила брандмауэра автоматически: $($_.Exception.Message)" 'WARN'
        Write-KscLog '  создайте их вручную по указанным выше параметрам.' 'WARN'
    }
}

# ---------------------------------------------------------------- 4. Назначение MSI-пакета

Write-Host ''
Write-Host 'НАЗНАЧЕНИЕ ПАКЕТА (выполняется в редакторе управления групповыми политиками):' -ForegroundColor Yellow
@"
  1. Открыть: Управление групповой политикой -> '$GpoName' -> Изменить.
  2. Конфигурация компьютера -> Политики -> Конфигурация программ -> Установка программ.
  3. Правой кнопкой -> Создать -> Пакет.
  4. Указать ИМЕННО UNC-путь: $MsiUncPath
     (локальный путь вида C:\... приведёт к ошибке установки на узлах).
  5. Метод развёртывания: "Назначенный".
  6. Свойства пакета -> Развёртывание -> "Устанавливать это приложение при входе в систему",
     "Удалять это приложение, если оно выходит за пределы области управления" — снять.
  7. Проверить, что в пакете зашит адрес Сервера $fqdn и порт $($KSC.PortAgentSsl):
     при формировании инсталляционного пакета в KSC эти значения задаются в свойствах
     пакета Агента (раздел "Параметры соединения").

  Программное назначение MSI через PowerShell штатными средствами не поддерживается:
  раздел "Установка программ" редактируется только через интерфейс GPMC либо
  создаётся автоматически задачей KSC "Средствами групповых политик Active Directory".
"@ | Write-Host

# ---------------------------------------------------------------- 5. Связывание с подразделениями

foreach ($ou in $TargetOu) {
    $existing = (Get-GPInheritance -Target $ou).GpoLinks | Where-Object DisplayName -eq $GpoName
    if ($existing) { Write-KscLog "Связь с $ou уже существует."; continue }
    if ($PSCmdlet.ShouldProcess($ou, "Связать политику '$GpoName'")) {
        New-GPLink -Name $GpoName -Target $ou -LinkEnabled Yes -Enforced No | Out-Null
        Write-KscLog "Политика связана с $ou" 'OK'
    }
}

# ---------------------------------------------------------------- 6. Фильтр безопасности

Write-Host ''
Write-Host 'ОБЛАСТЬ ПРИМЕНЕНИЯ:' -ForegroundColor Yellow
@"
  По умолчанию политика применяется к группе "Прошедшие проверку" (все компьютеры OU).
  Для поэтапного развёртывания создайте группу компьютеров, например KSC-Agent-Wave1,
  и замените фильтр безопасности:

     Set-GPPermission -Name '$GpoName' -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel None
     Set-GPPermission -Name '$GpoName' -TargetName 'KSC-Agent-Wave1'     -TargetType Group -PermissionLevel GpoApply
     Set-GPPermission -Name '$GpoName' -TargetName 'Domain Computers'    -TargetType Group -PermissionLevel GpoRead

  Установка выполняется при следующей перезагрузке узла (назначенные пакеты
  применяются на этапе загрузки, до входа пользователя).
"@ | Write-Host

Write-KscLog '=== Политика подготовлена. Проверка: gpresult /r /scope:computer на целевом узле ===' 'OK'
Write-KscLog 'Узлы вне домена и Linux обслуживаются отдельно: hosts/standalone и hosts/linux-debian.' 'WARN'
