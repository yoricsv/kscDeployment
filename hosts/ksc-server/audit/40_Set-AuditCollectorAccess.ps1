<#
.SYNOPSIS
    Доступ MP 10 Collector к журналу аудита СУБД: учётная запись, права, брандмауэр.

.DESCRIPTION
    Готовит узел СУБД к удалённому сбору событий коллектором MaxPatrol
    ($KSC.AuditCollectorHost). По требованиям к источникам Windows коллектору
    нужна учётная запись ОС, входящая в группу "Читатели журнала событий",
    с правом сетевого доступа к компьютеру и разрешением на удалённое
    подключение к WMI; используются TCP 135 и динамические порты RPC.

    Скрипт:
      1. Создаёт локальную учётную запись $KSC.AuditAccount (пароль запрашивается)
         либо обновляет параметры существующей.
      2. Включает её в группы "Event Log Readers" и "Distributed COM Users".
      3. Выдаёт право "Доступ к компьютеру из сети" и явно запрещает
         интерактивный, терминальный, пакетный вход и вход в качестве службы.
      4. Разрешает чтение журнала $KSC.AuditWinLogName (дескриптор CustomSD)
         и удалённое подключение к пространству имён WMI root\cimv2.
      5. Создаёт правила брандмауэра, разрешающие обращения только с адреса
         коллектора (группа правил "KSC Audit").

    Учётная запись служебная: интерактивный вход ей запрещён, пароль хранится
    в парольном хранилище и указывается в MaxPatrol при добавлении учётной записи.

.PARAMETER Rollback
    Удалить правила брандмауэра группы "KSC Audit" и вывести учётную запись
    из групп доступа. Сама учётная запись не удаляется.

.EXAMPLE
    .\40_Set-AuditCollectorAccess.ps1
    .\40_Set-AuditCollectorAccess.ps1 -Rollback
#>
[CmdletBinding()]
param([switch]$Rollback)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

$account = $KSC.AuditAccount
$collector = $KSC.AuditCollectorHost
$fwGroup = 'KSC Audit'

# Группы указываются по SID: имена локализованы (Читатели журнала событий и т. п.).
$groupSids = @{
    'S-1-5-32-573' = 'Event Log Readers (Читатели журнала событий)'
    'S-1-5-32-562' = 'Distributed COM Users (Пользователи DCOM)'
}

# ------------------------------------------------------------------ Откат

if ($Rollback) {
    Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($sid in $groupSids.Keys) {
        $group = Get-LocalGroup -SID $sid -ErrorAction SilentlyContinue
        if ($group) { Remove-LocalGroupMember -Group $group -Member $account -ErrorAction SilentlyContinue }
    }
    Write-KscLog "Правила группы '$fwGroup' удалены, учётная запись $account исключена из групп доступа." 'OK'
    return
}

# ------------------------------------------------------------------ 1. Учётная запись

$user = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
if (-not $user) {
    $pwdSec = Read-Host "Задайте пароль учётной записи $account (для подключения MP 10 Collector)" -AsSecureString
    $user = New-LocalUser -Name $account -Password $pwdSec `
        -FullName 'MP 10 Collector: чтение журнала аудита СУБД' `
        -Description 'Служебная УЗ сбора событий ИБ. Интерактивный вход запрещён.' `
        -PasswordNeverExpires -UserMayNotChangePassword
    Write-KscLog "Создана локальная учётная запись $account." 'OK'
}
else {
    Write-KscLog "Учётная запись $account уже существует — параметры будут обновлены." 'WARN'
    Set-LocalUser -Name $account -PasswordNeverExpires $true -UserMayChangePassword $false
}
Enable-LocalUser -Name $account
$userSid = (Get-LocalUser -Name $account).SID.Value

# ------------------------------------------------------------------ 2. Группы доступа

foreach ($sid in $groupSids.Keys) {
    $group = Get-LocalGroup -SID $sid -ErrorAction SilentlyContinue
    if (-not $group) {
        Write-KscLog "  группа $($groupSids[$sid]) не найдена — пропущена." 'WARN'
        continue
    }
    $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
    if ($members.SID.Value -contains $userSid) {
        Write-KscLog "  $account уже состоит в группе $($groupSids[$sid])."
    }
    else {
        Add-LocalGroupMember -Group $group -Member $account
        Write-KscLog "  $account добавлена в группу $($groupSids[$sid])." 'OK'
    }
}

# ------------------------------------------------------------------ 3. Права входа

function Grant-KscUserRight {
    <# Приводит состав указанного права к требуемому: добавляет SID, сохраняя остальных. #>
    param(
        [Parameter(Mandatory)][string]$Right,
        [Parameter(Mandatory)][string]$Sid
    )

    $exportFile = Join-Path $env:TEMP ('secpol-{0}.inf' -f ([guid]::NewGuid()))
    $importFile = Join-Path $env:TEMP ('secpol-{0}-new.inf' -f ([guid]::NewGuid()))
    $dbFile = Join-Path $env:TEMP ('secpol-{0}.sdb' -f ([guid]::NewGuid()))
    try {
        secedit /export /areas USER_RIGHTS /cfg $exportFile | Out-Null
        $current = (Select-String -Path $exportFile -Pattern "^$Right\s*=" -ErrorAction SilentlyContinue).Line
        $values = if ($current) { ($current -split '=', 2)[1].Trim() -split ',' | ForEach-Object { $_.Trim() } } else { @() }
        if ($values -contains "*$Sid") {
            Write-KscLog "  право $Right уже выдано."
            return
        }
        $values = @($values | Where-Object { $_ }) + "*$Sid"

        @(
            '[Unicode]'
            'Unicode=yes'
            '[Version]'
            'signature="$CHICAGO$"'
            'Revision=1'
            '[Privilege Rights]'
            "$Right = $($values -join ',')"
        ) | Set-Content -Path $importFile -Encoding Unicode

        secedit /configure /db $dbFile /cfg $importFile /areas USER_RIGHTS | Out-Null
        Write-KscLog "  право $Right выдано." 'OK'
    }
    finally {
        Remove-Item $exportFile, $importFile, $dbFile -Force -ErrorAction SilentlyContinue
    }
}

Write-KscLog '--- Права входа служебной учётной записи ---'
Grant-KscUserRight -Right 'SeNetworkLogonRight' -Sid $userSid
foreach ($deny in @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
        'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight')) {
    Grant-KscUserRight -Right $deny -Sid $userSid
}

# ------------------------------------------------------------------ 4. Доступ к журналу и WMI

# Классический журнал: права задаются дескриптором CustomSD.
# 0x1 — чтение, 0x2 — запись, 0x4 — очистка.
$logKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$($KSC.AuditWinLogName)"
if (-not (Test-Path $logKey)) {
    throw "Журнал '$($KSC.AuditWinLogName)' не создан. Сначала выполните 20_Install-AuditForwarder.ps1."
}
$sddl = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)' + "(A;;0x1;;;$userSid)"
Set-ItemProperty -Path $logKey -Name 'CustomSD' -Value $sddl
Write-KscLog "Права на журнал '$($KSC.AuditWinLogName)': чтение — $account и читатели журнала событий." 'OK'

# Удалённый опрос журнала выполняется через WMI: нужны Enable Account,
# Execute Methods и Remote Enable в пространстве имён root\cimv2.
function Grant-KscWmiAccess {
    # Дескриптор безопасности пространства имён изменяется методами класса
    # __systemsecurity: командлеты CIM не дают эквивалентного доступа к нему.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    param([string]$Namespace = 'root/cimv2', [Parameter(Mandatory)][string]$Sid)

    $wmiEnable = 0x1
    $wmiMethodExecute = 0x2
    $wmiRemoteEnable = 0x20
    $containerInherit = 0x2

    $sd = Invoke-WmiMethod -Namespace $Namespace -Path '__systemsecurity=@' -Name GetSecurityDescriptor
    if ($sd.ReturnValue -ne 0) { throw "Не удалось прочитать дескриптор безопасности WMI (код $($sd.ReturnValue))." }

    $descriptor = $sd.Descriptor
    if ($descriptor.DACL.Trustee.SIDString -contains $Sid) {
        Write-KscLog "  доступ к WMI $Namespace уже выдан."
        return
    }

    $trustee = ([wmiclass]"\\.\${Namespace}:Win32_Trustee").CreateInstance()
    $trustee.SidString = $Sid
    $ace = ([wmiclass]"\\.\${Namespace}:Win32_Ace").CreateInstance()
    $ace.AccessMask = $wmiEnable -bor $wmiMethodExecute -bor $wmiRemoteEnable
    $ace.AceFlags = $containerInherit
    $ace.AceType = 0
    $ace.Trustee = $trustee

    $descriptor.DACL += $ace
    $result = Invoke-WmiMethod -Namespace $Namespace -Path '__systemsecurity=@' -Name SetSecurityDescriptor -ArgumentList $descriptor
    if ($result.ReturnValue -ne 0) { throw "Не удалось применить дескриптор безопасности WMI (код $($result.ReturnValue))." }
    Write-KscLog "  доступ к WMI $Namespace выдан (Enable, Method Execute, Remote Enable)." 'OK'
}

Write-KscLog '--- Доступ к WMI ---'
Grant-KscWmiAccess -Sid $userSid

# ------------------------------------------------------------------ 5. Брандмауэр

Write-KscLog '--- Правила брандмауэра для коллектора ---'
Get-NetFirewallRule -Group $fwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName 'KSC Audit: RPC endpoint mapper 135 (MP 10 Collector)' -Group $fwGroup `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135 -RemoteAddress $collector -Profile Any `
    -Description 'Сопоставитель конечных точек RPC для удалённого чтения журнала событий' | Out-Null
Write-KscLog "  + TCP 135 <- $collector"

New-NetFirewallRule -DisplayName 'KSC Audit: динамические порты RPC (MP 10 Collector)' -Group $fwGroup `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 49152-65535 -RemoteAddress $collector -Profile Any `
    -Description 'Динамический диапазон RPC/DCOM для WMI' | Out-Null
Write-KscLog "  + TCP 49152-65535 <- $collector"

# Адрес коллектора должен присутствовать и в общем списке смежных СЗИ
if ($KSC.SecurityToolsHosts -notcontains $collector) {
    Write-KscLog "Добавьте $collector в SecurityToolsHosts (common/config.ps1) и перезапустите 10_Set-Firewall.ps1: иначе правила управления будут расходиться." 'WARN'
}

# ------------------------------------------------------------------ Итог

Write-Host ''
Write-Host '============ ПАРАМЕТРЫ ДЛЯ НАСТРОЙКИ ИСТОЧНИКА В MaxPatrol ============' -ForegroundColor Cyan
Write-Host "  Узел источника (актив):     $($KSC.AuditDbHost)" -ForegroundColor Gray
Write-Host "  Учётная запись ОС:          $env:COMPUTERNAME\$account (локальная)" -ForegroundColor Gray
Write-Host "  Журнал событий:             $($KSC.AuditWinLogName)" -ForegroundColor Gray
Write-Host "  Источник событий:           $($KSC.AuditWinLogSource)" -ForegroundColor Gray
Write-Host "  Коллектор:                  $collector" -ForegroundColor Gray
Write-Host "  Порты:                      TCP 135 + 49152-65535" -ForegroundColor Gray
Write-Host '=======================================================================' -ForegroundColor Cyan

Write-KscLog 'Пароль учётной записи сохраните в парольном хранилище: он потребуется при добавлении учётной записи в MaxPatrol.' 'WARN'
Write-KscLog '=== Доступ коллектора настроен. Следующий шаг: 90_Test-Audit.ps1 ===' 'OK'
