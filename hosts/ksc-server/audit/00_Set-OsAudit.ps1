<#
.SYNOPSIS
    Расширенный аудит операционной системы на узле KSC (Windows Server 2022).

.DESCRIPTION
    Приказ ОАЦ № 130 задаёт минимальный перечень регистрируемых событий.
    Сценарий включает этот минимум и расширяет его составом, который нужен
    для реагирования на инциденты и их расследования:

      1. Подкатегории расширенной политики аудита задаются по GUID, а не по
         названию: названия подкатегорий локализованы, и вызов auditpol с
         английским именем на русской сборке Windows завершается ошибкой.
      2. Командная строка в событиях создания процессов (4688), приоритет
         расширенной политики над устаревшей.
      3. Журналирование PowerShell: блоки сценариев, модули и транскрипция
         в защищённый каталог.
      4. Размеры и режим перезаписи журналов Security/System/Application
         и включение дополнительных каналов (PowerShell, планировщик, WinRM,
         брандмауэр, RDP, SMB, Defender).
      5. Аудит доступа (SACL) к каталогам KSC, СУБД и резервных копий:
         изменение и удаление файлов, смена прав, попытки отказа.
      6. Аудит изменений ветки реестра KasperskyLab.

    Локальные параметры перекрываются доменной групповой политикой: если узел
    входит в домен, тот же состав следует задать в GPO, иначе значения
    вернутся к прежним при очередном обновлении политики.

    Сценарий поддерживает -WhatIf: выполните пробный прогон до применения.

.PARAMETER SkipSacl
    Не изменять аудит доступа к каталогам и реестру (только политика и журналы).

.EXAMPLE
    .\00_Set-OsAudit.ps1 -WhatIf
    .\00_Set-OsAudit.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$SkipSacl)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

Write-KscLog '=== Расширенный аудит операционной системы ==='

# ------------------------------------------------------------------ 1. Подкатегории аудита

# GUID подкатегорий не зависят от языка системы (docs.microsoft.com,
# "Advanced security audit policy settings"). Значение: S — успех, F — отказ.
$subcategories = @(
    # Вход в систему и сессии (Приказ № 130, контроль сессий)
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Вход в систему';                      S = $true; F = $true }
    @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Выход из системы';                    S = $true; F = $false }
    @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Блокировка учётной записи';           S = $true; F = $true }
    @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Особый вход (привилегии)';            S = $true; F = $false }
    @{ Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Name = 'Прочие события входа/выхода (RDP)';   S = $true; F = $true }
    @{ Guid = '{0CCE9249-69AE-11D9-BED3-505054503030}'; Name = 'Членство в группах при входе';        S = $true; F = $false }

    # Проверка учётных данных
    @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Проверка учётных данных';             S = $true; F = $true }
    @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Служба проверки подлинности Kerberos'; S = $true; F = $true }
    @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Операции с билетами Kerberos';        S = $true; F = $true }
    @{ Guid = '{0CCE9241-69AE-11D9-BED3-505054503030}'; Name = 'Прочие события входа учётных записей'; S = $true; F = $true }

    # Управление учётными записями и полномочиями
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'Управление учётными записями';        S = $true; F = $true }
    @{ Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Name = 'Управление учётными записями компьютеров'; S = $true; F = $true }
    @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Управление группами безопасности';    S = $true; F = $true }
    @{ Guid = '{0CCE9239-69AE-11D9-BED3-505054503030}'; Name = 'Управление группами приложений';      S = $true; F = $true }
    @{ Guid = '{0CCE923A-69AE-11D9-BED3-505054503030}'; Name = 'Прочие события управления УЗ';        S = $true; F = $true }

    # Использование прав
    @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Использование особых прав';           S = $true; F = $true }
    @{ Guid = '{0CCE922A-69AE-11D9-BED3-505054503030}'; Name = 'Прочие события использования прав';   S = $false; F = $true }
    @{ Guid = '{0CCE924A-69AE-11D9-BED3-505054503030}'; Name = 'Изменение прав маркера доступа';      S = $true; F = $false }

    # Процессы (расследование инцидентов)
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Создание процесса';                   S = $true; F = $true }
    @{ Guid = '{0CCE922C-69AE-11D9-BED3-505054503030}'; Name = 'Завершение процесса';                 S = $true; F = $false }
    @{ Guid = '{0CCE9248-69AE-11D9-BED3-505054503030}'; Name = 'Подключение устройств (PnP)';         S = $true; F = $false }
    @{ Guid = '{0CCE922E-69AE-11D9-BED3-505054503030}'; Name = 'События RPC';                         S = $false; F = $true }

    # Доступ к объектам
    @{ Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Name = 'Файловая система (по SACL)';          S = $true; F = $true }
    @{ Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}'; Name = 'Реестр (по SACL)';                    S = $true; F = $true }
    @{ Guid = '{0CCE9220-69AE-11D9-BED3-505054503030}'; Name = 'Доступ к SAM';                        S = $false; F = $true }
    @{ Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Name = 'Общие папки';                         S = $true; F = $true }
    @{ Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Name = 'Подробный аудит общих папок';         S = $false; F = $true }
    @{ Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Name = 'Съёмные носители';                    S = $true; F = $true }
    @{ Guid = '{0CCE9222-69AE-11D9-BED3-505054503030}'; Name = 'События приложений (KSC)';            S = $true; F = $true }
    @{ Guid = '{0CCE9223-69AE-11D9-BED3-505054503030}'; Name = 'Работа с дескрипторами';              S = $false; F = $true }
    @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Name = 'Прочие события доступа к объектам';   S = $true; F = $true }

    # Изменение политик
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Изменение политики аудита';           S = $true; F = $true }
    @{ Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Name = 'Изменение политики проверки подлинности'; S = $true; F = $true }
    @{ Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Name = 'Изменение политики авторизации';      S = $true; F = $true }
    @{ Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Name = 'Изменение правил брандмауэра';        S = $true; F = $true }
    @{ Guid = '{0CCE9234-69AE-11D9-BED3-505054503030}'; Name = 'Прочие изменения политик';            S = $false; F = $true }

    # Система
    @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Name = 'Изменение состояния безопасности';    S = $true; F = $true }
    @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Расширение системы безопасности';     S = $true; F = $true }
    @{ Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Name = 'Целостность системы';                 S = $true; F = $true }
    @{ Guid = '{0CCE9214-69AE-11D9-BED3-505054503030}'; Name = 'Прочие системные события';            S = $false; F = $true }
)

Write-KscLog '--- Подкатегории расширенной политики аудита ---'
$applied = 0
foreach ($s in $subcategories) {
    if (-not $PSCmdlet.ShouldProcess($s.Name, 'Настроить аудит')) { continue }
    $success = if ($s.S) { 'enable' } else { 'disable' }
    $failure = if ($s.F) { 'enable' } else { 'disable' }
    $out = & auditpol.exe /set /subcategory:"$($s.Guid)" /success:$success /failure:$failure 2>&1
    if ($LASTEXITCODE -eq 0) {
        $applied++
        Write-KscLog ('  + {0}: успех={1}, отказ={2}' -f $s.Name, $success, $failure)
    }
    else {
        Write-KscLog "  ! не удалось настроить '$($s.Name)' ($($s.Guid)): $out" 'WARN'
    }
}
Write-KscLog "Настроено подкатегорий: $applied из $($subcategories.Count)." $(if ($applied -eq $subcategories.Count) { 'OK' } else { 'WARN' })

# Расширенная политика имеет приоритет над устаревшей категорийной
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -PropertyType DWord -Force | Out-Null

# ------------------------------------------------------------------ 2. Детализация событий

Write-KscLog '--- Детализация регистрируемых событий ---'

$auditPolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $auditPolicyKey)) { New-Item -Path $auditPolicyKey -Force | Out-Null }
New-ItemProperty -Path $auditPolicyKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
Write-KscLog '  + командная строка в событиях 4688' 'OK'

# ------------------------------------------------------------------ 3. Журналирование PowerShell

Write-KscLog '--- Журналирование PowerShell ---'

$transcriptDir = $KSC.AuditTranscriptDir
if (-not (Test-Path $transcriptDir)) { New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null }

# Транскрипты содержат вывод команд администратора: читать вправе только
# администраторы и система, учётная запись сбора получает чтение отдельно.
$acl = Get-Acl $transcriptDir
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
foreach ($id in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
if ($PSCmdlet.ShouldProcess($transcriptDir, 'Ограничить права')) { Set-Acl -Path $transcriptDir -AclObject $acl }

$psPolicies = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';      Name = 'EnableModuleLogging';      Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*';                 Value = '*'; Type = 'String' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Name = 'EnableTranscripting';      Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Name = 'EnableInvocationHeader';   Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Name = 'OutputDirectory';          Value = $transcriptDir; Type = 'String' }
)
foreach ($p in $psPolicies) {
    if (-not $PSCmdlet.ShouldProcess("$($p.Path)\$($p.Name)", 'Задать значение')) { continue }
    if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
    New-ItemProperty -Path $p.Path -Name $p.Name -Value $p.Value -PropertyType $p.Type -Force | Out-Null
}
Write-KscLog "  + блоки сценариев, модули, транскрипция -> $transcriptDir" 'OK'

# ------------------------------------------------------------------ 4. Журналы событий

Write-KscLog '--- Журналы событий ---'

# Журнал безопасности — основной источник; остальные каналы дают контекст
# при расследовании. Локальный объём рассчитан на несколько суток автономной
# работы: долговременное хранение (год) обеспечивает коллектор.
$logs = [ordered]@{
    'Security'                                                      = $KSC.AuditSecurityLogSizeMb
    'System'                                                        = 256
    'Application'                                                   = 256
    'Microsoft-Windows-PowerShell/Operational'                      = $KSC.AuditChannelSizeMb
    'Windows PowerShell'                                            = $KSC.AuditChannelSizeMb
    'Microsoft-Windows-TaskScheduler/Operational'                   = 64
    'Microsoft-Windows-WinRM/Operational'                           = 64
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' = 64
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 64
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 64
    'Microsoft-Windows-SMBServer/Security'                          = 64
    'Microsoft-Windows-Windows Defender/Operational'                = 64
}
foreach ($name in $logs.Keys) {
    $sizeBytes = $logs[$name] * 1MB
    if (-not $PSCmdlet.ShouldProcess("Журнал $name", "Включить, размер $($logs[$name]) МБ")) { continue }
    $out = & wevtutil.exe sl "$name" /e:true /ms:$sizeBytes /rt:false 2>&1
    if ($LASTEXITCODE -eq 0) { Write-KscLog ('  + {0}: {1} МБ' -f $name, $logs[$name]) }
    else { Write-KscLog "  ! канал '$name' недоступен: $out" 'WARN' }
}

# ------------------------------------------------------------------ 5. Аудит доступа к каталогам

if (-not $SkipSacl) {
    Write-KscLog '--- Аудит доступа к каталогам (SACL) ---'

    # Регистрируются изменения, удаление, смена прав и владельца. Чтение
    # не регистрируется: объём событий несоизмерим с их ценностью.
    $auditRights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $saclPaths = @(
        $KSC.AuditLogDir
        $KSC.MariaDbDataDir
        $KSC.BackupDir
        $KSC.KlShareDir
        $KSC.KscInstallDir
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($path in $saclPaths) {
        if (-not $PSCmdlet.ShouldProcess($path, 'Включить аудит изменений')) { continue }
        try {
            $dirAcl = Get-Acl -Path $path -Audit
            $rule = New-Object Security.AccessControl.FileSystemAuditRule(
                'Everyone', $auditRights, 'ContainerInherit,ObjectInherit', 'None', 'Success,Failure')
            $dirAcl.AddAuditRule($rule)
            Set-Acl -Path $path -AclObject $dirAcl
            Write-KscLog "  + $path : изменение, удаление, смена прав (успех и отказ)" 'OK'
        }
        catch {
            Write-KscLog "  ! $path : не удалось задать аудит — $($_.Exception.Message)" 'WARN'
        }
    }

    # ---------------------------------------------------------- 6. Аудит реестра

    Write-KscLog '--- Аудит ветки реестра KasperskyLab ---'
    $regPaths = @('HKLM:\SOFTWARE\KasperskyLab', 'HKLM:\SOFTWARE\WOW6432Node\KasperskyLab') |
        Where-Object { Test-Path $_ }

    foreach ($path in $regPaths) {
        if (-not $PSCmdlet.ShouldProcess($path, 'Включить аудит изменений')) { continue }
        try {
            $regAcl = Get-Acl -Path $path -Audit
            $rule = New-Object Security.AccessControl.RegistryAuditRule(
                'Everyone',
                [Security.AccessControl.RegistryRights]'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership',
                'ContainerInherit', 'None', 'Success,Failure')
            $regAcl.AddAuditRule($rule)
            Set-Acl -Path $path -AclObject $regAcl
            Write-KscLog "  + $path" 'OK'
        }
        catch {
            Write-KscLog "  ! $path : не удалось задать аудит — $($_.Exception.Message)" 'WARN'
        }
    }
}
else {
    Write-KscLog 'Аудит доступа к каталогам и реестру пропущен (-SkipSacl).' 'WARN'
}

# ------------------------------------------------------------------ Итог

Write-KscLog '--- Действующая политика аудита (сводка) ---'
& auditpol.exe /get /category:* | Select-Object -Skip 1 | Where-Object { $_ -match '\S' } | ForEach-Object {
    Write-Host "    $_" -ForegroundColor DarkGray
}

if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-KscLog 'Узел в домене: закрепите тот же состав аудита в GPO, иначе локальные значения будут перезаписаны при обновлении политики.' 'WARN'
}
Write-KscLog '=== Аудит ОС настроен. Следующий шаг: 10_Enable-DbAudit.ps1 ===' 'OK'
