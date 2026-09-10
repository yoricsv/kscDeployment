<#
.SYNOPSIS
    Харденинг сервера администрирования KSC (Windows Server 2022, роль "сервер управления СЗИ").

.DESCRIPTION
    Применяет расширенный (строгий) профиль усиления защиты для систем
    ограниченного доступа с поправками, обязательными для работоспособности KSC:

      * служба удалённого реестра остаётся в режиме "Вручную", иначе перестают
        работать задачи удалённой установки Агентов;
      * службы удалённых рабочих столов и удалённого управления сохраняются:
        Сервер администрируется с АРМ 10.20.30.15, отключение этих служб
        лишает узел управляемости;
      * PowerShell не переводится в режим ограниченного языка: в нём
        не работают ни сценарии этого репозитория, ни средства обслуживания;
      * управление запуском программ (AppLocker) включается в режиме
        наблюдения — блокировка на сервере с СУБД и инсталляторами KSC
        без предварительного разбора событий останавливает работу.

    Профили:
      Strict   — расширенный профиль (по умолчанию);
      Baseline — прежний базовый профиль, если строгий пока неприменим.

    Скрипт поддерживает -WhatIf: сначала выполните прогон без изменений.

.PARAMETER Level
    Strict (по умолчанию) либо Baseline.

.PARAMETER SkipTls
    Не изменять параметры SCHANNEL (если ими управляет групповая политика).

.PARAMETER SkipCredentialGuard
    Не включать защиту на основе виртуализации: на виртуальной машине
    без вложенной виртуализации она не запустится.

.PARAMETER EnforceAppLocker
    Включить управление запуском программ в режиме блокировки, а не наблюдения.

.EXAMPLE
    .\Invoke-Hardening.ps1 -WhatIf
    .\Invoke-Hardening.ps1
    .\Invoke-Hardening.ps1 -Level Baseline
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Strict', 'Baseline')][string]$Level = 'Strict',
    [switch]$SkipTls,
    [switch]$SkipCredentialGuard,
    [switch]$EnforceAppLocker
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Import-Module "$PSScriptRoot\..\..\..\common\WindowsBaseline.psm1" -Force
Assert-Elevated

Write-KscLog "=== Харденинг: Сервер администрирования KSC (профиль $Level) ==="

# ---------------------------------------------------------------- Общая часть

Disable-LegacyProtocols
if (-not $SkipTls) { Set-TlsHardening }
Set-AuthenticationHardening -CachedLogons 2
Set-RdpHardening -IdleTimeoutMinutes 15
Set-UacHardening
Set-AutorunHardening

# ---------------------------------------------------------------- Расширенный профиль

if ($Level -eq 'Strict') {
    Set-AuditPolicy -SecurityLogSizeKb 1048576 -Strict
    Set-PasswordPolicy -MinLength 14 -MaxAgeDays 60 -LockoutThreshold 5 -LockoutDurationMin 30
    Set-UserRightsHardening
    Set-CredentialProtection -SkipCredentialGuard:$SkipCredentialGuard
    Set-NetworkStackHardening
    Set-TelemetryHardening
    Set-UpdateHardening
    Set-ScriptHostHardening
    Set-PowerShellHardening -ExecutionPolicy RemoteSigned
    Set-LegalNotice
    Set-DefenderStrict
    Set-RemovableStorageHardening -Mode DenyWrite
    Set-AppLockerBaseline -Enforce:$EnforceAppLocker -AllowedPaths @(
        'C:\Program Files (x86)\Kaspersky Lab\'
        'C:\ProgramData\KasperskyLab\'
        "$($KSC.MariaDbInstallDir)\"
        "$($KSC.KlShareDir)\"
    )
} else {
    Set-AuditPolicy -SecurityLogSizeKb 1048576
    Set-DefenderBaseline
    Write-BaselineFallbackNotice
}

# ---------------------------------------------------------------- Службы
#
# Строгий перечень отключаемых служб применяется с исключениями: без них
# Сервер перестаёт выполнять свою роль.

$keepServices = @(
    'RemoteRegistry'   # задачи удалённой установки Агентов
    'TermService'      # администрирование с АРМ 10.20.30.15
    'SessionEnv'
    'UmRdpService'
    'WinRM'            # выполнение сценариев обслуживания с АРМ
)
Disable-UnneededServices -Keep $keepServices -Strict:($Level -eq 'Strict')

# ---------------------------------------------------------------- Специфика KSC

Write-KscLog '--- Параметры, специфичные для роли KSC ---'

$rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
if ($rr -and $PSCmdlet.ShouldProcess('RemoteRegistry', 'Режим запуска: вручную')) {
    Set-Service RemoteRegistry -StartupType Manual
    Write-KscLog '  + RemoteRegistry: запуск вручную (нужен для удалённой установки Агентов)' 'OK'
}

# Права на каталоги данных: только SYSTEM и администраторы
foreach ($dir in @($KSC.BackupDir, $KSC.MariaDbDataDir)) {
    if (-not (Test-Path $dir)) { continue }
    if ($PSCmdlet.ShouldProcess($dir, 'Ограничить NTFS-права')) {
        icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' /T /C /Q | Out-Null
        Write-KscLog "  + $dir : доступ только SYSTEM и Администраторы" 'OK'
    }
}

# Общая папка KLSHARE: чтение для прошедших проверку подлинности, запись запрещена
$share = Get-SmbShare -Name 'KLSHARE' -ErrorAction SilentlyContinue
if ($share -and $PSCmdlet.ShouldProcess('KLSHARE', 'Ограничить права общего ресурса')) {
    Revoke-SmbShareAccess -Name 'KLSHARE' -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue | Out-Null
    Grant-SmbShareAccess -Name 'KLSHARE' -AccountName 'NT AUTHORITY\Authenticated Users' -AccessRight Read -Force | Out-Null
    Grant-SmbShareAccess -Name 'KLSHARE' -AccountName 'BUILTIN\Administrators' -AccessRight Full -Force | Out-Null
    Write-KscLog '  + KLSHARE: чтение — прошедшие проверку подлинности, полный доступ — администраторы' 'OK'
}

# Подпись SMB на общем ресурсе: защита от подмены содержимого пакетов установки
if ($share -and $PSCmdlet.ShouldProcess('KLSHARE', 'Требовать шифрование SMB')) {
    Set-SmbServerConfiguration -EncryptData $false -RejectUnencryptedAccess $false -Force -ErrorAction SilentlyContinue
    Write-KscLog '  = Шифрование SMB не включено: часть Агентов и загрузчиков GPO не поддерживает SMB 3 с шифрованием.' 'WARN'
    Write-KscLog '    Целостность обеспечивается обязательной подписью SMB (Disable-LegacyProtocols).' 'WARN'
}

Write-KscLog "  ! Проверьте вручную: $($KSC.DomainNetBios)\$($KSC.SvcAccount) должна иметь запрет" 'WARN'
Write-KscLog '    "Отказать в локальном входе" и "Отказать во входе через службы удалённых рабочих столов".' 'WARN'
Write-KscLog "  ! Право 'Вход через службы удалённых рабочих столов' — только $($KSC.DomainNetBios)\$($KSC.AdminsGroup)." 'WARN'
Write-KscLog '    Задайте его доменной политикой либо параметром -RemoteInteractiveSids функции Set-UserRightsHardening.' 'WARN'

# ---------------------------------------------------------------- Проверка сохранения работоспособности

Write-KscLog '--- Контроль работоспособности после харденинга ---'
$critical = @('kladminserver', 'klnagent', 'KSCWebConsole', 'mysqld', 'MariaDB')
foreach ($name in $critical) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    $state = if ($svc.Status -eq 'Running') { 'OK' } else { 'ERROR' }
    Write-KscLog "  $($svc.Name): $($svc.Status)" $state
}

foreach ($port in @($KSC.PortAgentSsl, $KSC.PortMmc, $KSC.PortWebConsole)) {
    $listening = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    Write-KscLog "  порт $port : $(if ($listening) { 'прослушивается' } else { 'НЕ прослушивается' })" $(if ($listening) { 'OK' } else { 'ERROR' })
}

Write-KscLog 'После перезагрузки выполните 60_Test-Deployment.ps1: часть параметров вступает в силу только после неё.' 'WARN'
Write-HardeningSummary -Role "KSC Server ($Level)"
