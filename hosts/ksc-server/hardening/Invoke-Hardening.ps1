<#
.SYNOPSIS
    Харденинг сервера администрирования KSC (Windows Server 2022, роль "сервер управления СЗИ").

.DESCRIPTION
    Применяет базовый профиль усиления защиты из common\WindowsBaseline.psm1
    с поправками, обязательными для работоспособности KSC:

      * NetBIOS over TCP/IP НЕ отключается полностью — сохраняется при
        необходимости опроса Windows-доменов (по умолчанию отключается,
        так как используется опрос Active Directory);
      * служба удалённого реестра и RPC остаются доступными для подсети,
        иначе не работает удалённая установка Агентов;
      * RDP не отключается, но ограничен NLA и списком источников
        (правило брандмауэра из 10_Set-Firewall.ps1);
      * дополнительно ограничиваются права на каталоги KSC и СУБД.

    Скрипт поддерживает -WhatIf: сначала выполните прогон без изменений.

.EXAMPLE
    .\Invoke-Hardening.ps1 -WhatIf
    .\Invoke-Hardening.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$SkipTls)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Import-Module "$PSScriptRoot\..\..\..\common\WindowsBaseline.psm1" -Force
Assert-Elevated

Write-KscLog '=== Харденинг: Сервер администрирования KSC ==='

# ---------------------------------------------------------------- Базовый профиль

Disable-LegacyProtocols
if (-not $SkipTls) { Set-TlsHardening }
Set-AuthenticationHardening -CachedLogons 2
Set-RdpHardening -IdleTimeoutMinutes 15
Set-UacHardening
Set-AutorunHardening
Set-AuditPolicy -SecurityLogSizeKb 1048576
Set-DefenderBaseline

# Службы: на KSC оставляем те, что нужны для удалённой установки Агентов
Disable-UnneededServices -Keep @('RemoteRegistry')

# ---------------------------------------------------------------- Специфика KSC

Write-KscLog '--- Параметры, специфичные для роли KSC ---'

# Удалённый реестр требуется задачам удалённой установки Агентов,
# но запускается вручную и доступен только из подсети (правило брандмауэра).
$rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
if ($rr) {
    Set-Service RemoteRegistry -StartupType Manual
    Write-KscLog '  + RemoteRegistry: запуск вручную (нужен для удалённой установки Агентов)' 'OK'
}

# Права на каталог резервных копий: только SYSTEM и администраторы
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

# Запрет интерактивного входа сервисной учётной записи
Write-KscLog "  ! Проверьте вручную: $($KSC.DomainNetBios)\$($KSC.SvcAccount) должна иметь запрет" 'WARN'
Write-KscLog '    "Отказать в локальном входе" и "Отказать во входе через службы удалённых рабочих столов".' 'WARN'

# Ограничение локального входа
Write-KscLog "  ! Право 'Вход в систему через службы удалённых рабочих столов' — только $($KSC.DomainNetBios)\$($KSC.AdminsGroup)." 'WARN'

# ---------------------------------------------------------------- Проверка сохранения работоспособности

Write-KscLog '--- Контроль работоспособности после харденинга ---'
$critical = @{
    $KSC.PortAgentSsl   = 'приём Агентов'
    $KSC.PortMmc        = 'консоль MMC'
    $KSC.PortOpenApi    = 'OpenAPI'
    $KSC.PortWebConsole = 'Web Console'
}
foreach ($p in $critical.Keys) {
    $ok = Test-KscPort -ComputerName 'localhost' -Port $p
    Write-KscLog ('  порт {0} ({1}): {2}' -f $p, $critical[$p], $(if ($ok) { 'доступен' } else { 'НЕ доступен' })) $(if ($ok) { 'OK' } else { 'ERROR' })
}

Write-HardeningSummary -Role 'KSC Administration Server'
Write-KscLog 'После перезагрузки выполните 60_Test-Deployment.ps1 для приёмочной проверки.' 'WARN'
