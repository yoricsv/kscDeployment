<#
.SYNOPSIS
    Откат изменений реестра, выполненных скриптами харденинга.

.DESCRIPTION
    Читает файл отката, созданный модулем WindowsBaseline.psm1
    (C:\ProgramData\KscDeployment\rollback\rollback-<дата>.json), и
    восстанавливает прежние значения параметров реестра.

    Откат не затрагивает:
      * отключённые службы (восстанавливаются вручную по журналу);
      * компоненты Windows (SMBv1);
      * политику аудита (см. auditpol /clear и последующую перенастройку).
    Эти шаги перечисляются в отчёте как требующие ручного вмешательства.

.PARAMETER RollbackFile
    Путь к файлу отката. По умолчанию — самый свежий из каталога отката.

.EXAMPLE
    .\Restore-Baseline.ps1
    .\Restore-Baseline.ps1 -RollbackFile C:\ProgramData\KscDeployment\rollback\rollback-20260101-120000.json
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$RollbackFile)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\config.ps1"
Assert-Elevated

$dir = 'C:\ProgramData\KscDeployment\rollback'
if (-not $RollbackFile) {
    $RollbackFile = (Get-ChildItem $dir -Filter 'rollback-*.json' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1).FullName
}
if (-not $RollbackFile -or -not (Test-Path $RollbackFile)) { throw "Файл отката не найден. Каталог: $dir" }

Write-KscLog "Откат по файлу: $RollbackFile"
$entries = Get-Content $RollbackFile -Raw | ConvertFrom-Json

$restored = 0; $removed = 0; $failed = 0
foreach ($e in ($entries | Sort-Object Timestamp -Descending)) {
    try {
        if ($null -eq $e.OldValue) {
            if ($PSCmdlet.ShouldProcess("$($e.Path)\$($e.Name)", 'Удалить параметр (ранее отсутствовал)')) {
                Remove-ItemProperty -Path $e.Path -Name $e.Name -ErrorAction SilentlyContinue
                Write-KscLog "  - удалён $($e.Path)\$($e.Name)"
                $removed++
            }
        } else {
            if ($PSCmdlet.ShouldProcess("$($e.Path)\$($e.Name)", "Восстановить значение $($e.OldValue)")) {
                Set-ItemProperty -Path $e.Path -Name $e.Name -Value $e.OldValue
                Write-KscLog "  ~ восстановлено $($e.Path)\$($e.Name) = $($e.OldValue)"
                $restored++
            }
        }
    } catch {
        Write-KscLog "  ! ошибка отката $($e.Path)\$($e.Name): $($_.Exception.Message)" 'ERROR'
        $failed++
    }
}

Write-KscLog "Откат завершён: восстановлено $restored, удалено $removed, ошибок $failed." $(if ($failed) { 'WARN' } else { 'OK' })
Write-KscLog 'Требуют ручного восстановления: отключённые службы, компонент SMBv1, политика аудита.' 'WARN'
Write-KscLog 'Перезагрузите узел для применения изменений SCHANNEL и LSA.' 'WARN'
