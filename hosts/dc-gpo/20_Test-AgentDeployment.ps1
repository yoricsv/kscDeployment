<#
.SYNOPSIS
    Контроль охвата: какие узлы домена уже имеют Агент администрирования, а какие нет.

.DESCRIPTION
    Сопоставляет список компьютеров Active Directory с фактическим наличием
    службы Агента администрирования и формирует отчёт охвата — документ,
    подтверждающий выполнение требования "Агент на всех узлах сети".

    Источники данных:
      * Active Directory — перечень учётных записей компьютеров (включая
        неактивные, что позволяет выявить забытые объекты);
      * опрос узлов (служба klnagent) — фактическое состояние;
      * список исключений (файл exclusions.txt) — узлы, для которых установка
        Агента не предусмотрена (например, хост виртуализации).

    Узлы вне домена в AD отсутствуют и проверяются отдельно — их перечень
    ведётся в файле hosts/standalone/inventory.csv.

.PARAMETER InactiveDays
    Считать учётную запись компьютера неактивной, если она не обращалась
    к домену указанное число дней (по умолчанию 60).

.EXAMPLE
    .\20_Test-AgentDeployment.ps1
    .\20_Test-AgentDeployment.ps1 -InactiveDays 30
#>
[CmdletBinding()]
param(
    [int]$InactiveDays = 60,
    [string]$ReportDir = 'C:\ProgramData\KscDeployment\reports'
)

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\..\..\common\config.ps1"
Import-Module ActiveDirectory -ErrorAction Stop

$exclusionsFile = "$PSScriptRoot\exclusions.txt"
$exclusions = if (Test-Path $exclusionsFile) {
    Get-Content $exclusionsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }
} else { @() }

Write-KscLog "=== Контроль охвата Агентом администрирования ==="
Write-KscLog "Исключений в списке: $($exclusions.Count)"

$cutoff = (Get-Date).AddDays(-$InactiveDays)
$computers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate, IPv4Address, Enabled

$results = foreach ($c in $computers) {
    $status = 'не проверен'
    $agentVersion = ''
    $reachable = $false

    if ($exclusions -contains $c.Name) {
        $status = 'исключён'
    }
    elseif (-not $c.Enabled) {
        $status = 'учётная запись отключена'
    }
    elseif ($c.LastLogonDate -and $c.LastLogonDate -lt $cutoff) {
        $status = "неактивен с $($c.LastLogonDate.ToString('dd.MM.yyyy'))"
    }
    else {
        $reachable = Test-Connection -ComputerName $c.Name -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $reachable) {
            $status = 'недоступен по сети'
        } else {
            $svc = Get-Service -ComputerName $c.Name -Name 'klnagent*' -ErrorAction SilentlyContinue
            if ($svc) {
                $status = "Агент установлен ($($svc.Status))"
                try {
                    $agentVersion = (Get-CimInstance -ComputerName $c.Name -ClassName Win32_Product `
                        -Filter "Name LIKE '%Network Agent%'" -ErrorAction SilentlyContinue |
                        Select-Object -First 1).Version
                } catch {}
            } else {
                $status = 'АГЕНТ ОТСУТСТВУЕТ'
            }
        }
    }

    [pscustomobject]@{
        Имя           = $c.Name
        ОС            = $c.OperatingSystem
        IP            = $c.IPv4Address
        ПоследнийВход = if ($c.LastLogonDate) { $c.LastLogonDate.ToString('dd.MM.yyyy') } else { 'нет данных' }
        Доступен      = if ($reachable) { 'да' } else { 'нет' }
        Состояние     = $status
        ВерсияАгента  = $agentVersion
    }
}

# ---------------------------------------------------------------- Сводка

$total = @($results).Count
$installed = @($results | Where-Object Состояние -match 'Агент установлен').Count
$missing = @($results | Where-Object Состояние -eq 'АГЕНТ ОТСУТСТВУЕТ').Count
$excluded = @($results | Where-Object Состояние -eq 'исключён').Count
$unreachable = @($results | Where-Object Состояние -match 'недоступен|неактивен|отключена').Count

$coverage = if (($total - $excluded) -gt 0) { [math]::Round(100 * $installed / ($total - $excluded), 1) } else { 0 }

Write-Host ''
$results | Sort-Object Состояние, Имя | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

Write-Host ''
Write-Host "Всего учётных записей компьютеров ..... $total"        -ForegroundColor Cyan
Write-Host "Агент установлен ...................... $installed"    -ForegroundColor Green
Write-Host "Агент отсутствует ..................... $missing"      -ForegroundColor $(if ($missing) { 'Red' } else { 'Green' })
Write-Host "Исключены из охвата ................... $excluded"     -ForegroundColor Gray
Write-Host "Недоступны / неактивны ................ $unreachable"  -ForegroundColor Yellow
Write-Host "Охват .................................. $coverage %"  -ForegroundColor $(if ($coverage -ge 100) { 'Green' } else { 'Yellow' })

if ($missing -gt 0) {
    Write-Host ''
    Write-Host 'Узлы без Агента:' -ForegroundColor Red
    $results | Where-Object Состояние -eq 'АГЕНТ ОТСУТСТВУЕТ' | ForEach-Object { Write-Host "  $($_.Имя) ($($_.ОС))" }
}

# ---------------------------------------------------------------- Отчёт

if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
$csv = Join-Path $ReportDir ("agent-coverage-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$results | Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "Отчёт: $csv" -ForegroundColor Green
Write-KscLog "Охват Агентом: $coverage % ($installed из $($total - $excluded))" $(if ($coverage -ge 100) { 'OK' } else { 'WARN' })
Write-KscLog 'Не забудьте проверить узлы вне домена: hosts/standalone/inventory.csv и Linux: hosts/linux-debian.' 'WARN'
