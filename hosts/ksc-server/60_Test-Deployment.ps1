<#
.SYNOPSIS
    Приёмочная проверка развёрнутого Сервера администрирования KSC.

.DESCRIPTION
    Выполняет набор автоматических проверок и формирует отчёт (текст + CSV)
    для приобщения к материалам аттестации:

      1. Соответствие хоста требованиям (CPU/RAM/диски).
      2. Сетевая конфигурация: статический адрес, DNS, FQDN, PTR.
      3. Службы KSC и MariaDB.
      4. Прослушиваемые порты.
      5. Правила брандмауэра: управление ограничено АРМ администратора.
      6. Недоступность СУБД извне.
      7. Наличие и свежесть резервных копий.
      8. Наличие исключений антивируса.

    Отчёт: C:\ProgramData\KscDeployment\reports\acceptance-<дата>.txt / .csv

.EXAMPLE
    .\60_Test-Deployment.ps1
#>
[CmdletBinding()]
param([string]$ReportDir = 'C:\ProgramData\KscDeployment\reports')

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\..\..\common\config.ps1"

$results = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Area, [string]$Check, [string]$Expected, [string]$Actual, [bool]$Pass)
    $results.Add([pscustomobject]@{
        Область  = $Area
        Проверка = $Check
        Ожидание = $Expected
        Факт     = $Actual
        Результат = if ($Pass) { 'СООТВ.' } else { 'НЕ СООТВ.' }
    })
}

$fqdn = "$($KSC.KscHostName).$($KSC.DomainFqdn)"

# ---------------------------------------------------------------- 1. Ресурсы
$os = Get-CimInstance Win32_OperatingSystem
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$ram = [math]::Round($os.TotalVisibleMemorySize / 1MB)
Add-Check 'Ресурсы' 'Логических ядер' '>= 4 (реком. 6-8)' $cores ($cores -ge 4)
Add-Check 'Ресурсы' 'Оперативная память, ГБ' '>= 16' $ram ($ram -ge 15)

foreach ($d in @($KSC.DiskSystem, $KSC.DiskDatabase, $KSC.DiskData) | Select-Object -Unique) {
    $v = Get-Volume -DriveLetter $d.TrimEnd(':') -ErrorAction SilentlyContinue
    $free = if ($v) { [math]::Round($v.SizeRemaining / 1GB) } else { 0 }
    Add-Check 'Ресурсы' "Свободно на томе $d, ГБ" '>= 40' $free ($free -ge 40)
}

# ---------------------------------------------------------------- 2. Сеть
$ad = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
$dhcp = if ($ad) { (Get-NetIPInterface -InterfaceIndex $ad.ifIndex -AddressFamily IPv4).Dhcp } else { 'н/д' }
Add-Check 'Сеть' 'Адресация' 'Disabled (статическая)' $dhcp ($dhcp -eq 'Disabled')

$ip = if ($ad) { ((Get-NetIPConfiguration -InterfaceIndex $ad.ifIndex).IPv4Address | Select-Object -First 1).IPAddress } else { '' }
Add-Check 'Сеть' 'IP-адрес' $KSC.KscIp $ip ($ip -eq $KSC.KscIp)

$fwdOk = $false; $fwdVal = 'не разрешается'
try { $r = Resolve-DnsName $fqdn -Type A -ErrorAction Stop; $fwdVal = ($r.IPAddress -join ','); $fwdOk = $true } catch {}
Add-Check 'Сеть' "Прямая зона DNS ($fqdn)" $KSC.KscIp $fwdVal ($fwdOk -and $fwdVal -match [regex]::Escape($KSC.KscIp))

$ptrOk = $false; $ptrVal = 'нет записи'
try { $r = Resolve-DnsName $KSC.KscIp -Type PTR -ErrorAction Stop; $ptrVal = $r.NameHost; $ptrOk = $true } catch {}
Add-Check 'Сеть' 'Обратная зона DNS (PTR)' $fqdn $ptrVal $ptrOk

$domain = (Get-CimInstance Win32_ComputerSystem).Domain
Add-Check 'Сеть' 'Членство в домене' $KSC.DomainFqdn $domain ($domain -eq $KSC.DomainFqdn)

# ---------------------------------------------------------------- 3. Службы
foreach ($n in @('MariaDB', 'kladminserver_srv', 'klnagent_srv')) {
    $s = Get-Service $n -ErrorAction SilentlyContinue
    if (-not $s) { $s = Get-Service "$n*" -ErrorAction SilentlyContinue | Select-Object -First 1 }
    $st = if ($s) { $s.Status } else { 'отсутствует' }
    Add-Check 'Службы' "Служба $n" 'Running' $st ($st -eq 'Running')
}

# ---------------------------------------------------------------- 4. Порты
$listen = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).LocalPort | Select-Object -Unique
$expectPorts = [ordered]@{
    $KSC.PortAgentSsl   = 'Агенты SSL'
    $KSC.PortMmc        = 'Консоль MMC'
    $KSC.PortOpenApi    = 'OpenAPI'
    $KSC.PortWebConsole = 'Web Console'
    $KSC.PortWebSrvHttp = 'Веб-сервер'
    $KSC.PortMariaDb    = 'MariaDB'
}
foreach ($p in $expectPorts.Keys) {
    $ok = $listen -contains [int]$p
    Add-Check 'Порты' "$p ($($expectPorts[$p]))" 'слушается' $(if ($ok) { 'слушается' } else { 'нет' }) $ok
}

# ---------------------------------------------------------------- 5. Брандмауэр
$mgmt = Get-KscManagementHosts
$mgmtRules = @(
    @{ Name = 'KSC: RDP (управление)';      Port = 3389 }
    @{ Name = 'KSC: MMC-консоль 13291';     Port = $KSC.PortMmc }
    @{ Name = 'KSC: Web Console 8080';      Port = $KSC.PortWebConsole }
    @{ Name = 'KSC: OpenAPI 13299';         Port = $KSC.PortOpenApi }
)
foreach ($r in $mgmtRules) {
    $rule = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    if (-not $rule) { Add-Check 'Брандмауэр' $r.Name 'правило существует' 'отсутствует' $false; continue }
    $remote = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
    $restricted = $remote -and ($remote -notcontains 'Any')
    Add-Check 'Брандмауэр' "$($r.Name): источники" "только $($mgmt -join ', ')" ($remote -join ',') $restricted
}

$profiles = Get-NetFirewallProfile
foreach ($p in $profiles) {
    Add-Check 'Брандмауэр' "Профиль $($p.Name): входящие по умолчанию" 'Block' $p.DefaultInboundAction ($p.DefaultInboundAction -eq 'Block')
    Add-Check 'Брандмауэр' "Профиль $($p.Name): включён" 'True' $p.Enabled ($p.Enabled -eq $true)
}

# ---------------------------------------------------------------- 6. СУБД снаружи
$bindOk = $false
$iniPath = Join-Path $KSC.MariaDbDataDir 'my.ini'
if (Test-Path $iniPath) {
    $bindOk = (Select-String -Path $iniPath -Pattern '^\s*bind-address\s*=\s*127\.0\.0\.1' -Quiet)
}
Add-Check 'СУБД' 'bind-address' '127.0.0.1' $(if ($bindOk) { '127.0.0.1' } else { 'не задан / иной' }) $bindOk

# ---------------------------------------------------------------- 7. Резервные копии
$last = Get-ChildItem $KSC.BackupDir -Directory -ErrorAction SilentlyContinue |
    Where-Object Name -match '^\d{8}-\d{6}$' | Sort-Object Name -Descending | Select-Object -First 1
if ($last) {
    $age = (New-TimeSpan -Start ([datetime]::ParseExact($last.Name, 'yyyyMMdd-HHmmss', $null)) -End (Get-Date)).TotalHours
    Add-Check 'Резервирование' 'Возраст последней копии, ч' '<= 48' ([math]::Round($age, 1)) ($age -le 48)
} else {
    Add-Check 'Резервирование' 'Наличие резервной копии' 'есть' 'нет' $false
}
$task = Get-ScheduledTask -TaskName 'KSC - Резервное копирование Сервера администрирования' -ErrorAction SilentlyContinue
Add-Check 'Резервирование' 'Задание планировщика' 'зарегистрировано' $(if ($task) { $task.State } else { 'нет' }) ([bool]$task)

# ---------------------------------------------------------------- 8. Исключения антивируса
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $ex = (Get-MpPreference).ExclusionPath
    $need = @($KSC.MariaDbDataDir, $KSC.KlShareDir)
    foreach ($n in $need) {
        $ok = $ex -contains $n
        Add-Check 'Антивирус' "Исключение $n" 'задано' $(if ($ok) { 'задано' } else { 'нет' }) $ok
    }
}

# ---------------------------------------------------------------- Отчёт
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$txt = Join-Path $ReportDir "acceptance-$stamp.txt"
$csv = Join-Path $ReportDir "acceptance-$stamp.csv"

$passed = ($results | Where-Object Результат -eq 'СООТВ.').Count
$total = $results.Count

$header = @"
ПРОТОКОЛ ПРИЁМОЧНОЙ ПРОВЕРКИ
Сервер администрирования Kaspersky Security Center
Хост: $fqdn ($($KSC.KscIp)), ВМ: $($KSC.KscVmName)
Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm')
Результат: соответствует $passed из $total проверок
"@

$body = $results | Format-Table -AutoSize | Out-String -Width 200
($header + "`n" + $body) | Set-Content $txt -Encoding UTF8
$results | Export-Csv $csv -NoTypeInformation -Encoding UTF8

Write-Host $header -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$results | Where-Object Результат -eq 'НЕ СООТВ.' | ForEach-Object {
    Write-Host "НЕ СООТВ.: [$($_.Область)] $($_.Проверка) — ожидание '$($_.Ожидание)', факт '$($_.Факт)'" -ForegroundColor Red
}
Write-Host ''
Write-Host "Отчёт: $txt" -ForegroundColor Green
Write-Host "Таблица: $csv" -ForegroundColor Green
