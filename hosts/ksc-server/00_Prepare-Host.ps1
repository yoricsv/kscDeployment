<#
.SYNOPSIS
    Подготовка Windows Server 2022 к установке Kaspersky Security Center.

.DESCRIPTION
    Выполняет:
      * проверку соответствия хоста минимальным требованиям (CPU/RAM/диск/ОС);
      * проверку сетевой конфигурации (статический IP, DNS, FQDN, прямая/обратная зоны);
      * разметку дополнительных томов под БД и данные (если диск не разбит);
      * создание рабочих каталогов;
      * настройку схемы электропитания, часового пояса и синхронизации времени;
      * регистрацию исключений Windows Defender для каталогов СУБД и KSC.

    Скрипт идемпотентен: повторный запуск не ломает уже выполненные шаги.

.PARAMETER SkipDiskLayout
    Не выполнять разметку дополнительных томов (если разметка сделана заранее).

.EXAMPLE
    .\00_Prepare-Host.ps1
    .\00_Prepare-Host.ps1 -SkipDiskLayout
#>
[CmdletBinding()]
param(
    [switch]$SkipDiskLayout
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

Write-KscLog "=== Подготовка хоста $($KSC.KscHostName) ($($KSC.KscIp)) ==="

# ---------------------------------------------------------------- 1. Требования

$os = Get-CimInstance Win32_OperatingSystem
$cpuCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$ramGb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)

Write-KscLog "ОС: $($os.Caption) $($os.Version)"
Write-KscLog "Логических ядер: $cpuCores, ОЗУ: $ramGb ГБ"

if ($os.Caption -notmatch '2019|2022|2025') {
    Write-KscLog 'Версия ОС не входит в список проверенных (Windows Server 2019/2022/2025).' 'WARN'
}
if ($cpuCores -lt 6) {
    Write-KscLog "Ядер: $cpuCores. Для проектной ёмкости $($KSC.PlannedHosts) устройств рекомендуется не менее 6-8 vCPU." 'WARN'
}
if ($ramGb -lt 15) {
    Write-KscLog "ОЗУ: $ramGb ГБ. Требуется не менее 16 ГБ." 'ERROR'
    throw 'Недостаточно оперативной памяти.'
}

# ---------------------------------------------------------------- 2. Сеть

$adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
if (-not $adapter) { throw 'Не найден активный сетевой адаптер.' }

$ipCfg = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
$currentIp = ($ipCfg.IPv4Address | Select-Object -First 1).IPAddress
$dhcp = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).Dhcp

Write-KscLog "Адаптер: $($adapter.Name), IPv4: $currentIp, DHCP: $dhcp"

if ($dhcp -eq 'Enabled') {
    Write-KscLog 'Включён DHCP. В аттестованной сети требуется статическая адресация.' 'ERROR'
    Write-KscLog "Задайте адрес вручную: New-NetIPAddress -InterfaceIndex $($adapter.ifIndex) -IPAddress $($KSC.KscIp) -PrefixLength $($KSC.SubnetMaskLength) -DefaultGateway $($KSC.Gateway)" 'WARN'
}
if ($currentIp -ne $KSC.KscIp) {
    Write-KscLog "Текущий IP ($currentIp) не совпадает с заданным в config.ps1 ($($KSC.KscIp)). Проверьте конфигурацию." 'WARN'
}

$dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
Write-KscLog "DNS-серверы: $($dnsServers -join ', ')"
if ($dnsServers -notcontains $KSC.DomainController) {
    Write-KscLog "В списке DNS отсутствует контроллер домена $($KSC.DomainController)." 'ERROR'
}

# Членство в домене
$cs = Get-CimInstance Win32_ComputerSystem
if (-not $cs.PartOfDomain) {
    Write-KscLog "Хост не введён в домен. Введите: Add-Computer -DomainName $($KSC.DomainFqdn) -Restart" 'ERROR'
} else {
    Write-KscLog "Домен: $($cs.Domain)" 'OK'
}

# Проверка FQDN: прямая и обратная зоны
$expectedFqdn = "$($KSC.KscHostName).$($KSC.DomainFqdn)"
try {
    $fwd = Resolve-DnsName -Name $expectedFqdn -Type A -ErrorAction Stop
    Write-KscLog "Прямая зона: $expectedFqdn -> $($fwd.IPAddress -join ',')" 'OK'
} catch {
    Write-KscLog "Не разрешается прямое имя $expectedFqdn. Создайте A-запись на $($KSC.DomainController)." 'ERROR'
}
try {
    $rev = Resolve-DnsName -Name $KSC.KscIp -Type PTR -ErrorAction Stop
    Write-KscLog "Обратная зона: $($KSC.KscIp) -> $($rev.NameHost)" 'OK'
} catch {
    Write-KscLog "Нет PTR-записи для $($KSC.KscIp). Создайте обратную зону — иначе возможны сбои опроса сети." 'WARN'
}

if ($env:COMPUTERNAME -ne $KSC.KscHostName.ToUpper()) {
    Write-KscLog "Имя ОС ($env:COMPUTERNAME) отличается от ожидаемого ($($KSC.KscHostName)). Имя ВМ в гипервизоре ($($KSC.KscVmName)) на работу KSC не влияет, но FQDN должен быть именно $expectedFqdn." 'WARN'
}

# ---------------------------------------------------------------- 3. Разметка дисков

if (-not $SkipDiskLayout) {
    Write-KscLog '--- Проверка томов ---'
    $volumes = Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter, FileSystemLabel,
        @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB) } }, @{n = 'FreeGB'; e = { [math]::Round($_.SizeRemaining / 1GB) } }
    $volumes | Format-Table | Out-String | Write-Host

    $needD = -not (Get-Volume -DriveLetter $KSC.DiskDatabase.TrimEnd(':') -ErrorAction SilentlyContinue)
    $needE = -not (Get-Volume -DriveLetter $KSC.DiskData.TrimEnd(':') -ErrorAction SilentlyContinue)

    if ($needD -or $needE) {
        Write-KscLog "Тома $($KSC.DiskDatabase) и/или $($KSC.DiskData) отсутствуют." 'WARN'
        Write-KscLog 'Единый раздел на 400 ГБ нежелателен: рост БД или хранилища обновлений останавливает ОС.' 'WARN'
        Write-KscLog 'Варианты: (а) добавить виртуальные диски в гипервизоре и запустить 01_New-DiskLayout.ps1;' 'WARN'
        Write-KscLog '          (б) сжать C: и создать разделы вручную (diskmgmt.msc);' 'WARN'
        Write-KscLog "          (в) оставить один том — тогда в config.ps1 задайте DiskDatabase='C:' и DiskData='C:' и обязательно ограничьте хранилище событий." 'WARN'
    } else {
        Write-KscLog 'Тома под БД и данные присутствуют.' 'OK'
    }
}

# ---------------------------------------------------------------- 4. Каталоги

$dirs = @($KSC.MariaDbDataDir, $KSC.KlShareDir, $KSC.BackupDir, $KSC.UpdatesDir, $KSC.LogDir)
foreach ($d in $dirs) {
    $root = Split-Path -Qualifier $d
    if (-not (Test-Path $root)) {
        Write-KscLog "Том $root отсутствует — каталог $d не создан." 'WARN'
        continue
    }
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-KscLog "Создан каталог $d" 'OK'
    }
}

# Общая папка KLSHARE (создаётся инсталлятором, но каталог и NTFS-права готовим заранее)
if (Test-Path $KSC.KlShareDir) {
    $acl = Get-Acl $KSC.KlShareDir
    $acl.SetAccessRuleProtection($true, $false)
    $rules = @(
        New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Users', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    )
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    $rules | ForEach-Object { $acl.AddAccessRule($_) }
    Set-Acl -Path $KSC.KlShareDir -AclObject $acl
    Write-KscLog "NTFS-права на $($KSC.KlShareDir) приведены к минимально необходимым." 'OK'
}

# ---------------------------------------------------------------- 5. Питание, время, региональные настройки

powercfg /setactive SCHEME_MIN | Out-Null   # High performance
Write-KscLog 'Схема электропитания: высокая производительность.' 'OK'

w32tm /config /syncfromflags:domhier /update | Out-Null
Restart-Service w32time -ErrorAction SilentlyContinue
Write-KscLog 'Служба времени синхронизируется с иерархией домена.' 'OK'

# ---------------------------------------------------------------- 6. Исключения антивируса

$exclusionPaths = @(
    $KSC.MariaDbDataDir
    $KSC.KlShareDir
    $KSC.UpdatesDir
    $KSC.BackupDir
    'C:\Program Files (x86)\Kaspersky Lab'
    'C:\ProgramData\KasperskyLab'
)
$exclusionProcs = @(
    (Join-Path $KSC.MariaDbInstallDir 'bin\mysqld.exe')
    'C:\Program Files (x86)\Kaspersky Lab\Kaspersky Security Center\klserver.exe'
)

if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    foreach ($p in $exclusionPaths) { Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue }
    foreach ($p in $exclusionProcs) { Add-MpPreference -ExclusionProcess $p -ErrorAction SilentlyContinue }
    Write-KscLog 'Исключения Windows Defender добавлены.' 'OK'
} else {
    Write-KscLog 'Windows Defender не обнаружен — задайте исключения в используемом СЗИ вручную.' 'WARN'
    $exclusionPaths + $exclusionProcs | ForEach-Object { Write-KscLog "  исключить: $_" }
}

# ---------------------------------------------------------------- 7. Компоненты ОС

$features = @('NET-Framework-45-Core')
foreach ($f in $features) {
    $state = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
    if ($state -and -not $state.Installed) {
        Install-WindowsFeature -Name $f | Out-Null
        Write-KscLog "Установлен компонент $f" 'OK'
    }
}

Write-KscLog '=== Подготовка хоста завершена. Следующий шаг: 10_Set-Firewall.ps1 ===' 'OK'
