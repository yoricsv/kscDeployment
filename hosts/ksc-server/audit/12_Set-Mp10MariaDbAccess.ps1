<#
.SYNOPSIS
    Configures the MariaDB access required by the MaxPatrol VM MySQL Audit profile.

.DESCRIPTION
    Creates a separate read-only MariaDB account for the MP 10 Collector,
    optionally enables MariaDB remote access, and restricts TCP/3306 to the
    configured collector address.

    This script does not change KSC schemas, tables, rows, policies or data.
    The Windows account kscaudit remains a separate account used for the
    MariaDB-Audit Windows event log collection path.

.PARAMETER ConfigureRemoteAccess
    Add the managed bind_address and port settings to the MariaDB option file.
    A service restart is required unless -NoRestart is used.

.PARAMETER NoRestart
    Do not restart the MariaDB service after an option-file change.

.PARAMETER SkipFirewall
    Do not create the restricted inbound TCP/3306 firewall rule.

.PARAMETER WhatIf
    Show planned changes without prompting for passwords or changing the host.

.EXAMPLE
    .\12_Set-Mp10MariaDbAccess.ps1 -WhatIf

.EXAMPLE
    .\12_Set-Mp10MariaDbAccess.ps1 -ConfigureRemoteAccess
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ServiceName,
    [string]$IniPath,
    [switch]$ConfigureRemoteAccess,
    [switch]$NoRestart,
    [switch]$SkipFirewall
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

$account = if ($KSC.AuditMariaDbUser) { $KSC.AuditMariaDbUser } else { 'mp10audit' }
$collector = if ($KSC.AuditCollectorHost) { $KSC.AuditCollectorHost } else { '10.20.30.73' }
$bindAddress = if ($KSC.AuditMariaDbBindAddress) { $KSC.AuditMariaDbBindAddress } else { '10.20.30.75' }
$port = if ($KSC.PortMariaDb) { [int]$KSC.PortMariaDb } else { 3306 }
$firewallGroup = 'KSC Audit - MariaDB'
$managedBegin = '# >>> KSC-MP10-MARIADB BEGIN (managed by 12_Set-Mp10MariaDbAccess.ps1)'
$managedEnd = '# <<< KSC-MP10-MARIADB END'

function Get-MariaDbService {
    param([string]$Name)

    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
        if ($Name) { $_.Name -eq $Name }
        else { $_.Name -match '^(MariaDB|MySQL)' -or $_.DisplayName -match 'MariaDB|MySQL' }
    })
    if ($services.Count -eq 0) { throw 'MariaDB service was not found.' }
    if ($services.Count -gt 1) {
        throw "More than one MariaDB/MySQL service was found: $($services.Name -join ', '). Use -ServiceName."
    }
    $services[0]
}

function Get-DefaultsFileFromPathName {
    param([string]$PathName)

    if ($PathName -match '(?i)--defaults-file=(?:"([^"]+)"|(.+?\.ini)(?:\s|$))') {
        if ($Matches[1]) { return $Matches[1] }
        return $Matches[2]
    }
    return $null
}

function Get-MariaDbClient {
    $paths = @(
        (Join-Path $KSC.MariaDbInstallDir 'bin\mariadb.exe'),
        (Join-Path $KSC.MariaDbInstallDir 'bin\mysql.exe')
    )
    $paths += @(Get-ChildItem 'C:\Program Files\MariaDB*','C:\Program Files\MySQL*' `
        -Filter mariadb.exe -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName)
    $paths += @(Get-ChildItem 'C:\Program Files\MariaDB*','C:\Program Files\MySQL*' `
        -Filter mysql.exe -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName)
    $client = $paths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $client) { throw 'MariaDB client (mariadb.exe or mysql.exe) was not found.' }
    $client
}

function ConvertTo-SqlLiteral {
    param([Parameter(Mandatory)][string]$Value)
    $Value.Replace('\', '\\').Replace("'", "''")
}

function New-TemporaryClientConfig {
    param([Parameter(Mandatory)][string]$Password)

    $path = Join-Path $PSScriptRoot ('.mp10-root-{0}.ini' -f [guid]::NewGuid())
    $content = "[client]`nuser=root`npassword=$Password`nport=$port`nhost=127.0.0.1"
    Set-Content -Path $path -Value $content -Encoding ASCII
    $path
}

function Remove-TemporaryClientConfig {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return }
    try {
        $length = (Get-Item $Path).Length
        $stream = [IO.File]::Open($Path, 'Open', 'Write', 'None')
        try {
            $zeros = New-Object byte[] ([Math]::Max(1, [int]$length))
            $stream.Write($zeros, 0, $zeros.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
    }
    catch { Write-KscLog "Could not overwrite temporary credential file: $($_.Exception.Message)" 'WARN' }
    Remove-Item $Path -Force -ErrorAction SilentlyContinue
}

function Invoke-MariaDbSql {
    param(
        [Parameter(Mandatory)][string]$Client,
        [Parameter(Mandatory)][string]$Config,
        [Parameter(Mandatory)][string]$Sql
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @($Sql | & $Client "--defaults-file=$Config" --batch --skip-column-names 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $outputText = @($output | ForEach-Object { $_.ToString() })
    if ($exitCode -ne 0) { throw "MariaDB command failed (exit code $exitCode): $($outputText -join ' ')" }
    $outputText
}

function Update-ManagedRemoteBlock {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][int]$Port
    )

    $content = if (Test-Path $Path) { Get-Content -Path $Path -Raw } else { '' }
    $block = @(
        '[mysqld]'
        $managedBegin
        "bind_address=$Address"
        "port=$Port"
        $managedEnd
    ) -join "`r`n"
    $pattern = "(?ms)^\[mysqld\]\s*$([regex]::Escape($managedBegin)).*?$([regex]::Escape($managedEnd))\s*"
    if ($content -match $pattern) {
        $content = [regex]::Replace($content, $pattern, "$block`r`n")
    }
    else {
        if ($content -and -not $content.EndsWith("`r`n")) { $content += "`r`n" }
        $content += "`r`n$block`r`n"
    }
    $backup = "$Path.bak-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')
    Copy-Item -Path $Path -Destination $backup -Force
    Set-Content -Path $Path -Value $content -Encoding UTF8
    Write-KscLog "MariaDB option file updated: $Path (backup: $backup)" 'OK'
}

$service = Get-MariaDbService -Name $ServiceName
$defaultsFile = Get-DefaultsFileFromPathName -PathName $service.PathName
$selectedIni = if ($IniPath) { $IniPath } elseif ($defaultsFile) { $defaultsFile } else {
    Join-Path $KSC.MariaDbDataDir 'my.ini'
}
$client = Get-MariaDbClient

if ($WhatIfPreference) {
    Write-KscLog "WhatIf: create or verify MariaDB account '$account' for collector $collector." 'OK'
    Write-KscLog "WhatIf: grant SELECT on mysql.*, SHOW DATABASES and SHOW VIEW to '$account'." 'OK'
    if ($ConfigureRemoteAccess) {
        Write-KscLog "WhatIf: add bind_address=$bindAddress and port=$port to $selectedIni and restart $($service.Name)." 'OK'
    }
    if (-not $SkipFirewall) {
        Write-KscLog "WhatIf: allow TCP/$port only from $collector (firewall group '$firewallGroup')." 'OK'
    }
    return
}

$tmpCnf = $null
try {
    $rootPassword = Read-Host 'MariaDB root password (used only for account setup)' -AsSecureString
    $rootPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rootPassword))
    $tmpCnf = New-TemporaryClientConfig -Password $rootPlain
    [Array]::Clear($rootPlain.ToCharArray(), 0, $rootPlain.Length)

    $userSql = ConvertTo-SqlLiteral $account
    $hostSql = ConvertTo-SqlLiteral $collector
    $exists = Invoke-MariaDbSql -Client $client -Config $tmpCnf `
        -Sql "SELECT COUNT(*) FROM mysql.user WHERE User='$userSql' AND Host='$hostSql';"
    if ([int]$exists[0] -eq 0) {
        $dbPassword = Read-Host "Password for new MariaDB account $account (store it in the MP 10 vault)" -AsSecureString
        $dbPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbPassword))
        if ([string]::IsNullOrEmpty($dbPlain)) {
            throw "The password for new MariaDB account '$account' cannot be empty."
        }
        $dbSql = ConvertTo-SqlLiteral $dbPlain
        $createSql = @"
CREATE USER '$userSql'@'$hostSql' IDENTIFIED BY '$dbSql';
GRANT SELECT ON mysql.* TO '$userSql'@'$hostSql';
GRANT SHOW DATABASES ON *.* TO '$userSql'@'$hostSql';
GRANT SHOW VIEW ON *.* TO '$userSql'@'$hostSql';
FLUSH PRIVILEGES;
"@
        Invoke-MariaDbSql -Client $client -Config $tmpCnf -Sql $createSql | Out-Null
        Write-KscLog "MariaDB account '$account'@'$collector' created with read-only audit privileges." 'OK'
    }
    else {
        $grantSql = @"
GRANT SELECT ON mysql.* TO '$userSql'@'$hostSql';
GRANT SHOW DATABASES ON *.* TO '$userSql'@'$hostSql';
GRANT SHOW VIEW ON *.* TO '$userSql'@'$hostSql';
FLUSH PRIVILEGES;
"@
        Invoke-MariaDbSql -Client $client -Config $tmpCnf -Sql $grantSql | Out-Null
        Write-KscLog "MariaDB account '$account'@'$collector' already exists; password was not changed." 'WARN'
    }

    if ($ConfigureRemoteAccess) {
        if (-not (Test-Path $selectedIni)) { throw "MariaDB option file was not found: $selectedIni" }
        Update-ManagedRemoteBlock -Path $selectedIni -Address $bindAddress -Port $port
        if (-not $NoRestart) {
            Restart-Service -Name $service.Name -Force
            (Get-Service -Name $service.Name).WaitForStatus('Running', '00:03:00')
            Write-KscLog "MariaDB service '$($service.Name)' restarted." 'OK'
        }
        else {
            Write-KscLog 'MariaDB restart skipped; restart the service before testing remote access.' 'WARN'
        }
    }

    if (-not $SkipFirewall) {
        Get-NetFirewallRule -Group $firewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "KSC Audit: MariaDB TCP $port (MP 10 Collector)" `
            -Group $firewallGroup -Direction Inbound -Action Allow -Protocol TCP `
            -LocalPort $port -RemoteAddress $collector -Profile Any `
            -Description 'MariaDB access for the MaxPatrol VM MySQL Audit profile' | Out-Null
        Write-KscLog "TCP/$port allowed only from collector $collector." 'OK'
    }

    Write-Host ''
    Write-Host '============ MAXPATROL VM MARIADB PARAMETERS ============' -ForegroundColor Cyan
    Write-Host "  MariaDB host:       $($KSC.AuditDbHost)" -ForegroundColor Gray
    Write-Host "  MariaDB account:    $account@$collector" -ForegroundColor Gray
    Write-Host "  Database port:      $port" -ForegroundColor Gray
    Write-Host '  Privileges:         SELECT mysql.*, SHOW DATABASES, SHOW VIEW' -ForegroundColor Gray
    Write-Host '==========================================================' -ForegroundColor Cyan
}
finally {
    Remove-TemporaryClientConfig -Path $tmpCnf
}
