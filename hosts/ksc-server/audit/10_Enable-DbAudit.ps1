<#
.SYNOPSIS
    Enables MariaDB auditing (server_audit plugin) per Order No. 130 of the OAC.

.DESCRIPTION
    Runs on the database host (by default $KSC.AuditDbHost) and:

      1. Verifies that the server_audit.dll plugin library is present in the
         plugin directory.
      2. Creates the audit file directory and applies restrictive permissions
         (SYSTEM, administrators, the database service account, auditors group).
      3. Inserts the parameter block from 11_server_audit.ini.template into
         my.ini between the KSC-AUDIT BEGIN / KSC-AUDIT END markers (idempotent).
      4. Restarts the database service and verifies the effective server_audit_*
         variables and the presence of records in the audit file.

    The set of logged events is defined in common/config.ps1
    ($KSC.AuditEvents, $KSC.AuditExclUsers).

    Verification (step 4) requires the database root password; with -SkipVerify
    only the configuration is applied and the manual verification commands are
    printed.

    Existing KSC data is not touched: the script does not modify schemas,
    tables or rows; the only database queries are read-only
    (SHOW GLOBAL VARIABLES and SELECT 1).

.PARAMETER IniPath
    Path to my.ini. Detected automatically by default: <DataDir>\my.ini,
    then <InstallDir>\data\my.ini.

.PARAMETER ServiceName
    Database service name. Detected automatically by default (MariaDB, MySQL).

.PARAMETER SkipVerify
    Do not connect to the database to verify the applied settings.

.PARAMETER NoRestart
    Do not restart the service: the settings take effect at the next start.

.PARAMETER Rollback
    Remove the audit parameter block from my.ini (the plugin stops loading
    after the service restart). Audit files are not deleted.

.PARAMETER WhatIf
    Show the changes without creating directories, changing ACLs, editing my.ini
    or restarting MariaDB.

.EXAMPLE
    .\10_Enable-DbAudit.ps1
    .\10_Enable-DbAudit.ps1 -IniPath 'C:\Program Files\MariaDB 10.5\data\my.ini'
    .\10_Enable-DbAudit.ps1 -Rollback
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$IniPath,
    [string]$ServiceName,
    [switch]$SkipVerify,
    [switch]$NoRestart,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"
Assert-Elevated

# ASCII-only markers: my.ini is stored in a single-byte encoding, and
# non-ASCII characters in a marker would break the repeated block lookup.
$markerBegin = '# >>> KSC-AUDIT BEGIN (managed by 10_Enable-DbAudit.ps1, do not edit manually)'
$markerEnd = '# <<< KSC-AUDIT END'

# ------------------------------------------------------------------ Service and paths

if (-not $ServiceName) {
    $svc = Get-Service | Where-Object { $_.Name -in @('MariaDB', 'MySQL') -or $_.DisplayName -match 'MariaDB' } | Select-Object -First 1
    if (-not $svc) { throw 'Database service not found. Specify it with -ServiceName.' }
    $ServiceName = $svc.Name
}
Write-KscLog "Database service: $ServiceName"

$svcCim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
$svcAccount = $svcCim.StartName
# Path to mysqld in the service command line: "C:\...\bin\mysqld.exe" --defaults-file=...
$binPath = ([regex]'"?(?<p>[^"]+mysqld\.exe)"?').Match($svcCim.PathName).Groups['p'].Value
$installDir = if ($binPath) { Split-Path (Split-Path $binPath -Parent) -Parent } else { $KSC.MariaDbInstallDir }
$defaultsFile = ([regex]'--defaults-file="?(?<f>[^"]+\.ini)"?').Match($svcCim.PathName).Groups['f'].Value

Write-KscLog "Installation directory: $installDir"
Write-KscLog "Service account: $svcAccount"

if (-not $IniPath) {
    $IniPath = @($defaultsFile, (Join-Path $KSC.MariaDbDataDir 'my.ini'), (Join-Path $installDir 'data\my.ini')) |
        Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $IniPath -or -not (Test-Path $IniPath)) {
    throw 'my.ini not found. Specify the path with -IniPath.'
}
Write-KscLog "Configuration file: $IniPath"
if ($defaultsFile -and ((Resolve-Path $IniPath).Path -ne (Resolve-Path $defaultsFile).Path)) {
    Write-KscLog "Warning: the service command line points to '$defaultsFile', but this script edits '$IniPath'." 'WARN'
}

# ------------------------------------------------------------------ Rollback

if ($Rollback) {
    $text = Get-Content $IniPath -Raw
    if ($text -notmatch [regex]::Escape($markerBegin)) {
        Write-KscLog 'The audit parameter block is absent from my.ini - rollback is not required.' 'WARN'
        return
    }
    $pattern = '(?s)\r?\n?' + [regex]::Escape($markerBegin) + '.*?' + [regex]::Escape($markerEnd) + '\r?\n?'
    if ($PSCmdlet.ShouldProcess($IniPath, 'Remove the MariaDB audit parameter block')) {
        Copy-Item $IniPath "$IniPath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
        Set-Content -Path $IniPath -Value ([regex]::Replace($text, $pattern, "`r`n")) -Encoding ASCII
    }
    Write-KscLog 'Audit parameter block removed from my.ini. Restart the service to apply.' 'OK'
    return
}

# ------------------------------------------------------------------ 1. Plugin

$pluginDll = Join-Path $installDir 'lib\plugin\server_audit.dll'
if (-not (Test-Path $pluginDll)) {
    throw "Plugin library not found: $pluginDll. Check the MariaDB installation."
}
Write-KscLog "Plugin library found: $pluginDll" 'OK'

# ------------------------------------------------------------------ 2. Audit directory and permissions

$auditDir = $KSC.AuditLogDir
$auditFile = Join-Path $auditDir $KSC.AuditFileName
if ($PSCmdlet.ShouldProcess($auditDir, 'Create the audit directory and restrict its permissions')) {
    if (-not (Test-Path $auditDir)) {
        New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
        Write-KscLog "Audit directory created: $auditDir" 'OK'
    }

    # Audit file access: write - the database service and SYSTEM only, read - auditors.
    $acl = Get-Acl $auditDir
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

    function Add-AuditDirRule {
        param([string]$Identity, [string]$Rights)
        try {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $Identity, $Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
            Write-KscLog "  audit directory permission: $Identity -> $Rights"
        }
        catch {
            Write-KscLog "  failed to grant permissions to '$Identity': $($_.Exception.Message)" 'WARN'
        }
    }

    Add-AuditDirRule -Identity 'NT AUTHORITY\SYSTEM' -Rights 'FullControl'
    Add-AuditDirRule -Identity 'BUILTIN\Administrators' -Rights 'FullControl'
    if ($svcAccount -and $svcAccount -notmatch '^(LocalSystem|NT AUTHORITY\\SYSTEM)$') {
        Add-AuditDirRule -Identity $svcAccount -Rights 'Modify'
    }
    $auditorsGroup = "$($KSC.DomainNetBios)\$($KSC.AuditorsGroup)"
    Add-AuditDirRule -Identity $auditorsGroup -Rights 'ReadAndExecute'
    Set-Acl -Path $auditDir -AclObject $acl
    Write-KscLog "Permissions on $auditDir restricted (inheritance disabled)." 'OK'
}

# ------------------------------------------------------------------ 3. Parameters in my.ini

$templatePath = Join-Path $PSScriptRoot '11_server_audit.ini.template'
$block = (Get-Content $templatePath -Encoding UTF8 |
    Where-Object { $_ -notmatch '^\s*//' }) -join "`r`n"
$block = $block.
    Replace('{{AUDIT_FILE}}', $auditFile).
    Replace('{{ROTATE_SIZE}}', ($KSC.AuditRotateSizeMb * 1MB)).
    Replace('{{ROTATIONS}}', $KSC.AuditRotations).
    Replace('{{EVENTS}}', $KSC.AuditEvents).
    Replace('{{EXCL_USERS}}', $KSC.AuditExclUsers).
    Replace('{{QUERY_LOG_LIMIT}}', $KSC.AuditQueryLogLimit)
$block = "$markerBegin`r`n$($block.Trim())`r`n$markerEnd"

$ini = Get-Content $IniPath -Raw
if ($ini -match [regex]::Escape($markerBegin)) {
    $pattern = '(?s)' + [regex]::Escape($markerBegin) + '.*?' + [regex]::Escape($markerEnd)
    # Doubling '$' keeps the replacement text from being read as a group reference.
    $newIni = [regex]::Replace($ini, $pattern, $block.Replace('$', '$$'))
    $changeDescription = 'Update the MariaDB audit parameter block'
}
else {
    $newIni = $ini.TrimEnd() + "`r`n`r`n" + $block + "`r`n"
    $changeDescription = 'Add the MariaDB audit parameter block'
}
if ($PSCmdlet.ShouldProcess($IniPath, $changeDescription)) {
    Copy-Item $IniPath "$IniPath.bak-$(Get-Date -Format yyyyMMddHHmmss)"
    Set-Content -Path $IniPath -Value $newIni -Encoding ASCII
    Write-KscLog "$changeDescription completed." 'OK'
}

if ($WhatIfPreference) {
    Write-KscLog 'WhatIf complete: no MariaDB settings, ACLs or service state were changed.' 'OK'
    return
}

# ------------------------------------------------------------------ 4. Restart and verification

if ($NoRestart) {
    Write-KscLog 'Service restart skipped (-NoRestart): settings will apply at the next start.' 'WARN'
    return
}

Write-KscLog 'Restarting the database service (KSC will be unavailable for the duration)...'
if ($PSCmdlet.ShouldProcess($ServiceName, 'Restart the MariaDB service')) {
    Restart-Service $ServiceName -Force
}
(Get-Service $ServiceName).WaitForStatus('Running', '00:03:00')
Write-KscLog 'Service started.' 'OK'

if ($SkipVerify) {
    Write-KscLog "Verification skipped. Run manually: SHOW GLOBAL VARIABLES LIKE 'server_audit%';" 'WARN'
    return
}

$mysqlExe = Join-Path $installDir 'bin\mysql.exe'
if (-not (Test-Path $mysqlExe)) { $mysqlExe = Join-Path $installDir 'bin\mariadb.exe' }
if (-not (Test-Path $mysqlExe)) {
    Write-KscLog 'Client mysql.exe not found - verification skipped.' 'WARN'
    return
}

$rootPwdSec = Read-Host 'Database root password (for settings verification)' -AsSecureString
$verifyBaseDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
$verifyTempDir = Join-Path $verifyBaseDir 'KscDeployment\db-verification'
if (-not (Test-Path $verifyTempDir)) {
    New-Item -ItemType Directory -Path $verifyTempDir -Force | Out-Null
}
$tmpCnf = Join-Path $verifyTempDir ('ksc-audit-{0}.ini' -f ([guid]::NewGuid()))
try {
    $rootPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rootPwdSec))
    Set-Content -Path $tmpCnf -Value "[client]`nuser=root`npassword=$rootPlain`nport=$($KSC.PortMariaDb)`nhost=127.0.0.1" -Encoding ASCII
    icacls.exe $tmpCnf /inheritance:r /grant:r "$($env:USERNAME):R" 'SYSTEM:R' | Out-Null

    $vars = & $mysqlExe "--defaults-file=$tmpCnf" -N -B -e "SHOW GLOBAL VARIABLES LIKE 'server_audit%'" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Database connection error: $vars" }
    $vars | Out-String | Write-Host

    $loggingLine = @($vars | Where-Object { $_ -match '^\s*server_audit_logging\s+' }) | Select-Object -First 1
    $logging = if ($loggingLine -match '\s(?<value>ON|OFF)\s*$') { $Matches['value'].ToUpperInvariant() } else { $null }
    $outputLine = @($vars | Where-Object { $_ -match '^\s*server_audit_output_type\s+' }) | Select-Object -First 1
    $outputType = if ($outputLine -match '\s(?<value>\S+)\s*$') { $Matches['value'].ToLowerInvariant() } else { $null }
    $rotateLine = @($vars | Where-Object { $_ -match '^\s*server_audit_file_rotate_size\s+' }) | Select-Object -First 1
    $rotateSize = if ($rotateLine -match '\s(?<value>\d+)\s*$') { [int64]$Matches['value'] } else { 0 }
    if ($logging -ne 'ON' -or $outputType -ne 'file' -or $rotateSize -le 0) {
        $effective = ($vars | Out-String).Trim()
        throw "MariaDB did not apply the audit settings from '$IniPath'. Effective server_audit values:`n$effective`nService command line: $($svcCim.PathName)"
    }

    # Read-only probe query that produces an audit record
    & $mysqlExe "--defaults-file=$tmpCnf" -e 'SELECT 1 FROM information_schema.tables LIMIT 1' | Out-Null
}
finally {
    if (Test-Path $tmpCnf) {
        Set-Content -Path $tmpCnf -Value ('0' * 4096) -Encoding ASCII -ErrorAction SilentlyContinue
        Remove-Item $tmpCnf -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable rootPlain -ErrorAction SilentlyContinue
}

if (Test-Path $auditFile) {
    $last = Get-Content $auditFile -Tail 3
    Write-KscLog "Last records of the audit file ($auditFile):" 'OK'
    $last | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
}
else {
    Write-KscLog "Audit file $auditFile has not been created yet - check the service permissions on the directory." 'WARN'
}

Write-KscLog '=== Database audit enabled. Next step: 20_Install-AuditForwarder.ps1 ===' 'OK'
