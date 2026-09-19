<#
    Central configuration for the Kaspersky Security Center deployment.
    All repository scripts load this file:  . "$PSScriptRoot\..\..\common\config.ps1"

    WARNING: before the first run, review and update values in the "Site parameters"
    section when required. Passwords are NOT stored here; they are requested
    interactively or read from protected storage (see common/Get-KscSecret.ps1).
#>

# ------------------------- Site parameters -------------------------

$Global:KSC = [ordered]@{

    # --- Domain and network ---
    DomainFqdn        = 'domain.local'          # AD domain FQDN (REPLACE)
    DomainNetBios     = 'DOM'                   # Domain NetBIOS name (REPLACE)
    Subnet            = '10.20.30.0/24'         # Single administration segment
    SubnetMaskLength  = 24
    Gateway           = '10.20.30.1'            # Gateway (REPLACE if different)

    DomainController  = '10.20.30.10'           # Domain controller / DNS
    HypervisorHost    = '10.20.30.11'           # Virtualization host
    RdsHost           = '10.20.30.15'           # Administrator workstation (single management point)

    # --- KSC Administration Server ---
    KscHostName       = 'ksc'                   # OS name (NetBIOS)
    KscVmName         = 'ksc-soc'               # VM name in the hypervisor
    KscIp             = '10.20.30.20'           # Static address (REPLACE if different)

    # --- Ports ---
    PortAgentSsl      = 13000                   # Agent -> Server (TCP/UDP)
    PortAgentNoSsl    = 14000                   # Agent -> Server without SSL
    PortServerToAgent = 15000                   # Server -> Agent (UDP)
    PortMmc           = 13291                   # MMC console
    PortOpenApi       = 13299                   # OpenAPI / Web Console -> Server
    PortWebConsole    = 8080                    # Web Console (HTTPS)
    PortWebSrvHttp    = 8060                    # KSC web server (standalone packages)
    PortWebSrvHttps   = 8061
    PortMariaDb       = 3306

    # --- Disks and directories ---
    DiskSystem        = 'C:'                    # OS + KSC
    DiskDatabase      = 'D:'                    # MariaDB data
    DiskData          = 'E:'                    # KLSHARE, updates, backups

    MariaDbDataDir    = 'D:\MariaDB\data'
    KlShareDir        = 'E:\KLSHARE'
    BackupDir         = 'E:\KSC-Backup'
    UpdatesDir        = 'E:\KSC-Updates'
    LogDir            = 'C:\ProgramData\KscDeployment\logs'

    # --- Database ---
    MariaDbVersion    = '10.11'                 # LTS branch (check the KSC compatibility matrix)
    MariaDbInstallDir = 'C:\Program Files\MariaDB 10.11'
    DbName            = 'ksc'
    DbUser            = 'kscadmin'
    DbHost            = 'localhost'
    InnoDbBufferPool  = '6G'                    # ~40% of 16 GB RAM
    InnoDbLogFileSize = '1G'

    # --- Accounts ---
    SvcAccount        = 'svc_ksc'               # Administration Server service
    DeployAccount     = 'svc_ksc_deploy'        # Remote agent deployment
    AdminsGroup       = 'KSC-Admins'            # "Main administrator" role
    OperatorsGroup    = 'KSC-Operators'         # "Operator" role (security tools, monitoring)
    AuditorsGroup     = 'KSC-Auditors'          # "Auditor" role (read-only)

    # --- Capacity and retention ---
    PlannedHosts      = 1000                    # Planning capacity (actual maximum <= 254)
    ActualHostsMax    = 254                     # /24 segment capacity
    RetentionDays     = 365                     # Event and report retention: 1 year
    EventsLimit       = 20000000                # Event storage record limit
    BackupKeepCopies  = 30                      # Backup rotation depth (days)

    # --- Security tools (access to the KSC host for management/monitoring) ---
    # List the IP addresses of connected security tool servers.
    SecurityToolsHosts = @(
        # '10.20.30.16',   # SIEM / event collector
        # '10.20.30.17'    # Monitoring system
    )

    # --- SIEM event export ---
    SiemHost          = ''                      # Collector IP (empty = export disabled)
    SiemPort          = 514
    SiemProtocol      = 'TCP'                   # TCP | UDP
    SiemFormat        = 'CEF'                   # CEF | LEEF

    # --- OS and application audit (OAC Order No. 130 + investigation extensions) ---
    # The order defines the minimum; coverage is extended with events needed
    # to reconstruct an incident (processes, PowerShell, file access).
    KscInstallDir         = 'C:\Program Files (x86)\Kaspersky Lab\Kaspersky Security Center'
    AuditTranscriptDir    = 'C:\ProgramData\KscDeployment\pstranscripts'  # PowerShell transcripts
    AuditSecurityLogSizeMb = 1024               # Security log: local buffer
    AuditChannelSizeMb    = 256                 # Other channels (PowerShell, Kaspersky Event Log)

    # --- Database audit (OAC Order No. 130, event list item 2) ---
    # Pipeline: server_audit plugin -> file -> converter service -> Windows event log
    # -> remote reading by the MP 10 Collector. On Windows, the plugin can write
    # only to a file (MDEV-19851: SYSLOG is not supported on this platform).
    AuditDbHost         = '10.20.30.75'         # Database host (MP 10 event source)
    AuditCollectorHost  = '10.20.30.73'         # MP 10 Collector: allowed collection source
    AuditAccount        = 'kscaudit'            # Local Windows account for collector log access
    AuditLogDir         = 'D:\MariaDB\audit'    # Audit file directory (outside the data directory)
    AuditFileName       = 'server_audit.log'
    AuditRotateSizeMb   = 100                   # File size before rotation
    AuditRotations      = 20                    # Rotation depth (local buffer ~2 GB)
    AuditQueryLogLimit  = 2048                  # Maximum query text length in a record

    # Audited event classes:
    #   CONNECT - session monitoring, including failed attempts; logged for all accounts.
    #   QUERY   - all statements (select/insert/update/delete/call/lock and others).
    #   TABLE   - objects affected by the statement.
    AuditEvents         = 'CONNECT,QUERY,TABLE'

    # Accounts excluded from QUERY/TABLE logging (CONNECT is always logged).
    # The Administration Server service account generates a continuous stream
    # of technical queries; full logging can produce hundreds of GB per day
    # and overload the SIEM delivery pipeline. Empty value = strict mode:
    # actions of every account are logged without exception.
    AuditExclUsers      = 'kscadmin'

    # Windows event log receiving the audit records
    AuditWinLogName     = 'MariaDB-Audit'
    AuditWinLogSource   = 'MariaDB-ServerAudit'
    AuditWinLogSizeMb   = 1024                  # Local log buffer (overwrite when full)
    AuditForwardPeriodMin = 1                   # Converter start interval, minutes
    AuditHeartbeatMin   = 15                    # Heartbeat interval, minutes
}

# ------------------------- Helper functions -------------------------

function Write-KscLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO'
    )
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$stamp] [$Level] $Message"
    $color = switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } 'OK' { 'Green' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color

    if (-not (Test-Path $Global:KSC.LogDir)) {
        New-Item -ItemType Directory -Path $Global:KSC.LogDir -Force | Out-Null
    }
    $logFile = Join-Path $Global:KSC.LogDir ('deploy-{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
    Add-Content -Path $logFile -Value $line -Encoding UTF8
}

function Assert-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The script must be run with administrator privileges.'
    }
}

function Get-KscManagementHosts {
    <# List of addresses allowed to manage the KSC host. #>
    @($Global:KSC.RdsHost) + @($Global:KSC.SecurityToolsHosts) | Where-Object { $_ }
}

function Test-KscPort {
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][int]$Port)
    (Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningAction SilentlyContinue).TcpTestSucceeded
}
