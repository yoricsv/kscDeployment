<#
    Единая точка конфигурации развёртывания Kaspersky Security Center.
    Все скрипты репозитория подключают этот файл:  . "$PSScriptRoot\..\..\common\config.ps1"

    ВНИМАНИЕ: перед первым запуском проверьте и при необходимости измените значения
    в секции "Параметры площадки". Пароли здесь НЕ хранятся — они запрашиваются
    интерактивно или читаются из защищённого хранилища (см. common/Get-KscSecret.ps1).
#>

# ------------------------- Параметры площадки -------------------------

$Global:KSC = [ordered]@{

    # --- Домен и сеть ---
    DomainFqdn        = 'domain.local'          # FQDN домена AD  (ЗАМЕНИТЬ)
    DomainNetBios     = 'DOM'                   # NetBIOS-имя домена (ЗАМЕНИТЬ)
    Subnet            = '10.20.30.0/24'         # Единственный сегмент АС
    SubnetMaskLength  = 24
    Gateway           = '10.20.30.1'            # Шлюз (ЗАМЕНИТЬ при отличии)

    DomainController  = '10.20.30.10'           # Контроллер домена / DNS
    HypervisorHost    = '10.20.30.11'           # Хост виртуализации
    RdsHost           = '10.20.30.15'           # АРМ администратора (единственная точка управления)

    # --- Сервер администрирования KSC ---
    KscHostName       = 'ksc'                   # Имя ОС (NetBIOS)
    KscVmName         = 'ksc-soc'               # Имя ВМ в гипервизоре
    KscIp             = '10.20.30.20'           # Статический адрес (ЗАМЕНИТЬ при отличии)

    # --- Порты ---
    PortAgentSsl      = 13000                   # Агент -> Сервер (TCP/UDP)
    PortAgentNoSsl    = 14000                   # Агент -> Сервер без SSL
    PortServerToAgent = 15000                   # Сервер -> Агент (UDP)
    PortMmc           = 13291                   # Консоль MMC
    PortOpenApi       = 13299                   # OpenAPI / Web Console -> Сервер
    PortWebConsole    = 8080                    # Web Console (HTTPS)
    PortWebSrvHttp    = 8060                    # Веб-сервер KSC (автономные пакеты)
    PortWebSrvHttps   = 8061
    PortMariaDb       = 3306

    # --- Диски и каталоги ---
    DiskSystem        = 'C:'                    # ОС + KSC
    DiskDatabase      = 'D:'                    # Данные MariaDB
    DiskData          = 'E:'                    # KLSHARE, обновления, резервные копии

    MariaDbDataDir    = 'D:\MariaDB\data'
    KlShareDir        = 'E:\KLSHARE'
    BackupDir         = 'E:\KSC-Backup'
    UpdatesDir        = 'E:\KSC-Updates'
    LogDir            = 'C:\ProgramData\KscDeployment\logs'

    # --- СУБД ---
    MariaDbVersion    = '10.11'                 # LTS-ветка (сверять с матрицей совместимости KSC)
    MariaDbInstallDir = 'C:\Program Files\MariaDB 10.11'
    DbName            = 'ksc'
    DbUser            = 'kscadmin'
    DbHost            = 'localhost'
    InnoDbBufferPool  = '6G'                    # ~40% от 16 ГБ ОЗУ
    InnoDbLogFileSize = '1G'

    # --- Учётные записи ---
    SvcAccount        = 'svc_ksc'               # Служба Сервера администрирования
    DeployAccount     = 'svc_ksc_deploy'        # Удалённая установка агентов
    AdminsGroup       = 'KSC-Admins'            # Роль "Главный администратор"
    OperatorsGroup    = 'KSC-Operators'         # Роль "Оператор" (смежные СЗИ, мониторинг)
    AuditorsGroup     = 'KSC-Auditors'          # Роль "Аудитор" (только чтение)

    # --- Ёмкость и хранение ---
    PlannedHosts      = 1000                    # Проектный запас (фактически <= 254)
    ActualHostsMax    = 254                     # Ёмкость сегмента /24
    RetentionDays     = 365                     # Срок хранения событий и отчётов: 1 год
    EventsLimit       = 20000000                # Лимит записей в хранилище событий
    BackupKeepCopies  = 30                      # Глубина ротации резервных копий (дней)

    # --- Смежные СЗИ (доступ к хосту KSC для управления/мониторинга) ---
    # Перечислите IP-адреса серверов смежных средств защиты информации.
    SecurityToolsHosts = @(
        # '10.20.30.16',   # SIEM / коллектор событий
        # '10.20.30.17'    # Система мониторинга
    )

    # --- Экспорт событий в SIEM ---
    SiemHost          = ''                      # IP коллектора (пусто = экспорт выключен)
    SiemPort          = 514
    SiemProtocol      = 'TCP'                   # TCP | UDP
    SiemFormat        = 'CEF'                   # CEF | LEEF
}

# ------------------------- Служебные функции -------------------------

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
        throw 'Скрипт должен выполняться с правами администратора.'
    }
}

function Get-KscManagementHosts {
    <# Список адресов, которым разрешено управление хостом KSC. #>
    @($Global:KSC.RdsHost) + @($Global:KSC.SecurityToolsHosts) | Where-Object { $_ }
}

function Test-KscPort {
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][int]$Port)
    (Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningAction SilentlyContinue).TcpTestSucceeded
}
