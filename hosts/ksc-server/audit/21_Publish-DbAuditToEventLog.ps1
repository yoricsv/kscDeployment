<#
.SYNOPSIS
    Перенос записей файла аудита MariaDB в журнал событий Windows.

.DESCRIPTION
    Рабочий сценарий конвертера: читает новые строки файла server_audit.log,
    разбирает их на поля и записывает в журнал Windows, откуда события
    забирает MP 10 Collector.

    Устанавливается и регистрируется в планировщике скриптом
    20_Install-AuditForwarder.ps1; самостоятельный запуск нужен только
    для диагностики.

    Особенности:
      * позиция чтения хранится в файле состояния, повторная отправка
        записей исключена;
      * ротация файла плагином отслеживается по уменьшению размера: остаток
        дочитывается из server_audit.log.1, после чего чтение продолжается
        с начала нового файла;
      * параллельный запуск блокируется мьютексом;
      * через AuditHeartbeatMin в журнал пишется служебная запись (код 1100),
        по которой в SIEM контролируется работоспособность источника.

    Формат записи плагина:
        timestamp,serverhost,username,host,connectionid,queryid,operation,database,object,retcode

.PARAMETER StateFile
    Файл состояния (позиция чтения). По умолчанию
    C:\ProgramData\KscDeployment\audit-forwarder-state.json.

.PARAMETER MaxBytesPerRun
    Предел объёма файла аудита, обрабатываемого за один запуск (защита от лавины).
    Остаток читается следующим запуском. По умолчанию 64 МБ.

.EXAMPLE
    .\21_Publish-DbAuditToEventLog.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$StateFile = 'C:\ProgramData\KscDeployment\audit-forwarder-state.json',
    [int]$MaxBytesPerRun = 64MB
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\..\common\config.ps1"

$auditFile = Join-Path $KSC.AuditLogDir $KSC.AuditFileName
$logName = $KSC.AuditWinLogName
$source = $KSC.AuditWinLogSource

# Предельный размер сообщения события Windows — 31 839 символов.
$messageLimit = 30000

# Коды событий: сессии 1001-1003, команды 1010-1013, объекты 1020,
# служебные 1100 (контроль работоспособности) и 1101 (ошибка конвертера).
$eventIds = @{
    CONNECT             = 1001
    DISCONNECT          = 1002
    FAILED_CONNECT      = 1003
    QUERY               = 1010
    QUERY_DDL           = 1011
    QUERY_DML           = 1012
    QUERY_DML_NO_SELECT = 1012
    QUERY_DCL           = 1013
    TABLE               = 1020
    READ                = 1020
    WRITE               = 1020
    CREATE              = 1011
    ALTER               = 1011
    DROP                = 1011
    RENAME              = 1011
}

$recordPattern = [regex]'^(?<ts>\d{8}\s\d{2}:\d{2}:\d{2}),(?<srvhost>[^,]*),(?<user>[^,]*),(?<host>[^,]*),(?<connid>\d*),(?<queryid>\d*),(?<op>[A-Z_]+),(?<db>[^,]*),(?<obj>.*),(?<ret>-?\d+)\s*$'

# ------------------------------------------------------------------ Состояние

function Read-ForwarderState {
    if (Test-Path $StateFile) {
        try { return Get-Content $StateFile -Raw | ConvertFrom-Json }
        catch { Write-Verbose "Файл состояния повреждён, чтение начнётся с конца файла аудита." }
    }
    $size = if (Test-Path $auditFile) { (Get-Item $auditFile).Length } else { 0 }
    [pscustomobject]@{ Position = $size; LastHeartbeat = '1970-01-01T00:00:00'; Forwarded = 0 }
}

function Save-ForwarderState {
    param($State)
    $dir = Split-Path $StateFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $State | ConvertTo-Json -Depth 3 | Set-Content $StateFile -Encoding UTF8
}

# ------------------------------------------------------------------ Разбор и запись

function ConvertTo-AuditEvent {
    <# Строка файла аудита -> объект с полями события ИБ (Приказ ОАЦ № 130, п. 2). #>
    param([string]$Line)

    $m = $recordPattern.Match($Line)
    if (-not $m.Success) { return $null }

    $ts = $m.Groups['ts'].Value
    $parsed = [datetime]::MinValue
    [void][datetime]::TryParseExact($ts, 'yyyyMMdd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$parsed)

    $op = $m.Groups['op'].Value
    $ret = [int]$m.Groups['ret'].Value
    $srcHost = $m.Groups['host'].Value

    $id = if ($eventIds.ContainsKey($op)) { $eventIds[$op] } else { 1099 }
    if ($op -eq 'CONNECT' -and $ret -ne 0) { $id = $eventIds['FAILED_CONNECT'] }

    # Плагин помечает все команды как QUERY: класс определяется по тексту,
    # иначе изменение полномочий и операции со схемой неотличимы от выборок.
    if ($id -eq $eventIds['QUERY']) {
        $sql = $m.Groups['obj'].Value.TrimStart("'", ' ', "`t")
        switch -Regex ($sql) {
            '^(?i)(GRANT|REVOKE|CREATE\s+USER|DROP\s+USER|ALTER\s+USER|RENAME\s+USER|SET\s+PASSWORD|CREATE\s+ROLE|DROP\s+ROLE)' { $id = $eventIds['QUERY_DCL']; break }
            '^(?i)(CREATE|ALTER|DROP|TRUNCATE|RENAME)\b' { $id = $eventIds['QUERY_DDL']; break }
            '^(?i)(INSERT|UPDATE|DELETE|REPLACE|LOAD\s+DATA|CALL|LOCK|UNLOCK)\b' { $id = $eventIds['QUERY_DML']; break }
        }
    }

    $type = if ($id -eq 1003 -or $ret -ne 0) { 'Warning' } else { 'Information' }

    $message = @(
        "Аудит СУБД MariaDB: $op"
        "event_time=$(if ($parsed -ne [datetime]::MinValue) { $parsed.ToString('yyyy-MM-dd HH:mm:ss') } else { $ts })"
        "db_user=$($m.Groups['user'].Value)"
        "src_host=$srcHost"
        "server_host=$($m.Groups['srvhost'].Value)"
        "db_host=$($KSC.AuditDbHost)"
        "database=$($m.Groups['db'].Value)"
        "object=$($m.Groups['obj'].Value)"
        "operation=$op"
        "connection_id=$($m.Groups['connid'].Value)"
        "query_id=$($m.Groups['queryid'].Value)"
        "return_code=$ret"
        "raw=$Line"
    ) -join "`r`n"

    if ($message.Length -gt $messageLimit) { $message = $message.Substring(0, $messageLimit) + '...[обрезано]' }

    [pscustomobject]@{ EventId = $id; EntryType = $type; Message = $message }
}

function Write-AuditEvent {
    param([int]$EventId, [string]$EntryType, [string]$Message)
    Write-EventLog -LogName $logName -Source $source -EventId $EventId -EntryType $EntryType -Message $Message
}

function Read-AuditTail {
    <#
        Читает завершённые строки файла начиная с байтовой позиции $From.
        Возвращает строки и новую позицию — конец последнего перевода строки,
        поэтому недописанная плагином строка будет прочитана при следующем запуске.
    #>
    param([string]$Path, [long]$From)

    $empty = [pscustomobject]@{ Lines = @(); Position = $From }
    if (-not (Test-Path $Path)) { return $empty }

    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $start = if ($From -gt $fs.Length) { 0 } else { $From }
        $available = $fs.Length - $start
        if ($available -le 0) { return [pscustomobject]@{ Lines = @(); Position = $start } }

        # Ограничение объёма за один запуск: остаток будет прочитан следующим.
        $toRead = [int][Math]::Min($available, $MaxBytesPerRun)
        [void]$fs.Seek($start, 'Begin')
        $buffer = New-Object byte[] $toRead
        $read = $fs.Read($buffer, 0, $toRead)

        $lastLf = [Array]::LastIndexOf($buffer, [byte]10, $read - 1)
        if ($lastLf -lt 0) { return [pscustomobject]@{ Lines = @(); Position = $start } }

        $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $lastLf + 1)
        $lines = $text -split "`r?`n" | Where-Object { $_ -ne '' }
        [pscustomobject]@{ Lines = $lines; Position = $start + $lastLf + 1 }
    }
    finally { $fs.Dispose() }
}

# ------------------------------------------------------------------ Основной цикл

$mutex = New-Object Threading.Mutex($false, 'Global\KscDbAuditForwarder')
if (-not $mutex.WaitOne(0)) {
    Write-Verbose 'Предыдущий запуск ещё выполняется — выход.'
    return
}

try {
    if (-not [Diagnostics.EventLog]::SourceExists($source)) {
        throw "Источник событий '$source' не зарегистрирован. Выполните 20_Install-AuditForwarder.ps1."
    }

    $state = Read-ForwarderState
    $sent = 0
    $skipped = 0

    # Ротация: файл стал короче сохранённой позиции — остаток лежит в .1
    if ((Test-Path $auditFile) -and (Get-Item $auditFile).Length -lt $state.Position) {
        $rotated = "$auditFile.1"
        if (Test-Path $rotated) {
            $tail = Read-AuditTail -Path $rotated -From $state.Position
            foreach ($line in $tail.Lines) {
                $ev = ConvertTo-AuditEvent -Line $line
                if ($ev) { Write-AuditEvent -EventId $ev.EventId -EntryType $ev.EntryType -Message $ev.Message; $sent++ }
                elseif ($line) { $skipped++ }
            }
        }
        $state.Position = 0
    }

    $batch = Read-AuditTail -Path $auditFile -From $state.Position
    foreach ($line in $batch.Lines) {
        $ev = ConvertTo-AuditEvent -Line $line
        if ($ev) { Write-AuditEvent -EventId $ev.EventId -EntryType $ev.EntryType -Message $ev.Message; $sent++ }
        elseif ($line) { $skipped++ }
    }
    $state.Position = $batch.Position
    $state.Forwarded = [int]$state.Forwarded + $sent

    $lastHb = [datetime]::Parse($state.LastHeartbeat)
    if ((Get-Date) -gt $lastHb.AddMinutes($KSC.AuditHeartbeatMin)) {
        $hb = @(
            'Аудит СУБД MariaDB: контроль работоспособности источника'
            "db_host=$($KSC.AuditDbHost)"
            "audit_file=$auditFile"
            "position=$($state.Position)"
            "forwarded_total=$($state.Forwarded)"
            "forwarded_now=$sent"
            "unparsed_now=$skipped"
        ) -join "`r`n"
        Write-AuditEvent -EventId 1100 -EntryType 'Information' -Message $hb
        $state.LastHeartbeat = (Get-Date).ToString('s')
    }

    Save-ForwarderState -State $state
    Write-Verbose "Передано записей: $sent, не распознано строк: $skipped, позиция: $($state.Position)."
}
catch {
    if ([Diagnostics.EventLog]::SourceExists($source)) {
        Write-EventLog -LogName $logName -Source $source -EventId 1101 -EntryType 'Error' `
            -Message "Ошибка конвертера аудита СУБД: $($_.Exception.Message)"
    }
    throw
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
