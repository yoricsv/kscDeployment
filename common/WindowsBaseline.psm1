<#
    WindowsBaseline.psm1 — общий модуль харденинга узлов Windows.

    Модуль содержит атомарные функции усиления защиты, применяемые
    скриптами hosts/*/hardening/Invoke-Hardening.ps1 с учётом роли узла.

    Принципы:
      * каждая функция идемпотентна и пишет журнал через Write-KscLog;
      * каждая функция поддерживает -WhatIf (SupportsShouldProcess);
      * перед изменением реестра сохраняется прежнее значение в файл отката
        C:\ProgramData\KscDeployment\rollback\<дата>.json;
      * функции не выключают то, что требуется для работы KSC
        (порты Агента, общая папка KLSHARE, RPC для удалённой установки).

    Подключение:
        Import-Module "$PSScriptRoot\..\..\common\WindowsBaseline.psm1" -Force
#>

Set-StrictMode -Version Latest

$script:RollbackDir = 'C:\ProgramData\KscDeployment\rollback'
$script:SecPolBackup = $null
$script:RollbackFile = Join-Path $script:RollbackDir ("rollback-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$script:RollbackData = [System.Collections.Generic.List[object]]::new()

function Save-RollbackEntry {
    param([string]$Path, [string]$Name, $OldValue, $NewValue)
    $script:RollbackData.Add([pscustomobject]@{
        Path = $Path; Name = $Name; OldValue = $OldValue; NewValue = $NewValue
        Timestamp = (Get-Date).ToString('s')
    })
    if (-not (Test-Path $script:RollbackDir)) { New-Item -ItemType Directory -Path $script:RollbackDir -Force | Out-Null }
    $script:RollbackData | ConvertTo-Json -Depth 4 | Set-Content $script:RollbackFile -Encoding UTF8
}

function Set-RegValue {
    <# Безопасная установка значения реестра с сохранением прежнего состояния. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String', 'MultiString', 'QWord', 'ExpandString')][string]$Type = 'DWord',
        [string]$Comment = ''
    )
    if (-not (Test-Path $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Создать раздел реестра')) { New-Item -Path $Path -Force | Out-Null }
    }
    $old = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($old -eq $Value) {
        Write-KscLog "  = $Name уже равно $Value $Comment"
        return
    }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Установить $Value")) {
        Save-RollbackEntry -Path $Path -Name $Name -OldValue $old -NewValue $Value
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-KscLog "  + $Name = $Value (было: $(if ($null -eq $old) { 'не задано' } else { $old })) $Comment" 'OK'
    }
}

# ============================================================================
#  Протоколы и устаревшие компоненты
# ============================================================================

function Disable-LegacyProtocols {
    <# Отключение SMBv1, LLMNR, NetBIOS over TCP/IP, WPAD, mDNS. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$KeepNetBios)

    Write-KscLog '--- Устаревшие сетевые протоколы ---'

    # SMBv1 — снят с поддержки, используется семейством вымогателей
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq 'Enabled') {
        if ($PSCmdlet.ShouldProcess('SMB1Protocol', 'Отключить компонент')) {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-KscLog '  + SMBv1 отключён (требуется перезагрузка)' 'OK'
        }
    } else { Write-KscLog '  = SMBv1 уже отключён' }

    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -Comment '(сервер SMBv1)'
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Comment '(обязательная подпись SMB)'
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1

    # LLMNR — источник перехвата хешей (responder-атаки)
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Comment '(LLMNR отключён)'

    # WPAD — автоматическое обнаружение прокси
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride' -Value 1

    if (-not $KeepNetBios) {
        $nics = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
        foreach ($n in $nics) {
            # 2 = отключить NetBIOS over TCP/IP
            Set-RegValue -Path $n.PSPath -Name 'NetbiosOptions' -Value 2 -Comment '(NetBIOS over TCP/IP)'
        }
    }
}

function Set-TlsHardening {
    <# Отключение SSL 2.0/3.0, TLS 1.0/1.1 и слабых шифров; включение TLS 1.2/1.3. #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-KscLog '--- Криптографические протоколы ---'
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

    $disable = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
    foreach ($proto in $disable) {
        foreach ($role in @('Server', 'Client')) {
            Set-RegValue -Path "$base\$proto\$role" -Name 'Enabled' -Value 0 -Comment "($proto/$role)"
            Set-RegValue -Path "$base\$proto\$role" -Name 'DisabledByDefault' -Value 1
        }
    }
    foreach ($proto in @('TLS 1.2')) {
        foreach ($role in @('Server', 'Client')) {
            Set-RegValue -Path "$base\$proto\$role" -Name 'Enabled' -Value 1 -Comment "($proto/$role)"
            Set-RegValue -Path "$base\$proto\$role" -Name 'DisabledByDefault' -Value 0
        }
    }

    # Слабые алгоритмы
    $ciphers = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
    foreach ($c in @('RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'DES 56/56', 'NULL')) {
        Set-RegValue -Path "$ciphers\$c" -Name 'Enabled' -Value 0 -Comment "(шифр $c)"
    }
    foreach ($h in @('MD5')) {
        Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$h" -Name 'Enabled' -Value 0
    }

    # .NET — использовать системные протоколы (иначе консоли и утилиты падают на TLS 1.2)
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
        Set-RegValue -Path $k -Name 'SchUseStrongCrypto' -Value 1
        Set-RegValue -Path $k -Name 'SystemDefaultTlsVersions' -Value 1
    }
    Write-KscLog '  ! Изменения SCHANNEL применяются после перезагрузки.' 'WARN'
}

function Set-AuthenticationHardening {
    <# NTLM, LSA, кеширование учётных данных, анонимный доступ. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$CachedLogons = 2)

    Write-KscLog '--- Аутентификация и LSA ---'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    # Только NTLMv2, отказ от LM и NTLMv1
    Set-RegValue -Path $lsa -Name 'LmCompatibilityLevel' -Value 5 -Comment '(только NTLMv2)'
    Set-RegValue -Path $lsa -Name 'NoLMHash' -Value 1 -Comment '(не хранить LM-хеш)'
    Set-RegValue -Path $lsa -Name 'RestrictAnonymous' -Value 1 -Comment '(анонимное перечисление запрещено)'
    Set-RegValue -Path $lsa -Name 'RestrictAnonymousSAM' -Value 1
    Set-RegValue -Path $lsa -Name 'EveryoneIncludesAnonymous' -Value 0
    Set-RegValue -Path $lsa -Name 'RunAsPPL' -Value 1 -Comment '(защита LSA от выгрузки памяти)'
    Set-RegValue -Path $lsa -Name 'DisableDomainCreds' -Value 1 -Comment '(не хранить учётные данные сетевых ресурсов)'

    # Минимальная стойкость сеанса NTLM SSP
    Set-RegValue -Path "$lsa\MSV1_0" -Name 'NTLMMinClientSec' -Value 537395200 -Comment '(NTLMv2 + 128-бит шифрование)'
    Set-RegValue -Path "$lsa\MSV1_0" -Name 'NTLMMinServerSec' -Value 537395200

    # Кеш доменных входов
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Value "$CachedLogons" -Type String -Comment '(кешируемых входов)'

    # WDigest — запрет хранения пароля в открытом виде в памяти
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0

    # Ограничение удалённого доступа к SAM только администраторам
    Set-RegValue -Path $lsa -Name 'RestrictRemoteSAM' -Value 'O:BAG:BAD:(A;;RC;;;BA)' -Type String
}

function Set-RdpHardening {
    <# RDP: NLA, высокий уровень шифрования, ограничение по времени простоя. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$DisableRdp, [int]$IdleTimeoutMinutes = 15)

    Write-KscLog '--- Удалённый рабочий стол ---'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

    if ($DisableRdp) {
        Set-RegValue -Path $ts -Name 'fDenyTSConnections' -Value 1 -Comment '(RDP запрещён)'
        return
    }

    Set-RegValue -Path $ts -Name 'fDenyTSConnections' -Value 0
    Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'UserAuthentication' -Value 1 -Comment '(NLA обязательна)'
    Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'SecurityLayer' -Value 2 -Comment '(TLS)'
    Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'MinEncryptionLevel' -Value 3 -Comment '(высокий уровень шифрования)'
    Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisableClip' -Value 1 -Comment '(буфер обмена отключён)'
    Set-RegValue -Path "$ts\WinStations\RDP-Tcp" -Name 'fDisableCdm' -Value 1 -Comment '(проброс дисков отключён)'

    $ms = $IdleTimeoutMinutes * 60000
    Set-RegValue -Path $ts -Name 'MaxIdleTime' -Value $ms -Comment "(разрыв простаивающего сеанса через $IdleTimeoutMinutes мин)"
    Set-RegValue -Path $ts -Name 'MaxDisconnectionTime' -Value 60000 -Comment '(завершение отключённого сеанса через 1 мин)'
    Set-RegValue -Path $ts -Name 'fResetBroken' -Value 1
}

function Set-AuditPolicy {
    <# Расширенная политика аудита: события, необходимые для расследования инцидентов. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$SecurityLogSizeKb = 1048576, [switch]$Strict)

    Write-KscLog '--- Политика аудита ---'

    $subcategories = @(
        @{ Name = 'Logon';                          Flags = '/success:enable /failure:enable' }
        @{ Name = 'Logoff';                         Flags = '/success:enable' }
        @{ Name = 'Account Lockout';                Flags = '/success:enable /failure:enable' }
        @{ Name = 'Special Logon';                  Flags = '/success:enable' }
        @{ Name = 'Other Logon/Logoff Events';      Flags = '/success:enable /failure:enable' }
        @{ Name = 'User Account Management';        Flags = '/success:enable /failure:enable' }
        @{ Name = 'Security Group Management';      Flags = '/success:enable /failure:enable' }
        @{ Name = 'Process Creation';               Flags = '/success:enable' }
        @{ Name = 'Audit Policy Change';            Flags = '/success:enable /failure:enable' }
        @{ Name = 'Authentication Policy Change';   Flags = '/success:enable' }
        @{ Name = 'Sensitive Privilege Use';        Flags = '/success:enable /failure:enable' }
        @{ Name = 'Security State Change';          Flags = '/success:enable' }
        @{ Name = 'Security System Extension';      Flags = '/success:enable' }
        @{ Name = 'System Integrity';               Flags = '/success:enable /failure:enable' }
        @{ Name = 'Removable Storage';              Flags = '/success:enable /failure:enable' }
        @{ Name = 'File Share';                     Flags = '/success:enable /failure:enable' }
        @{ Name = 'Other Object Access Events';     Flags = '/success:enable /failure:enable' }
    )

    if ($Strict) {
        # Расширенный профиль: события, необходимые для восстановления хода атаки.
        $subcategories += @(
            @{ Name = 'Credential Validation';          Flags = '/success:enable /failure:enable' }
            @{ Name = 'Kerberos Service Ticket Operations'; Flags = '/success:enable /failure:enable' }
            @{ Name = 'Kerberos Authentication Service';    Flags = '/success:enable /failure:enable' }
            @{ Name = 'Computer Account Management';    Flags = '/success:enable /failure:enable' }
            @{ Name = 'Distribution Group Management';  Flags = '/success:enable /failure:enable' }
            @{ Name = 'Other Account Management Events'; Flags = '/success:enable /failure:enable' }
            @{ Name = 'Process Termination';            Flags = '/success:enable' }
            @{ Name = 'Registry';                       Flags = '/failure:enable' }
            @{ Name = 'Detailed File Share';            Flags = '/failure:enable' }
            @{ Name = 'Filtering Platform Connection';  Flags = '/failure:enable' }
            @{ Name = 'Filtering Platform Packet Drop'; Flags = '/failure:enable' }
            @{ Name = 'MPSSVC Rule-Level Policy Change'; Flags = '/success:enable /failure:enable' }
            @{ Name = 'Other Policy Change Events';     Flags = '/failure:enable' }
            @{ Name = 'Security Group Management';      Flags = '/success:enable /failure:enable' }
            @{ Name = 'Other System Events';            Flags = '/success:enable /failure:enable' }
            @{ Name = 'Group Membership';               Flags = '/success:enable' }
            @{ Name = 'PNP Activity';                   Flags = '/success:enable' }
            @{ Name = 'Certification Services';         Flags = '/success:enable /failure:enable' }
        )
        Write-KscLog '  Строгий профиль аудита: учтите рост объёма журнала и потока событий в систему мониторинга.' 'WARN'
    }
    foreach ($s in $subcategories) {
        if ($PSCmdlet.ShouldProcess($s.Name, 'Настроить аудит')) {
            $out = cmd /c "auditpol /set /subcategory:`"$($s.Name)`" $($s.Flags)" 2>&1
            if ($LASTEXITCODE -eq 0) { Write-KscLog "  + аудит: $($s.Name)" }
            else { Write-KscLog "  ! не удалось настроить аудит '$($s.Name)': $out" 'WARN' }
        }
    }

    # Приоритет расширенной политики над устаревшей
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1

    # Командная строка в событиях создания процессов (4688)
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1

    # Размеры журналов: годовое хранение обеспечивается выгрузкой в KSC/SIEM,
    # локально держим достаточный буфер на случай потери связи.
    $logs = @{ 'Security' = $SecurityLogSizeKb; 'System' = 262144; 'Application' = 262144 }
    foreach ($log in $logs.Keys) {
        if ($PSCmdlet.ShouldProcess("Журнал $log", "Размер $($logs[$log]) КБ")) {
            wevtutil sl $log /ms:$($logs[$log] * 1024) /rt:false 2>&1 | Out-Null
            Write-KscLog "  + журнал ${log}: $([math]::Round($logs[$log]/1024)) МБ, перезапись старых событий"
        }
    }

    # Журналирование PowerShell
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -Type String
}

function Disable-UnneededServices {
    <#
        Отключение служб, не используемых в аттестованном контуре.

        С параметром -Strict дополнительно отключаются службы, создающие
        неконтролируемые каналы взаимодействия и способы удалённого запуска кода.
        Перечень -Keep обязателен там, где служба нужна роли узла.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Keep = @(), [switch]$Strict)

    Write-KscLog '--- Неиспользуемые службы ---'
    $candidates = @(
        @{ Name = 'XblAuthManager';  Reason = 'Xbox' }
        @{ Name = 'XblGameSave';     Reason = 'Xbox' }
        @{ Name = 'XboxNetApiSvc';   Reason = 'Xbox' }
        @{ Name = 'MapsBroker';      Reason = 'Карты' }
        @{ Name = 'lfsvc';           Reason = 'Геолокация' }
        @{ Name = 'SharedAccess';    Reason = 'Общий доступ к подключению Интернета' }
        @{ Name = 'RemoteAccess';    Reason = 'Маршрутизация и удалённый доступ' }
        @{ Name = 'SSDPSRV';         Reason = 'SSDP-обнаружение' }
        @{ Name = 'upnphost';        Reason = 'UPnP' }
        @{ Name = 'WerSvc';          Reason = 'Отчёты об ошибках (передача данных вовне)' }
        @{ Name = 'PrintNotify';     Reason = 'Уведомления печати' }
        @{ Name = 'Fax';             Reason = 'Факс' }
        @{ Name = 'WMPNetworkSvc';   Reason = 'Общий доступ мультимедиа' }
    )

    if ($Strict) {
        $candidates += @(
            @{ Name = 'RemoteRegistry';  Reason = 'Удалённый реестр: чтение параметров узла по сети' }
            @{ Name = 'seclogon';        Reason = 'Вторичный вход: запуск от имени другой учётной записи' }
            @{ Name = 'TermService';     Reason = 'Службы удалённых рабочих столов' }
            @{ Name = 'SessionEnv';      Reason = 'Настройка удалённого рабочего стола' }
            @{ Name = 'UmRdpService';    Reason = 'Перенаправление устройств в сеансах RDP' }
            @{ Name = 'WinRM';           Reason = 'Удалённое управление Windows' }
            @{ Name = 'WSearch';         Reason = 'Индексирование содержимого' }
            @{ Name = 'PhoneSvc';        Reason = 'Телефония' }
            @{ Name = 'RetailDemo';      Reason = 'Демонстрационный режим' }
            @{ Name = 'dmwappushservice'; Reason = 'Передача диагностических сведений' }
            @{ Name = 'DiagTrack';       Reason = 'Телеметрия' }
            @{ Name = 'DPS';             Reason = 'Диагностическая политика' }
            @{ Name = 'TapiSrv';         Reason = 'Телефония TAPI' }
            @{ Name = 'Browser';         Reason = 'Обозреватель компьютеров (устаревший протокол)' }
            @{ Name = 'IISADMIN';        Reason = 'Служба администрирования IIS' }
            @{ Name = 'ftpsvc';          Reason = 'FTP-сервер' }
            @{ Name = 'simptcp';         Reason = 'Простые службы TCP/IP' }
            @{ Name = 'sshd';            Reason = 'Сервер OpenSSH' }
        )
        Write-KscLog '  Строгий профиль: отключаются также службы удалённого доступа и диагностики.'
        Write-KscLog '  Службы, нужные роли узла, передайте в -Keep: иначе узел потеряет управляемость.' 'WARN'
    }
    foreach ($c in $candidates) {
        if ($Keep -contains $c.Name) { Write-KscLog "  = $($c.Name) оставлена по требованию роли"; continue }
        $svc = Get-Service -Name $c.Name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ($PSCmdlet.ShouldProcess($c.Name, 'Остановить и отключить')) {
            Stop-Service $c.Name -Force -ErrorAction SilentlyContinue
            Set-Service $c.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-KscLog "  + служба $($c.Name) отключена ($($c.Reason))" 'OK'
        }
    }

    # Диспетчер очереди печати на серверах без роли печати (PrintNightmare)
    if ($Keep -notcontains 'Spooler') {
        $sp = Get-Service Spooler -ErrorAction SilentlyContinue
        if ($sp -and $PSCmdlet.ShouldProcess('Spooler', 'Остановить и отключить')) {
            Stop-Service Spooler -Force -ErrorAction SilentlyContinue
            Set-Service Spooler -StartupType Disabled
            Write-KscLog '  + служба Spooler отключена (класс уязвимостей PrintNightmare)' 'OK'
        }
    }
}

function Set-UacHardening {
    <# Контроль учётных записей: максимальный уровень, защищённый рабочий стол. #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-KscLog '--- Контроль учётных записей (UAC) ---'
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegValue -Path $p -Name 'EnableLUA' -Value 1
    Set-RegValue -Path $p -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Comment '(запрос согласия на защищённом рабочем столе)'
    Set-RegValue -Path $p -Name 'ConsentPromptBehaviorUser' -Value 0 -Comment '(повышение для пользователей запрещено)'
    Set-RegValue -Path $p -Name 'PromptOnSecureDesktop' -Value 1
    Set-RegValue -Path $p -Name 'FilterAdministratorToken' -Value 1
    Set-RegValue -Path $p -Name 'LocalAccountTokenFilterPolicy' -Value 0 -Comment '(удалённое повышение локальных учётных записей запрещено)'
    Set-RegValue -Path $p -Name 'InactivityTimeoutSecs' -Value 900 -Comment '(блокировка сеанса через 15 мин)'
    Set-RegValue -Path $p -Name 'DontDisplayLastUserName' -Value 1
}

function Set-AutorunHardening {
    <# Запрет автозапуска со съёмных носителей. #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-KscLog '--- Съёмные носители и автозапуск ---'
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Value 1
}

function Set-DefenderBaseline {
    <# Базовые параметры Microsoft Defender (если он используется как дополнительный контроль). #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-KscLog 'Microsoft Defender недоступен — шаг пропущен.' 'WARN'
        return
    }
    Write-KscLog '--- Microsoft Defender ---'
    if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Применить базовые параметры')) {
        Set-MpPreference -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Write-KscLog '  + Облачная защита и отправка образцов отключены (изолированный контур), защита от нежелательного ПО включена.' 'OK'
    }
}

# ============================================================================
#  Расширенный (строгий) профиль
#
#  Функции ниже применяются к системам для служебного пользования.
#  Часть из них меняет параметры, способные нарушить работу узла при
#  неверном применении (политика паролей, назначение прав, управление
#  запуском программ), поэтому каждая функция:
#    * поддерживает -WhatIf;
#    * перед изменением локальной политики безопасности сохраняет её
#      выгрузку secedit в каталоге отката;
#    * средства управления запуском программ по умолчанию включаются
#      в режиме наблюдения, а не блокировки.
# ============================================================================

function Backup-LocalSecurityPolicy {
    <#
        Выгрузка локальной политики безопасности для последующего отката.

        Выгрузка выполняется один раз за запуск: иначе вторая выгрузка
        уже содержит изменения предыдущего шага и откат возвращает
        узел не в исходное состояние.
    #>
    [CmdletBinding()]
    param()
    if ($script:SecPolBackup -and (Test-Path $script:SecPolBackup)) { return $script:SecPolBackup }
    if ($WhatIfPreference) {
        Write-KscLog '  Выгрузка локальной политики безопасности не выполняется: предварительный просмотр.'
        return $null
    }
    if (-not (Test-Path $script:RollbackDir)) { New-Item -ItemType Directory -Path $script:RollbackDir -Force | Out-Null }
    $file = Join-Path $script:RollbackDir ("secpol-{0}-{1}.inf" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8))
    secedit /export /cfg $file /quiet | Out-Null
    if (Test-Path $file) {
        $script:SecPolBackup = $file
        Write-KscLog "  Выгрузка локальной политики безопасности до изменений: $file"
        Write-KscLog "  Откат: secedit /configure /db secedit.sdb /cfg `"$file`" /overwrite"
        return $file
    }
    Write-KscLog '  ! Не удалось выгрузить локальную политику безопасности.' 'WARN'
    return $null
}

function Invoke-SecEditTemplate {
    <# Применение фрагмента шаблона локальной политики безопасности. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][string]$Description
    )
    if (-not $PSCmdlet.ShouldProcess($Description, 'Применить локальную политику безопасности')) { return }

    $inf = Join-Path $env:TEMP ("ksc-secpol-{0}.inf" -f [guid]::NewGuid())
    $log = Join-Path $script:RollbackDir 'secedit-apply.log'
    try {
        # Шаблон secedit читается в кодировке Unicode.
        $content = "[Unicode]`r`nUnicode=yes`r`n$Body`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n"
        Set-Content -Path $inf -Value $content -Encoding Unicode
        secedit /configure /db secedit.sdb /cfg $inf /log $log /quiet | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-KscLog "  + $Description" 'OK' }
        else { Write-KscLog "  ! $Description : secedit вернул код $LASTEXITCODE, подробности в $log" 'WARN' }
    } finally {
        Remove-Item $inf -Force -ErrorAction SilentlyContinue
    }
}

function Set-PasswordPolicy {
    <#
        Политика паролей и блокировки локальных учётных записей.

        На узле в домене доменные учётные записи подчиняются доменной политике;
        эти параметры действуют на локальные учётные записи узла, которые
        как раз и остаются наиболее слабым местом.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$MinLength = 14,
        [int]$MaxAgeDays = 60,
        [int]$MinAgeDays = 1,
        [int]$History = 24,
        [int]$LockoutThreshold = 5,
        [int]$LockoutDurationMin = 30
    )
    Write-KscLog '--- Политика паролей и блокировки локальных учётных записей ---'
    Backup-LocalSecurityPolicy | Out-Null

    $body = @"
[System Access]
MinimumPasswordLength = $MinLength
PasswordComplexity = 1
PasswordHistorySize = $History
MaximumPasswordAge = $MaxAgeDays
MinimumPasswordAge = $MinAgeDays
ClearTextPassword = 0
LockoutBadCount = $LockoutThreshold
LockoutDuration = $LockoutDurationMin
ResetLockoutCount = $LockoutDurationMin
EnableGuestAccount = 0
"@
    Invoke-SecEditTemplate -Body $body -Description "пароль от $MinLength символов, блокировка после $LockoutThreshold попыток на $LockoutDurationMin мин, гостевая запись отключена"

    # Хранение обратимо зашифрованных паролей и запрет пустых паролей по сети
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Comment '(сетевой вход с пустым паролем запрещён)'
}

function Set-UserRightsHardening {
    <#
        Назначение прав пользователей.

        Ключевая мера: локальным учётным записям запрещается сетевой вход и
        вход через службы удалённых рабочих столов. Это прекращает боковое
        перемещение по сети с использованием одинакового локального пароля —
        типовой способ развития атаки после захвата одного узла.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$RemoteInteractiveSids = @(),
        [switch]$DenyRemoteInteractiveForAll
    )
    Write-KscLog '--- Назначение прав пользователей ---'
    Backup-LocalSecurityPolicy | Out-Null

    # S-1-5-113 — «Локальная учётная запись», S-1-5-114 — «Локальная учётная
    # запись, входящая в группу администраторов», S-1-5-32-546 — «Гости».
    $denyNetwork = '*S-1-5-113,*S-1-5-32-546'
    $denyRemote = if ($DenyRemoteInteractiveForAll) { '*S-1-5-113,*S-1-5-32-546,*S-1-5-32-545' } else { '*S-1-5-113,*S-1-5-32-546' }

    $lines = @(
        "SeDenyNetworkLogonRight = $denyNetwork"
        "SeDenyRemoteInteractiveLogonRight = $denyRemote"
        'SeDenyBatchLogonRight = *S-1-5-32-546'
        'SeDenyServiceLogonRight = *S-1-5-32-546'
        # Отладка программ — только администраторы: право позволяет читать
        # память процессов и извлекать учётные данные.
        'SeDebugPrivilege = *S-1-5-32-544'
        # Олицетворение клиента и создание маркера — только служебные субъекты.
        'SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-6,*S-1-5-19,*S-1-5-20'
        'SeCreateTokenPrivilege ='
        'SeTcbPrivilege ='
        # Локальный вход — администраторы (и, для рядовых узлов, пользователи).
        'SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11'
    )
    if ($RemoteInteractiveSids.Count -gt 0) {
        $lines += "SeRemoteInteractiveLogonRight = $($RemoteInteractiveSids -join ',')"
    }

    Invoke-SecEditTemplate -Body ("[Privilege Rights]`r`n" + ($lines -join "`r`n")) `
        -Description 'локальным учётным записям запрещён сетевой и удалённый интерактивный вход, отладка программ — только администраторам'

    if ($RemoteInteractiveSids.Count -eq 0) {
        Write-KscLog '  ! Право "Вход через службы удалённых рабочих столов" не изменялось: задайте -RemoteInteractiveSids' 'WARN'
        Write-KscLog '    с идентификатором группы администраторов KSC, иначе перечень остаётся прежним.' 'WARN'
    }
}

function Set-CredentialProtection {
    <#
        Защита учётных данных в памяти: изоляция LSA средствами
        виртуализации (Credential Guard) и защита процесса LSASS.

        Требуется поддержка виртуализации и UEFI. На виртуальной машине
        необходима вложенная виртуализация; при её отсутствии параметры
        записываются, но остаются недействующими — это фиксируется в отчёте.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$SkipCredentialGuard)

    Write-KscLog '--- Защита учётных данных ---'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-RegValue -Path $lsa -Name 'RunAsPPL' -Value 1 -Comment '(LSASS как защищённый процесс)'
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Value 1

    # Запрет сохранения паролей и передачи учётных данных недоверенным узлам
    $cd = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
    Set-RegValue -Path $cd -Name 'AllowProtectedCreds' -Value 1
    Set-RegValue -Path $cd -Name 'AllowDefaultCredentials' -Value 0
    Set-RegValue -Path $cd -Name 'AllowDefCredentialsWhenNTLMOnly' -Value 0

    if ($SkipCredentialGuard) {
        Write-KscLog '  = Credential Guard пропущен по параметру запуска'
        return
    }

    $dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    Set-RegValue -Path $dg -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Comment '(защита на основе виртуализации)'
    Set-RegValue -Path $dg -Name 'RequirePlatformSecurityFeatures' -Value 1 -Comment '(безопасная загрузка)'
    Set-RegValue -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" -Name 'Enabled' -Value 1
    Set-RegValue -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" -Name 'Locked' -Value 0
    Set-RegValue -Path $lsa -Name 'LsaCfgFlags' -Value 1 -Comment '(Credential Guard с блокировкой UEFI)'

    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
    if ($vbs -and $vbs.VirtualizationBasedSecurityStatus -eq 2) {
        Write-KscLog '  + защита на основе виртуализации активна' 'OK'
    } else {
        Write-KscLog '  ! Защита на основе виртуализации не активна: проверьте поддержку вложенной виртуализации' 'WARN'
        Write-KscLog '    на уровне гипервизора и режим загрузки UEFI с безопасной загрузкой. Параметры применятся после перезагрузки.' 'WARN'
    }
}

function Set-NetworkStackHardening {
    <# Сетевой стек: маршрутизация от источника, перенаправления ICMP, туннели IPv6, WinRM. #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-KscLog '--- Сетевой стек ---'
    $tcpip = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    Set-RegValue -Path $tcpip -Name 'DisableIPSourceRouting' -Value 2 -Comment '(маршрутизация от источника запрещена)'
    Set-RegValue -Path $tcpip -Name 'EnableICMPRedirect' -Value 0 -Comment '(перенаправления ICMP игнорируются)'
    Set-RegValue -Path $tcpip -Name 'PerformRouterDiscovery' -Value 0
    Set-RegValue -Path $tcpip -Name 'KeepAliveTime' -Value 300000
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Value 2

    # Переходные механизмы IPv6 создают неконтролируемые каналы связи
    $tr = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition'
    Set-RegValue -Path $tr -Name 'Teredo_State' -Value 'Disabled' -Type String
    Set-RegValue -Path $tr -Name '6to4_State' -Value 'Disabled' -Type String
    Set-RegValue -Path $tr -Name 'ISATAP_State' -Value 'Disabled' -Type String
    Set-RegValue -Path $tr -Name 'IPHTTPS_ClientState' -Value 3 -Comment '(IP-HTTPS отключён)'

    # Многоадресное разрешение имён и общий доступ
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_AllowNetBridge_NLA' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_ShowSharedAccessUI' -Value 0

    # Гостевой доступ SMB: соединение без проверки подлинности
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0 -Comment '(гостевой доступ SMB запрещён)'
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Value 1

    # Защищённый канал с контроллером домена
    $nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    Set-RegValue -Path $nl -Name 'RequireSignOrSeal' -Value 1
    Set-RegValue -Path $nl -Name 'SealSecureChannel' -Value 1
    Set-RegValue -Path $nl -Name 'SignSecureChannel' -Value 1
    Set-RegValue -Path $nl -Name 'RequireStrongKey' -Value 1

    # Удалённое управление: только шифрованные сеансы, без обычной проверки подлинности
    foreach ($k in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
                     'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client')) {
        Set-RegValue -Path $k -Name 'AllowBasic' -Value 0 -Comment '(обычная проверка подлинности WinRM запрещена)'
        Set-RegValue -Path $k -Name 'AllowUnencryptedTraffic' -Value 0
    }
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowDigest' -Value 0
}

function Set-ScriptHostHardening {
    <#
        Ограничение интерпретаторов, используемых для запуска вредоносного кода:
        сервер сценариев Windows, PowerShell 2.0, файлы .hta.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$KeepWindowsScriptHost)

    Write-KscLog '--- Интерпретаторы сценариев ---'

    # PowerShell 2.0 не поддерживает ведение журнала блоков сценариев,
    # поэтому применяется для обхода регистрации событий.
    $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
    if ($v2 -and $v2.State -eq 'Enabled') {
        if ($PSCmdlet.ShouldProcess('MicrosoftWindowsPowerShellV2', 'Отключить компонент')) {
            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-KscLog '  + PowerShell 2.0 отключён (не ведёт журнал блоков сценариев)' 'OK'
        }
    } else { Write-KscLog '  = PowerShell 2.0 не установлен' }

    if (-not $KeepWindowsScriptHost) {
        Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Value 0 -Comment '(wscript/cscript запрещены)'
        Set-RegValue -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Value 0
        Write-KscLog '  ! Проверьте, что сценарии входа в систему и обслуживания не используют wscript/cscript.' 'WARN'
    }
}

function Set-PowerShellHardening {
    <#
        Ведение журнала и ограничение запуска сценариев PowerShell.

        Режим ограниченного языка (ConstrainedLanguage) включается только
        параметром -ConstrainedLanguage: он ломает сценарии настоящего
        репозитория и большинство средств администрирования, поэтому
        применяется на рядовых узлах, но не на узлах управления.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('AllSigned', 'RemoteSigned')][string]$ExecutionPolicy = 'AllSigned',
        [switch]$ConstrainedLanguage,
        [string]$TranscriptDir = 'C:\ProgramData\PSTranscripts'
    )
    Write-KscLog '--- PowerShell ---'
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

    Set-RegValue -Path $base -Name 'EnableScripts' -Value 1
    Set-RegValue -Path $base -Name 'ExecutionPolicy' -Value $ExecutionPolicy -Type String
    Set-RegValue -Path "$base\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1
    Set-RegValue -Path "$base\ModuleLogging" -Name 'EnableModuleLogging' -Value 1
    Set-RegValue -Path "$base\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String
    Set-RegValue -Path "$base\Transcription" -Name 'EnableTranscripting' -Value 1
    Set-RegValue -Path "$base\Transcription" -Name 'EnableInvocationHeader' -Value 1
    Set-RegValue -Path "$base\Transcription" -Name 'OutputDirectory' -Value $TranscriptDir -Type String

    if (-not (Test-Path $TranscriptDir)) {
        if ($PSCmdlet.ShouldProcess($TranscriptDir, 'Создать каталог стенограмм')) {
            New-Item -ItemType Directory -Path $TranscriptDir -Force | Out-Null
            icacls $TranscriptDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'BUILTIN\Users:(OI)(CI)(WD,AD,WEA,WA)' /Q | Out-Null
        }
    }

    if ($ConstrainedLanguage) {
        Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' `
            -Name '__PSLockdownPolicy' -Value '4' -Type String -Comment '(режим ограниченного языка)'
        Write-KscLog '  ! Режим ограниченного языка ломает сценарии развёртывания: применяйте только на рядовых узлах.' 'WARN'
    }

    if ($ExecutionPolicy -eq 'AllSigned') {
        Write-KscLog '  ! Политика AllSigned требует подписи сценариев корпоративным сертификатом.' 'WARN'
        Write-KscLog '    До внедрения подписи применяйте -ExecutionPolicy RemoteSigned.' 'WARN'
    }
}

function Set-DefenderStrict {
    <#
        Расширенные параметры Microsoft Defender: правила сокращения
        поверхности атаки, защита сети, защита от изменения параметров.

        Правила сокращения поверхности атаки по умолчанию включаются в режиме
        наблюдения (AuditMode): в режиме блокировки они способны прервать
        работу прикладного ПО, поэтому переход к блокировке выполняется после
        разбора собранных событий.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([switch]$Enforce)

    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-KscLog 'Microsoft Defender недоступен — расширенные параметры пропущены.' 'WARN'
        return
    }
    Write-KscLog '--- Microsoft Defender: расширенный профиль ---'

    # Идентификаторы правил сокращения поверхности атаки
    $asr = [ordered]@{
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Блокировать создание дочерних процессов приложениями Office'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Блокировать создание исполняемого содержимого приложениями Office'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Блокировать внедрение кода в другие процессы из Office'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Блокировать запуск загруженного содержимого через JavaScript/VBScript'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Блокировать выполнение потенциально скрытых сценариев'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Блокировать вызовы Win32 API из макросов Office'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Блокировать кражу учётных данных из lsass.exe'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Блокировать недоверенные и неподписанные процессы со съёмных носителей'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Блокировать запуск исполняемого содержимого из почты и веб-почты'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Блокировать запуск исполняемых файлов без признаков доверия'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Расширенная защита от программ-вымогателей'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Блокировать создание процессов командами PsExec и WMI'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Блокировать создание исполняемого содержимого приложениями связи Office'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Блокировать создание дочерних процессов Adobe Reader'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Блокировать сохранение копий учётных данных из подсистемы WMI'
    }
    $action = if ($Enforce) { 'Enabled' } else { 'AuditMode' }

    if ($PSCmdlet.ShouldProcess('Правила сокращения поверхности атаки', "Режим: $action")) {
        foreach ($id in $asr.Keys) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $action -ErrorAction SilentlyContinue
        }
        Write-KscLog "  + правил сокращения поверхности атаки: $($asr.Count), режим $action" 'OK'
        if (-not $Enforce) {
            Write-KscLog '    Режим наблюдения: события регистрируются, запуск не блокируется.' 'WARN'
            Write-KscLog '    Через 2–4 недели разберите события 1121/1122 и включите блокировку: -Enforce.' 'WARN'
        }
    }

    if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Применить расширенные параметры')) {
        # Изолированный контур: обращения к облачным службам исключены
        Set-MpPreference -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $false -DisableArchiveScanning $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableRemovableDriveScanning $false -ErrorAction SilentlyContinue
        Set-MpPreference -EnableNetworkProtection ($(if ($Enforce) { 'Enabled' } else { 'AuditMode' })) -ErrorAction SilentlyContinue
        Set-MpPreference -EnableControlledFolderAccess ($(if ($Enforce) { 'Enabled' } else { 'AuditMode' })) -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue
        Write-KscLog '  + защита сети и контролируемый доступ к папкам, режим соответствует правилам ASR' 'OK'
    }

    Write-KscLog '  ! Если основным средством защиты узла является Kaspersky Endpoint Security,' 'WARN'
    Write-KscLog '    Defender переходит в пассивный режим: правила ASR продолжают действовать,' 'WARN'
    Write-KscLog '    постоянная защита файлов обеспечивается Kaspersky Endpoint Security.' 'WARN'
}

function Set-RemovableStorageHardening {
    <#
        Съёмные носители.

        Основной механизм — контроль устройств Kaspersky Endpoint Security:
        он даёт правила по типам, моделям и пользователям. Параметры ниже
        обеспечивают защиту на время до применения политики KSC и при её отказе.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([ValidateSet('DenyWrite', 'DenyAll')][string]$Mode = 'DenyWrite')

    Write-KscLog "--- Съёмные носители: $Mode ---"
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
    $classes = @{
        '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' = 'Съёмные диски'
        '{53f56308-b6bf-11d0-94f2-00a0c91efb8b}' = 'Ленточные накопители'
        '{6ac27878-a6fa-4155-ba85-f98f491d4f33}' = 'Устройства WPD'
    }
    # Значения записываются явно в обоих режимах: иначе переход
    # с DenyAll на DenyWrite оставляет действующим запрет чтения и запуска.
    $denyAll = [int]($Mode -eq 'DenyAll')
    foreach ($c in $classes.Keys) {
        Set-RegValue -Path "$base\$c" -Name 'Deny_Write' -Value 1 -Comment "($($classes[$c]): запись)"
        Set-RegValue -Path "$base\$c" -Name 'Deny_Read' -Value $denyAll -Comment "($($classes[$c]): чтение)"
        Set-RegValue -Path "$base\$c" -Name 'Deny_Execute' -Value $denyAll
    }
    Set-RegValue -Path $base -Name 'Deny_All' -Value $denyAll
    Write-KscLog '  Учтите: запрет чтения со съёмных носителей препятствует доставке дистрибутивов и обновлений' 'WARN'
    Write-KscLog '  в изолированном контуре. Предусмотрите порядок временного снятия запрета для учтённых носителей.' 'WARN'
}

function Set-LegalNotice {
    <# Предупреждение при входе в систему. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Caption = 'Информационная система ограниченного доступа',
        [string]$Text
    )
    if (-not $Text) {
        $Text = @'
Доступ к системе предоставляется только уполномоченным лицам.
Действия пользователя регистрируются и контролируются.
Обработка сведений, не предусмотренных назначением системы, запрещена.
Продолжая вход, вы подтверждаете ознакомление с регламентом обеспечения кибербезопасности.
'@
    }
    Write-KscLog '--- Предупреждение при входе ---'
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegValue -Path $p -Name 'legalnoticecaption' -Value $Caption -Type String
    Set-RegValue -Path $p -Name 'legalnoticetext' -Value $Text -Type String
}

function Set-AppLockerBaseline {
    <#
        Управление запуском программ (AppLocker).

        Политика создаётся в режиме наблюдения: правила по умолчанию
        разрешают запуск из каталогов Windows и Program Files и регистрируют
        всё остальное. Переход к блокировке выполняется параметром -Enforce
        после разбора собранных событий — иначе узел теряет работоспособность
        при первом же запуске программы из нестандартного расположения.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Enforce,
        [string[]]$AllowedPaths = @()
    )
    Write-KscLog '--- Управление запуском программ (AppLocker) ---'

    $svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-KscLog '  ! Служба AppIDSvc отсутствует: AppLocker недоступен на этом выпуске.' 'WARN'
        return
    }
    if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
        Write-KscLog '  ! Модуль AppLocker недоступен.' 'WARN'
        return
    }

    $mode = if ($Enforce) { 'Enabled' } else { 'AuditOnly' }
    $extra = ''
    foreach ($path in $AllowedPaths) {
        $extra += @"
    <FilePathRule Id="$([guid]::NewGuid())" Name="Разрешено: $path" Description="Согласованное расположение" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="$path*" /></Conditions>
    </FilePathRule>
"@
    }

    $xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$mode">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="Программы из каталога Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="Программы из каталога Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="Все программы для администраторов" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
$extra
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="$mode">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="Сценарии из каталога Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c" Name="Сценарии из каталога Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="Все сценарии для администраторов" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="$mode">
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="Установочные пакеты из каталога Windows\Installer" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54" Name="Все установочные пакеты для администраторов" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

    if ($AllowedPaths.Count -gt 0) {
        Write-KscLog '  ! Разрешённые расположения задаются путём и действуют для всех пользователей.' 'WARN'
        Write-KscLog '    До включения блокировки убедитесь, что у обычных пользователей нет права записи' 'WARN'
        Write-KscLog '    ни в эти каталоги, ни во вложенные: иначе правило обходится подменой файла.' 'WARN'
        foreach ($path in $AllowedPaths) { Write-KscLog "    проверьте разрешения: icacls `"$path`"" 'WARN' }
    }

    $policyFile = Join-Path $env:TEMP ("ksc-applocker-{0}.xml" -f [guid]::NewGuid())
    try {
        Set-Content -Path $policyFile -Value $xml -Encoding UTF8
        if ($PSCmdlet.ShouldProcess('Политика AppLocker', "Применить в режиме $mode")) {
            if (-not (Test-Path $script:RollbackDir)) { New-Item -ItemType Directory -Path $script:RollbackDir -Force | Out-Null }
            $before = Join-Path $script:RollbackDir ("applocker-before-{0}.xml" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Get-AppLockerPolicy -Local -Xml -ErrorAction SilentlyContinue | Set-Content $before -Encoding UTF8
            Set-AppLockerPolicy -XmlPolicy $policyFile -ErrorAction Stop
            Set-Service AppIDSvc -StartupType Automatic
            Start-Service AppIDSvc -ErrorAction SilentlyContinue
            Write-KscLog "  + политика применена в режиме $mode, прежняя сохранена: $before" 'OK'
            if (-not $Enforce) {
                Write-KscLog '    Режим наблюдения: разберите события журнала AppLocker и добавьте' 'WARN'
                Write-KscLog '    согласованные расположения через -AllowedPaths, затем включите -Enforce.' 'WARN'
            }
        }
    } catch {
        Write-KscLog "  ! Не удалось применить политику AppLocker: $($_.Exception.Message)" 'WARN'
    } finally {
        Remove-Item $policyFile -Force -ErrorAction SilentlyContinue
    }
}

function Set-UpdateHardening {
    <# Обновления: только внутренний источник, автоматическая перезагрузка запрещена. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$WsusUrl = '')

    Write-KscLog '--- Обновления операционной системы ---'
    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegValue -Path $au -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1
    Set-RegValue -Path $au -Name 'AUOptions' -Value 3 -Comment '(загружать, устанавливать по решению администратора)'

    if ($WsusUrl) {
        $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        Set-RegValue -Path $wu -Name 'WUServer' -Value $WsusUrl -Type String
        Set-RegValue -Path $wu -Name 'WUStatusServer' -Value $WsusUrl -Type String
        Set-RegValue -Path $au -Name 'UseWUServer' -Value 1 -Comment '(только внутренний сервер обновлений)'
    } else {
        Write-KscLog '  ! Внутренний сервер обновлений не задан. В изолированном контуре обновления' 'WARN'
        Write-KscLog '    доставляются учтённым носителем; порядок описан в руководстве администратора.' 'WARN'
    }

    # Доставка обновлений между узлами по сети создаёт неучтённый канал обмена
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Value 0
}

function Set-TelemetryHardening {
    <# Передача сведений о работе системы за пределы контура. #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-KscLog '--- Передача диагностических сведений ---'
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Comment '(диагностические данные не передаются)'
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowUnsolicited' -Value 0 -Comment '(удалённый помощник запрещён)'
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
}

function Write-HardeningSummary {
    param([string]$Role)
    Write-KscLog "=== Харденинг роли '$Role' завершён ===" 'OK'
    if (Test-Path $script:RollbackFile) {
        Write-KscLog "Файл отката: $script:RollbackFile"
        Write-KscLog 'Откат выполняется скриптом common\Restore-Baseline.ps1 -RollbackFile <путь>.'
    }
    Write-KscLog 'Часть параметров (SCHANNEL, SMBv1, RunAsPPL) применяется после перезагрузки.' 'WARN'
}

Export-ModuleMember -Function Set-RegValue, Disable-LegacyProtocols, Set-TlsHardening,
    Set-AuthenticationHardening, Set-RdpHardening, Set-AuditPolicy, Disable-UnneededServices,
    Set-UacHardening, Set-AutorunHardening, Set-DefenderBaseline, Write-HardeningSummary,
    Backup-LocalSecurityPolicy, Invoke-SecEditTemplate, Set-PasswordPolicy, Set-UserRightsHardening,
    Set-CredentialProtection, Set-NetworkStackHardening, Set-ScriptHostHardening, Set-PowerShellHardening,
    Set-DefenderStrict, Set-RemovableStorageHardening, Set-LegalNotice, Set-AppLockerBaseline,
    Set-UpdateHardening, Set-TelemetryHardening
