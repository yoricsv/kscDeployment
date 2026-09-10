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
    param([int]$SecurityLogSizeKb = 1048576)

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
    <# Отключение служб, не используемых на серверах в аттестованном контуре. #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Keep = @())

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
    Set-UacHardening, Set-AutorunHardening, Set-DefenderBaseline, Write-HardeningSummary
