<#
.SYNOPSIS
    Создание в Active Directory подразделений, групп и служебных учётных записей для KSC.

.DESCRIPTION
    Выполняется на контроллере домена (или на узле с установленным RSAT).
    Создаёт:

      * подразделение OU=KSC (служебные объекты системы антивирусной защиты);
      * группы безопасности: KSC-Admins, KSC-Operators, KSC-Auditors;
      * служебные учётные записи:
          svc_ksc         — учётная запись службы Сервера администрирования;
          svc_ksc_deploy  — удалённая установка Агентов (локальный администратор на узлах);
      * запрет смены пароля пользователем и бессрочный пароль для служебных записей;
      * описание объектов (заполняется поле Description для инвентаризации).

    Пароли задаются интерактивно и нигде не сохраняются.

.PARAMETER OuPath
    DN родительского контейнера. По умолчанию — корень домена.

.PARAMETER WhatIf
    Показать планируемые действия без изменений в каталоге.

.EXAMPLE
    .\00_New-KscAccounts.ps1
    .\00_New-KscAccounts.ps1 -OuPath 'OU=Service,DC=domain,DC=local'
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$OuPath)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"

Import-Module ActiveDirectory -ErrorAction Stop

$domainDn = (Get-ADDomain).DistinguishedName
if (-not $OuPath) { $OuPath = $domainDn }
$kscOu = "OU=KSC,$OuPath"

Write-KscLog "=== Создание объектов AD для KSC в $OuPath ==="

# ---------------------------------------------------------------- 1. Подразделение

if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$kscOu'" -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($kscOu, 'Создать подразделение')) {
        New-ADOrganizationalUnit -Name 'KSC' -Path $OuPath -ProtectedFromAccidentalDeletion $true `
            -Description 'Служебные объекты системы антивирусной защиты Kaspersky Security Center'
        Write-KscLog "Создано подразделение $kscOu" 'OK'
    }
} else { Write-KscLog "Подразделение $kscOu уже существует." }

# ---------------------------------------------------------------- 2. Группы

$groups = @(
    @{ Name = $KSC.AdminsGroup;    Desc = 'KSC: роль "Главный администратор" — полное управление системой антивирусной защиты' }
    @{ Name = $KSC.OperatorsGroup; Desc = 'KSC: роль "Оператор" — запуск задач, просмотр событий; смежные СЗИ и дежурная смена' }
    @{ Name = $KSC.AuditorsGroup;  Desc = 'KSC: роль "Аудитор" — только чтение отчётов и журнала событий' }
)
foreach ($g in $groups) {
    if (Get-ADGroup -Filter "Name -eq '$($g.Name)'" -ErrorAction SilentlyContinue) {
        Write-KscLog "Группа $($g.Name) уже существует."
        continue
    }
    if ($PSCmdlet.ShouldProcess($g.Name, 'Создать группу безопасности')) {
        New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security -Path $kscOu -Description $g.Desc
        Write-KscLog "Создана группа $($g.Name)" 'OK'
    }
}

# ---------------------------------------------------------------- 3. Служебные учётные записи

$accounts = @(
    @{ Name = $KSC.SvcAccount
       Display = 'KSC Administration Server Service'
       Desc = 'Служба Сервера администрирования KSC. Интерактивный вход запрещён.' }
    @{ Name = $KSC.DeployAccount
       Display = 'KSC Remote Deployment'
       Desc = 'Удалённая установка Агентов администрирования. Локальный администратор на управляемых узлах.' }
)

foreach ($a in $accounts) {
    if (Get-ADUser -Filter "SamAccountName -eq '$($a.Name)'" -ErrorAction SilentlyContinue) {
        Write-KscLog "Учётная запись $($a.Name) уже существует."
        continue
    }
    $securePwd = Read-Host "Задайте пароль для $($a.Name) (не менее 16 символов)" -AsSecureString
    if ($PSCmdlet.ShouldProcess($a.Name, 'Создать учётную запись')) {
        New-ADUser -Name $a.Name -SamAccountName $a.Name `
            -UserPrincipalName "$($a.Name)@$($KSC.DomainFqdn)" `
            -DisplayName $a.Display -Description $a.Desc `
            -Path $kscOu -AccountPassword $securePwd -Enabled $true `
            -PasswordNeverExpires $true -CannotChangePassword $true
        Write-KscLog "Создана учётная запись $($a.Name)" 'OK'
    }
}

# ---------------------------------------------------------------- 4. Проверка и вывод

Write-KscLog '--- Созданные объекты ---'
Get-ADObject -SearchBase $kscOu -Filter * -Properties Description |
    Where-Object ObjectClass -in @('user', 'group') |
    Select-Object Name, ObjectClass, Description |
    Format-Table -AutoSize | Out-String | Write-Host

# ---------------------------------------------------------------- 5. Дальнейшие шаги (вручную/отдельными скриптами)

Write-Host ''
Write-Host 'ДАЛЬНЕЙШИЕ ШАГИ:' -ForegroundColor Yellow
@"
  1. Включить администраторов в группу $($KSC.AdminsGroup):
       Add-ADGroupMember -Identity $($KSC.AdminsGroup) -Members <учётные записи>

  2. Выдать $($KSC.DeployAccount) права локального администратора на управляемых узлах.
     Рекомендуемый способ — GPO "Ограниченные группы" / "Локальные пользователи и группы":
       Конфигурация компьютера -> Настройка -> Параметры панели управления ->
       Локальные пользователи и группы -> Группа "Администраторы" -> Обновить ->
       Добавить участника $($KSC.DomainNetBios)\$($KSC.DeployAccount)
     Применять только к OU с рабочими станциями и серверами (НЕ к контроллерам домена).

  3. Ограничить служебные учётные записи политикой прав пользователя:
       $($KSC.SvcAccount)        -> "Отказать в локальном входе", "Отказать во входе через RDP"
       $($KSC.DeployAccount)     -> "Отказать в локальном входе", "Отказать во входе через RDP"

  4. Включить для служебных записей флаг "Учётная запись важна и не может быть делегирована"
     (защита от передачи билета Kerberos):
       Set-ADAccountControl -Identity $($KSC.SvcAccount) -AccountNotDelegated `$true
       Set-ADAccountControl -Identity $($KSC.DeployAccount) -AccountNotDelegated `$true

  5. Добавить служебные записи в группу "Protected Users" ТОЛЬКО после проверки
     совместимости: группа запрещает NTLM, что может нарушить удалённую установку.
"@ | Write-Host

Write-KscLog '=== Следующий шаг: 10_New-AgentGpo.ps1 ===' 'OK'
