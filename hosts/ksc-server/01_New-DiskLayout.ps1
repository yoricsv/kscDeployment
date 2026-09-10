<#
.SYNOPSIS
    Разметка томов сервера KSC: D: (данные MariaDB) и E: (KLSHARE, обновления, резервные копии).

.DESCRIPTION
    Два режима работы:

      1. -Mode NewDisks  — в гипервизоре добавлены отдельные виртуальные диски.
         Скрипт инициализирует все диски в состоянии RAW и создаёт на них тома D: и E:.

      2. -Mode ShrinkC   — диск один (400 ГБ, единый раздел C:).
         Скрипт сжимает C: до заданного размера и создаёт из освободившегося
         пространства тома D: и E:.

    Рекомендуемая раскладка для 400 ГБ:
        C: 120 ГБ  — ОС и KSC
        D: 150 ГБ  — данные MariaDB
        E: 130 ГБ  — KLSHARE, хранилище обновлений, резервные копии

    ВНИМАНИЕ: операции с разделами необратимы. Перед запуском сделайте снимок ВМ.

.EXAMPLE
    .\01_New-DiskLayout.ps1 -Mode NewDisks
    .\01_New-DiskLayout.ps1 -Mode ShrinkC -SystemSizeGB 120 -DbSizeGB 150
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('NewDisks', 'ShrinkC')][string]$Mode,
    [int]$SystemSizeGB = 120,
    [int]$DbSizeGB = 150,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\..\common\config.ps1"
Assert-Elevated

$dbLetter = $KSC.DiskDatabase.TrimEnd(':')
$dataLetter = $KSC.DiskData.TrimEnd(':')

if (-not $Force) {
    Write-KscLog 'Операции с разделами необратимы. Убедитесь, что снимок ВМ создан.' 'WARN'
    $answer = Read-Host 'Продолжить? (yes/no)'
    if ($answer -ne 'yes') { Write-KscLog 'Отменено пользователем.'; return }
}

switch ($Mode) {

    'NewDisks' {
        $raw = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Sort-Object Number
        if ($raw.Count -lt 2) {
            throw "Найдено RAW-дисков: $($raw.Count). Добавьте в гипервизоре два диска (под D: и E:) и повторите."
        }

        $targets = @(
            @{ Disk = $raw[0]; Letter = $dbLetter;   Label = 'DB' }
            @{ Disk = $raw[1]; Letter = $dataLetter; Label = 'DATA' }
        )
        foreach ($t in $targets) {
            if ($PSCmdlet.ShouldProcess("Disk $($t.Disk.Number)", "Инициализация и создание тома $($t.Letter):")) {
                Initialize-Disk -Number $t.Disk.Number -PartitionStyle GPT -Confirm:$false
                New-Partition -DiskNumber $t.Disk.Number -UseMaximumSize -DriveLetter $t.Letter |
                    Format-Volume -FileSystem NTFS -NewFileSystemLabel $t.Label -AllocationUnitSize 65536 -Confirm:$false | Out-Null
                Write-KscLog "Создан том $($t.Letter): (метка $($t.Label), диск $($t.Disk.Number))" 'OK'
            }
        }
    }

    'ShrinkC' {
        $c = Get-Partition -DriveLetter C
        $supported = Get-PartitionSupportedSize -DriveLetter C
        $targetBytes = $SystemSizeGB * 1GB

        if ($targetBytes -lt $supported.SizeMin) {
            throw "Нельзя сжать C: до $SystemSizeGB ГБ: минимум $([math]::Round($supported.SizeMin/1GB)) ГБ."
        }
        if ($PSCmdlet.ShouldProcess('C:', "Сжатие до $SystemSizeGB ГБ")) {
            Resize-Partition -DriveLetter C -Size $targetBytes
            Write-KscLog "C: сжат до $SystemSizeGB ГБ." 'OK'
        }

        $disk = Get-Disk -Number $c.DiskNumber
        if ($PSCmdlet.ShouldProcess("Disk $($disk.Number)", "Создание тома $dbLetter`: на $DbSizeGB ГБ")) {
            New-Partition -DiskNumber $disk.Number -Size ($DbSizeGB * 1GB) -DriveLetter $dbLetter |
                Format-Volume -FileSystem NTFS -NewFileSystemLabel 'DB' -AllocationUnitSize 65536 -Confirm:$false | Out-Null
            Write-KscLog "Создан том $dbLetter`: ($DbSizeGB ГБ)" 'OK'
        }
        if ($PSCmdlet.ShouldProcess("Disk $($disk.Number)", "Создание тома $dataLetter`: на оставшемся пространстве")) {
            New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter $dataLetter |
                Format-Volume -FileSystem NTFS -NewFileSystemLabel 'DATA' -Confirm:$false | Out-Null
            Write-KscLog "Создан том $dataLetter`: (остаток пространства)" 'OK'
        }
    }
}

Get-Volume | Where-Object DriveLetter | Format-Table DriveLetter, FileSystemLabel,
    @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB) } }, @{n = 'FreeGB'; e = { [math]::Round($_.SizeRemaining / 1GB) } } |
    Out-String | Write-Host

Write-KscLog 'Разметка завершена.' 'OK'
