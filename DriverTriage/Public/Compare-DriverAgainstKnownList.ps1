function Compare-DriverAgainstKnownList {
    <#
    .SYNOPSIS
    Cruza un driver contra una lista de drivers ya conocidos como abusables (por hash y, mas debil, por
    nombre de archivo). Por defecto usa la muestra de ejemplo incluida: en produccion, reemplaza
    Data/known_vulnerable_sample.csv por el feed completo de loldrivers.io.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sha256,
        [string]$ListPath
    )
    if (-not $ListPath) { $ListPath = Join-Path (Join-Path $script:ModuleRoot 'Data') 'known_vulnerable_sample.csv' }
    if (-not (Test-Path -LiteralPath $ListPath)) { return $null }
    $list = Import-Csv -LiteralPath $ListPath
    $fileName = Split-Path -Path $Path -Leaf

    $hashHit = $null
    if ($Sha256) { $hashHit = $list | Where-Object { $_.Sha256 -and $_.Sha256.ToLowerInvariant() -eq $Sha256.ToLowerInvariant() } | Select-Object -First 1 }
    if ($hashHit) {
        return [pscustomobject]@{ Matched = $true; MatchType = 'Hash'; Confidence = 'Confirmed'; Name = $hashHit.Name; Source = $hashHit.Source; Note = $hashHit.Note }
    }

    $nameHit = $list | Where-Object { $_.Name -and $_.Name.ToLowerInvariant() -eq $fileName.ToLowerInvariant() } | Select-Object -First 1
    if ($nameHit) {
        return [pscustomobject]@{ Matched = $true; MatchType = 'FileName'; Confidence = 'Heuristic'; Name = $nameHit.Name; Source = $nameHit.Source; Note = $nameHit.Note + ' (coincidencia solo por nombre: el hash no coincide o no esta en la lista; puede ser una version distinta o un archivo homonimo legitimo.)' }
    }

    [pscustomobject]@{ Matched = $false; MatchType = $null; Confidence = $null; Name = $null; Source = $null; Note = $null }
}
