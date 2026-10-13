$script:SeverityOrder = 'Low', 'Medium', 'High', 'Critical'

function Get-DtConfig {
    if (-not $script:DtConfig) {
        $path = Join-Path (Join-Path $script:ModuleRoot 'Data') 'capabilities.psd1'
        $script:DtConfig = Import-PowerShellDataFile -Path $path
    }
    $script:DtConfig
}

function Get-DtSeverityRank {
    param([string]$Severity)
    ([array]::IndexOf($script:SeverityOrder, $Severity)) + 1   # 0 si no existe
}

function Get-DtSeverityFromScore {
    param([double]$Score, [hashtable]$Thresholds)
    if ($Score -ge $Thresholds.Critical) { return 'Critical' }
    if ($Score -ge $Thresholds.High) { return 'High' }
    if ($Score -ge $Thresholds.Medium) { return 'Medium' }
    if ($Score -ge $Thresholds.Low) { return 'Low' }
    return 'None'
}

function Get-DtHashId {
    param([Parameter(Mandatory)][string]$InputString)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').Substring(0, 16)
    }
    finally { $sha.Dispose() }
}

function Get-DtFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Format-DtSafeText {
    # Todo texto leido de un binario es input no confiable: sin control chars, longitud acotada.
    param($Text, [int]$Max = 400)
    $t = [regex]::Replace([string]$Text, '[\r\n\t]+', ' ')
    $t = [regex]::Replace($t, '[\x00-\x1F\x7F]', '')
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    $t
}

function ConvertTo-DtFinding {
    param(
        [string]$Rule, [string]$Title, [string]$Severity,
        [string]$Path, [string]$Hash, [string]$Evidence, [string]$Mitre, [string]$Confidence = 'Heuristic'
    )
    [pscustomobject][ordered]@{
        Id         = 'DT-' + (Get-DtHashId "$Rule|$Path|$Hash").Substring(0, 8)
        Rule       = $Rule
        Severity   = $Severity
        Confidence = $Confidence
        Title      = $Title
        Path       = $Path
        Hash       = $Hash
        Evidence   = Format-DtSafeText $Evidence 600
        Mitre      = $Mitre
    }
}
