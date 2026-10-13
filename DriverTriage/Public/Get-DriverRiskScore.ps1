function Get-DriverRiskScore {
    <#
    .SYNOPSIS
    Combina capacidad x exposicion x confianza en un puntaje final y una severidad.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Capability,
        [Parameter(Mandatory)][psobject]$Exposure,
        [Parameter(Mandatory)][psobject]$Trust,
        [hashtable]$Config
    )
    if (-not $Config) { $Config = Get-DtConfig }
    $score = [Math]::Round($Capability.Subtotal * $Exposure.Multiplier * $Trust.Multiplier, 2)
    $severity = Get-DtSeverityFromScore -Score $score -Thresholds $Config.SeverityThresholds
    [pscustomobject]@{
        Score    = $score
        Severity = $severity
        Breakdown = "capacidad=$($Capability.Subtotal) x exposicion=$($Exposure.Multiplier) ($($Exposure.Classification)) x confianza=$($Trust.Multiplier) ($($Trust.Status))"
    }
}
