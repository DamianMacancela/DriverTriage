function Measure-DriverTriageAccuracy {
    <#
    .SYNOPSIS
    Metricas sobre un corpus ETIQUETADO: matriz de confusion por umbral, recall@K y una ablacion simple
    por categoria de capacidad. Esto es evaluacion, no deteccion: sin un corpus real y representativo
    (p.ej. LOLDrivers para los positivos, una instalacion limpia de Windows para los negativos), estas
    cifras no dicen nada sobre el desempeno en produccion. Ver docs/METHODOLOGY.md.
    .EXAMPLE
    $r = Invoke-DriverTriageScan -Path .\tests\data
    Measure-DriverTriageAccuracy -Result $r.Results -LabelsPath .\tests\data\labels.sample.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Result,
        [Parameter(Mandatory)][string]$LabelsPath,
        [double[]]$Thresholds,
        [int[]]$TopK = @(1, 3, 5, 10)
    )
    $labels = Get-Content -LiteralPath $LabelsPath -Raw | ConvertFrom-Json
    $labelMap = @{}
    foreach ($p in $labels.PSObject.Properties) { $labelMap[$p.Name.ToLowerInvariant()] = [bool]$p.Value }

    $labeled = foreach ($r in $Result) {
        $key = $null
        if ($r.Sha256 -and $labelMap.ContainsKey($r.Sha256.ToLowerInvariant())) { $key = $r.Sha256.ToLowerInvariant() }
        elseif ($r.FileName -and $labelMap.ContainsKey($r.FileName.ToLowerInvariant())) { $key = $r.FileName.ToLowerInvariant() }
        if ($null -ne $key) { [pscustomobject]@{ Result = $r; IsVulnerable = $labelMap[$key] } }
    }
    $labeled = @($labeled)
    if ($labeled.Count -eq 0) { throw 'Ningun resultado coincide con las etiquetas (por Sha256 o FileName).' }
    $posCount = @($labeled | Where-Object IsVulnerable).Count
    $negCount = $labeled.Count - $posCount
    if ($posCount -eq 0 -or $negCount -eq 0) { Write-Warning 'El corpus etiquetado no tiene ambas clases representadas; las metricas no son significativas.' }

    if (-not $Thresholds) {
        $cfg = Get-DtConfig
        $Thresholds = @($cfg.SeverityThresholds.Low, $cfg.SeverityThresholds.Medium, $cfg.SeverityThresholds.High, $cfg.SeverityThresholds.Critical)
    }

    $confusion = foreach ($t in $Thresholds) {
        $tp = @($labeled | Where-Object { $_.IsVulnerable -and $_.Result.Score -ge $t }).Count
        $fn = @($labeled | Where-Object { $_.IsVulnerable -and $_.Result.Score -lt $t }).Count
        $fp = @($labeled | Where-Object { -not $_.IsVulnerable -and $_.Result.Score -ge $t }).Count
        $tn = @($labeled | Where-Object { -not $_.IsVulnerable -and $_.Result.Score -lt $t }).Count
        $precision = if (($tp + $fp) -gt 0) { [Math]::Round($tp / ($tp + $fp), 3) } else { $null }
        $recall = if (($tp + $fn) -gt 0) { [Math]::Round($tp / ($tp + $fn), 3) } else { $null }
        $fpr = if (($fp + $tn) -gt 0) { [Math]::Round($fp / ($fp + $tn), 3) } else { $null }
        [pscustomobject][ordered]@{ Threshold = $t; TP = $tp; FP = $fp; FN = $fn; TN = $tn; Precision = $precision; Recall = $recall; FalsePositiveRate = $fpr }
    }

    $ranked = @($labeled | Sort-Object { $_.Result.Score } -Descending)
    $recallAtK = foreach ($k in $TopK) {
        $top = @($ranked | Select-Object -First ([Math]::Min($k, $ranked.Count)))
        $caught = @($top | Where-Object IsVulnerable).Count
        [pscustomobject]@{ K = $k; VulnerableInTopK = $caught; OfTotalVulnerable = $posCount; RecallAtK = if ($posCount -gt 0) { [Math]::Round($caught / $posCount, 3) } else { $null } }
    }

    $meanVuln = ($labeled | Where-Object IsVulnerable | ForEach-Object { $_.Result.Score } | Measure-Object -Average).Average
    $meanBenign = ($labeled | Where-Object { -not $_.IsVulnerable } | ForEach-Object { $_.Result.Score } | Measure-Object -Average).Average
    $baselineSeparation = [Math]::Round(($meanVuln - $meanBenign), 3)

    $categories = @($labeled | ForEach-Object { $_.Result.CapabilityHits } | ForEach-Object { $_.Category } | Select-Object -Unique)
    $ablation = foreach ($cat in $categories) {
        $scores = foreach ($l in $labeled) {
            $kept = @($l.Result.CapabilityHits | Where-Object { $_.Category -ne $cat })
            $sub = 0.0; foreach ($h in $kept) { $sub += [double]$h.Weight }
            [pscustomobject]@{ IsVulnerable = $l.IsVulnerable; Score = $sub * $l.Result.Exposure.Multiplier * $l.Result.Trust.Multiplier }
        }
        $mv = ($scores | Where-Object IsVulnerable | ForEach-Object Score | Measure-Object -Average).Average
        $mb = ($scores | Where-Object { -not $_.IsVulnerable } | ForEach-Object Score | Measure-Object -Average).Average
        $sepWithout = [Math]::Round(($mv - $mb), 3)
        [pscustomobject]@{ CategoryRemoved = $cat; SeparationWithout = $sepWithout; ContributionToSeparation = [Math]::Round($baselineSeparation - $sepWithout, 3) }
    }
    $ablation = @($ablation | Sort-Object ContributionToSeparation -Descending)

    [pscustomobject]@{
        LabeledCount        = $labeled.Count
        VulnerableCount     = $posCount
        BenignCount         = $negCount
        ConfusionByThreshold = @($confusion)
        RecallAtK           = @($recallAtK)
        MeanScoreVulnerable = [Math]::Round($meanVuln, 3)
        MeanScoreBenign     = [Math]::Round($meanBenign, 3)
        BaselineSeparation  = $baselineSeparation
        AblationByCategory  = $ablation
    }
}
