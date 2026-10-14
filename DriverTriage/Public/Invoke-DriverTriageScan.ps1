function Invoke-DriverTriageScan {
    <#
    .SYNOPSIS
    Orquesta el pipeline completo: inventario -> parseo -> capacidad -> exposicion -> confianza ->
    puntaje -> cruce con lista conocida -> JSON + HTML.
    .EXAMPLE
    Invoke-DriverTriageScan -Path .\tests\data -OutputDirectory .\out
    .EXAMPLE
    Invoke-DriverTriageScan -UseSystemInventory -OutputDirectory .\out   # Windows, drivers cargados
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(ParameterSetName = 'Path')][string[]]$Path,
        [Parameter(ParameterSetName = 'System')][switch]$UseSystemInventory,
        [string]$KnownListPath,
        [switch]$IncludeClean,
        [string]$OutputDirectory = (Join-Path (Get-Location) 'drivertriage-out')
    )
    $config = Get-DtConfig
    if ($UseSystemInventory) { $files = @(Get-DriverInventory -UseSystemInventory) }
    else { $files = @(Get-DriverInventory -Path $Path) }

    $results = [System.Collections.Generic.List[object]]::new()
    $findings = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()

    $totalCount = $files.Count
    $index = 0

    foreach ($f in $files) {
        $index++
        if ($totalCount -gt 3) {
            Write-Progress -Activity 'DriverTriage: Analizando drivers' -Status "[$index / $totalCount] $($f.Name)" -PercentComplete ([int](($index / $totalCount) * 100))
        }
        $info = $null
        try { $info = Get-DriverPEInfo -Path $f.FullName } catch { $info = $null }
        if (-not $info -or -not $info.Success) {
            $err = if ($info) { $info.Error } else { 'excepcion al leer el archivo' }
            $errors.Add([pscustomobject]@{ Path = $f.FullName; Error = $err })
            continue
        }

        $cap = Get-DriverCapabilityScore -Info $info -Config $config
        $exp = Get-DriverExposure -Info $info -Config $config
        $trust = Get-DriverTrust -Path $f.FullName -Config $config
        $risk = Get-DriverRiskScore -Capability $cap -Exposure $exp -Trust $trust -Config $config
        $known = Compare-DriverAgainstKnownList -Path $f.FullName -Sha256 $info.Sha256 -ListPath $KnownListPath

        $result = [pscustomobject][ordered]@{
            Path                 = $f.FullName
            FileName             = $f.Name
            Sha256               = $info.Sha256
            FileSizeBytes        = $info.FileSizeBytes
            Is64Bit              = $info.Is64Bit
            Subsystem            = $info.Subsystem
            IsDriverLike         = $info.IsDriverLike
            ImportParseTruncated = $info.ImportParseTruncated
            HasRWXSection        = $info.HasRWXSection
            RWXSections          = $info.RWXSections
            CapabilityHits       = $cap.Hits
            CapabilitySubtotal   = $cap.Subtotal
            Exposure             = $exp
            Trust                = $trust
            Score                = $risk.Score
            Severity             = $risk.Severity
            Breakdown            = $risk.Breakdown
            KnownListMatch       = $known
        }
        $results.Add($result)

        if ($info.HasRWXSection) {
            $findings.Add((ConvertTo-DtFinding -Rule 'DT004' -Title "Seccion ejecutable y modificable (RWX) detectada" -Severity 'High' -Confidence 'Confirmed' `
                -Path $f.FullName -Hash $info.Sha256 -Evidence "Secciones RWX: $(($info.RWXSections) -join ', '). Violacion del principio W^X en espacio de kernel." -Mitre 'T1055'))
        }

        if ($known.Matched -and $known.MatchType -eq 'Hash') {
            $findings.Add((ConvertTo-DtFinding -Rule 'DT002' -Title "Driver vulnerable conocido (coincidencia por hash)" -Severity 'Critical' -Confidence 'Confirmed' `
                -Path $f.FullName -Hash $info.Sha256 -Evidence "Coincide con '$($known.Name)' de $($known.Source). $($known.Note)" -Mitre 'T1068'))
        }
        elseif ($known.Matched -and $known.MatchType -eq 'FileName') {
            $findings.Add((ConvertTo-DtFinding -Rule 'DT003' -Title "Nombre coincide con un driver vulnerable conocido (hash distinto)" -Severity 'High' -Confidence 'Heuristic' `
                -Path $f.FullName -Hash $info.Sha256 -Evidence "Nombre de archivo coincide con '$($known.Name)' de $($known.Source), pero el hash no coincide. $($known.Note)" -Mitre 'T1036.005'))
        }

        if ($risk.Severity -ne 'None' -or $IncludeClean) {
            $hitSummary = ($cap.Hits | ForEach-Object { "$($_.Detail) (+$($_.Weight))" }) -join '; '
            if (-not $hitSummary) { $hitSummary = 'sin capacidades peligrosas detectadas' }
            $dt001Severity = $risk.Severity; if ($dt001Severity -eq 'None') { $dt001Severity = 'Low' }
            $findings.Add((ConvertTo-DtFinding -Rule 'DT001' -Title "Puntaje de capacidades peligrosas: $($risk.Score)" -Severity $dt001Severity -Confidence 'Heuristic' `
                -Path $f.FullName -Hash $info.Sha256 -Evidence "$($risk.Breakdown). Capacidades: $hitSummary" -Mitre 'T1068'))
        }
    }

    if ($totalCount -gt 3) {
        Write-Progress -Activity 'DriverTriage: Analizando drivers' -Completed
    }

    $findings = @($findings | Sort-Object @{ Expression = { Get-DtSeverityRank $_.Severity }; Descending = $true })
    $resolvedOutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    if (-not (Test-Path -LiteralPath $resolvedOutDir)) { New-Item -ItemType Directory -Path $resolvedOutDir -Force | Out-Null }
    $jsonPath = Join-Path $resolvedOutDir 'findings.json'
    $htmlPath = Join-Path $resolvedOutDir 'report.html'

    $resultsForJson = $results | Select-Object Path, FileName, Sha256, FileSizeBytes, Is64Bit, Subsystem, IsDriverLike, ImportParseTruncated, HasRWXSection, RWXSections, CapabilityHits, CapabilitySubtotal, Exposure, Trust, Score, Severity, Breakdown, KnownListMatch
    ConvertTo-Json -InputObject $resultsForJson -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Export-DriverTriageReport -Result $results -Path $htmlPath

    [pscustomobject]@{
        ScannedCount = $results.Count
        ErrorCount   = $errors.Count
        BySeverity   = ($results | Group-Object Severity | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ' '
        Results      = @($results)
        Findings     = $findings
        Errors       = @($errors)
        FindingsPath = $jsonPath
        ReportPath   = $htmlPath
    }
}
