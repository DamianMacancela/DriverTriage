function Export-DriverTriageReport {
    <#
    .SYNOPSIS
    Reporte HTML estatico y autocontenido. Todo valor se codifica: nombres de driver, publishers y
    cadenas extraidas del binario son input hostil.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result, [Parameter(Mandatory)][string]$Path, [string]$Title = 'DriverTriage - informe de auditoria')
    $enc = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }
    $cls = @{ Critical = 'crit'; High = 'high'; Medium = 'med'; Low = 'low'; None = 'none' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendLine("<title>$(& $enc $Title)</title>")
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px 8px;font-size:13px;vertical-align:top}th{background:#222;color:#fff;text-align:left}.crit td:first-child{background:#b00020;color:#fff}.high td:first-child{background:#e65100;color:#fff}.med td:first-child{background:#f9a825}.low td:first-child{background:#c5e1a5}.none td:first-child{background:#eee}.warn{font-size:12px;color:#7a4b00}code{font-size:12px}</style>')
    [void]$sb.AppendLine("<h1>$(& $enc $Title)</h1><p>Generado: $(Get-Date -Format s) | Drivers: $(@($Result).Count)</p>")
    [void]$sb.AppendLine("<p class='warn'>Heuristica de solo lectura, nunca una prueba de explotabilidad. Cruza siempre con investigacion manual antes de bloquear o reportar.</p>")

    [void]$sb.AppendLine('<table><tr><th>Severidad</th><th>Archivo</th><th>SHA-256</th><th>Puntaje</th><th>Exposicion</th><th>Confianza</th><th>Lista conocida</th><th>Capacidades</th></tr>')
    foreach ($r in $Result) {
        $capList = ($r.CapabilityHits | ForEach-Object { '<li>' + (& $enc "$($_.Source): $($_.Detail) (+$($_.Weight))") + '</li>' }) -join ''
        if (-not $capList) { $capList = '<li>ninguna</li>' }
        $known = 'no'
        if ($r.KnownListMatch -and $r.KnownListMatch.Matched) { $known = "$(& $enc $r.KnownListMatch.MatchType) / $(& $enc $r.KnownListMatch.Confidence) -> $(& $enc $r.KnownListMatch.Name)" }
        $sevClass = $cls[[string]$r.Severity]; if (-not $sevClass) { $sevClass = 'none' }
        [void]$sb.AppendLine("<tr class='$sevClass'><td>$(& $enc $r.Severity)</td><td>$(& $enc $r.FileName)</td><td><code>$(& $enc $r.Sha256)</code></td><td>$(& $enc $r.Score)</td><td>$(& $enc $r.Exposure.Classification)</td><td>$(& $enc $r.Trust.Status)$(if($r.Trust.Signer){' ('+(& $enc $r.Trust.Signer)+')'})</td><td>$known</td><td><ul>$capList</ul></td></tr>")
    }
    [void]$sb.AppendLine('</table></html>')
    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}
