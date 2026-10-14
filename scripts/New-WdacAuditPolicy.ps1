<#
.SYNOPSIS
Genera un BORRADOR de politica WDAC en modo AUDITORIA (nunca enforce) a partir de los hallazgos de
severidad alta/critica de DriverTriage. Requiere Windows. Revisa el XML generado antes de desplegarlo.
.NOTES
Modo auditoria = no bloquea nada, solo registra eventos si el driver se cargaria. Es el unico modo que
este script produce a proposito.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FindingsJsonPath,
    [string]$OutputPath = '.\drivertriage-wdac-audit.xml',
    [double]$MinScore = 8
)
if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) {
    throw 'New-CIPolicy requiere el modulo ConfigCI de Windows (no disponible en este sistema).'
}
$results = Get-Content -LiteralPath $FindingsJsonPath -Raw | ConvertFrom-Json
$targets = @($results | Where-Object { $_.Score -ge $MinScore })
if ($targets.Count -eq 0) { Write-Warning "Ningun driver supera el puntaje minimo ($MinScore)."; return }

$tmpDir = Join-Path $env:TEMP ("wdac-audit-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    $i = 0
    foreach ($t in $targets) {
        $i++
        $leaf = Split-Path -Path $t.Path -Leaf
        $destFile = Join-Path $tmpDir ("{0:D4}_{1}" -f $i, $leaf)
        Copy-Item -LiteralPath $t.Path -Destination $destFile -ErrorAction SilentlyContinue
    }

    New-CIPolicy -FilePath $OutputPath -ScanPath $tmpDir -Level Hash -UserPEs -Audit -Fallback Hash
    Write-Output "Politica de AUDITORIA generada: $OutputPath ($($targets.Count) driver(s)). Revisala antes de desplegar."
}
finally {
    if (Test-Path -LiteralPath $tmpDir) {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

