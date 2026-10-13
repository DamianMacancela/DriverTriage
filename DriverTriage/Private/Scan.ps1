# Escaneo de opcodes y cadenas sobre los bytes crudos. Heuristicas de solo lectura (no desensamblan,
# no respetan limites de instruccion): sirven de senal de apoyo, nunca de prueba por si solas.

function Find-DtBytePattern {
    # Busca TODAS las ocurrencias no superpuestas de $Pattern dentro de $Haystack[$Start..$End).
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Haystack, [Parameter(Mandatory)][byte[]]$Pattern, [int]$Start = 0, [int]$End = -1)
    if ($End -lt 0) { $End = $Haystack.Length }
    $count = 0
    $i = $Start
    $lastByte = $End - $Pattern.Length
    while ($i -le $lastByte) {
        $match = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Pattern[$j]) { $match = $false; break }
        }
        if ($match) { $count++; $i += $Pattern.Length } else { $i++ }
    }
    $count
}

function Find-DtOpcodePattern {
    <#
    .SYNOPSIS
    Cuenta ocurrencias de cada patron de opcode SOLO dentro de secciones marcadas ejecutables.
    .NOTES
    Heuristica de alto riesgo de falsos positivos: un byte de datos puede coincidir por azar con un opcode.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][object[]]$Sections, [Parameter(Mandatory)][object[]]$Patterns)
    $execSections = @($Sections | Where-Object IsExecutable)
    foreach ($p in $Patterns) {
        $total = 0
        foreach ($s in $execSections) {
            $start = [int]$s.PointerToRawData
            $len = [int][Math]::Min($s.SizeOfRawData, $s.VirtualSize)
            if ($len -le 0) { $len = [int]$s.SizeOfRawData }
            $end = [Math]::Min($Bytes.Length, $start + $len)
            if ($start -ge $end) { continue }
            $total += Find-DtBytePattern -Haystack $Bytes -Pattern ([byte[]]$p.Bytes) -Start $start -End $end
        }
        if ($total -gt 0) {
            [pscustomobject]@{ Name = $p.Name; Count = $total; Weight = $p.Weight; Mitre = $p.Mitre }
        }
    }
}

function Find-DtDangerousString {
    <#
    .SYNOPSIS
    Busca cadenas configuradas en ASCII y UTF-16LE en TODO el archivo (no solo en secciones de datos:
    algunos packers mueven cadenas fuera de las secciones declaradas).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][object[]]$Patterns)
    foreach ($p in $Patterns) {
        $asciiPattern = [Text.Encoding]::ASCII.GetBytes([string]$p.Text)
        $widePattern = [Text.Encoding]::Unicode.GetBytes([string]$p.Text)
        $hits = (Find-DtBytePattern -Haystack $Bytes -Pattern $asciiPattern) + (Find-DtBytePattern -Haystack $Bytes -Pattern $widePattern)
        if ($hits -gt 0) {
            [pscustomobject]@{ Text = $p.Text; Count = $hits; Weight = $p.Weight; Category = $p.Category; Mitre = $p.Mitre }
        }
    }
}
