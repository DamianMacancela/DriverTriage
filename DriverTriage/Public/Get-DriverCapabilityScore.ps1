function Get-DriverCapabilityScore {
    <#
    .SYNOPSIS
    Puntua capacidades peligrosas a partir de imports, cadenas y opcodes. Funcion pura (sin red ni disco
    salvo los bytes ya cargados en $Info).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Info, [hashtable]$Config)
    if (-not $Config) { $Config = Get-DtConfig }
    $hits = [System.Collections.Generic.List[object]]::new()

    foreach ($fn in ($Info.ImportFunctionNames | Select-Object -Unique)) {
        if ($Config.ImportWeights.ContainsKey($fn)) {
            $w = $Config.ImportWeights[$fn]
            $hits.Add([pscustomobject]@{ Source = 'Import'; Detail = $fn; Category = $w.Category; Weight = $w.Weight; Mitre = $w.Mitre })
        }
    }

    if ($Info.RawBytes) {
        foreach ($s in (Find-DtDangerousString -Bytes $Info.RawBytes -Patterns $Config.DangerousStrings)) {
            $hits.Add([pscustomobject]@{ Source = 'String'; Detail = "'$($s.Text)' x$($s.Count)"; Category = $s.Category; Weight = $s.Weight; Mitre = $s.Mitre })
        }
        foreach ($o in (Find-DtOpcodePattern -Bytes $Info.RawBytes -Sections $Info.Sections -Patterns $Config.OpcodePatterns)) {
            $hits.Add([pscustomobject]@{ Source = 'Opcode'; Detail = "$($o.Name) x$($o.Count)"; Category = 'Opcode'; Weight = $o.Weight; Mitre = $o.Mitre })
        }
    }

    if ($Info.Sections) {
        $rwxWeight = 4
        $rwxCategory = 'WritableExecutableSection'
        $rwxMitre = 'T1055'
        if ($Config.StructuralWeights -and $Config.StructuralWeights.RWXSection) {
            $rwxWeight = $Config.StructuralWeights.RWXSection.Weight
            $rwxCategory = $Config.StructuralWeights.RWXSection.Category
            $rwxMitre = $Config.StructuralWeights.RWXSection.Mitre
        }
        foreach ($sec in ($Info.Sections | Where-Object { $_.IsRWX })) {
            $hits.Add([pscustomobject]@{
                Source   = 'Section'
                Detail   = "RWX Section '$($sec.Name)'"
                Category = $rwxCategory
                Weight   = $rwxWeight
                Mitre    = $rwxMitre
            })
        }
    }

    $subtotal = 0.0
    foreach ($h in $hits) { $subtotal += [double]$h.Weight }

    [pscustomobject]@{ Hits = @($hits); Subtotal = [Math]::Round($subtotal, 2) }
}
