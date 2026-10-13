function Get-DriverTrust {
    <#
    .SYNOPSIS
    Estado de firma Authenticode. Solo funciona en Windows; en otros SO (o si el cmdlet no existe)
    devuelve Unknown sin fallar, para que el resto del pipeline siga siendo portable.
    .NOTES
    LIMITACION: la verificacion de firma no consulta revocacion en el momento de carga del driver real;
    un certificado revocado puede seguir reportando 'Valid' aqui. Ver docs/METHODOLOGY.md.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [hashtable]$Config)
    if (-not $Config) { $Config = Get-DtConfig }

    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Status = 'Unknown'; Signer = $null; Multiplier = $Config.TrustMultipliers.Unknown; Reason = 'Get-AuthenticodeSignature no disponible en este sistema operativo.' }
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    $signer = $null
    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1' }

    switch ($sig.Status) {
        'Valid' {
            $known = @($Config.KnownVendors | Where-Object { $signer -and $signer -like "*$_*" })
            if ($known.Count -gt 0) {
                [pscustomobject]@{ Status = 'Valid'; Signer = $signer; Multiplier = $Config.TrustMultipliers.ValidKnownVendor; Reason = 'Firma valida de un publisher conocido.' }
            }
            else {
                [pscustomobject]@{ Status = 'Valid'; Signer = $signer; Multiplier = $Config.TrustMultipliers.ValidOther; Reason = 'Firma valida de un publisher no listado como conocido.' }
            }
        }
        'NotSigned' {
            [pscustomobject]@{ Status = 'Unsigned'; Signer = $null; Multiplier = $Config.TrustMultipliers.Unsigned; Reason = 'El archivo no esta firmado.' }
        }
        default {
            [pscustomobject]@{ Status = 'Invalid'; Signer = $signer; Multiplier = $Config.TrustMultipliers.Invalid; Reason = "Firma invalida o no verificable: $($sig.Status)." }
        }
    }
}
