#Requires -Version 5.1
# DriverTriage - puntua drivers de kernel por capacidades peligrosas para encontrar candidatos BYOVD
# que aun no estan en ninguna lista. Solo lectura y solo defensivo: no genera ni contiene codigo de explotacion.

$script:ModuleRoot = $PSScriptRoot

foreach ($dir in 'Private', 'Public') {
    $files = Get-ChildItem -Path (Join-Path $PSScriptRoot $dir) -Filter '*.ps1' -File | Sort-Object Name
    foreach ($f in $files) { . $f.FullName }
}

Initialize-DtNative

Export-ModuleMember -Function `
    Get-DriverInventory, Get-DriverPEInfo, Get-DriverCapabilityScore, Get-DriverExposure, Get-DriverTrust, `
    Get-DriverRiskScore, Compare-DriverAgainstKnownList, Invoke-DriverTriageScan, Export-DriverTriageReport, `
    Measure-DriverTriageAccuracy
