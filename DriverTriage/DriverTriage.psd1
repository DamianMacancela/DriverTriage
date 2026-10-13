@{
    RootModule        = 'DriverTriage.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '06c09273-27cf-470f-8034-63a24d4a2866'
    Author            = 'Damian Fabricio Macancela'
    Description       = 'Puntua drivers de kernel de Windows por capacidades peligrosas (mapeo de memoria fisica, terminacion de procesos, MSR/puertos de E/S, cadenas de dispositivo) para priorizar candidatos BYOVD desconocidos, cruzados contra una lista de drivers ya conocidos. Solo lectura y solo defensivo.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-DriverInventory', 'Get-DriverPEInfo', 'Get-DriverCapabilityScore', 'Get-DriverExposure', 'Get-DriverTrust',
        'Get-DriverRiskScore', 'Compare-DriverAgainstKnownList', 'Invoke-DriverTriageScan', 'Export-DriverTriageReport',
        'Measure-DriverTriageAccuracy'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('BYOVD', 'KernelDriver', 'ThreatHunting', 'BlueTeam', 'MITRE-ATTACK', 'WDAC', 'Windows')
            LicenseUri = 'https://github.com/DamianMacancela/DriverTriage/blob/main/LICENSE'
            ProjectUri = 'https://github.com/DamianMacancela/DriverTriage'
        }
    }
}
