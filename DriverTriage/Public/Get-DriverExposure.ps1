function Get-DriverExposure {
    <#
    .SYNOPSIS
    Heuristica de exposicion: el driver crea un dispositivo accesible sin control de acceso explicito?
    .NOTES
    LIMITACION: se basa solo en que funciones importa, no en el flujo de control real. Un driver puede
    importar IoCreateDeviceSecure y de todos modos usar un SDDL permisivo, o resolver la API en tiempo de
    ejecucion (GetProcAddress-like via MmGetSystemRoutineAddress) y evadir esta deteccion por completo.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Info, [hashtable]$Config)
    if (-not $Config) { $Config = Get-DtConfig }
    $names = $Info.ImportFunctionNames
    $hasDevice = @($names | Where-Object { $Config.ExposureImports.DeviceCreate -contains $_ }).Count -gt 0
    $hasSecure = @($names | Where-Object { $Config.ExposureImports.DeviceCreateSecure -contains $_ }).Count -gt 0
    $hasSymlink = @($names | Where-Object { $Config.ExposureImports.SymbolicLink -contains $_ }).Count -gt 0

    if ($hasDevice -and -not $hasSecure) {
        $class = 'UnsecuredDevice'; $reason = 'IoCreateDevice sin IoCreateDeviceSecure: sin control de acceso declarado.'
    }
    elseif ($hasSecure) {
        $class = 'SecuredDevice'; $reason = 'IoCreateDeviceSecure presente: probable SDDL (no verificado, el SDDL puede ser permisivo).'
    }
    else {
        $class = 'NoDeviceObject'; $reason = 'Sin import de creacion de dispositivo detectado (puede resolverse en tiempo de ejecucion).'
    }

    [pscustomobject]@{
        Classification = $class
        Multiplier     = [double]$Config.ExposureMultipliers[$class]
        HasSymbolicLink = $hasSymlink
        Reason         = $reason
    }
}
