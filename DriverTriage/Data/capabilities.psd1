# Pesos y patrones de deteccion. Archivo de datos puro (Import-PowerShellDataFile: no ejecuta codigo).
# Los pesos son HIPOTESIS de partida, no verdades medidas: calibralos con Measure-DriverTriageAccuracy
# contra un corpus etiquetado (ver docs/METHODOLOGY.md). Ajusta por entorno.
@{
    # Peso por funcion importada. Categoria y Mitre son informativos (para el reporte), no afectan el calculo.
    ImportWeights = @{
        'MmMapIoSpace'                 = @{ Weight = 5; Category = 'PhysicalMemoryMap';  Mitre = 'T1055' }
        'MmMapIoSpaceEx'               = @{ Weight = 5; Category = 'PhysicalMemoryMap';  Mitre = 'T1055' }
        'ZwMapViewOfSection'           = @{ Weight = 3; Category = 'SectionMapping';     Mitre = 'T1055' }
        'NtMapViewOfSection'           = @{ Weight = 3; Category = 'SectionMapping';     Mitre = 'T1055' }
        'MmMapLockedPagesSpecifyCache' = @{ Weight = 3; Category = 'MdlMapping';         Mitre = 'T1055' }
        'MmProbeAndLockPages'          = @{ Weight = 2; Category = 'MdlMapping';         Mitre = 'T1055' }
        'MmGetPhysicalAddress'         = @{ Weight = 2; Category = 'PhysicalMemoryMap';  Mitre = 'T1055' }
        'ZwOpenProcess'                = @{ Weight = 2; Category = 'ProcessAccess';      Mitre = 'T1055' }
        'PsLookupProcessByProcessId'   = @{ Weight = 2; Category = 'ProcessAccess';      Mitre = 'T1055' }
        'ObReferenceObjectByHandle'    = @{ Weight = 2; Category = 'HandleAccess';       Mitre = 'T1055' }
        'ZwTerminateProcess'           = @{ Weight = 4; Category = 'ProcessTermination'; Mitre = 'T1489' }
        'PsTerminateSystemThread'      = @{ Weight = 2; Category = 'ProcessTermination'; Mitre = 'T1489' }
        'ZwCreateFile'                 = @{ Weight = 1; Category = 'FileIO';             Mitre = 'T1106' }
        'ZwWriteFile'                  = @{ Weight = 1; Category = 'FileIO';             Mitre = 'T1106' }
        'ZwSetValueKey'                = @{ Weight = 1; Category = 'RegistryWrite';      Mitre = 'T1112' }
        'ZwDeleteValueKey'             = @{ Weight = 1; Category = 'RegistryWrite';      Mitre = 'T1112' }
        'IoAllocateMdl'                = @{ Weight = 1; Category = 'MdlMapping';         Mitre = 'T1055' }
    }

    # Importaciones que solo sirven para la heuristica de EXPOSICION (no suman puntaje de capacidad por si solas).
    ExposureImports = @{
        DeviceCreate       = @('IoCreateDevice')
        DeviceCreateSecure = @('IoCreateDeviceSecure')
        SymbolicLink       = @('IoCreateSymbolicLink')
    }

    # Cadenas (ASCII y UTF-16LE) cuya sola presencia en el binario es una senal fuerte.
    DangerousStrings = @(
        @{ Text = '\Device\PhysicalMemory'; Weight = 5; Category = 'PhysicalMemoryDeviceName'; Mitre = 'T1055' }
    )

    # Patrones de opcode: heuristica de ALTO riesgo de falsos positivos (no respeta limites de instruccion).
    # Peso deliberadamente bajo: es una senal de apoyo, no una prueba.
    OpcodePatterns = @(
        @{ Name = 'RDMSR';              Bytes = @(0x0F, 0x32); Weight = 2; Mitre = 'T1014' }
        @{ Name = 'WRMSR';              Bytes = @(0x0F, 0x30); Weight = 2; Mitre = 'T1014' }
        @{ Name = 'IN (puerto, imm8)';  Bytes = @(0xE4);       Weight = 1; Mitre = 'T1014' }
        @{ Name = 'OUT (puerto, imm8)'; Bytes = @(0xE6);       Weight = 1; Mitre = 'T1014' }
    )

    # Multiplicador segun si el driver expone un dispositivo accesible sin control de acceso explicito.
    ExposureMultipliers = @{
        UnsecuredDevice = 1.5   # IoCreateDevice sin IoCreateDeviceSecure
        SecuredDevice   = 0.7   # IoCreateDeviceSecure presente (probable SDDL, no garantizado)
        NoDeviceObject  = 0.5   # ningun import de creacion de dispositivo detectado
    }

    # Multiplicador segun el estado de firma (Windows); en otros SO o si no se puede verificar: Unknown = 1.0.
    TrustMultipliers = @{
        ValidKnownVendor = 0.5
        ValidOther        = 1.0
        Invalid           = 1.3
        Unsigned          = 1.3
        Unknown           = 1.0
    }

    # Umbrales de severidad sobre el puntaje final (capacidad x exposicion x confianza).
    SeverityThresholds = @{
        Low      = 1
        Medium   = 4
        High     = 8
        Critical = 14
    }

    # Publishers conocidos y confiables para el multiplicador ValidKnownVendor (ajustar por entorno).
    KnownVendors = @(
        'Microsoft Windows', 'Microsoft Corporation', 'Intel Corporation', 'NVIDIA Corporation',
        'Advanced Micro Devices, Inc.', 'Realtek Semiconductor Corp.'
    )
}
