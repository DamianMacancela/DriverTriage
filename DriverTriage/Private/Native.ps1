# Carga el parser de PE (C#) una sola vez por sesion y expone un wrapper en PowerShell.

function Initialize-DtNative {
    if (-not ('DriverTriage.PEParser' -as [type])) {
        $csPath = Join-Path $PSScriptRoot 'PEParser.cs'
        Add-Type -Path $csPath -ErrorAction Stop
    }
}

function Read-DriverPEInfo {
    <#
    .SYNOPSIS
    Parsea un archivo PE (DOS/NT headers, secciones, tabla de importacion). Solo lectura, sin ejecutar nada.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Initialize-DtNative
    $bytes = [IO.File]::ReadAllBytes($Path)
    $r = [DriverTriage.PEParser]::Parse($bytes)
    if (-not $r.Success) {
        return [pscustomobject]@{ Success = $false; Error = $r.Error; Path = $Path }
    }

    $sections = foreach ($s in $r.Sections) {
        [pscustomobject][ordered]@{
            Name             = $s.Name
            VirtualAddress   = $s.VirtualAddress
            VirtualSize      = $s.VirtualSize
            SizeOfRawData    = $s.SizeOfRawData
            PointerToRawData = $s.PointerToRawData
            IsExecutable     = $s.IsExecutable
            IsWritable       = $s.IsWritable
        }
    }

    $imports = foreach ($m in $r.Imports) {
        $funcs = foreach ($f in $m.Functions) {
            if ($f.IsOrdinal) { "#$($f.Ordinal)" } else { $f.Name }
        }
        [pscustomobject][ordered]@{ Dll = $m.DllName; Functions = @($funcs) }
    }
    $allFunctionNames = @($r.Imports | ForEach-Object { $_.Functions } | Where-Object { -not $_.IsOrdinal } | ForEach-Object { $_.Name })

    [pscustomobject][ordered]@{
        Success               = $true
        Path                  = $Path
        Machine               = '0x{0:X}' -f $r.Machine
        Is64Bit               = $r.Is64Bit
        Subsystem             = $r.Subsystem
        IsDriverLike          = $r.IsDriverLike
        SizeOfImage           = $r.SizeOfImage
        TimeDateStamp         = $r.TimeDateStamp
        HasSecurityDirectory  = $r.HasSecurityDirectory
        ImportParseTruncated  = $r.ImportParseTruncated
        Sections              = @($sections)
        Imports               = @($imports)
        ImportFunctionNames   = $allFunctionNames
        RawBytes              = $bytes
    }
}
