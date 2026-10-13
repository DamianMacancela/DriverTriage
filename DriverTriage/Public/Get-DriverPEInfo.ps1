function Get-DriverPEInfo {
    <#
    .SYNOPSIS
    Parsea un driver y agrega metadatos (hash, tamano). Base para el resto del pipeline.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipelineByPropertyName)][Alias('FullName')][string]$Path)
    process {
        $info = Read-DriverPEInfo -Path $Path
        if (-not $info.Success) { return $info }
        $hash = Get-DtFileSha256 -Path $Path
        $size = (Get-Item -LiteralPath $Path).Length
        $info | Add-Member -NotePropertyName Sha256 -NotePropertyValue $hash -PassThru |
            Add-Member -NotePropertyName FileSizeBytes -NotePropertyValue $size -PassThru
    }
}
