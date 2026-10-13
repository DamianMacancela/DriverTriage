function Get-DriverInventory {
    <#
    .SYNOPSIS
    Enumera drivers a analizar: desde el sistema vivo (Windows) o desde rutas dadas (cualquier SO, para
    pruebas y para analizar una carpeta de drivers extraidos).
    .EXAMPLE
    Get-DriverInventory -Path C:\Windows\System32\drivers
    .EXAMPLE
    Get-DriverInventory -UseSystemInventory    # Windows: drivers actualmente cargados
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(ParameterSetName = 'Path')][string[]]$Path,
        [Parameter(ParameterSetName = 'System')][switch]$UseSystemInventory
    )
    if ($UseSystemInventory) {
        if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
            throw 'UseSystemInventory requiere Windows (Get-CimInstance no disponible).'
        }
        Get-CimInstance -ClassName Win32_SystemDriver |
            Where-Object { $_.PathName } |
            ForEach-Object {
                $p = $_.PathName -replace '^\\\?\?\\', '' -replace '^"|"$', ''
                if (Test-Path -LiteralPath $p) { Get-Item -LiteralPath $p }
            }
        return
    }
    if (-not $Path) { throw 'Especifica -Path o -UseSystemInventory.' }
    foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p -PathType Container) {
            Get-ChildItem -LiteralPath $p -Recurse -File -Include '*.sys' -ErrorAction SilentlyContinue
        }
        elseif (Test-Path -LiteralPath $p -PathType Leaf) {
            Get-Item -LiteralPath $p
        }
        else {
            Write-Warning "Ruta no encontrada: $p"
        }
    }
}
