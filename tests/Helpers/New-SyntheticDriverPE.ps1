# Construye un PE64 minimo y valido en bytes, SOLO para generar fixtures de prueba.
# No es un cargador ni un enlazador real: basta con que sea internamente consistente
# para que nuestro propio parser (Private/Native.ps1) lo lea correctamente.
# No se distribuye ningun binario de terceros ni de driver real: todo el contenido es sintetico.

function New-SyntheticDriverPE {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        # @(@{ Dll = 'ntoskrnl.exe'; Functions = @('MmMapIoSpace','ZwTerminateProcess') }, ...)
        [object[]]$Imports = @(),
        [string[]]$AsciiStrings = @(),   # literales ASCII a incrustar en .idata (p.ej. rutas de dispositivo)
        [string[]]$WideStrings = @(),    # literales UTF-16LE (las cadenas de kernel suelen ser UNICODE)
        [byte[][]]$OpcodeSequences = @(),# secuencias de bytes a incrustar en .text (p.ej. 0x0F,0x32 = RDMSR)
        [switch]$Signed                  # simula 'firmado' solo marcando un data directory de Security (sin verificar)
    )

    # El operador unario ',' evita que PowerShell "desenrolle" la lista (IEnumerable) en el pipeline
    # cuando esta vacia; sin el, $x = New-ByteList asignaria $null.
    function New-ByteList { , [System.Collections.Generic.List[byte]]::new() }
    function Add-U8  { param($L, [byte]$V) $L.Add($V) }
    function Add-U16 { param($L, [uint16]$V) $L.AddRange([BitConverter]::GetBytes($V)) }
    function Add-U32 { param($L, [uint32]$V) $L.AddRange([BitConverter]::GetBytes($V)) }
    function Add-U64 { param($L, [uint64]$V) $L.AddRange([BitConverter]::GetBytes($V)) }
    function Add-Bytes { param($L, [byte[]]$V) $L.AddRange($V) }
    function Add-AsciiZ { param($L, [string]$S) $L.AddRange([Text.Encoding]::ASCII.GetBytes($S)); $L.Add(0) }
    function Pad-To { param($L, [int]$Boundary) while ($L.Count % $Boundary -ne 0) { $L.Add(0) } }

    $SectionAlign = 0x1000
    $FileAlign    = 0x200
    function Align { param([int]$V, [int]$A) [int]([Math]::Ceiling($V / [double]$A) * $A) }

    # ---------- 1) Construir el contenido crudo de .idata (tabla de importacion + cadenas) ----------
    # Layout dentro de .idata (offsets relativos al INICIO de la seccion, se convierten a RVA al final):
    #   [0]            Import Directory Table: (NumDlls+1) entradas de 20 bytes (la ultima es ceros)
    #   [despues]      Por cada DLL: ILT (N+1 x 8 bytes, PE32+), IAT (N+1 x 8 bytes, copia de ILT)
    #   [despues]      Por cada funcion: Hint/Name (2 bytes hint + nombre + \0, alineado a 2)
    #   [despues]      Nombre de cada DLL (ASCII + \0)
    #   [despues]      Cadenas ASCII y UTF-16LE arbitrarias (para el escaneo de indicadores peligrosos)
    $idata = New-ByteList
    $dllCount = @($Imports).Count
    $dirTableBytes = ($dllCount + 1) * 20
    for ($i = 0; $i -lt $dirTableBytes; $i++) { $idata.Add(0) }   # reservar, se rellena al final

    $thunkBlocks = @()   # por dll: @{ IltOffset; IatOffset; FuncCount }
    foreach ($imp in $Imports) {
        $funcs = @($imp.Functions)
        $iltOff = $idata.Count
        for ($i = 0; $i -le $funcs.Count; $i++) { Add-U64 $idata 0 }   # ILT (placeholder)
        $iatOff = $idata.Count
        for ($i = 0; $i -le $funcs.Count; $i++) { Add-U64 $idata 0 }   # IAT (placeholder)
        $thunkBlocks += [pscustomobject]@{ IltOffset = $iltOff; IatOffset = $iatOff; FuncCount = $funcs.Count }
    }

    $hintNameOffsets = @()   # por dll: array de offsets (uno por funcion)
    foreach ($imp in $Imports) {
        $offs = @()
        foreach ($fn in @($imp.Functions)) {
            if ($idata.Count % 2 -ne 0) { $idata.Add(0) }
            $offs += $idata.Count
            Add-U16 $idata 0            # Hint
            Add-AsciiZ $idata $fn        # Nombre de la funcion
        }
        $hintNameOffsets += , $offs
    }

    $dllNameOffsets = @()
    foreach ($imp in $Imports) {
        $dllNameOffsets += $idata.Count
        Add-AsciiZ $idata ([string]$imp.Dll)
    }

    foreach ($s in $AsciiStrings) { Add-AsciiZ $idata $s }
    foreach ($s in $WideStrings) { $idata.AddRange([Text.Encoding]::Unicode.GetBytes($s)); Add-U16 $idata 0 }

    # ---------- 2) Seccion .text: relleno + secuencias de opcode a detectar ----------
    $text = New-ByteList
    Add-Bytes $text (@(0x90) * 64)   # NOPs de relleno
    foreach ($seq in $OpcodeSequences) { Add-Bytes $text $seq; Add-U8 $text 0x90 }
    if ($text.Count -eq 0) { Add-U8 $text 0x90 }

    # ---------- 3) Calcular RVAs/offsets de archivo (dos secciones: .text, .idata) ----------
    $headersSize = Align (0x80 + 4 + 20 + 240 + 2 * 40) $FileAlign   # DOS hdr(0x80) + PE sig + COFF + OptHdr64 + 2 secciones
    $textRawOff  = $headersSize
    $textRawSize = Align ([Math]::Max($text.Count, 1)) $FileAlign
    $textVA      = $SectionAlign
    $textVSize   = [Math]::Max($text.Count, 1)

    $idataRawOff = $textRawOff + $textRawSize
    $idataRawSize = Align ([Math]::Max($idata.Count, 1)) $FileAlign
    $idataVA     = Align ($textVA + $textVSize) $SectionAlign
    $idataVSize  = [Math]::Max($idata.Count, 1)

    $sizeOfImage = Align ($idataVA + $idataVSize) $SectionAlign

    # ---------- 4) Resolver direcciones dentro de .idata ahora que conocemos idataVA ----------
    $dir = New-ByteList
    for ($d = 0; $d -lt $dllCount; $d++) {
        $iltRva = $idataVA + $thunkBlocks[$d].IltOffset
        $iatRva = $idataVA + $thunkBlocks[$d].IatOffset
        $nameRva = $idataVA + $dllNameOffsets[$d]
        Add-U32 $dir ([uint32]$iltRva)
        Add-U32 $dir 0            # TimeDateStamp
        Add-U32 $dir 0            # ForwarderChain
        Add-U32 $dir ([uint32]$nameRva)
        Add-U32 $dir ([uint32]$iatRva)
    }
    for ($i = 0; $i -lt 20; $i++) { $dir.Add(0) }   # entrada nula de terminacion

    $final = New-ByteList
    Add-Bytes $final $dir.ToArray()
    $restStart = $dir.Count
    for ($i = $restStart; $i -lt $idata.Count; $i++) { $final.Add($idata[$i]) }

    for ($d = 0; $d -lt $dllCount; $d++) {
        $iltOff = $thunkBlocks[$d].IltOffset
        $iatOff = $thunkBlocks[$d].IatOffset
        $offs = $hintNameOffsets[$d]
        for ($f = 0; $f -lt $offs.Count; $f++) {
            $hnRva = [uint64]($idataVA + $offs[$f])
            $bytes = [BitConverter]::GetBytes($hnRva)
            for ($b = 0; $b -lt 8; $b++) { $final[$iltOff + $f * 8 + $b] = $bytes[$b]; $final[$iatOff + $f * 8 + $b] = $bytes[$b] }
        }
    }
    $idataFinal = $final.ToArray()

    # ---------- 5) Encabezados ----------
    $file = New-ByteList
    # DOS header (64 bytes)
    Add-U16 $file 0x5A4D                      # e_magic 'MZ'
    Add-Bytes $file (@(0) * 0x3A)              # relleno hasta e_lfanew (offset 0x3C)
    Add-U32 $file 0x80                         # e_lfanew
    Pad-To $file 0x80

    # PE signature + COFF header
    Add-Bytes $file ([Text.Encoding]::ASCII.GetBytes('PE')); Add-U16 $file 0
    Add-U16 $file 0x8664                       # Machine = AMD64
    Add-U16 $file 2                            # NumberOfSections
    Add-U32 $file 0                            # TimeDateStamp
    Add-U32 $file 0                            # PointerToSymbolTable
    Add-U32 $file 0                            # NumberOfSymbols
    Add-U16 $file 240                          # SizeOfOptionalHeader (IMAGE_OPTIONAL_HEADER64)
    $characteristics = 0x0002 -bor 0x0020 -bor 0x0002   # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    Add-U16 $file ([uint16]0x0022)

    # Optional header 64
    Add-U16 $file 0x20B                        # Magic PE32+
    Add-U8 $file 14; Add-U8 $file 0             # Linker version
    Add-U32 $file ([uint32]$textVSize)          # SizeOfCode
    Add-U32 $file ([uint32]$idataVSize)         # SizeOfInitializedData
    Add-U32 $file 0                             # SizeOfUninitializedData
    Add-U32 $file ([uint32]$textVA)             # AddressOfEntryPoint (dummy, dentro de .text)
    Add-U32 $file ([uint32]$textVA)             # BaseOfCode
    Add-U64 $file 0x0000000140000000            # ImageBase (tipico de driver x64)
    Add-U32 $file ([uint32]$SectionAlign)
    Add-U32 $file ([uint32]$FileAlign)
    Add-U16 $file 10; Add-U16 $file 0           # OS version
    Add-U16 $file 0; Add-U16 $file 0            # Image version
    Add-U16 $file 10; Add-U16 $file 0           # Subsystem version
    Add-U32 $file 0                             # Win32VersionValue
    Add-U32 $file ([uint32]$sizeOfImage)
    Add-U32 $file ([uint32]$headersSize)
    Add-U32 $file 0                             # CheckSum
    Add-U16 $file 1                             # Subsystem = NATIVE (tipico de drivers de kernel)
    Add-U16 $file 0                             # DllCharacteristics
    Add-U64 $file 0x40000                       # SizeOfStackReserve
    Add-U64 $file 0x1000                        # SizeOfStackCommit
    Add-U64 $file 0x100000                      # SizeOfHeapReserve
    Add-U64 $file 0x1000                        # SizeOfHeapCommit
    Add-U32 $file 0                             # LoaderFlags
    Add-U32 $file 16                            # NumberOfRvaAndSizes

    # DataDirectory[16]: solo llenamos Import(1) y opcionalmente Security(4, no verificado por nuestro parser)
    for ($i = 0; $i -lt 16; $i++) {
        if ($i -eq 1) { Add-U32 $file ([uint32]$idataVA); Add-U32 $file ([uint32]$idataFinal.Length) }
        elseif ($i -eq 4 -and $Signed) { Add-U32 $file 0; Add-U32 $file 1 }   # marcador no-verificable, solo para pruebas
        else { Add-U32 $file 0; Add-U32 $file 0 }
    }

    # Section headers
    function Add-SectionHeader { param($L, [string]$Name, $VSize, $VA, $RawSize, $RawOff, [uint32]$Chars)
        $n = [Text.Encoding]::ASCII.GetBytes($Name)
        $nb = New-Object byte[] 8
        [Array]::Copy($n, $nb, [Math]::Min(8, $n.Length))
        Add-Bytes $L $nb
        Add-U32 $L ([uint32]$VSize); Add-U32 $L ([uint32]$VA)
        Add-U32 $L ([uint32]$RawSize); Add-U32 $L ([uint32]$RawOff)
        Add-U32 $L 0; Add-U32 $L 0; Add-U16 $L 0; Add-U16 $L 0
        Add-U32 $L $Chars
    }
    Add-SectionHeader $file '.text'  $textVSize  $textVA  $textRawSize  $textRawOff  ([uint32]0x60000020L)   # CODE|EXEC|READ
    Add-SectionHeader $file '.idata' $idataVSize $idataVA $idataRawSize $idataRawOff ([uint32]0xC0000040L)   # INIT_DATA|READ|WRITE

    Pad-To $file $headersSize

    $textBytes = $text.ToArray()
    Add-Bytes $file $textBytes
    Pad-To $file ($textRawOff + $textRawSize)

    Add-Bytes $file $idataFinal
    Pad-To $file ($idataRawOff + $idataRawSize)

    [IO.File]::WriteAllBytes($Path, $file.ToArray())
    Get-Item -LiteralPath $Path
}
