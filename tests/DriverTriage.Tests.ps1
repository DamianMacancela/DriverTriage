BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers/New-SyntheticDriverPE.ps1')
    Import-Module (Join-Path $PSScriptRoot '../DriverTriage/DriverTriage.psd1') -Force
    $script:Data = Join-Path $PSScriptRoot 'data'
    $script:Vuln = Join-Path $script:Data 'vulnerable-like.sys'
    $script:Benign = Join-Path $script:Data 'benign-like.sys'
    if (-not (Test-Path $script:Vuln)) {
        $vulnImports = @(@{ Dll = 'ntoskrnl.exe'; Functions = @('MmMapIoSpace', 'ZwTerminateProcess', 'IoCreateDevice', 'ZwOpenProcess') }, @{ Dll = 'hal.dll'; Functions = @('READ_PORT_UCHAR') })
        New-SyntheticDriverPE -Path $script:Vuln -Imports $vulnImports -WideStrings @('\Device\PhysicalMemory') -OpcodeSequences @(, [byte[]](0x0F, 0x32)) | Out-Null
    }
    if (-not (Test-Path $script:Benign)) {
        $benignImports = @(@{ Dll = 'ntoskrnl.exe'; Functions = @('ZwCreateFile', 'ZwWriteFile', 'IoCreateDeviceSecure', 'IoCreateSymbolicLink') })
        New-SyntheticDriverPE -Path $script:Benign -Imports $benignImports | Out-Null
    }
    $script:Result = Invoke-DriverTriageScan -Path $script:Data -OutputDirectory (Join-Path $TestDrive 'out') -IncludeClean
    $script:VulnRes = $script:Result.Results | Where-Object FileName -eq 'vulnerable-like.sys'
    $script:BenignRes = $script:Result.Results | Where-Object FileName -eq 'benign-like.sys'
}

Describe 'Parser de PE (DOS/NT/secciones/imports)' {
    It 'identifica x64 y subsistema nativo (tipico de driver)' {
        $script:VulnRes.Is64Bit | Should -Be $true
        $script:VulnRes.IsDriverLike | Should -Be $true
    }
    It 'extrae los nombres de funcion importados' {
        ($script:VulnRes | Select-Object -ExpandProperty CapabilityHits).Detail | Should -Contain 'MmMapIoSpace'
    }
}

Describe 'Puntaje de capacidades' {
    It 'el driver vulnerable-like puntua mucho mas alto que el benigno' {
        $script:VulnRes.Score | Should -BeGreaterThan $script:BenignRes.Score
    }
    It 'severidad Critical para el patron BYOVD clasico' {
        $script:VulnRes.Severity | Should -Be 'Critical'
    }
    It 'severidad Low para imports benignos de archivo' {
        $script:BenignRes.Severity | Should -Be 'Low'
    }
    It 'detecta la cadena de memoria fisica' {
        $script:VulnRes.CapabilityHits.Detail -join ';' | Should -Match 'PhysicalMemory'
    }
    It 'detecta el opcode RDMSR solo en la seccion ejecutable' {
        $script:VulnRes.CapabilityHits.Detail -join ';' | Should -Match 'RDMSR'
    }
}

Describe 'Exposicion' {
    It 'dispositivo sin IoCreateDeviceSecure se clasifica como UnsecuredDevice' {
        $script:VulnRes.Exposure.Classification | Should -Be 'UnsecuredDevice'
    }
    It 'IoCreateDeviceSecure se clasifica como SecuredDevice' {
        $script:BenignRes.Exposure.Classification | Should -Be 'SecuredDevice'
    }
}

Describe 'Lista de drivers conocidos' {
    It 'coincidencia por hash es Confirmed' {
        $h = (Get-FileHash -LiteralPath $script:Vuln -Algorithm SHA256).Hash
        $list = Join-Path $TestDrive 'known.csv'
        "Name,Sha256,Source,Note`nx.sys,$h,test,nota" | Set-Content -LiteralPath $list
        $k = Compare-DriverAgainstKnownList -Path $script:Vuln -Sha256 $h -ListPath $list
        $k.Matched | Should -Be $true
        $k.MatchType | Should -Be 'Hash'
        $k.Confidence | Should -Be 'Confirmed'
    }
    It 'coincidencia solo por nombre es Heuristic (hash distinto)' {
        $copy = Join-Path $TestDrive 'rtcore64.sys'
        Copy-Item -LiteralPath $script:Vuln -Destination $copy
        $list = Join-Path $TestDrive 'known2.csv'
        "Name,Sha256,Source,Note`nrtcore64.sys,0000000000000000000000000000000000000000000000000000000000000000,test,nota" | Set-Content -LiteralPath $list
        $k = Compare-DriverAgainstKnownList -Path $copy -Sha256 (Get-FileHash $copy -Algorithm SHA256).Hash -ListPath $list
        $k.Matched | Should -Be $true
        $k.MatchType | Should -Be 'FileName'
        $k.Confidence | Should -Be 'Heuristic'
    }
    It 'sin coincidencia -> Matched false' {
        $list = Join-Path $TestDrive 'known3.csv'
        "Name,Sha256,Source,Note`nnada.sys,0,test,nota" | Set-Content -LiteralPath $list
        $k = Compare-DriverAgainstKnownList -Path $script:Benign -Sha256 'ff' -ListPath $list
        $k.Matched | Should -Be $false
    }
}

Describe 'Reporte HTML' {
    It 'codifica HTML en todos los campos (anti-XSS)' {
        $fakeResult = [pscustomobject]@{
            FileName = '<script>alert(1)</script>'; Sha256 = 'x'; Score = 1; Severity = 'Low'
            CapabilityHits = @([pscustomobject]@{ Source='Import'; Detail='<img src=x onerror=alert(1)>'; Weight=1 })
            Exposure = [pscustomobject]@{ Classification = 'NoDeviceObject' }
            Trust = [pscustomobject]@{ Status = 'Unknown'; Signer = $null }
            KnownListMatch = [pscustomobject]@{ Matched = $false }
        }
        $p = Join-Path $TestDrive 'r.html'
        Export-DriverTriageReport -Result @($fakeResult) -Path $p
        $html = Get-Content $p -Raw
        $html | Should -Not -Match '<script>alert'
        $html | Should -Not -Match '<img src=x'
    }
}

Describe 'Metricas (Measure-DriverTriageAccuracy)' {
    It 'recall@1 captura el unico vulnerable cuando su score es el mas alto' {
        $labels = Join-Path $TestDrive 'labels.json'
        '{"vulnerable-like.sys": true, "benign-like.sys": false}' | Set-Content -LiteralPath $labels
        $m = Measure-DriverTriageAccuracy -Result $script:Result.Results -LabelsPath $labels -TopK @(1)
        ($m.RecallAtK | Where-Object K -eq 1).RecallAtK | Should -Be 1
    }
    It 'la ablacion de PhysicalMemoryMap reduce la separacion entre clases' {
        $labels = Join-Path $TestDrive 'labels2.json'
        '{"vulnerable-like.sys": true, "benign-like.sys": false}' | Set-Content -LiteralPath $labels
        $m = Measure-DriverTriageAccuracy -Result $script:Result.Results -LabelsPath $labels
        ($m.AblationByCategory | Where-Object CategoryRemoved -eq 'PhysicalMemoryMap').ContributionToSeparation | Should -BeGreaterThan 0
    }
}

Describe 'Entradas vacias' {
    It 'capacidad sobre info sin bytes no falla' {
        $info = [pscustomobject]@{ ImportFunctionNames = @(); RawBytes = $null; Sections = @() }
        $cap = Get-DriverCapabilityScore -Info $info
        $cap.Subtotal | Should -Be 0
    }
}
