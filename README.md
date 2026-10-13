# DriverTriage

Puntúa drivers de kernel de Windows por **capacidades peligrosas** (mapeo de memoria física, terminación
arbitraria de procesos, acceso a MSR/puertos de E/S, cadena `\Device\PhysicalMemory`) para priorizar
candidatos **BYOVD desconocidos** — los que aún no están en ninguna lista de bloqueo — en vez de depender
solo de hashes ya catalogados. Solo lectura. Solo defensivo. Sin código de explotación.

## Por qué

Las listas de bloqueo (Microsoft, LOLDrivers) son reactivas: cubren lo ya descubierto. Esta herramienta
prueba una hipótesis distinta — que la combinación de **capacidad + exposición + confianza** predice el
riesgo de un driver incluso si nunca ha sido reportado — y la **evalúa con métricas**, no con intuición.
Ver [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) para el diseño completo, las limitaciones y el roadmap.

## Arquitectura

```mermaid
flowchart LR
  I[Inventario: sistema vivo o carpeta] --> P[Parser PE propio<br/>C# vía Add-Type]
  P --> C[Puntaje de capacidad<br/>imports + cadenas + opcodes]
  P --> E[Exposición<br/>IoCreateDevice vs Secure]
  I --> T[Confianza<br/>Authenticode, solo Windows]
  C --> S[Puntaje final = capacidad x exposición x confianza]
  E --> S
  T --> S
  S --> K[Cruce con lista de conocidos]
  S --> R[Reporte HTML + JSON]
  K --> R
  S --> M[Measure-DriverTriageAccuracy<br/>sobre corpus etiquetado]
```

## Instalación y primer uso

```powershell
Import-Module .\DriverTriage\DriverTriage.psd1

# Demo sin drivers reales: genera 2 fixtures SINTETICAS y las analiza
. .\tests\Helpers\New-SyntheticDriverPE.ps1
New-SyntheticDriverPE -Path .\tests\data\vulnerable-like.sys `
    -Imports @(@{Dll='ntoskrnl.exe';Functions=@('MmMapIoSpace','ZwTerminateProcess','IoCreateDevice','ZwOpenProcess')},@{Dll='hal.dll';Functions=@('READ_PORT_UCHAR')}) `
    -WideStrings @('\Device\PhysicalMemory') -OpcodeSequences @(,[byte[]](0x0F,0x32))
New-SyntheticDriverPE -Path .\tests\data\benign-like.sys `
    -Imports @(@{Dll='ntoskrnl.exe';Functions=@('ZwCreateFile','ZwWriteFile','IoCreateDeviceSecure','IoCreateSymbolicLink')})

$r = Invoke-DriverTriageScan -Path .\tests\data -OutputDirectory .\out -IncludeClean
$r.Results | Format-Table FileName, Score, Severity
Start-Process .\out\report.html
```

**Sobre un sistema real (Windows):**

```powershell
Invoke-DriverTriageScan -UseSystemInventory -OutputDirectory .\out        # drivers cargados ahora mismo
Invoke-DriverTriageScan -Path C:\Windows\System32\drivers -OutputDirectory .\out   # todo el store
```

## Cómo se calcula el puntaje

```
puntaje = (Σ pesos de capacidad detectada) × multiplicador_exposición × multiplicador_confianza
```

| Señal | Ejemplo | Peso |
|---|---|---|
| Import `MmMapIoSpace` | Mapeo de memoria física arbitraria | 5 |
| Import `ZwTerminateProcess` | Terminación de proceso (abuso típico anti-EDR) | 4 |
| Cadena `\Device\PhysicalMemory` | Indicador clásico de BYOVD | 5 |
| Opcode `RDMSR`/`WRMSR` en sección ejecutable | Acceso a registros de modelo específico | 2 |
| `IoCreateDevice` sin `IoCreateDeviceSecure` | Dispositivo sin control de acceso declarado | ×1.5 |
| Sin firma o firma inválida | Reduce la confianza en el binario | ×1.3 |

Pesos y umbrales en [`DriverTriage/Data/capabilities.psd1`](DriverTriage/Data/capabilities.psd1) — son
hipótesis ajustables, no constantes fijas.

## Por qué el puntaje no es la última palabra

Cada hallazgo de severidad Alta o Crítica se cruza contra
[`DriverTriage/Data/known_vulnerable_sample.csv`](DriverTriage/Data/known_vulnerable_sample.csv) (una
**muestra de solo 2 entradas** — reemplázala por el feed completo de
[loldrivers.io](https://www.loldrivers.io/) antes de usar en producción). Una coincidencia por hash es
`Confirmed`; una coincidencia solo por nombre de archivo es `Heuristic` (puede ser una versión distinta o
un homónimo legítimo).

## Validación con métricas, no solo con intuición

```powershell
$r = Invoke-DriverTriageScan -Path .\tests\data -OutputDirectory .\out -IncludeClean
Measure-DriverTriageAccuracy -Result $r.Results -LabelsPath .\tests\data\labels.sample.json
```

Produce: matriz de confusión por umbral (precisión/recall/FPR), **recall@K**, y una **ablación por
categoría de capacidad** (qué señal aporta más a separar vulnerables de benignos). Ver
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) para cómo construir un corpus etiquetado real.

## Límites éticos (obligatorios)

- Solo análisis estático y defensivo. **Cero código de explotación, cero PoC.**
- `tests/data/*.sys` son binarios **sintéticos** generados por
  [`tests/Helpers/New-SyntheticDriverPE.ps1`](tests/Helpers/New-SyntheticDriverPE.ps1), no drivers reales.
  El repo nunca distribuye binarios de terceros.
- Un hallazgo nuevo sobre software de terceros se reporta primero al fabricante (ver
  [`SECURITY.md`](SECURITY.md)), nunca se publica antes de coordinar.
- Pruebas solo en VMs/sistemas propios o con autorización.

## Limitaciones conocidas

| Limitación | Detalle |
|---|---|
| Resolución dinámica de APIs | Un driver que resuelve `MmMapIoSpace` en tiempo de ejecución evade la detección por import |
| Exposición por imports, no por flujo de control | `IoCreateDeviceSecure` no garantiza un SDDL restrictivo |
| Opcodes sin desensamblado real | Puede coincidir dentro de una instrucción más larga u operando |
| Firma válida ≠ benigno | Varios drivers vulnerables conocidos están firmados legítimamente |
| `Get-DriverTrust` requiere Windows | En Linux/macOS siempre devuelve `Unknown` (documentado, no oculto) |

Detalle completo en [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## Desarrollo

```powershell
Invoke-Pester .\tests -CI
Invoke-ScriptAnalyzer .\DriverTriage -Recurse
```

El parser de PE es C# puro compilado vía `Add-Type` (`DriverTriage/Private/PEParser.cs`): lee bytes de
archivo directamente, sin mapear el binario en memoria ni ejecutar nada.

## Roadmap

Desensamblado real para opcodes y rastreo de IOCTL (Capstone/Ghidra) · detección de resolución dinámica de
APIs · generación de política WDAC en modo auditoría (borrador en `scripts/New-WdacAuditPolicy.ps1`) ·
curva ROC/AUC y calibración formal de pesos con un corpus mayor.

## Uso autorizado

Defensa únicamente. Ver [`SECURITY.md`](SECURITY.md).

## Licencia

MIT
