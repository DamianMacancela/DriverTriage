# Metodologia

## Hipotesis
Las listas de bloqueo de drivers (hash, nombre+version, certificado) son **reactivas**: solo cubren lo ya
descubierto y reportado. DriverTriage prueba una hipotesis distinta: que un conjunto pequeño de
**capacidades** (mapeo de memoria fisica, terminacion arbitraria de procesos, acceso a MSR/puertos de E/S,
creacion de un dispositivo sin control de acceso) predice razonablemente si un driver desconocido es
candidato a abuso tipo BYOVD, sin depender de que ya este catalogado.

## Como se calcula el puntaje

```
puntaje = (suma de pesos de capacidad detectada) x multiplicador_de_exposicion x multiplicador_de_confianza
```

| Componente | Fuente de la señal | Riesgo de falso positivo |
|---|---|---|
| Capacidad (imports) | Tabla de importación (parser C# en `Private/PEParser.cs`, envuelto por `Private/Native.ps1`) | Bajo: el nombre importado es exacto, pero su USO real no se verifica (ver Limitaciones) |
| Capacidad (cadenas) | Búsqueda de literales ASCII/UTF-16LE en todo el archivo | Bajo-medio: la cadena puede estar en un comentario o en código muerto |
| Capacidad (opcodes) | Búsqueda de secuencias de bytes SOLO en secciones ejecutables | **Alto**: no respeta límites de instrucción; un byte de un operando puede coincidir por azar. Peso deliberadamente bajo (1-2) |
| Capacidad (estructura PE)| Detección de secciones RWX (violación de W^X: ejecutables y modificables) | Bajo: anomalía estructural verificable directamente en las cabeceras de sección |
| Exposición | Presencia de `IoCreateDevice` vs `IoCreateDeviceSecure` | Medio: heurística de imports, no de flujo de control real |
| Confianza | `Get-AuthenticodeSignature` (solo Windows) | La verificación no consulta revocación al momento de carga real |

Los pesos y umbrales estan en `DriverTriage/Data/capabilities.psd1`. Son **hipotesis de partida**, no
resultados medidos. Ajustalos y vuelve a evaluar con `Measure-DriverTriageAccuracy`.

## Limitaciones conocidas (documentadas a proposito, no ocultas)

1. **Resolucion dinamica de APIs.** Si un driver intenta resolver funciones en tiempo de ejecucion, DriverTriage penaliza la presencia de `MmGetSystemRoutineAddress` (T1106) y `ZwLoadDriver` (T1543.003) para evitar el absorbente cero en la ecuacion de riesgo. No obstante, si el binario resuelve APIs ofuscadas mediante hashing de nombres o barrido manual de memoria, la tabla de importacion no reflejara la funcion final. Mitigacion futura: rastreo de flujo de datos y decompilacion headless (Ghidra).
2. **Exposicion por imports, no por flujo de control.** `IoCreateDeviceSecure` no garantiza un SDDL
   restrictivo; un driver puede usarlo con un descriptor de seguridad permisivo y seguir siendo explotable.
3. **Opcodes sin desensamblado real.** El escaneo de bytes puede coincidir dentro de una instruccion mas
   larga o en datos embebidos en una seccion ejecutable (constantes, tablas de salto).
4. **Firma valida no implica benigno.** Varios drivers vulnerables conocidos estan firmados legitimamente
   (son controladores reales con bugs, no malware). El multiplicador de confianza por eso es moderado
   (1.3x para no firmado/invalido, 0.5x-1.0x para firmado), nunca determinante por si solo.
5. **La lista de conocidos incluida es una MUESTRA.** `Data/known_vulnerable_sample.csv` tiene solo 2
   entradas de ejemplo para probar el pipeline. Para uso real, reemplazar por el feed completo de
   https://www.loldrivers.io/.
6. **Heuristica de pais/exposicion no sustituye analisis binario profesional.** Esta herramienta prioriza
   candidatos para revision humana; no certifica explotabilidad ni ausencia de ella.

## Evaluacion con `Measure-DriverTriageAccuracy`

Requiere un corpus ETIQUETADO (ground truth): un mapa de SHA-256 o nombre de archivo a `true`/`false`
(vulnerable/benigno). El repo incluye solo 2 fixtures SINTETICAS (`tests/data/`) para demostrar que el
pipeline de metricas funciona, no para medir desempeno real.

Para una evaluacion real:
- **Positivos:** descarga (bajo tu propia responsabilidad y en un entorno aislado) una muestra de drivers
  de https://www.loldrivers.io/, calcula sus hashes y etiquetalos `true`.
- **Negativos:** usa los drivers de una instalacion limpia de Windows (`C:\Windows\System32\drivers`),
  etiquetados `false`.
- Corre `Invoke-DriverTriageScan` sobre ambos conjuntos, luego `Measure-DriverTriageAccuracy` con las
  etiquetas reales.

Metricas que produce:
- **Matriz de confusion por umbral** (Precision, Recall, tasa de falsos positivos).
- **Recall@K**: de los K drivers con mayor puntaje, cuantos son realmente vulnerables. Util porque en la
  practica un analista revisa los K mas sospechosos, no todos.
- **Ablacion por categoria**: cuanto aporta cada categoria de capacidad a separar las dos clases (recalcula
  el puntaje quitando esa categoria y mide el cambio en la separacion de medias). Util para podar señales
  que no aportan o para justificar sus pesos con datos, no con intuicion.

## Roadmap de investigacion

- Desensamblado real (Capstone o Ghidra headless) para el escaneo de opcodes y para rastrear el despacho
  de IOCTL hasta la API peligrosa (resuelve la limitacion de exposicion por imports).
- Deteccion de resolucion dinamica de APIs (constantes de hash de nombre de funcion, patrones de
  `MmGetSystemRoutineAddress`).
- Generacion de borrador de politica WDAC en modo auditoria para los hallazgos de severidad alta/critica
  (ver `scripts/New-WdacAuditPolicy.ps1`).
- Curva ROC / AUC con un corpus mayor, y calibracion formal de pesos (regresion logistica sobre los
  hits binarios por categoria como features, usando el label como variable dependiente).
