# Politica de seguridad

## Alcance y proposito
DriverTriage es una herramienta DEFENSIVA de solo lectura. Puntua drivers de kernel por capacidades
peligrosas para priorizar la revision manual. No contiene, genera ni facilita codigo de explotacion.

## Divulgacion responsable
Si usas esta herramienta y encuentras un driver de un **tercero** con puntaje alto que no esta en ninguna
lista publica (loldrivers.io, bloqueo de Microsoft):

1. NO publiques el hallazgo ni el binario.
2. Repórtalo primero al fabricante del driver.
3. Si no responde en un plazo razonable, reporta a MSRC (secure@microsoft.com) y/o solicita una entrada en
   https://www.loldrivers.io/.
4. Solo tras la coordinacion (parche o confirmacion de que no habra parche) considera una publicacion
   tecnica, sin PoC de explotacion, siguiendo divulgacion coordinada estandar (p.ej. 90 dias).

## Reporte de vulnerabilidades EN esta herramienta
Abre un *Security Advisory* privado en GitHub (pestaña Security). No publiques detalles en issues publicos.

## Limites de diseño
- Sin ejecucion de codigo de terceros: solo se leen bytes de archivo.
- Sin red: todo el analisis es local.
- Los binarios de terceros NUNCA se redistribuyen en este repositorio; solo hashes y metadatos.
- `tests/data/*.sys` son binarios SINTETICOS generados por `tests/Helpers/New-SyntheticDriverPE.ps1`,
  no drivers reales.
