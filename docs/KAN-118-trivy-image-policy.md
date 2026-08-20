# KAN-118 — Política confiable de Trivy image/container

## Propósito

Detectar vulnerabilidades High/Critical realmente presentes en la imagen final, sin bloquear por contenido descartado de stages de build, deuda heredada o fallas operativas del scanner.

## Decisión

- `PASS`: scan completo, DB vigente, imagen íntegra y cero findings nuevos.
- `WARN`: findings heredados o nuevos sin versión corregida.
- `BLOCK`: finding High/Critical nuevo y corregible, o el tag ya no representa la imagen escaneada.
- `BUILD_ERROR`: HEAD o la base confiable no pudieron producir una imagen.
- `SCANNER_ERROR`: scan incompleto, evidencia ausente/inválida, metadata faltante o DB con más de 24 horas.

La comparación usa `target estable + class + type + CVE + package + installed version`. Para targets del sistema operativo se elimina únicamente el ID efímero de la imagen, conservando distribución y versión. Así, un rebuild legítimo no convierte deuda heredada en hallazgos nuevos, pero un paquete nuevo en otro target no queda suprimido.

## Integridad

- Base y HEAD provienen de los SHA confiables del evento de GitHub.
- Ambas imágenes se construyen con `--pull` y se escanean con el mismo snapshot de Trivy DB.
- Trivy recibe el ID inmutable `sha256:...`, nunca el tag mutable.
- Después del scan se comprueba que el tag todavía resuelva al ID evaluado.
- `.trivyignore`, `trivy.yaml` y `trivy.yml` del consumidor se neutralizan después del build, por lo que la imagen sigue representando el commit exacto.
- El workflow expone `scanned-image-id`, el SHA-256 del archive y el commit sujeto. El job de publicación verifica los tres valores antes de cargar la imagen.

## Shape Up

La deuda heredada permanece visible como `WARN` y no detiene el PR. Solo una regresión corregible, una alteración del subject o una imposibilidad técnica de confiar en el resultado produce rojo. Esto protege el flujo sin convertir cada CVE histórica en un bloqueo del ciclo.

## Feedback

Cada finding nuevo muestra target/layer, CVE, paquete, versión instalada/corregida, severidad, título, advisory y remediación. Los datos también se publican como annotations de GitHub; no es necesario descargar el artifact para entender el fallo.

## Contrato de publicación

El job de seguridad exporta exactamente la imagen escaneada como un artifact efímero. El job de publicación valida su manifest y SHA-256, carga ese archive, publica la imagen en un registry efímero y vuelve a descargarla. Solo permite `PASS` cuando el Docker image ID descargado coincide con el ID aprobado por Trivy.

TI-10 se probó en ambos sentidos: el mismo subject produjo `PASS`; reemplazar el tag publicado por otra imagen mantuvo el scan original verde, pero el contrato de publicación produjo `BLOCK` con los IDs esperado/real y la corrección. El registry vive únicamente durante el job y no usa GCP ni credenciales persistentes.

## Evidencia

TI-01 a TI-11 se validaron exclusivamente en GitHub Actions. TI-05, TI-06, TI-09 y el camino negativo de TI-10 usan fault injection y nunca deben fusionarse.
