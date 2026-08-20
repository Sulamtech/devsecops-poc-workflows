# KAN-118 — Política confiable de Gitleaks

## Propósito

Detectar credenciales introducidas por todos los commits del Pull Request sin permitir que el mismo cambio se autoapruebe mediante `.gitleaksignore` o `gitleaks:allow`.

## Decisiones

- Gitleaks CLI `8.30.1` se descarga desde su release oficial y se verifica con un SHA-256 fijado.
- El rango confiable es el SHA base del evento hasta el SHA head exacto del PR.
- El `.gitleaksignore` del checkout se trata como entrada no confiable y se retira antes del scan.
- `--ignore-gitleaks-allow` deshabilita las supresiones inline aportadas por el consumidor.
- Base64/hex/percent se decodifican hasta profundidad 1 y ZIP/tar se inspeccionan hasta profundidad 1.
- `--max-target-megabytes 0` evita omitir silenciosamente archivos grandes.
- Las excepciones se leen exclusivamente desde
  `.devsecops/gitleaks-exceptions.tsv` en el SHA base confiable. Cada fila contiene
  `fingerprint<TAB>expires<TAB>owner<TAB>reason`.
- Una fecha inválida o expirada produce `POLICY_ERROR`; el PR actual no puede renovar
  su propia excepción.
- Un hallazgo que coincide con una excepción vigente del SHA base produce `WARN`
  verde. El summary muestra fingerprint, owner, expiración y razón, pero nunca el
  valor encontrado.
- Los secretos se redactan al 100 % tanto en logs como en JSON.
- El resultado distingue `PASS`, `WARN`, `BLOCK`, `POLICY_ERROR` y `SCANNER_ERROR`.

## Feedback

Un `BLOCK` muestra regla, archivo, línea, commit y fingerprint, además del impacto y los pasos de remediación. Nunca muestra el valor encontrado.

## Límite conocido

Gitleaks detecta valores presentes en archivos, historial, contenido decodificado o
archives. No puede reconstruir de forma general un secreto que solo nace al concatenar
fragmentos durante runtime. GL-05 se registra como falso negativo conocido; las reglas
SAST y el guard de confianza actuales no compensan esa limitación y no se presentan
como cobertura implementada.

## Evidencia requerida

Los casos se ejecutaron visualmente en GitHub Actions. Los PRs adversariales se
cerraron sin fusionarse después de aceptar la evidencia.
