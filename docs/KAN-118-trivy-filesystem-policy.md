# KAN-118 — Política confiable de Trivy filesystem/SCA

## Propósito

Detectar regresiones High/Critical sin bloquear el trabajo por deuda heredada y sin confundir un scanner roto, una base desactualizada o evidencia incompleta con un resultado limpio.

## Decisión

- `PASS`: scanner ejecutado, DB vigente, evidencia determinística y cero riesgo nuevo.
- `WARN`: CVE heredada, CVE nueva sin fix o manifest JavaScript que nunca tuvo lockfile.
- `BLOCK`: CVE High/Critical nueva con fix, CVE presente en el snapshot CISA KEV confiable o eliminación de un lockfile confiable.
- `SCANNER_ERROR`: scan incompleto, JSON inválido, metadata ausente o DB con más de 24 horas.

La comparación usa `target + CVE + package + installed version`. El target evita que una vulnerabilidad presente en un manifest suprima accidentalmente el mismo hallazgo introducido en otro.

El snapshot KEV incluido en este branch contiene únicamente los CVE necesarios para las pruebas del PoC. No es un catálogo productivo completo; una adopción real debe generar, revisar y versionar el snapshot completo de CISA antes de publicar el workflow.

El VEX también contiene únicamente la decisión TF-11 del laboratorio y vence el
`2026-08-31T23:59:59Z`. Un VEX vencido genera `POLICY_ERROR`; los archivos VEX
aportados por el consumidor no son una raíz de confianza.

## Integridad

- Base y HEAD se obtienen del evento confiable de GitHub, no del PR.
- Base y HEAD se escanean con el mismo snapshot de las bases de Trivy.
- Un baseline añadido por el mismo PR no participa en la comparación.
- Una decisión `not_affected` solo se acepta desde el VEX materializado por el workflow confiable, con producto/PURL exacto, owner y expiración.
- `continue-on-error` solo permite que el classifier interprete el fallo del scanner; cualquier scan fallido termina en `SCANNER_ERROR`.
- Los PR de laboratorio permanecen Draft y no se fusionan.

## Feedback

Cada finding nuevo muestra decisión, target, relación `direct`/`indirect`, estado KEV, CVE, package, installed/fixed version, severidad, título y advisory. Los findings corregibles o conocidos como explotados producen annotations de error; los que aún no tienen fix y no son KEV producen annotations de warning.

## Evidencia validada

TF-01 a TF-14 se validaron exclusivamente en GitHub Actions. Los casos normales usaron el canary `79b028197b2af2d18a5484b50ac1bb375be4ba48`; TF-11 usó la corrección VEX `e5b9533966f7f617acbe01660fa992afcc246bdb`. TF-12 y TF-13 utilizaron branches de fault injection separados y no fusionables.

Un check rojo solo cuenta como evidencia cuando `trivy-fs-decision.json`, el summary y las annotations coinciden con el estado esperado.
