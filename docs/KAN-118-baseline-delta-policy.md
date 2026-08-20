# KAN-118 — Política baseline/delta para Shape Up

## Propósito

Evitar que la deuda heredada detenga un ciclo Shape Up sin convertir seguridad en un control informativo. El pipeline muestra todo el riesgo conocido, pero bloquea únicamente el riesgo nuevo introducido por el cambio.

## Decisión de policy

| Control | Evidencia completa | Condición de bloqueo |
|---|---|---|
| Gitleaks | JSON transitorio, summary y annotations | Cualquier secreto confirmado en el historial |
| Semgrep | SARIF completo + SARIF delta | Finding nuevo frente al commit confiable de comparación |
| Trivy filesystem | SARIF HEAD + JSON base/HEAD/delta | CVE CRITICAL/HIGH corregible presente en HEAD y ausente del commit base |
| Trivy image | SARIF HEAD + JSON base/HEAD/delta | CVE CRITICAL/HIGH corregible presente en la imagen HEAD y ausente en la imagen del commit base |

La ausencia de fix reduce el hallazgo a deuda informativa en este PoC. La explotación confirmada, los secretos y la integridad de la cadena de suministro nunca se aceptan mediante baseline.

## Raíz de confianza

- En Pull Requests, Semgrep y Trivy usan el SHA confiable de la rama base.
- En pushes a `main`, usan el SHA anterior informado por GitHub.
- Trivy analiza base y HEAD con la misma copia de su vulnerability DB; una actualización del feed no convierte deuda heredada en una regresión del PR.
- En `workflow_dispatch` sin commit anterior, HEAD se compara consigo mismo y el reporte completo permanece visible.
- Los reusable workflows y las Actions externas permanecen fijados por SHA.
- Solo Gitleaks recibe `pull-requests: read`, necesario para enumerar los commits del PR; ningún job recibe permisos de escritura.

## Baseline Trivy

El baseline no es una lista estática de CVE. Es el resultado de escanear el commit base confiable durante la misma ejecución y con la misma vulnerability DB usada para HEAD.

La clave de comparación es `VulnerabilityID + PkgName + InstalledVersion`:

- existe en base y HEAD → deuda heredada visible, decisión `WARN`, no bloquea;
- existe solo en HEAD → regresión introducida, decisión `BLOCK`;
- existe solo en base → riesgo removido por el cambio.

Cambiar la versión de un paquete sin eliminar la vulnerabilidad genera una nueva clave y exige revisión; no se oculta como deuda heredada.

`.security/.trivyignore` deja de ser autoridad para calcular el delta. Esto evita que un hallazgo publicado después de crear el baseline bloquee un PR que no modificó la dependencia.

## Flujo de una ejecución

1. GitHub determina el commit confiable de comparación.
2. Los tests del stack se ejecutan de forma independiente.
3. Gitleaks revisa el historial completo.
4. Semgrep genera reporte completo y luego analiza el delta.
5. Trivy genera el SARIF completo de HEAD y descarga una sola copia de su DB.
6. Trivy escanea base y HEAD reutilizando esa misma DB, sin actualizarla entre ambos lados.
7. El job calcula el delta y publica ID, paquete, versión instalada, versión corregida, severidad y descripción.
8. Cualquier finding exclusivo de HEAD hace fallar el check; base/HEAD/delta permanecen
   en el runner solo durante el job y la decisión visible queda en summary/annotations.

## Escenarios del PoC

1. **Baseline**: una CVE presente en base y HEAD aparece en SARIF, pero el delta queda en cero.
2. **Regresión**: una nueva CVE CRITICAL/HIGH corregible produce delta mayor que cero y bloquea.
3. **Secret leak**: un secreto de prueba detectado por Gitleaks bloquea.
4. **Fixed**: al corregir o revertir la regresión, todos los checks regresan a verde.

Los secretos de prueba deben ser ficticios y revocables. Nunca se usa una credencial real.

## Métricas

- Duración de cada job registrada por GitHub Actions.
- Conteo de findings introducidos y heredados publicado en `GITHUB_STEP_SUMMARY`.
- SARIF completo y JSON base/HEAD/delta conservados durante siete días.
- Estabilidad evaluada ejecutando cada escenario en los tres stacks.
- Falsos positivos documentados con scanner, regla, evidencia y decisión humana.

## Rollback

Los consumidores pueden volver a `poc-v1.0.1` fijando el SHA:

```text
ad9d553563cb027877f2c676cab7894bb095edc6
```

El rollback elimina el comportamiento delta y restaura el gate CRITICAL/HIGH absoluto; por eso solo debe usarse para recuperar una falla del mecanismo, no para evadir un hallazgo.
