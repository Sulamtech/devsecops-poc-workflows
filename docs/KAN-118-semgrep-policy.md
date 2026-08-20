# KAN-118 — Política confiable de Semgrep

## Propósito

Bloquear flujos nuevos y explotables sin convertir cada uso de una API peligrosa en un falso positivo.

## Política

- Java usa taint tracking desde `@QueryParam` hasta `Runtime.exec` o `ProcessBuilder`.
- Un comando constante sin input externo no se clasifica automáticamente como command injection.
- React permite JSX normal y el sanitizador `escapeHtml` aprobado antes de `dangerouslySetInnerHTML`.
- La asignación directa de parámetros a `element.innerHTML` se clasifica como CWE-79.
- La policy está materializada por el reusable workflow; no se descarga desde un registry mutable.
- `.semgrepignore` y `nosemgrep` aportados por el consumidor no pueden suprimir un hard stop.

## Límite de Community Edition

Semgrep CE analiza por archivo. La regla actual no demuestra propagación a través de
un método wrapper, incluso cuando source y sink permanecen en el mismo archivo
(`SG-04`), ni taint source-to-sink entre archivos (`SG-05`). Ambos casos están
versionados con `todoruleid` para que el test falle si el comportamiento del motor
cambia y obligue a reclasificar la expectativa.

`SG-04` y `SG-05` son falsos negativos conocidos, no cobertura aprobada. Para cerrar
esa brecha se requiere modelar wrappers concretos, usar Semgrep Code/Pro con análisis
interfile o introducir una segunda herramienta capaz de demostrar el flujo. El
workflow publica `KNOWN_FN_INTERFILE` para `SG-05`; nunca convierte cero findings en
un falso verde.

Los archivos excluidos o generados no pueden quedar silenciosamente fuera del modelo.
La única exclusión central del PoC es `generated/sg12/**`, con owner, justificación
y expiración `2026-08-31`. El gate la omite del scan bloqueante, pero vuelve a
escanear cada archivo excluido que cambió. Si encuentra un sink, emite `WARN` y el
summary muestra path, owner, expiración y razón. Una exclusión local del consumidor
sigue sin ser confiable.

Un finding sobre código seguro (`SG-14`) obliga a calibrar la regla en el policy pack:
no se permite añadir `nosemgrep` o `.semgrepignore` en el consumidor. Las variantes
de import y llamada de `SG-15` viven en las pruebas versionadas de la regla.

## Pruebas de reglas

La policy versionada y sus archivos `ruleid`/`ok`/`todoruleid` viven en
`.github/actions/semgrep-policy/`. `rules.java` cubre las variantes directas,
`static import` y `ProcessBuilder` de `SG-15`, además del límite intrafile `SG-04`.
El fixture interfile de `SG-05` vive en `fixtures/semgrep/sg05/`.

`validate-semgrep-policy.yml` ejecuta `semgrep scan --test` cuando cambia la policy o
sus fixtures en un pull request, y también permite ejecución manual. La validación
interfile separada exige cero findings mientras el caso siga marcado como
`todoruleid`; una detección futura falla el check para forzar revisión de la
clasificación y la documentación.

## Resultado

- `PASS`: scanner ejecutado, JSON válido y cero findings nuevos.
- `WARN`: finding visible bajo una exclusión central, justificada y vigente.
- `BLOCK`: uno o más flujos nuevos definidos como hard stop.
- `POLICY_ERROR`: regla inválida o policy no ejecutable.
- `SCANNER_ERROR`: fallo técnico o evidencia inconsistente.

Cada `BLOCK` debe mostrar rule ID, CWE, archivo, línea, source, sink y remediación específica al stack.

## Evidencia validada

Los ocho casos se validaron en GitHub Actions con el reusable workflow
`109d1c43c9926bcb90ed58074faf0f0ce9b6aa54`.

- `PASS`: SG-02 (comando constante), SG-07 (sanitizador aprobado) y SG-10 (escaping normal de React).
- `BLOCK`: SG-03 (taint hacia `ProcessBuilder`), SG-08 (sanitizador falso), SG-09 (`innerHTML`) y SG-11 (`nosemgrep`).
- `ACTIONABLE_BLOCK`: SG-16 confirmó annotations con rule ID, CWE, archivo, línea, source, sink y remediación.

El classifier inicialmente falló dentro del contenedor por depender de `base64 --decode`, opción no portable en BusyBox. Se reemplazó por JSON compacto con `jq -c`; los bloqueos ahora terminan explícitamente con exit code `10` y conservan evidencia JSON.

Los PRs de laboratorio permanecen Draft y no se fusionan.
