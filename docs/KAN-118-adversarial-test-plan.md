# KAN-118 — Plan adversarial DevSecOps

## Propósito

Validar que los controles no solo detecten fixtures evidentes, sino que resistan evasiones, distingan vulnerabilidad de error técnico, minimicen falsos positivos y entreguen una remediación comprensible sin interrumpir innecesariamente un ciclo Shape Up.

Este documento es la especificación de pruebas. No describe controles como aprobados hasta que cada caso tenga evidencia de GitHub Actions.

## Principios Shape Up

1. Los criterios de bloqueo se acuerdan durante shaping, no durante el desarrollo del PR.
2. La deuda heredada se hace visible y se gestiona con owner/SLA; no interrumpe la apuesta actual.
3. Un finding de scanner no equivale automáticamente a una vulnerabilidad explotable.
4. Un bloqueo excepcional debe ser determinista, accionable y resoluble sin una cola manual de Security.
5. Los errores del scanner o de policy se distinguen de los rechazos de seguridad.
6. Las excepciones son específicas, auditables, aprobadas desde una raíz confiable y tienen expiración.

## Taxonomía obligatoria

| Estado | Significado | Resultado del PR | Acción |
|---|---|---|---|
| `PASS` | El control se ejecutó y no encontró riesgo accionable nuevo | Verde | Ninguna |
| `WARN` | Deuda heredada, riesgo nuevo no confirmado o finding de baja confianza | Verde con summary/annotation | Triage asíncrono con owner/SLA |
| `BLOCK` | Riesgo nuevo preacordado como hard stop o manipulación del control | Rojo | Corregir o usar excepción predefinida |
| `POLICY_ERROR` | Regla inválida, baseline corrupto/expirado o decisión imposible | No se reporta como vulnerabilidad | Corregir policy; no contar como prueba negativa válida |
| `SCANNER_ERROR` | Timeout, outage, DB inaccesible o fallo interno | No se reporta como vulnerabilidad | Contingencia y reintento auditado; publish/deploy falla cerrado |

### Hard stops propuestos

- Secreto o credencial confirmada introducida por el cambio.
- Inyección nueva con source no confiable, sink peligroso y ausencia de sanitización/allowlist.
- Vulnerabilidad nueva Critical o High con fix y evidencia de aplicabilidad; Critical conocida como explotada se evalúa aunque no tenga fix.
- Alteración o bypass del workflow, policy pack, baseline confiable, firma o procedencia.
- Tests/build obligatorios que no se ejecutaron o fueron neutralizados.

No bloquean automáticamente: severidad nominal sin contexto, sink peligroso con input constante/controlado, deuda heredada, CVE no aplicable, finding de baja confianza o scanner outage en un PR que no publica/despliega.

## Contrato de feedback al desarrollador

Cada resultado distinto de `PASS` debe aparecer en `GITHUB_STEP_SUMMARY` y, cuando exista ubicación, como annotation. El summary debe incluir:

| Campo | SAST | SCA/imagen | Secretos |
|---|---|---|---|
| Clasificación | CWE + regla | CVE + severidad | Tipo + regla |
| Ubicación | Archivo y línea | Manifest/lockfile/imagen + paquete | Archivo, línea y commit |
| Evidencia | Source → sink o patrón | Instalada → fixed + dependency path | Fingerprint; valor siempre redactado |
| Motivo | Por qué es explotable o warning | Por qué aplica al artefacto | Por qué parece credencial |
| Impacto | Consecuencia concreta | Consecuencia/advisory | Acceso potencial comprometido |
| Remediación | Patrón seguro o sanitizador | Versión fija/upgrade/remove | Revocar, rotar, retirar del historial y usar secret manager |
| Decisión | `WARN/BLOCK/...` | `WARN/BLOCK/...` | `WARN/BLOCK/...` |
| Excepción | Owner, justificación, alcance, expiración | Igual | Solo falso positivo confirmado; nunca para secreto real activo |

Reglas adicionales:

- Nunca imprimir el secreto, token o credencial.
- Un simple conteo no cumple el contrato.
- Debe diferenciarse `0 findings` de `scanner no ejecutado`.
- Los links deben apuntar al código/advisory y no solamente al artifact descargable.
- La recomendación debe ser específica al stack; no usar “actualice la dependencia” sin versión o ruta.

## Evidencia común por caso

Cada ejecución debe registrar:

1. ID del caso, repositorio, PR, SHA base y SHA head.
2. SHA del reusable workflow y versión/digest del scanner.
3. Fixture exacta y resultado esperado antes de ejecutar.
4. Estado esperado y real de todos los jobs.
5. Rule ID/CVE/fingerprint esperado y real.
6. Summary y annotations visibles para un developer.
7. Artifact raw SARIF/JSON y checksum.
8. Duración, reintentos y estabilidad en al menos dos ejecuciones cuando aplique.
9. Resultado TP/TN/FP/FN y decisión de calibración.

## Matriz A — Política y Shape Up

| ID | Caso | Resultado esperado | Evidencia específica |
|---|---|---|---|
| POL-01 | Deuda heredada sin cambios | `WARN`, PR verde | Full report conserva findings; delta cero |
| POL-02 | Finding Medium nuevo de baja confianza | `WARN`, PR verde | Owner/SLA generado sin hard stop |
| POL-03 | High nuevo pero no aplicable al runtime | `WARN`, PR verde | Razón de no aplicabilidad documentada |
| POL-04 | High/Critical nuevo, aplicable y con fix | `BLOCK` | Paquete, versión fija y advisory visibles |
| POL-05 | Inyección source-to-sink de alta confianza | `BLOCK` | Source, sink, CWE y remediación visibles |
| POL-06 | Sink peligroso con input constante/allowlist | `PASS` o `WARN`, nunca blocker automático | Regla demuestra true negative o baja confianza |
| POL-07 | Excepción aprobada y vigente desde base confiable | `WARN`, PR verde | Owner, scope y expiración visibles |
| POL-08 | Excepción expirada | `POLICY_ERROR` o `BLOCK` según ruta | Fecha y owner identificados |
| POL-09 | Scanner outage en PR sin publish | `SCANNER_ERROR`, no se confunde con vuln | Contingencia, reintento y SLA |
| POL-10 | Scanner outage antes de publish/deploy | `SCANNER_ERROR`, publish bloqueado | Ningún artefacto publicado |

## Matriz B — Integridad y bypass del pipeline

| ID | Ataque/cambio | Resultado esperado | Control probado |
|---|---|---|---|
| INT-01 | Eliminar el job `security` del caller | Detector: `BLOCK`; merge: pendiente | Required workflow/check fuera del control del repositorio |
| INT-02 | Cambiar el SHA central por tag, branch o SHA no aprobado | `BLOCK` | Allowlist de SHAs/releases aprobados |
| INT-03 | Añadir `continue-on-error` al caller | `BLOCK` | Policy de workflow |
| INT-04 | Cambiar `permissions` a escritura innecesaria | `BLOCK` | Default deny y permisos máximos |
| INT-05 | Cambiar trigger para que el PR no ejecute | Detector: `BLOCK`; merge: pendiente | Required workflow/check siempre presente |
| INT-06 | Añadir `[skip ci]` o equivalente | Detección contractual; merge: pendiente | Ruleset/branch protection de GitHub |
| INT-07 | Modificar baseline en el mismo PR que introduce la vuln | La vuln sigue en `BLOCK` | Baseline leído del base SHA |
| INT-08 | Modificar policy/rules en el consumidor | Sin efecto sobre policy confiable | Separación policy/consumer |
| INT-09 | Artifact SARIF/JSON ausente o corrupto | `POLICY_ERROR` | Validación de esquema y `if-no-files-found` |
| INT-10 | Reutilizar un artifact de otro SHA | `BLOCK` | Binding repo/run/SHA/checksum |
| INT-11 | Ejecutar un workflow viejo mediante rollback | Solo SHA aprobado; resultado identificable | Rollback controlado |
| INT-12 | Mismo SHA central produce diferente rule count | `POLICY_ERROR` | Policy pack reproducible; sin registry drift no versionado |
| INT-13 | Action basada en Node deprecado o incompatible | `SCANNER_ERROR` antes de ruptura | Compatibilidad de runtime y upgrade path |
| INT-14 | PR desde fork sin permisos adicionales | Controles ejecutan sin secretos ni write token | Least privilege |

## Matriz C — Gitleaks

| ID | Fixture/ataque | Resultado esperado | Clasificación |
|---|---|---|---|
| GL-01 | AWS access key + secret ficticios en archivo nuevo | Detecta ambos | TP / `BLOCK` |
| GL-02 | Secreto añadido y borrado en commit posterior | Sigue detectándolo en historial | TP / `BLOCK` |
| GL-03 | Token en archivo renombrado | Detecta | TP / `BLOCK` |
| GL-04 | Secreto codificado en Base64 | Detecta con decode configurado o registra limitación | TP o FN conocido |
| GL-05 | Secreto dividido y concatenado en runtime | No reconstruye el valor; limitación explícita sin compensación vigente | FN conocido |
| GL-06 | Secreto dentro de ZIP/tar | Detecta dentro de profundidad acordada o registra límite | TP o FN conocido |
| GL-07 | Secreto en archivo grande | Lo inspecciona sin omisión por tamaño y detecta el secreto | `BLOCK_NO_SIZE_SKIP` |
| GL-08 | Referencia segura `process.env.SECRET` | No detecta | TN / `PASS` |
| GL-09 | Valor placeholder de documentación | No bloquea tras calibración aprobada | TN o FP corregido |
| GL-10 | `.gitleaksignore` añadido en el mismo PR | No autoaprueba el leak | `BLOCK` |
| GL-11 | `gitleaks:allow` junto al secreto | Bypass rechazado salvo excepción confiable | `BLOCK` |
| GL-12 | Fingerprint aprobado en base, vigente | No bloquea; permanece auditable | `WARN` |
| GL-13 | Fingerprint aprobado pero expirado | Excepción inválida | `POLICY_ERROR/BLOCK` |
| GL-14 | Output/log | Valor 100% redactado; ubicación y respuesta visibles | Contrato DX |

## Matriz D — Semgrep y reglas propias

| ID | Fixture/ataque | Resultado esperado | Clasificación |
|---|---|---|---|
| SG-01 | Query param llega a `Runtime.exec` | Detecta flujo | TP / `BLOCK` |
| SG-02 | `Runtime.exec("fixed-command")` sin input externo | No se clasifica automáticamente como inyección | TN o `WARN` |
| SG-03 | Query param llega a `ProcessBuilder` | Detecta flujo | TP / `BLOCK` |
| SG-04 | Wrapper intermedio alrededor del sink | Detecta o registra límite intrafile | TP/FN conocido |
| SG-05 | Source y sink en archivos diferentes | Detecta si motor lo soporta; CE registra limitación | TP/FN conocido |
| SG-06 | Input Next.js llega a `dangerouslySetInnerHTML` | Detecta | TP / `BLOCK` |
| SG-07 | HTML pasa por sanitizador aprobado | No bloquea | TN / `PASS` |
| SG-08 | HTML usa sanitizador falso/no-op | Detecta | TP / `BLOCK` |
| SG-09 | XSS mediante `innerHTML`, `outerHTML` u otro sink definido | Detecta | TP / `BLOCK` |
| SG-10 | Render React normal `{userInput}` | No detecta | TN / `PASS` |
| SG-11 | Comentario `nosemgrep` en finding bloqueante | Supresión no confiable rechazada | `BLOCK` |
| SG-12 | Archivo excluido/generado contiene sink | Exclusión visible y justificada | `WARN` o `BLOCK` según path |
| SG-13 | Regla YAML inválida | No se presenta como vulnerabilidad | `POLICY_ERROR` |
| SG-14 | Regla demasiado amplia detecta código seguro | Caso falla como FP y obliga calibración | FP |
| SG-15 | Variantes sintácticas/alias/import estático | Mismo resultado semántico | TP |
| SG-16 | Rule ID, CWE, source/sink y fix ausentes del summary | Caso DX falla aunque el scanner bloquee | No aprobado |
| SG-17 | Pruebas unitarias `ruleid`, `ok`, `todoruleid` | Todas pasan antes de publicar policy pack | Regla versionable |

## Matriz E — Trivy filesystem/SCA

| ID | Fixture/ataque | Resultado esperado | Clasificación |
|---|---|---|---|
| TF-01 | Dependencia directa Critical/High con fix | Detecta | TP / `BLOCK` |
| TF-02 | Dependencia transitiva Critical/High con fix | Detecta y muestra dependency path | TP / `BLOCK` |
| TF-03 | Misma dependencia actualizada a fixed version | No aparece en delta | TN / `PASS` |
| TF-04 | Manifest con rango pero sin lockfile | No queda verde silencioso | `WARN/POLICY_ERROR` |
| TF-05 | Eliminar lockfile en el PR | Cambio visible y evaluado | `BLOCK` si impide análisis confiable |
| TF-06 | CVE heredada aprobada desde base | Full report sí, delta no | `WARN` |
| TF-07 | Añadir CVE y baseline en el mismo PR | Sigue bloqueando | `BLOCK` |
| TF-08 | Mismo CVE afecta otro paquete/target | Excepción no se aplica globalmente por accidente | `BLOCK` |
| TF-09 | CVE sin fix y no explotada | Visible, no hard stop automático | `WARN` |
| TF-10 | CVE sin fix pero KEV/explotación confirmada | Decisión de hard stop explícita | `BLOCK` o aislamiento |
| TF-11 | Advisory vendor indica backport/no afectado | No bloquea tras evidencia | TN/FP corregido |
| TF-12 | Base de Trivy desactualizada | No reporta `PASS` limpio | `SCANNER_ERROR/WARN` |
| TF-13 | DB download/outage/timeout | Diferencia outage de cero findings | `SCANNER_ERROR` |
| TF-14 | Summary | Lista CVE, paquete, installed/fixed, target, title y URL | Contrato DX |

## Matriz F — Trivy imagen

| ID | Fixture/ataque | Resultado esperado | Clasificación |
|---|---|---|---|
| TI-01 | Base image introduce CVE fixable | Detecta | TP / `BLOCK` |
| TI-02 | Paquete vulnerable instalado en Dockerfile | Detecta | TP / `BLOCK` |
| TI-03 | Paquete vulnerable solo en build stage y ausente del final | No bloquea imagen final; SCA puede informar | TN |
| TI-04 | Imagen final actualizada a versión corregida | Delta cero | TN / `PASS` |
| TI-05 | Cambio de base después del scan | Imposible: scan y publish ligados al mismo digest | `BLOCK` si difiere |
| TI-06 | Tag mutable apunta a otro digest | Se usa digest calculado, no tag | Integridad |
| TI-07 | CVE de filesystem ignorada afecta paquete distinto en imagen | Baseline scoped evita supresión cruzada | `BLOCK` |
| TI-08 | Build falla antes del scan | No se reporta imagen limpia | Build failure |
| TI-09 | Scan termina sin JSON/SARIF | No se reporta `PASS` | `SCANNER_ERROR` |
| TI-10 | Imagen que se publica no coincide con la escaneada | Publish bloqueado | `BLOCK` |
| TI-11 | Summary | Incluye target/layer, paquete, installed/fixed, CVE y advisory | Contrato DX |

## Matriz G — Tests, build y experiencia del desarrollador

| ID | Caso | Resultado esperado |
|---|---|---|
| DX-01 | Test command devuelve éxito sin ejecutar tests | Detectar cero tests y rechazar |
| DX-02 | Test marcado skip/todo para ocultar regresión | Cambio visible; threshold/policy acordada |
| DX-03 | Build no produce artifact esperado | No reportar verde |
| DX-04 | Check rojo por vulnerabilidad | Summary cumple todos los campos del contrato |
| DX-05 | Check rojo por policy inválida | Encabezado `POLICY_ERROR`, no “vulnerability found” |
| DX-06 | Check rojo por outage | Encabezado `SCANNER_ERROR`, incluye reintento/SLA |
| DX-07 | Check verde | Indica scanner ejecutado, versión, targets y cero riesgo accionable nuevo |
| DX-08 | Warning | PR permanece verde, pero annotation, owner y SLA son visibles |
| DX-09 | Developer nuevo abre el check sin descargar artifacts | Puede entender causa y remediación desde summary |
| DX-10 | Hallazgo tiene varias soluciones | Recomienda la opción segura del stack y enlaza advisory |
| DX-11 | Acción/runtime deprecado | Warning técnico separado de findings de la aplicación |
| DX-12 | Artifact contiene información sensible | Redacción validada antes de upload |

## Orden de ejecución

### Fase 1 — Harness y policy pack

1. Separar workflow, policy pack y fixtures.
2. Añadir esquema/metadata obligatoria y pruebas unitarias de reglas.
3. Implementar renderer único de summaries y annotations.
4. Añadir validadores de baseline, expiración y artifacts.

### Fase 2 — Pruebas de integridad

Ejecutar `INT-*` antes de confiar en los scanners. Si un actor puede eliminar el control o cambiar la configuración del detector, los demás resultados demuestran detección, no enforcement.

### Fase 3 — Scanner por scanner

Ejecutar Gitleaks, Semgrep, Trivy filesystem e imagen incluyendo TP, TN, FP, FN y bypasses. No corregir varias variables en un mismo PR de prueba.

### Fase 4 — Shape Up y developer experience

Ejecutar `POL-*` y `DX-*`, medir tiempo de resolución sin intervención manual y comprobar que warning/block/error sean distinguibles.

### Fase 5 — Estabilidad

Repetir casos críticos, simular outage y rollback, comparar rule count/digests y verificar resultados deterministas.

## Criterios go/no-go

### Go

- 100% del corpus obligatorio produce el estado esperado.
- Cero bypasses abiertos en `INT-*` para rutas protegidas.
- Cero falsos negativos en hard stops definidos.
- Falsos positivos bloqueantes dentro del umbral acordado durante shaping.
- Todo blocker ofrece remediación self-service.
- Scanner/policy errors nunca se presentan como vulnerabilidades.
- Baselines y excepciones son scoped, confiables y expiran.
- La imagen escaneada queda ligada por digest al futuro publish/deploy.

### No-go

- Un hard stop atraviesa en verde.
- Un PR puede neutralizar el required workflow/check.
- Un cambio puede autoaprobar su baseline o supresión.
- Un scanner no ejecutado aparece como `PASS`.
- El developer solo recibe conteos o exit codes sin causa/remediación.
- Una regla bloqueante carece de tests TP/TN/FP/FN.
- El mismo SHA de policy produce resultados no reproducibles sin explicación.

## Alcance de “100%”

“100%” significa que todos los casos versionados y criterios de aceptación pasan. No significa ausencia absoluta de vulnerabilidades desconocidas. El corpus debe crecer con incidentes, post-mortems, nuevas técnicas de evasión y cambios de stack.
