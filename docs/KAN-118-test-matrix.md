# KAN-118 — Matriz de pruebas del PoC DevSecOps

> La evidencia UC-00 a UC-07 valida el mecanismo inicial, pero no constituye todavía un go definitivo. La validación ampliada de bypasses, falsos positivos, falsos negativos, integridad y experiencia del desarrollador se define en [KAN-118-adversarial-test-plan.md](KAN-118-adversarial-test-plan.md).

## Objetivo

Demostrar con evidencia de GitHub Actions que el flujo permite cambios legítimos y rechaza únicamente regresiones accionables. Los Pull Requests negativos son fixtures desechables: nunca se fusionan.

## Regla de decisión

- **Verde:** tests, build y controles de seguridad terminan correctamente.
- **Rojo esperado:** falla al menos el control responsable del riesgo introducido; otro control de seguridad puede detectar el mismo riesgo como defensa en profundidad. Tests y controles no relacionados deben ejecutarse.
- **Baseline:** la deuda heredada permanece visible en SARIF pero no bloquea.
- **Remediación:** se crea desde `main` en una rama limpia; no se reutiliza el historial contaminado del PR negativo.

## Casos de uso

| ID | Repositorio | Cambio controlado | Control esperado | Resultado esperado |
|---|---|---|---|---|
| UC-00 | Los cuatro | Código baseline sin regresión | Suite completa | Verde |
| UC-01 | NestJS | Credencial AWS ficticia con formato detectable | Gitleaks | Rojo; PR no fusionable por política |
| UC-02 | Spring Boot | `log4j-core:2.14.1` en fixture Maven | Trivy filesystem delta | Rojo por CVE High/Critical nueva |
| UC-03 | Quarkus | Input HTTP enviado a `Runtime.exec` | Semgrep delta / CWE-78 | Rojo por command injection |
| UC-04 | Next.js | Input HTTP renderizado con `dangerouslySetInnerHTML` | Semgrep delta / CWE-79 | Rojo por XSS |
| UC-05 | Los cuatro | Cambio seguro independiente desde `main` | Suite completa | Verde; demuestra recuperación |
| UC-06 | Repositorio con baseline | Hallazgo ya aprobado, sin empeorar | Reporte completo + delta | Verde; el hallazgo sigue en evidencia |
| UC-07 | Workflow central | Referencia del consumidor a SHA anterior conocido | Rollback | Regresa al comportamiento anterior sin editar el scanner |

## Evidencia obligatoria

Por cada caso se conserva:

1. URL del Pull Request y SHA del commit probado.
2. URL del run de GitHub Actions.
3. Estado de cada job, no solo el resultado agregado.
4. Artifact SARIF/JSON correspondiente durante siete días.
5. Hallazgo esperado, control responsable y decisión go/no-go.

## Evidencia ejecutada

| Caso | Evidencia | Resultado |
|---|---|---|
| UC-00 | PR baseline fusionados en [NestJS](https://github.com/Sul4m/devsecops-poc-nestjs/pull/2), [Spring Boot](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/2) y [Quarkus](https://github.com/Sul4m/devsecops-poc-quarkus/pull/2); [run Next.js](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29882082758) | Verde |
| UC-01 | [NestJS PR #4](https://github.com/Sul4m/devsecops-poc-nestjs/pull/4), [run](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29882819104) | Gitleaks bloqueó; Semgrep también detectó las dos credenciales AWS ficticias |
| UC-02 | [Spring Boot PR #4](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/4), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29883295672) | Trivy delta bloqueó tres CVE High/Critical nuevas |
| UC-03 | [Quarkus PR #4](https://github.com/Sul4m/devsecops-poc-quarkus/pull/4), [run](https://github.com/Sul4m/devsecops-poc-quarkus/actions/runs/29882822326) | Semgrep bloqueó `poc-java-command-execution` |
| UC-04 | [Next.js PR #6](https://github.com/Sul4m/devsecops-poc-nextjs/pull/6), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29882974965) | Semgrep bloqueó `poc-react-untrusted-html` |
| UC-05 | PRs de remediación [NestJS #6](https://github.com/Sul4m/devsecops-poc-nestjs/pull/6), [Spring Boot #6](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/6), [Quarkus #6](https://github.com/Sul4m/devsecops-poc-quarkus/pull/6) y [Next.js #4](https://github.com/Sul4m/devsecops-poc-nextjs/pull/4) | Los cuatro escenarios terminaron verdes |
| UC-06 | [Spring Boot PR apilado #7](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/7), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29883296872) | Verde con deuda heredada visible y delta cero |
| UC-07 | [Next.js PR rollback #8](https://github.com/Sul4m/devsecops-poc-nextjs/pull/8), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29883399022) | Verde al volver al SHA inmutable `poc-v1.1.1` |

## Evidencia adversarial Gitleaks

Todos los casos usan el reusable workflow `b454bd8a6797eb83dd0b37ec6de57570d1e251cf`. Los PR permanecen Draft y no deben fusionarse.

| Caso | Evidencia | Resultado |
|---|---|---|
| GL-02 | [NestJS PR #9](https://github.com/Sul4m/devsecops-poc-nestjs/pull/9), [run](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29975001242) | `BLOCK`; detectó dos credenciales ficticias eliminadas posteriormente de HEAD |
| GL-03 | [NestJS PR #10](https://github.com/Sul4m/devsecops-poc-nestjs/pull/10), [run](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29975002984) | `BLOCK`; detectó las credenciales después del renombrado |
| GL-08 | [NestJS PR #11](https://github.com/Sul4m/devsecops-poc-nestjs/pull/11), [run](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29975004318) | `PASS`; `process.env` no produjo falso positivo |
| GL-09 | [NestJS PR #12](https://github.com/Sul4m/devsecops-poc-nestjs/pull/12), [run](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29975005748) | `PASS`; placeholder documental no produjo falso positivo |
| GL-10 | [NestJS PR #13](https://github.com/Sul4m/devsecops-poc-nestjs/pull/13), [run](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29975007340) | `BLOCK`; el `.gitleaksignore` del mismo PR no suprimió el hallazgo |
| GL-11 | [NestJS PR #14](https://github.com/Sul4m/devsecops-poc-nestjs/pull/14), [run](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29975008259) | `BLOCK`; `gitleaks:allow` no suprimió el hallazgo |
| GL-14 | [Artifact y annotations del run GL-02](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/29975001242) | JSON y logs sin valores sin redactar; annotations muestran regla, archivo, línea y remediación self-service |

## Evidencia adversarial Semgrep

Todos los casos usan el reusable workflow `109d1c43c9926bcb90ed58074faf0f0ce9b6aa54`. Los PR permanecen Draft y no deben fusionarse.

| Caso | Evidencia | Resultado |
|---|---|---|
| SG-02 | [Quarkus PR #9](https://github.com/Sul4m/devsecops-poc-quarkus/pull/9), [run](https://github.com/Sul4m/devsecops-poc-quarkus/actions/runs/29976270195) | `PASS`; un comando constante sin input externo no produjo falso positivo |
| SG-03 | [Quarkus PR #10](https://github.com/Sul4m/devsecops-poc-quarkus/pull/10), [run](https://github.com/Sul4m/devsecops-poc-quarkus/actions/runs/29976273142) | `BLOCK`; `@QueryParam` llegó a `ProcessBuilder` |
| SG-07 | [Next.js PR #11](https://github.com/Sul4m/devsecops-poc-nextjs/pull/11), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29976286319) | `PASS`; el sanitizador `escapeHtml` aprobado evitó el falso positivo |
| SG-08 | [Next.js PR #12](https://github.com/Sul4m/devsecops-poc-nextjs/pull/12), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29976290008) | `BLOCK`; un sanitizador no-op no rompió el flujo de taint |
| SG-09 | [Next.js PR #13](https://github.com/Sul4m/devsecops-poc-nextjs/pull/13), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29976292879) | `BLOCK`; detectó asignación directa de input a `element.innerHTML` |
| SG-10 | [Next.js PR #14](https://github.com/Sul4m/devsecops-poc-nextjs/pull/14), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29976295689) | `PASS`; el escaping normal de React no produjo falso positivo |
| SG-11 | [Quarkus PR #11](https://github.com/Sul4m/devsecops-poc-quarkus/pull/11), [run](https://github.com/Sul4m/devsecops-poc-quarkus/actions/runs/29976275270) | `BLOCK`; `nosemgrep` no suprimió el hard stop |
| SG-16 | [Annotations del run SG-03](https://github.com/Sul4m/devsecops-poc-quarkus/actions/runs/29976273142/job/89108578186) | `ACTIONABLE_BLOCK`; informó rule ID, CWE-78, archivo/línea, source, sink y remediación |

## Evidencia adversarial Trivy filesystem/SCA

Los PR permanecen Draft y no deben fusionarse.

| Caso | Evidencia | Resultado |
|---|---|---|
| TF-01 | [Spring Boot PR #4](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/4), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29978037518) | `BLOCK`; detectó tres CVE Log4j directas y corregibles |
| TF-02 | [Spring Boot PR #14](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/14), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29978044245) | `BLOCK`; resolvió `log4j-core` como dependencia `indirect` |
| TF-03 | [Spring Boot PR #6](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/6), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29978039391) | `PASS`; la versión corregida eliminó el delta |
| TF-04 | [Next.js PR #16](https://github.com/Sul4m/devsecops-poc-nextjs/pull/16), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29978031787) | `WARN`; manifest con rango sin lockfile no quedó verde silencioso |
| TF-05 | [Next.js PR #17](https://github.com/Sul4m/devsecops-poc-nextjs/pull/17), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29978033334) | `BLOCK`; detectó eliminación del lockfile confiable |
| TF-06 | [Spring Boot PR #11](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/11), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29978040307) | `WARN`; tres findings heredados visibles, delta cero y check verde |
| TF-07 | [Spring Boot PR #13](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/13), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29978041407) | `BLOCK`; `.trivyignore` y `trivy.yaml` del mismo PR no ocultaron Log4Shell |
| TF-08 | [Spring Boot PR #12](https://github.com/Sul4m/devsecops-poc-spring-boot/pull/12), [run](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29978042788) | `BLOCK`; el mismo CVE heredado en otro target siguió siendo nuevo |
| TF-09 | [Next.js PR #18](https://github.com/Sul4m/devsecops-poc-nextjs/pull/18), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29978034515) | `WARN`; CVE Critical sin fix permaneció visible y no bloqueó |
| TF-10 | [Next.js PR #19](https://github.com/Sul4m/devsecops-poc-nextjs/pull/19), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29978036087) | `BLOCK`; CVE-2025-54236 sin fix bloqueó por CISA KEV |
| TF-11 | [Next.js PR #22](https://github.com/Sul4m/devsecops-poc-nextjs/pull/22), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29978110438) | `WARN`; dos findings quedaron `SUPPRESSED` solo por VEX confiable, exacto y vigente |
| TF-12 | [Next.js PR #20](https://github.com/Sul4m/devsecops-poc-nextjs/pull/20), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29977800120) | `SCANNER_ERROR`; DB mayor a 24 horas nunca se interpretó como limpia |
| TF-13 | [Next.js PR #21](https://github.com/Sul4m/devsecops-poc-nextjs/pull/21), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29977832012) | `SCANNER_ERROR`; outage real del repositorio OCI quedó separado de findings |
| TF-14 | [Job y annotations de TF-02](https://github.com/Sul4m/devsecops-poc-spring-boot/actions/runs/29978044245/job/89113891112) | Summary y annotations muestran target, relación, KEV, CVE, package, installed/fixed, severidad, título, advisory y remediación |

## Evidencia adversarial Trivy image/container

El gate central está en el [Draft PR #26](https://github.com/Sul4m/devsecops-poc-workflows/pull/26). Los PR consumidores y los fault injections permanecen Draft y no deben fusionarse.

| Caso | Evidencia | Resultado |
|---|---|---|
| TI-01 | [Next.js PR #25](https://github.com/Sul4m/devsecops-poc-nextjs/pull/25), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984005235) | `BLOCK`; 13 CVE corregibles introducidas por `alpine:3.16.0` |
| TI-02 | [Next.js PR #26](https://github.com/Sul4m/devsecops-poc-nextjs/pull/26), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984221619) | `BLOCK`; detectó dos findings nuevos de `lodash@4.17.20` instalado dentro de la imagen |
| TI-03 | [Next.js PR #27](https://github.com/Sul4m/devsecops-poc-nextjs/pull/27), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984236598) | `WARN`; el paquete vulnerable descartado con el build stage no apareció en la imagen final |
| TI-04 | [Next.js PR #24](https://github.com/Sul4m/devsecops-poc-nextjs/pull/24), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29983986304) | `WARN`; HEAD/base tuvieron IDs distintos pero delta cero y cuatro findings heredados |
| TI-05 | [Next.js PR #29](https://github.com/Sul4m/devsecops-poc-nextjs/pull/29), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984177605), [fault PR #27](https://github.com/Sul4m/devsecops-poc-workflows/pull/27) | `BLOCK`; detectó reconstrucción del tag después del scan |
| TI-06 | [Next.js PR #30](https://github.com/Sul4m/devsecops-poc-nextjs/pull/30), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984190981), [fault PR #28](https://github.com/Sul4m/devsecops-poc-workflows/pull/28) | `BLOCK`; detectó que el tag mutable pasó a otra imagen |
| TI-07 | [Next.js PR #32](https://github.com/Sul4m/devsecops-poc-nextjs/pull/32), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984246962) | `BLOCK`; neutralizó dos ignore files y mantuvo visible `CVE-2022-30065` |
| TI-08 | [Next.js PR #28](https://github.com/Sul4m/devsecops-poc-nextjs/pull/28), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984266139) | `BUILD_ERROR`; HEAD falló y nunca se informó una imagen limpia |
| TI-09 | [Next.js PR #31](https://github.com/Sul4m/devsecops-poc-nextjs/pull/31), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984201673), [fault PR #29](https://github.com/Sul4m/devsecops-poc-workflows/pull/29) | `SCANNER_ERROR`; JSON/SARIF vacíos no se interpretaron como cero findings |
| TI-10 | [PASS PR #34](https://github.com/Sul4m/devsecops-poc-nextjs/pull/34), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/30105715139); [BLOCK PR #35](https://github.com/Sul4m/devsecops-poc-nextjs/pull/35), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/30105692367); [contrato central PR #31](https://github.com/Sul4m/devsecops-poc-workflows/pull/31) | El mismo subject quedó `PASS`; sustituir el tag después del publish dejó security verde y produjo `BLOCK` con image IDs esperado/real y remediación |
| TI-11 | [Job y annotations de TI-01](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/29984005235/job/89131768451) | `ACTIONABLE_BLOCK`; 10 annotations visibles incluyen título, CVE, paquete, installed/fixed, target, advisory y remediación |

## Evidencia tests, build y experiencia del desarrollador

El gate inicial está en el [Draft PR #33](https://github.com/Sul4m/devsecops-poc-workflows/pull/33). Los casos validan el resultado del check, no la promoción a `main`.

| Caso | Evidencia | Resultado |
|---|---|---|
| DX-01 | [PASS PR #37](https://github.com/Sul4m/devsecops-poc-nextjs/pull/37), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/30106778205); [BLOCK PR #38](https://github.com/Sul4m/devsecops-poc-nextjs/pull/38), [run](https://github.com/Sul4m/devsecops-poc-nextjs/actions/runs/30106762727) | El happy path ejecutó 1 unit + 1 e2e. El caso `--passWithNoTests` terminó con exit 0 y JSON válido, pero el gate rechazó `numTotalTests: 0` con `BLOCK` y remediación |
| DX-02 | [PASS PR #40](https://github.com/Sul4m/devsecops-poc-nextjs/pull/40), [WARN PR #42](https://github.com/Sul4m/devsecops-poc-nextjs/pull/42), [skip BLOCK PR #41](https://github.com/Sul4m/devsecops-poc-nextjs/pull/41), [same-count bypass PR #43](https://github.com/Sul4m/devsecops-poc-nextjs/pull/43), [todo BLOCK PR #44](https://github.com/Sul4m/devsecops-poc-nextjs/pull/44), [gate PR #35](https://github.com/Sul4m/devsecops-poc-workflows/pull/35) | Compara identidades contra la base confiable: deuda heredada queda `WARN` con owner/SLA; cualquier skip/todo nuevo produce `BLOCK`, incluso si el conteo agregado permanece `1 → 1` |

El primer intento con `poc-v1.2.0` terminó con Semgrep exit code 7 por una regla JSX inválida. Ese rojo no se aceptó como evidencia de vulnerabilidad. La corrección `poc-v1.2.1` llegó al gate de delta y produjo los rule IDs esperados.

## Criterios go/no-go

**Go preliminar del mecanismo** si UC-00 a UC-06 producen exactamente el comportamiento esperado y el rollback UC-07 es viable por SHA inmutable. El go definitivo requiere aprobar el plan adversarial completo.

**No-go** si un secreto, dependencia High/Critical o regresión SAST atraviesa en verde; si la deuda baseline bloquea cambios legítimos; o si un fallo se oculta mediante `continue-on-error`, `exit-code: 0` sin enforcement posterior o un bypass equivalente.

## Ensayo final visual obligatorio

El PoC no obtendrá el go definitivo únicamente porque un agente consulte runs, artifacts o logs por consola. Al terminar los casos individuales se ejecutará un dress rehearsal operado como trabajo normal de desarrollo, y el resultado se revisará visualmente en la interfaz de GitHub junto con el usuario.

El ensayo incluirá cambios reales de aplicación y cubrirá, como mínimo:

1. PR limpio: tests, build y scanners ejecutados; estados y summaries coherentes.
2. PR adversarial mixto: cada job independiente detecta su regresión sin ocultar los demás resultados.
3. Deuda heredada: permanece verde como `WARN`, con owner y SLA visibles.
4. Error de policy y error operativo: aparecen como `POLICY_ERROR`/`SCANNER_ERROR`, nunca como vulnerabilidad.
5. Intentos de bypass: ignores, supresiones, `passWithNoTests`, skips/todos, cambio de subject y alteración del workflow no producen falsos verdes.
6. Corrección del mismo PR: al retirar las regresiones, los checks cambian al estado esperado sin limpiar evidencia histórica.

La evidencia aceptada será la vista de checks del PR, summaries, annotations y artifacts enlazados desde GitHub. La lectura por CLI seguirá sirviendo para diagnóstico, pero no sustituirá la aceptación visual final.

## Aislamiento y limpieza

- Repositorios privados y separados de SaleADS.
- Solo credenciales ficticias; ningún secreto real.
- Sin GCP, IaC, datos corporativos ni despliegue cloud en esta etapa.
- Cerrar sin fusionar los PR negativos al terminar la evidencia.
- Eliminar fixtures y ramas de prueba después de la decisión final del PoC.
