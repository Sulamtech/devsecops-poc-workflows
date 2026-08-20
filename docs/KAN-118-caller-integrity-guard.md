# KAN-118 — Guard de integridad del caller

## Propósito

Este guard inspecciona workflows y rutas cambiadas del consumidor sin ejecutar su código. Su objetivo es producir feedback accionable para `INT-02`, `INT-03`, `INT-04`, `INT-07` e `INT-08` antes de confiar en los resultados de Semgrep, Trivy o Gitleaks.

## Boundary de ejecución, no raíz de confianza

El reusable workflow obtiene `caller_integrity_guard.rb` y `caller-integrity-policy.json` desde un commit central inmutable. Esto hace reproducible el detector cuando se invoca, pero **no crea una raíz de confianza ni un enforcement inviolable**. El checkout del consumidor solo aporta datos: workflows YAML y nombres de archivos cambiados. El parser usa `YAML.safe_load`, no admite aliases y nunca evalúa comandos, Actions o scripts del caller.

La Action compuesta que contiene el guard se fija al commit
`12ec9679308426e59a5a74a49c02dde2f167193c`. Separa el código confiable ya
materializado del reusable workflow que lo consume y evita cargar scripts desde el PR
del consumidor o desde una rama/tag mutable. Los consumidores deberán fijarse al
commit final revisado del reusable, añadido mediante una actualización explícita de la
allowlist.

## Semántica del diff

En `pull_request`, el guard valida los commits base/head del evento, calcula `git merge-base(base, head)` y analiza exclusivamente `merge-base..head`. En `push`, usa `before..sha`. La lista usa `git diff --name-only -z --diff-filter=ACMRTD`, por lo que conserva nombres con saltos de línea e incluye adiciones, copias, modificaciones, renames, cambios de tipo y eliminaciones. Si falta un commit, no existe merge-base o `git diff` falla, el resultado es `SCANNER_ERROR` y no se continúa con una lista parcial.

La allowlist de workflows **no vive en el PR ni se acepta como input `workflow_call`**, pero tampoco es un trust anchor. El reusable lee `${{ vars.DEVSECOPS_APPROVED_WORKFLOW_SHAS }}` desde el contexto del repositorio/organización caller. GitHub documenta que los `env` del caller no se propagan a un reusable y que la forma soportada de compartir configuración es una variable de repositorio u organización mediante `vars`; además, el contexto del called workflow se evalúa desde el caller. Un actor con acceso `write` al repositorio puede administrar esta variable y una variable de repositorio puede prevalecer sobre una organizacional. Véase [Reusing workflow configurations](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#limitations-of-reusable-workflows) y [Contexts reference — vars](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#vars-context).

### Configuración obligatoria del caller

Crear `DEVSECOPS_APPROVED_WORKFLOW_SHAS` como variable de repositorio o de organización restringida a los repositorios autorizados. Su valor es un array JSON no vacío, sin duplicados y compuesto solo por SHA Git de 40 caracteres:

```json
["ad9d553563cb027877f2c676cab7894bb095edc6", "e81bb14dbdcac024b92d524ad3ee7edcdae354d8", "<sha-post-merge-del-guard>"]
```

Si la variable falta, está vacía, contiene JSON inválido, un tag, un SHA corto o duplicados, el guard produce `POLICY_ERROR` y falla su job. El contenido del PR no modifica directamente la variable, pero un actor con acceso `write` sobre el caller sí puede hacerlo fuera del diff. Por eso la variable es configuración operativa mutable, no aprobación independiente.

La configuración de validación central contiene actualmente releases ya revisadas:

- `ad9d553563cb027877f2c676cab7894bb095edc6` (`poc-v1.0.1`).
- `e81bb14dbdcac024b92d524ad3ee7edcdae354d8` (`poc-v1.2.1`).

Agregar una versión exige revisar el diff central, fusionar el cambio y actualizar la variable externa con el SHA post-merge. Un tag no es evidencia de aprobación.

## Decisiones y remediación

| Caso | Decisión | Feedback |
|---|---|---|
| Ref mutable o SHA central no aprobado | `BLOCK` | Pin exacto y release aprobado |
| Job privilegiado sin `needs: integrity` | `BLOCK` | Ordenar el job detrás del guard antes de ejecutar el reusable |
| Action JavaScript aprobada con runtime distinto de `node24` | `SCANNER_ERROR` | Actualizar a un SHA revisado compatible y renovar la atestación central |
| `continue-on-error` distinto de `false` | `BLOCK` | Retirar bypass; usar `if: always()` solo para evidencia |
| Permisos implícitos, amplios o de escritura | `BLOCK` | Solo scopes de lectura aprobados (`contents` y, cuando el caller lo requiere, `pull-requests`) |
| Baseline modificado por el consumidor | `BLOCK` | Flujo separado y confiable basado en base SHA |
| Reglas/policy locales modificadas | `BLOCK` | Cambio revisado en el repo central y consumo por SHA |
| YAML o policy inválida | `POLICY_ERROR` | Corregir contrato; no reportar como vulnerabilidad |
| Checkout/input inaccesible | `SCANNER_ERROR` | Reintentar y resolver runtime antes de publish/deploy |

## Decisión lógica frente a enforcement de GitHub

`BLOCK` es una decisión lógica del detector: genera exit code no cero y una conclusión roja para ese job. Solo se convierte en impedimento de merge cuando GitHub exige externamente ese check. Sin required check, ruleset o branch protection, `BLOCK` **no impide** que el PR se fusione.

La validación del catálogo distingue entre **evidencia ejecutada** y **control
efectivo**. Una evidencia puede quedar validada con
`control_outcome: unsupported` cuando GitHub demuestra que la capacidad no está
disponible. Eso no convierte el caso en PASS ni autoriza rollout.

El workflow `audit-platform-capabilities.yml` consulta las APIs de rulesets y
branch protection con permisos de solo lectura. En el repositorio privado del
PoC sobre GitHub Free, ambas responden `HTTP 403`; por eso INT-01, INT-05 e
INT-06 permanecen como gaps de enforcement y sostienen el NO-GO.

El guard se ejecuta porque el caller lo invoca. Por sí solo no puede impedir que un PR elimine el job, retire el trigger o use `[skip ci]`:

- `INT-01` requiere que el check exista fuera del control del PR.
- `INT-05` requiere un required workflow/check que siempre se programe.
- `INT-06` requiere ruleset o branch protection que rechace el merge si falta el check.

La organización personal actual limita required workflows y parte del enforcement centralizado. `INT-01`, `INT-05`, `INT-06` y cualquier garantía marcada con `platform_evidence_required` permanecen **no validados a nivel de plataforma / enforcement pendiente**. Un check verde del guard o un snapshot contractual no debe presentarse como evidencia de enforcement.

La referencia al propio guard se valida igual que los otros reusables: identidad central exacta, SHA completo y pertenencia a `DEVSECOPS_APPROVED_WORKFLOW_SHAS`. Esto detecta inconsistencias contra la configuración actual, pero no elimina el límite de autoridad: quien controla la variable puede aprobar otro SHA.

Los jobs privilegiados declarados en `approved_privileged_jobs` deben incluir
`integrity` en `needs`. La validación de permisos y SHA por sí sola no basta: sin esa
dependencia, GitHub puede ejecutar en paralelo un reusable obsoleto mientras el guard
termina rojo. El orden protege la ejecución privilegiada y `publish`; no sustituye el
required check externo que impide fusionar el PR.

El job `security` de `ci.yml` puede solicitar `id-token: write` únicamente cuando
consume por SHA el reusable central aprobado. En esta configuración el token se usa
para firmar la aprobación del artefacto exacto cuando
`export-image-artifact: true`; no concede acceso GCP porque WIF conserva claims
separados para la ruta de publish. El job también debe depender de `integrity`.

Cada Action externa aprobada tiene una atestación de runtime ligada a
`identity@SHA` en `approved_action_runtimes`. Las Actions JavaScript solo admiten
`node24`; `node20`, `node16` u otro runtime Node producen
`SCANNER_ERROR/ACTION_RUNTIME_UNSUPPORTED` antes de confiar en la Action. Las Actions
`composite` o `docker` se registran explícitamente con su tipo y no se clasifican como
runtime Node. La atestación se revisa contra `action.yml` o `action.yaml` del mismo SHA
inmutable al actualizar la allowlist. Una atestación faltante o sobrante invalida la
policy completa.

Durante la validación end-to-end dentro del repositorio central se excluyen los
reusable workflows allowlisted: son implementaciones confiables revisadas, no input del
caller. Esto evita confundir mecanismos internos fail-closed —por ejemplo capturar el
exit code y clasificarlo después— con un bypass del consumidor. En un consumidor no
existe esta excepción: todos sus workflows y todos sus `uses` job-level/step-level se
inspeccionan.

Los consumidores no invocan la Action compuesta directamente. Solo llaman al reusable workflow post-merge aprobado; una referencia directa a `.github/actions/caller-integrity` no está en la allowlist del caller y se bloquea.

## Evidencia

El reusable workflow genera JSON transitorio, annotations y `GITHUB_STEP_SUMMARY`. El
JSON no se publica como artifact. Un resultado `BLOCK`, `POLICY_ERROR` o
`SCANNER_ERROR` falla el job; `PASS` y `WARN` permanecen verdes. Esa evidencia valida
la ejecución y la decisión del detector, no que GitHub haya impedido un merge. La
ejecución de fixtures y del guard ocurre solo en GitHub Actions.

El guard también bloquea `pull_request_target`, `secrets: inherit`, interpolación de
`secrets.*` dentro de shell y flujos evidentes desde variables secretas hacia output,
red, serialización o archivos. `upload-artifact` no está aprobado para callers del
PoC; la imagen exacta escaneada es una excepción interna y efímera del reusable
central.

Las fixtures `INT-11-PRIVILEGED-NOT-GATED` e `INT-13-NODE20` prueban,
respectivamente, el orden obligatorio del job privilegiado y la clasificación técnica
del runtime incompatible. Son contrato del detector; la evidencia de plataforma exige
además un PR real y, para impedir merge, el enforcement externo descrito arriba.

## Criterio de rollout en SaleADS

No promover este guard como control preventivo hasta que SaleADS aporte evidencia de plataforma administrada fuera del repositorio consumidor:

1. ruleset o branch protection activo sobre las ramas objetivo;
2. required workflow/check que el PR no pueda omitir ni renombrar;
3. administración de variables y excepciones separada del actor que propone el cambio;
4. prueba negativa donde omitir el workflow, cambiar el trigger o usar `[skip ci]` rechace efectivamente el merge;
5. rollback y contingencia auditables para mantener continuidad durante outages.

Hasta cumplir estos puntos, el resultado del PoC es **detección/contrato**, no enforcement preventivo.
