# KAN-115 — Decisión go/no-go

**Fecha:** 2026-07-24  
**Decisión:** **NO-GO para rollout en SaleADS**

La cadena técnica de CD es viable en el laboratorio aislado, pero esta decisión
no autoriza cambios en repositorios, identidades, registries, ArgoCD ni clusters
corporativos.

## Evidencia favorable

| Capacidad | Resultado |
|---|---|
| Camino feliz | CI → WIF → Artifact Registry → firma keyless → GitOps → ArgoCD → GKE completado |
| Scanner outage | `SCANNER_ERROR`, publish omitido y runtime sin cambios ([run 30130800861](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/30130800861)) |
| Artefacto manipulado | `BLOCK` antes de autenticación GCP, publish y GitOps ([run 30130971663](https://github.com/Sul4m/devsecops-poc-nestjs/actions/runs/30130971663)) |
| Admission | Kyverno rechazó una imagen real sin la identidad de firma aprobada (`054d37c`) |
| Rollback | GitOps restauró el digest firmado; ArgoCD quedó `Synced/Healthy` y el canary `1/1` (`7088df9`) |
| Catálogo adversarial | **92/92** casos con evidencia: 77 de plataforma y 15 de contrato |
| Contratos centrales | PR [#36](https://github.com/Sul4m/devsecops-poc-workflows/pull/36) con policy pack, caller integrity, Semgrep rules y capability audit |
| Teardown | Proyecto GCP `DELETE_REQUESTED`; variables GCP, secret/fork/collaborator temporales y branches adversariales retirados |

## Bloqueadores del rollout

1. Completar 92/92 significa que todos los escenarios tienen evidencia, **no**
   que todos los controles sean efectivos. Seis casos conservan
   `control_outcome: unsupported`: `INT-01`, `INT-05`, `INT-06`, `GL-05`,
   `SG-04` y `SG-05`.
2. GitHub Free no ofrece rulesets/branch protection en estos repositorios
   privados: ambas APIs devolvieron `HTTP 403`. Por eso eliminar el job,
   retirar el trigger o usar `[skip ci]` todavía puede evitar el enforcement.
3. Gitleaks no reconstruye secretos concatenados solo en runtime. Semgrep
   Community Edition no demostró propagación por wrapper ni entre archivos.
   Los fixtures usan `KNOWN_FN`, no falsos PASS.
4. La autoridad corporativa, required checks, WIF, ArgoCD y admission de
   SaleADS no fueron modificados ni validados; el resultado pertenece al
   laboratorio aislado.
5. El workflow central aún requiere release inmutable, canary por cohorte,
   métricas y rollback aprobados antes de exponer sus 22 consumidores.

## Condiciones para cambiar a GO

- Resolver los seis outcomes `unsupported` o aprobar controles compensatorios
  con owner, justificación, SLA y vencimiento.
- Demostrar required checks/rulesets y autoridad externa en una plataforma que
  soporte enforcement para repositorios privados.
- Publicar una versión inmutable del workflow central, con canary, cohortes,
  métricas, rollback probado y blast radius documentado.
- Asignar owners y SLA para policy errors, outages, falsos positivos,
  excepciones y deuda baseline.

## Teardown completado

Antes de eliminar el proyecto se observaron 1 clúster GKE, 1 repositorio de
Artifact Registry, 4 service accounts, 2 WIF pools y 1 router. Se eliminó
`devsecops-poc-503420` y se verificó lifecycle `DELETE_REQUESTED`.

En GitHub se retiraron las variables que apuntaban a GCP, el secret canary,
los branches/PRs adversariales nuevos, el fork y colaborador temporal de
INT-14. La política de forks privados volvió a ejecución deshabilitada, sin
write tokens ni secrets.

## Alcance autorizado

Se autoriza conservar el PoC como evidencia y referencia de diseño. No se
autoriza promoverlo a SaleADS hasta que se cumplan las condiciones anteriores y
Security/Platform registren una nueva decisión.
