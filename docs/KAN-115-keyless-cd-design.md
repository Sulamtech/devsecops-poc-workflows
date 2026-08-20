# KAN-115 — CD keyless, privado y efímero

## Propósito

Validar que una imagen aprobada por CI sea exactamente la que llega a GCP y
que GKE rechace imágenes sin la identidad de firma esperada. El PoC no usa
credenciales JSON, no expone servicios públicamente y se elimina al terminar.

## Flujo de confianza

1. `reusable-security.yml` compila y escanea HEAD contra su base confiable.
2. Si Trivy permite la imagen, exporta el archivo Docker exacto y firma
   keylessly su manifiesto de sujeto.
3. `reusable-gcp-publish.yml` verifica esa firma y los hashes antes de
   autenticarse.
4. GitHub OIDC entra a GCP mediante un provider restringido al repositorio,
   rama, caller workflow y reusable workflow esperados.
5. Se publica el archivo aprobado en Artifact Registry, se vuelve a descargar
   por digest y se compara su Docker image ID.
6. Cosign firma el digest con la identidad del reusable workflow central.
7. El workflow solo actualiza el digest de la rama `gitops`.
8. ArgoCD sincroniza esa rama; Kyverno deniega imágenes sin firma válida.

## Aislamiento y costo

- Proyecto: `devsecops-poc-503420`.
- Región/zona: `us-central1` / `us-central1-a`.
- Un clúster zonal, un nodo pequeño y sin `LoadBalancer`.
- Nodos privados; salida temporal por Cloud NAT.
- Presupuesto mensual de USD 10 con alertas 50/90/100.
- Artifact Registry con tags inmutables.
- Teardown inmediato después del dress rehearsal.

El presupuesto alerta pero no constituye un límite duro. El control real del
costo es la vida corta del clúster y la verificación final de cero recursos
facturables.

## Política Shape Up

Los hallazgos heredados permanecen visibles sin bloquear. La promoción se
detiene únicamente ante una regresión accionable, evidencia ausente,
scanner fallido, cambio del sujeto aprobado, autenticación fuera del trust
boundary o firma inválida. No existe bypass por `continue-on-error`.

## Rollback

Rollback significa revertir el digest en Git a la última revisión admitida.
ArgoCD reconcilia ese estado; no se usa `kubectl set image` ni una imagen
reconstruida. Si el scanner o Sigstore no están disponibles, no se publica un
nuevo digest y la versión vigente continúa operando.

## Evidencia de admission y rollback

- Se copió temporalmente una imagen OCI real a Artifact Registry sin firma
  Cosign (`sha256:278fb9d...`) y se promovió únicamente mediante la rama
  `gitops` en el commit `054d37c`.
- Kyverno rechazó la creación del pod con
  `Image rejected: use the immutable digest signed by the approved central
  publish workflow`.
- El rollout conservó disponible el pod firmado anterior (`1/1`); no hubo
  sustitución por la imagen no aprobada.
- El commit de rollback `7088df9` restauró el digest firmado
  `sha256:e438fe2...`; ArgoCD volvió a `Synced/Healthy`.
- La imagen temporal y sus manifests se eliminaron. La inmutabilidad de tags,
  deshabilitada solo para limpiar la fixture, quedó restaurada.

Como prueba adicional de `failurePolicy: Fail`, el commit `f44b046` intentó un
digest inexistente y admission lo rechazó por `MANIFEST_UNKNOWN`; el rollback
`c4c716b` restauró el mismo estado sano.

## Teardown ejecutado

Después de completar 92/92 validaciones y registrar el NO-GO, se eliminó el
proyecto aislado `devsecops-poc-503420`. El inventario previo contenía un
clúster GKE, un Artifact Registry, cuatro service accounts, dos WIF pools y un
router. La verificación posterior devolvió lifecycle `DELETE_REQUESTED`.

También se retiraron de GitHub las variables GCP, el secret canary, los
branches y PRs adversariales nuevos, el fork privado y el colaborador temporal.
No se tocaron activos SaleADS.
