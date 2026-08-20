# KAN-118 — Confianza de GitHub Actions e incidente LiteLLM

## Problema que cubre

Un scanner de repositorio no basta cuando el propio workflow puede leer un secreto y
copiarlo a un log, archivo, artifact o destino de red. El incidente de
`Sale-ADS/litellm-gateway#15` demuestra una ruta de exfiltración distinta a un secreto
commiteado: el valor nace en `secrets.*` durante la ejecución.

## Controles configurados

- Workflows y Actions externos deben usar identidad aprobada y SHA inmutable.
- Los workflows de PR usan permisos explícitos de solo lectura y no pueden usar
  `continue-on-error` para neutralizar un gate.
- `pull_request_target` está prohibido en los callers inspeccionados.
- `secrets: inherit` está prohibido.
- Interpolar `secrets.*` directamente dentro de `run` se bloquea.
- Un secreto ligado mediante `env` se bloquea si fluye hacia comandos típicos de
  output, serialización, red o archivado.
- `upload-artifact` no está aprobado para callers del PoC. Los reportes estructurados
  viven únicamente durante el job; la interfaz muestra summaries y annotations.
- La única excepción es el artifact efímero de la imagen exacta ya escaneada, generado
  dentro del reusable central para el contrato scan-to-publish, con retención de un día.
- `CODEOWNERS` asigna revisión sobre workflows, Actions, policy y scripts.
- Dependabot revisa semanalmente las Actions, pero toda actualización conserva revisión
  humana y pin por SHA.

## Límite honesto

El guard es detección, no una raíz de confianza. Un actor con capacidad de escritura
puede intentar eliminar el caller completo. El cierre real de `INT-01`, `INT-05`,
`INT-06` e `INT-14` requiere rulesets/branch protection fuera del repositorio:

1. required checks con nombres estables;
2. aprobación de CODEOWNERS para cambios de workflow;
3. prohibición de bypass para administradores durante la prueba;
4. ejecución en PRs de forks con token read-only y sin secrets;
5. comprobación visual de que eliminar/cambiar el trigger no habilita merge.

## Respuesta al incidente

Estos controles previenen recurrencia, pero no reemplazan la respuesta operativa:

- rotar todas las credenciales potencialmente expuestas;
- auditar GitHub Audit Log y Cloud Audit Logs en la ventana del incidente;
- identificar repositorios que comparten `GCP_SA_KEY*`;
- migrar el CD a Workload Identity Federation antes de conservar despliegues en GCP;
- eliminar credenciales, artifacts y recursos temporales al cerrar el PoC.
