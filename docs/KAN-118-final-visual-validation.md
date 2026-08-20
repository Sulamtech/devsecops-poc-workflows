# KAN-118 — Dress rehearsal visual final

## Regla de aceptación

La aceptación ocurre mirando GitHub Actions con el usuario. La CLI sirve para
diagnóstico, pero no sustituye la evidencia visual. Ningún PR adversarial se fusiona.

## Secuencia

1. Crear un PR limpio con cambios reales en los cuatro stacks.
2. Confirmar checks verdes, summaries comprensibles y build output verificable.
3. Crear un PR mixto con una mutación por control para demostrar que solo falla el gate
   correspondiente y que los demás scanners siguen siendo evidencia válida.
4. Probar deuda heredada para observar `WARN` con owner y SLA, sin bloqueo.
5. Probar por separado `POLICY_ERROR` y `SCANNER_ERROR`; ninguno puede aparecer verde.
6. Intentar bypass: eliminar security, cambiar trigger, `[skip ci]`, SHA no aprobado,
   `continue-on-error`, policy local, secret en `run`, `secrets: inherit` y artifact.
7. Corregir el mismo PR y observar la transición visual de rojo/amarillo a verde.
8. Confirmar que los required checks impiden merge cuando falta, falla o se omite un gate.

## Qué debe entender un developer sin descargar archivos

Cada check debe indicar:

- decisión: `PASS`, `WARN`, `BLOCK`, `POLICY_ERROR` o `SCANNER_ERROR`;
- vulnerabilidad o fallo contractual;
- archivo y línea cuando aplica;
- impacto;
- corrección concreta;
- owner y SLA para deuda aceptada;
- diferencia entre vulnerabilidad, policy inválida y outage.

Los JSON de Jest y scanners son evidencia transitoria del runner. No se publican como
artifacts. El único artifact permitido es la imagen exacta escaneada cuando se habilita
explícitamente el contrato de publish.

## Go / no-go

**Go:** todos los casos implementados producen visualmente el estado esperado, ningún
bypass habilita merge y la corrección del mismo PR restaura los checks.

**No-go:** falso verde, finding sin remediación, artifact sensible, check omitible,
scanner outage clasificado como PASS o publish de una imagen distinta a la escaneada.
