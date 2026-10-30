# Severidad, redacción de hallazgos e informes

Contenido: [Escala](#escala-de-severidad) · [Confianza](#niveles-de-confianza) · [Matriz de riesgo de respaldo](#matriz-de-riesgo-de-respaldo) · [Anatomía](#anatomía-de-un-buen-hallazgo) · [Mal/bien](#ejemplos-de-redacción) · [Informe ejecutivo](#informe-ejecutivo) · [Informe técnico](#informe-técnico) · [Remediación](#remediación-tres-niveles) · [Priorización](#priorización-de-la-remediación) · [Retest](#retest)

## Escala de severidad

| Severidad | CVSS v4.0 | Significado operativo | SLA de remediación sugerido* |
|---|---|---|---|
| Crítica | 9.0–10.0 | Compromiso masivo de datos o control total, explotable fácilmente | Inmediata (horas–7 días), con mitigación temporal |
| Alta | 7.0–8.9 | Acceso a datos sensibles o funciones privilegiadas | ≤ 30 días |
| Media | 4.0–6.9 | Impacto limitado o requiere condiciones | ≤ 90 días |
| Baja | 0.1–3.9 | Impacto menor / defensa en profundidad | Siguiente ciclo |
| Informativa | 0.0 | Buena práctica / sin riesgo directo | Opcional |

\* Los SLA son una sugerencia; el cliente/regulación manda (p. ej., PCI exige tratar vulnerabilidades críticas/altas con prontitud según su proceso de clasificación).

Si la severidad final difiere de la banda CVSS, escribe `severity_justification` (ajuste contextual: ver `references/07-cwe-cvss-epss-attack.md`).

## Niveles de confianza

- **Confirmado**: reproducido con evidencia (o demostrado en código/configuración inequívoca).
- **Probable**: fuerte indicio, falta confirmar por límite de alcance o de entorno.
- **Por validar**: candidato derivado de revisión estática; incluir en un anexo, no en el cuerpo principal.

## Matriz de riesgo de respaldo

Cuando no puedas puntuar con CVSS v4 (p. ej., falla de proceso, ausencia de control, riesgo de IA sin vector claro), usa Probabilidad × Impacto (1–5 cada uno) y documenta el criterio:

| Prob \ Impacto | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| 5 | Media | Media | Alta | Crítica | Crítica |
| 4 | Baja | Media | Alta | Alta | Crítica |
| 3 | Baja | Media | Media | Alta | Alta |
| 2 | Baja | Baja | Media | Media | Alta |
| 1 | Baja | Baja | Baja | Media | Media |

## Anatomía de un buen hallazgo

1. **ID y título** que dice el fallo y el lugar: "BOLA en `GET /v2/accounts/{id}/statements` permite leer extractos de otros clientes".
2. **Resumen** en 2–3 frases (qué, dónde, qué impacto).
3. **Marcos**: categorías OWASP (API/LLM/ASI), CWE principal, ASVS/NIST/PCI/ISO (automático desde la matriz).
4. **Ubicación**: método + ruta, versión, entorno, componente, repositorio/archivo y línea si hay código.
5. **Descripción técnica** de la causa raíz.
6. **Pasos de reproducción** con petición mínima, identidades usadas y resultado esperado vs. observado; datos enmascarados.
7. **Impacto**: en datos (qué y cuántos), en negocio y en cumplimiento.
8. **Severidad**: vector CVSS v4, puntuación, severidad final, justificación, confianza.
9. **Remediación**: correctiva, preventiva, detectiva, y **cómo verificar**.
10. **Referencias**: capítulo/ID de los marcos y artículos relevantes.

## Ejemplos de redacción

| Mal | Bien |
|---|---|
| "La API es insegura." | "El endpoint `GET /v2/orders/{id}` devuelve pedidos de otros usuarios (autorización por objeto ausente). Confirmado con dos cuentas de prueba." |
| "Falta HSTS" (como Alta) | "Falta HSTS en `api.ejemplo.com`; riesgo bajo por tráfico solo desde apps móviles con *certificate pinning*. Agrupado en H-014 (Configuración)." |
| "El LLM filtra información." | "El asistente devuelve fragmentos de documentos del tenant B al usuario del tenant A porque el recuperador filtra por similitud sin ACL (canario `CANARIO-B-91c2` apareció en 4/10 intentos). Impacto: fuga entre tenants." |
| "Aplicar buenas prácticas." | "Aplicar el filtro `tenant_id = :principal.tenant` en `DocumentRepository.search`, añadir prueba de integración con dos tenants en CI y alertar si un resultado tiene `tenant_id` distinto al del principal." |

## Informe ejecutivo

Estructura (`assets/templates/informe-ejecutivo.md`): propósito y alcance en tres líneas · **postura de riesgo** global en lenguaje de negocio (sin siglas) · tabla de hallazgos por severidad · **tres riesgos principales** con impacto y recomendación · fortalezas observadas · hoja de ruta 30/60/90 días · limitaciones y lo no probado · próximos pasos (retest). Máximo 2–3 páginas.

## Informe técnico

Estructura (`assets/templates/informe-tecnico.md`): metodología y marcos con versiones · alcance y reglas de compromiso · resumen de resultados (tabla y gráfico por severidad/categoría) · hallazgos detallados · matriz de mapeo cruzado · apéndices (inventario, checklists con estado, herramientas, cuentas usadas, descartes y falsos positivos) · plan de remediación · glosario.

## Remediación: tres niveles

- **Correctiva**: arreglar la instancia (parche, filtro, configuración).
- **Preventiva**: que no reaparezca (biblioteca/patrón central de autorización, política en gateway, plantilla de IaC, regla SAST, prueba automatizada en CI, revisión de diseño).
- **Detectiva**: que se vea si pasa (log de decisiones de autorización, alerta por patrón de enumeración, métrica de gasto de tokens).

## Priorización de la remediación

Ordena por **reducción de riesgo por esfuerzo**. Suele ser: (1) autorización por objeto/función central (arregla familias de hallazgos), (2) quitar/proteger activos olvidados, (3) límites de recursos en gateway, (4) endurecer identidad y tokens, (5) configuración y cabeceras, (6) observabilidad. En IA: reducir agencia y permisos, aislamiento por tenant, validación en sinks, tope de gasto.

## Retest

Repite la reproducción original, prueba variantes de evasión (otro método, otra versión, otro formato de ID, codificaciones), confirma que la detección funciona y registra estado: **Cerrado**, **Parcial**, **Abierto** o **Riesgo aceptado** (con responsable y fecha de revisión). Usa `assets/templates/retest.md`.
