# [H-000] Título: fallo + ubicación + efecto

| Campo | Valor |
|---|---|
| **Severidad** | Crítica / Alta / Media / Baja / Informativa |
| **CVSS v4.0** | `CVSS:4.0/AV:…` · puntuación: X.X (CVSS-B / BT / BE) |
| **Confianza** | Confirmado / Probable / Por validar |
| **Estado** | Abierto / Parcial / Cerrado / Riesgo aceptado |
| **Categorías OWASP** | p. ej. API1:2023 · LLM02:2026 · ASI03:2026 |
| **CWE principal** | CWE-___ |
| **Mapeo** | ASVS: V__ · NIST 800-53: __ · ATT&CK/ATLAS: __ · PCI DSS 4.0.1: __ · ISO 27001:2022: __ |
| **Ubicación** | Método + ruta · versión · entorno · componente/archivo:línea |
| **Checklist** | p. ej. AUTHZ-01 |
| **Descubierto** | Fecha UTC · identidad(es) de prueba usadas |

## Resumen
2–3 frases: qué falla, dónde y qué permite hacer.

## Descripción técnica
Causa raíz. Qué control debería existir y por qué no funciona.

## Pasos de reproducción
1. Precondiciones (identidades, objetos creados).
2. Petición mínima (enmascarada):
```http
GET /v2/accounts/{id-de-A}/statements HTTP/1.1
Host: staging-api.ejemplo.com
Authorization: Bearer [redactado: token de B]
```
3. Respuesta observada (recortada y enmascarada) vs. esperada (403/404).
4. Variantes probadas (otros métodos, versiones, formatos de ID).

## Impacto
- **Datos**: qué datos y cuántos registros/usuarios alcanzables.
- **Negocio**: fraude, reputación, operación.
- **Cumplimiento**: requisito/brecha (p. ej. PCI DSS 4.0.1 Req. 7 y 6.2.4).
- **Probabilidad**: explotabilidad, exposición, precondiciones.

## Severidad y justificación
Vector CVSS v4.0 → puntuación. Ajuste contextual (si aplica): motivo.

## Remediación
- **Correctiva**: …
- **Preventiva**: … (patrón/política/prueba en CI)
- **Detectiva**: … (log/alerta)
- **Cómo verificar**: prueba exacta que debe pasar tras la corrección.
- **Esfuerzo estimado**: bajo / medio / alto · **Responsable sugerido**:

## Evidencia
Referencias a archivos (`evidencia/H-000/…`), capturas enmascaradas, hashes.

## Referencias
- OWASP: …
- ASVS / NIST / CWE: …
