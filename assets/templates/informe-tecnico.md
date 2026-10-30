# Informe técnico — Auditoría de seguridad de API

**Cliente:** … · **Activo:** … · **Periodo:** … · **Autoría:** … · **Versión:** 1.0 · **Clasificación:** Confidencial

## Índice
1. Resumen de resultados · 2. Alcance y reglas de compromiso · 3. Metodología y marcos · 4. Inventario · 5. Modelo de amenazas · 6. Hallazgos · 7. Matriz de mapeo cruzado · 8. Plan de remediación · 9. Apéndices

## 1. Resumen de resultados
Tabla de severidad (Crítica…Informativa), gráfico por categoría OWASP, y lista corta de hallazgos críticos/altos con su ID.

## 2. Alcance y reglas de compromiso
Resumen de `scope-roe.md`: hosts, entornos, ventana, límites, cuentas de prueba, exclusiones. Lo **no probado** y por qué.

## 3. Metodología y marcos
- Fases: alcance → contexto → inventario → modelado de amenazas → revisión estática → pruebas dinámicas guiadas → valoración → reporte → retest (basado en NIST SP 800-115, SP 800-228 y OWASP WSTG).
- Marcos y versiones: OWASP API Security Top 10 **2023**; OWASP Top 10 for LLM Applications **2026**; OWASP Top 10 for Agentic Applications **2026**; ASVS **5.0** (nivel objetivo L_); NIST SP 800-228, 800-53 r5, CSF 2.0, AI RMF; MITRE ATT&CK/ATLAS; CWE; CVSS **v4.0**; PCI DSS **4.0.1**; ISO/IEC 27001:**2022** (y 42001 si aplica).
- Herramientas utilizadas (versión).
- Criterios de severidad (CVSS v4.0 + ajuste contextual) y niveles de confianza.

## 4. Inventario
Tabla de endpoints (método, ruta, exposición, autenticación, datos, versión, estado). APIs *shadow/zombie* detectadas. Componentes de IA (AIBOM mínimo) si aplica.

## 5. Modelo de amenazas
Diagrama de flujo de datos y fronteras de confianza; escenarios priorizados (probabilidad × impacto) con técnica ATT&CK/ATLAS.

## 6. Hallazgos
Un bloque por hallazgo con el formato de `hallazgo.md` (ordenados por severidad). Los hallazgos de baja severidad de configuración pueden agruparse en un hallazgo con lista de afectados.

## 7. Matriz de mapeo cruzado
Salida de `scripts/findings_matrix.py` (OWASP, CWE, ASVS, NIST 800-53, ATT&CK/ATLAS, PCI DSS, ISO 27001), más cobertura por categoría.

## 8. Plan de remediación
| Prioridad | Hallazgos | Acción (correctiva · preventiva · detectiva) | Responsable | Plazo | Esfuerzo |
|---|---|---|---|---|---|

## 9. Apéndices
- A. Checklists completados (01–07) con estado y referencias de evidencia.
- B. Cuentas/identidades de prueba y datos creados (para limpieza).
- C. Candidatos descartados y falsos positivos (con motivo).
- D. Evidencia (índice) y política de retención.
- E. Glosario.
- F. Referencias y fuentes con versiones y fecha de verificación.
