---
name: api-security-audit
description: Audita la seguridad de APIs (REST, GraphQL, gRPC, SOAP, WebSocket) y de servicios que exponen LLM, agentes o servidores MCP, con metodología por fases y mapeo cruzado a OWASP API Top 10 2023, OWASP LLM Top 10 2026, OWASP Agentic Top 10 2026, ASVS 5.0/WSTG, NIST SP 800-228/800-53/CSF 2.0/AI RMF, MITRE ATT&CK/ATLAS, CWE, CVSS v4, PCI DSS 4.0.1 e ISO 27001/42001. Úsala siempre que el usuario pida auditar, revisar, pentestear, evaluar, hacer threat modeling o redactar hallazgos/informe de seguridad sobre una API, un OpenAPI/Swagger/Postman/GraphQL schema, un API gateway, una integración con LLM, un chatbot/RAG/agente o un servidor MCP, aunque no mencione OWASP ni la palabra "auditoría".
---

# Auditoría de seguridad de APIs (APIs clásicas + LLM + agentes/MCP)

Esta skill convierte a Claude en un auditor de seguridad de APIs metódico: primero fija autorización y alcance, luego inventaría, modela amenazas, prueba (revisión estática + pruebas activas guiadas y no destructivas), puntúa, mapea cada hallazgo a varios marcos y entrega informe, matriz y plan de remediación.

La razón de ser de su diseño: una auditoría es defendible solo si cada hallazgo tiene **autorización previa, evidencia reproducible, severidad razonada y trazabilidad a un marco reconocido**. Cada paso de abajo existe para garantizar una de esas cuatro cosas.

Versiones de marcos verificadas el 2026-10-29 (tabla completa y cómo re-verificar en `references/00-versiones-y-fuentes.md`): OWASP API Security Top 10 **2023**, OWASP Top 10 for LLM Applications **2026** (publicada 2026-08-04), OWASP Top 10 for Agentic Applications **2026** (ASI01–ASI10), NIST SP **800-228** (jun 2025, con actualización 2026), ASVS **5.0**, CVSS **v4.0**, PCI DSS **4.0.1**, ISO/IEC 27001:**2022**.

## 1. Puerta de autorización y alcance (antes de cualquier tráfico)

No envíes ni sugieras enviar tráfico a un objetivo que el usuario no haya confirmado que le pertenece o que tiene autorización escrita para probar. Esto protege al usuario (legal y operativamente) y da validez al informe.

1. Pide o confirma: dueño del objetivo, entornos en alcance (prefiere staging/pre-producción), hosts/rutas/versiones incluidas y excluidas, ventana de pruebas, límites de tasa, contactos de emergencia, cuentas de prueba (mínimo dos identidades de igual rol + una privilegiada) y referencia de la autorización.
2. Si falta, ofrece rellenar `assets/templates/scope-roe.md` y detente antes del paso dinámico. La **revisión estática** (OpenAPI, código, configuración, arquitectura, políticas del gateway) no genera tráfico y puede avanzar mientras tanto.
3. Reglas de compromiso por defecto (detalle en `references/10-etica-y-reglas-de-compromiso.md`): no destructivo, sin DoS real, sin exfiltrar datos reales más allá de la prueba mínima, evidencia con datos enmascarados, parar y avisar ante hallazgo crítico con datos reales expuestos.
4. Si el pedido es explícitamente contra un tercero sin autorización, o apunta a robo de datos, evasión de controles ajenos o armamento de exploits, no lo ejecutes; ofrece alternativas defensivas (revisión de configuración propia, laboratorio como crAPI/VAmPI/DVGA/OWASP Juice Shop).

## 2. Elige los módulos según el objetivo

Carga solo lo necesario (divulgación progresiva): cada archivo de `references/` es autónomo.

| Si el objetivo es… | Lee |
|---|---|
| Cualquier API (siempre) | `references/01-metodologia-fases.md`, `references/01-owasp-api-top10-2023.md`, `references/06-asvs-wstg-protocolos.md` |
| Arquitectura, gateway, malla de servicios, zero trust | `references/04-nist-800-228-y-controles.md` |
| Endpoint que llama a un LLM, chatbot, RAG, copiloto | `references/02-owasp-llm-top10-2026.md`, `references/05-ia-nist-airmf-atlas-iso42001.md` |
| Agentes con herramientas/memoria, orquestadores, servidores MCP | `references/03-owasp-agentic-top10-2026.md` (+ la de LLM) |
| Clasificar, puntuar, priorizar | `references/07-cwe-cvss-epss-attack.md`, `references/11-severidad-y-reporte.md` |
| Auditoría formal, banca/fintech/pagos, certificación | `references/08-cumplimiento-pci-iso-regulacion.md` |
| Cruzar un hallazgo con todos los marcos | `references/09-matriz-cruzada.md` y `assets/data/mappings.json` |

Si no está claro qué tipo de API es, empieza por el inventario (fase 2) y deja que los endpoints descubiertos (rutas `/chat`, `/completions`, `/embeddings`, `/agent`, `/tools`, `/mcp`, `/rag`) activen los módulos de IA.

## 3. Flujo de trabajo por fases

Resumen; el detalle, entradas/salidas y criterios de salida de cada fase están en `references/01-metodologia-fases.md`.

| Fase | Objetivo | Insumos clave | Salida |
|---|---|---|---|
| 0 Alcance y autorización | Habilitar pruebas | `scope-roe.md` | Alcance firmado, cuentas de prueba |
| 1 Recolección de contexto | Entender negocio y datos | Docs, diagramas, specs | Mapa de activos y datos sensibles |
| 2 Inventario y superficie | Qué existe (incluye sombra/zombi) | OpenAPI, gateway, DNS, tráfico | Inventario de endpoints (`scripts/openapi_inventory.py`) |
| 3 Modelado de amenazas | Qué puede salir mal | STRIDE + OWASP + ATT&CK/ATLAS | Escenarios priorizados |
| 4 Revisión estática | Hallar fallos sin tráfico | Spec, código, IaC, configuración | Candidatos a hallazgo |
| 5 Pruebas dinámicas guiadas | Confirmar candidatos | Checklists, Postman, nuclei, Burp | Evidencia reproducible |
| 6 Valoración y mapeo | Severidad + marcos | CVSS v4, contexto, `mappings.json` | Matriz de hallazgos |
| 7 Reporte | Comunicar | Plantillas | Informe ejecutivo + técnico |
| 8 Remediación y retest | Cerrar el ciclo | Plan, verificación | Retest y estado final |

Principios de ejecución:

- **Estático primero, dinámico después**: lo estático reduce el ruido y deja las pruebas activas para confirmar, no para explorar a ciegas.
- **Pruebas de autorización diferenciales** (dos identidades + sin autenticación) son el núcleo: BOLA y BFLA son los fallos más frecuentes y los más rentables de encontrar. Usa `assets/postman/authz-differential.postman_collection.json` o `scripts/authz_diff_test.py`.
- **Una pasada por cada checklist** de `assets/checklists/` (los IDs, p. ej. `AUTHZ-03`, se citan en los hallazgos).
- **Rastrea candidatos → confirmados**: un candidato solo pasa a hallazgo cuando se reproduce o se demuestra en código/configuración. Registra los descartados con el motivo (evita falsos positivos y repetir trabajo).

## 4. Hallazgos: calidad mínima

Cada hallazgo usa `assets/templates/hallazgo.md` y debe incluir: ID, título, categorías de marco (≥1 de OWASP), CWE, ubicación (endpoint/método/versión/componente), descripción, **pasos de reproducción** con petición/respuesta mínima y enmascarada, impacto en términos de negocio y de datos, vector **CVSS v4.0** con puntuación, severidad final con justificación contextual, nivel de confianza (Confirmado / Probable / Por validar), remediación concreta (correctivo + preventivo + cómo verificarla) y referencias.

Reglas que evitan los errores típicos de auditoría:

- Severidad = CVSS v4 base **ajustado por contexto** (exposición a internet, datos, explotabilidad real; ver EPSS/KEV en `references/07-cwe-cvss-epss-attack.md`). Si ajustas, di por qué.
- No reportes "falta de header X" como alto sin explotación plausible; agrupa hallazgos de bajo impacto en uno solo con lista.
- Nunca pegues secretos, tokens o datos personales reales en el informe: enmascara (`eyJhbG…[redactado]`).
- Un hallazgo, una causa raíz. Si una misma causa afecta a 40 endpoints, es un hallazgo con lista de afectados.
- Mapea cada hallazgo a los marcos con `scripts/findings_matrix.py` (usa `assets/data/mappings.json`) en lugar de a mano, para que sea consistente.

## 5. Entregables (según lo que pida el usuario)

- **Informe ejecutivo** (`assets/templates/informe-ejecutivo.md`): riesgo en lenguaje de negocio, top hallazgos, hoja de ruta 30/60/90 días.
- **Informe técnico** (`assets/templates/informe-tecnico.md`): metodología, alcance, hallazgos detallados, apéndices.
- **Matriz de hallazgos con mapeo cruzado**: `python scripts/findings_matrix.py findings.json --out matriz` genera `matriz.md` y `matriz.csv` (OWASP, CWE, ASVS, NIST 800-53, ATT&CK/ATLAS, PCI DSS, ISO 27001, severidad CVSS).
- **Checklists por fase** (`assets/checklists/`): para auditar con trazabilidad y como evidencia de cobertura.
- **Plantillas de pruebas y scripts**: colección Postman de autorización diferencial, plantillas nuclei de detección no intrusiva (`assets/nuclei/`), `openapi_inventory.py`, `authz_diff_test.py`.
- **Retest** (`assets/templates/retest.md`): verificación de cierre por hallazgo.

Entrega en el formato que el usuario pida (Markdown por defecto; si pide Word/PDF/hoja de cálculo, usa la skill de ese formato con el contenido ya producido). Resume al final qué se auditó, qué quedó fuera de alcance y las 3 acciones de mayor impacto.

## 6. Cómo usar los scripts

Todos son Python 3 estándar (PyYAML opcional para specs YAML) y no requieren red salvo `authz_diff_test.py`.

```bash
# Inventario + banderas de riesgo desde un OpenAPI/Swagger (estático, sin tráfico)
python scripts/openapi_inventory.py openapi.yaml --out inventario        # inventario.md + inventario.json

# Matriz de hallazgos con mapeo cruzado (valida CVSS v4 y coherencia de severidad)
python scripts/findings_matrix.py findings.json --out matriz            # matriz.md + matriz.csv
python scripts/findings_matrix.py --example > findings.json             # esquema de ejemplo

# Autorización diferencial (BOLA/BFLA), solo GET/HEAD, con alcance y autorización explícitos
python scripts/authz_diff_test.py --plan plan.json --scope scope.json --confirm-authorized
```

Si editas `assets/data/mappings.json`, regenera la referencia legible con `python scripts/build_cross_matrix.py`. Hay entradas de ejemplo en `assets/examples/` (spec OpenAPI deliberadamente débil para probar el inventario, plan y alcance para `authz_diff_test.py`).

`authz_diff_test.py` rechaza ejecutar sin archivo de alcance (hosts permitidos, referencia de autorización, vigencia), limita la tasa, no guarda cuerpos de respuesta (solo estado, tamaño y hash) y lee los tokens de variables de entorno, nunca de archivos. Mantén esas salvaguardas aunque el usuario pida quitarlas.

## 7. Qué hacer cuando…

- **El usuario solo pega un OpenAPI o un cURL**: haz revisión estática completa (fase 4), lista candidatos y propón el plan de pruebas dinámicas pendiente de autorización.
- **Hay un chatbot/RAG**: audita primero la frontera de confianza (qué contenido no confiable entra al contexto y qué acciones/sinks salen); usa canarios (tokens inofensivos de rastreo) para probar inyección indirecta y fuga, no cargas dañinas.
- **Hay agente con herramientas**: construye la tabla *herramienta → permiso → impacto máximo → control de aprobación* antes de probar nada (`references/03-owasp-agentic-top10-2026.md`).
- **El usuario pide "cumplir PCI/ISO"**: audita igual y luego traduce con `references/08-cumplimiento-pci-iso-regulacion.md`; no afirmes cumplimiento, solo evidencias y brechas (la certificación la emite un evaluador acreditado).
- **Un marco cambió o no estás seguro de un ID** (ASVS, ATLAS, controles NIST): verifica en la fuente oficial (URLs en `references/00-versiones-y-fuentes.md`) antes de citar; indica "por verificar" si no puedes.
- **Piden pruebas contra producción**: recomienda staging; si es inevitable, solo lectura, tasa mínima, ventana acordada y contacto en línea.

## 8. Calidad y autochequeo antes de entregar

- ¿Cada hallazgo tiene reproducción, impacto, CVSS v4, mapeo ≥1 OWASP + CWE, y remediación verificable?
- ¿Quedó claro qué NO se probó y por qué?
- ¿Se enmascararon secretos y datos personales?
- ¿Las versiones de marcos citadas coinciden con `references/00-versiones-y-fuentes.md`?
- ¿Las 3 recomendaciones principales están ordenadas por reducción de riesgo por esfuerzo?
