# Checklist 08 — Herramientas de apoyo y flujo de trabajo

Todas se usan **solo con autorización** (ver `references/10-etica-y-reglas-de-compromiso.md`). Verifica el estado actual de cada herramienta antes de recomendarla; el ecosistema cambia.

## Proxy y pruebas manuales

| Herramienta | Uso en la auditoría |
|---|---|
| Burp Suite (Pro/Community) | Proxy, Repeater, Intruder (tasa baja), Comparer; sesiones con 2+ identidades |
| Extensiones de Burp: Autorize, AuthMatrix | Autorización diferencial (BOLA/BFLA) automatizada con varias identidades |
| Extensión InQL (GraphQL) | Introspección, generación de consultas, pruebas de autorización por campo |
| Extensión JWT Editor | Inspección y pruebas de validación de JWT (alg, claims, `kid`) |
| Param Miner / Logger++ | Descubrimiento de parámetros y cabeceras ocultas; registro de tráfico |
| OWASP ZAP | Alternativa de código abierto: proxy, escaneo con OpenAPI/GraphQL, automatización en CI |
| Postman / Bruno / Insomnia | Colecciones reproducibles y pruebas de contrato; usa `assets/postman/…` |
| curl / httpie | Reproducción mínima para el informe |

## Escáneres y análisis

| Herramienta | Uso |
|---|---|
| nuclei (+ `assets/nuclei/*.yaml`) | Detección no intrusiva de exposición de documentación, CORS, errores verbosos, introspección GraphQL, cabeceras |
| Schemathesis / RESTler / Dredd (basados en la especificación) | Pruebas de contrato y fuzzing guiado por OpenAPI, en entorno de pruebas |
| testssl.sh / sslyze | Configuración TLS |
| Semgrep / CodeQL / SAST del cliente | Revisión de código: autorización por objeto, sinks, secretos |
| Trivy / Grype / OSV-Scanner / Dependency-Check | SCA y contenedores; SBOM (CycloneDX/SPDX) |
| Gitleaks / TruffleHog | Secretos en repositorios |
| kube-bench / Prowler / ScoutSuite | Configuración de nube y Kubernetes |
| `scripts/openapi_inventory.py` | Inventario y candidatos desde OpenAPI (estático) |
| `scripts/authz_diff_test.py` | Autorización diferencial de solo lectura con alcance y límites |
| `scripts/findings_matrix.py` | Matriz de hallazgos con mapeo cruzado |

## IA/LLM

| Herramienta/Enfoque | Uso |
|---|---|
| Conjuntos de evaluación propios con canarios | Pruebas repetibles de inyección indirecta, fuga entre tenants, exfiltración vía Markdown |
| Marcos de evaluación/red teaming de LLM de código abierto vigentes (p. ej. garak, promptfoo, PyRIT) | Barridos automatizados de categorías LLM01/LLM02/LLM07; verifica su versión y licencia, y configúralos para tu alcance |
| Trazas de agentes/observabilidad de LLM | Revisión de llamadas a herramientas, tokens y costo |
| Escáneres de modelos/artefactos | Verificación de formato de serialización y firmas de modelos |

## Laboratorios de práctica (legales)

crAPI, VAmPI, DVGA, Damn Vulnerable RESTaurant, OWASP Juice Shop, PortSwigger Web Security Academy.

## Flujo recomendado en una sesión de pruebas

1. `openapi_inventory.py` → candidatos.
2. Postman/`authz_diff_test.py` con A, B, rol bajo y sin auth sobre todos los endpoints con identificador (AUTHZ-01/03).
3. Autenticación y tokens (AUTHN-02…06) con Burp + JWT Editor.
4. Propiedades (AUTHZ-04/05) con Repeater en entorno de pruebas.
5. Recursos y flujos (RES/BIZ) con umbrales bajos.
6. nuclei de configuración (`assets/nuclei`) y TLS.
7. IA/agentes con canarios (checklists 06 y 07).
8. Volcar hallazgos en `findings.json` → `findings_matrix.py`.
