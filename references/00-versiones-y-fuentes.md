# Versiones vigentes y fuentes oficiales

Verificado el **2026-10-29**. Los marcos cambian; antes de citar un ID o un número de requisito que no esté aquí, confírmalo en la fuente oficial. Si no puedes verificar, escribe "por verificar" en el informe.

## Tabla de versiones

| Marco | Versión usada | Notas |
|---|---|---|
| OWASP API Security Top 10 | **2023** (API1–API10) | Segunda edición, tras la de 2019. |
| OWASP Top 10 for LLM Applications | **2026** (LLM01–LLM10), publicada 2026-08-04 | Ranking contrastado con datos de incidentes reales. Sustituye a la edición 2025; los mapeos hechos contra 2024/2025 deben revisarse. Incluye un apéndice que mapea las 10 categorías a 9 marcos externos. |
| OWASP Top 10 for Agentic Applications | **2026** (ASI01–ASI10), publicada 2025-12-09 | Extiende, no reemplaza, el Top 10 de LLM. |
| OWASP MCP Top 10 | Vigente (ver sitio oficial) | Capa de conexión agente-herramientas. No se reproduce aquí su lista: consúltala en genai.owasp.org. |
| OWASP ASVS | **5.0** | Capítulos usados a nivel de capítulo (V1…V17). Verifica el ID de requisito exacto en la fuente antes de citarlo. |
| OWASP WSTG | Rama estable vigente | Categorías INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT, APIT. |
| NIST SP 800-228 | Final jun 2025 (+ actualización 2026) | Protección de APIs en sistemas cloud-native: controles pre-runtime y runtime, básicos y avanzados. |
| NIST SP 800-53 | Rev. 5 | Familias AC, IA, SC, SI, CM, AU, SR, RA, SA. |
| NIST CSF | 2.0 | Funciones GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER. |
| NIST SP 800-207 | Zero Trust Architecture | Principios para authN/Z por petición. |
| NIST SP 800-115 | Guía de pruebas y evaluación de seguridad | Base metodológica de planificación, descubrimiento, ataque y reporte. |
| NIST AI RMF 1.0 + AI 600-1 | AI RMF 1.0; Perfil GenAI (AI 600-1) | Funciones GOVERN, MAP, MEASURE, MANAGE. |
| MITRE ATT&CK | Enterprise (versión vigente) | IDs Txxxx. |
| MITRE ATLAS | Versión vigente | IDs AML.Txxxx; verifica antes de citar, el catálogo cambia. |
| CWE | Catálogo vigente + CWE Top 25 de la edición más reciente | Usa siempre la edición más reciente del Top 25. |
| CVSS | **v4.0** | Cálculo con la calculadora oficial de FIRST. |
| EPSS | Versión vigente de FIRST | Probabilidad de explotación en 30 días. |
| CISA KEV | Catálogo vivo | Si la CVE está en KEV, tratarla como explotada activamente. |
| PCI DSS | **4.0.1** | Los requisitos "futuros" de 4.0 ya son obligatorios desde 2025-03-31. |
| ISO/IEC 27001 | **2022** (Anexo A de 93 controles) | |
| ISO/IEC 42001 | 2023 | Sistema de gestión de IA. |
| CIS Controls | v8.1 | Sucesor de los SANS Top 20 / Critical Security Controls. |

## Fuentes oficiales

- OWASP API Security: https://owasp.org/API-Security/
- OWASP GenAI Security Project (LLM, Agentic, MCP): https://genai.owasp.org/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-228: https://doi.org/10.6028/NIST.SP.800-228 (y https://csrc.nist.gov/pubs/sp/800/228/final)
- NIST CSRC (800-53, 800-207, 800-115): https://csrc.nist.gov/
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- MITRE ATT&CK: https://attack.mitre.org/ · MITRE ATLAS: https://atlas.mitre.org/
- CWE: https://cwe.mitre.org/ (Top 25: https://cwe.mitre.org/top25/)
- CVSS v4.0 (calculadora): https://www.first.org/cvss/calculator/4.0
- EPSS: https://www.first.org/epss/ · CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- SANS (material de pruebas web, manejo de incidentes): https://www.sans.org/
- CIS Controls: https://www.cisecurity.org/controls
- PCI SSC: https://www.pcisecuritystandards.org/ · ISO: https://www.iso.org/
- RFC 9700 (OAuth 2.0 Security BCP), RFC 8725 (JWT BCP), RFC 7636 (PKCE), RFC 9457 (Problem Details), FAPI 2.0 (OpenID Foundation) para banca abierta.

## Cómo re-verificar rápidamente

1. Busca "<marco> latest version" y abre la fuente oficial, no un blog.
2. Compara el nombre y el orden de las categorías con las tablas de `references/01-owasp-api-top10-2023.md`, `02-…`, `03-…`.
3. Si cambió algo, actualiza `assets/data/mappings.json` (campo `meta.verified_on`) y las referencias afectadas antes de auditar.

## Qué es SANS aquí

SANS no publica un único "Top 10" de APIs; su aporte útil para esta skill es (a) la lista **CWE/SANS Top 25** (hoy mantenida por MITRE como CWE Top 25), (b) los **CIS/SANS Critical Security Controls** (hoy CIS Controls v8.1) como línea base de higiene, (c) metodología de pruebas de aplicaciones web y de **manejo de incidentes** (preparación, identificación, contención, erradicación, recuperación, lecciones aprendidas) y (d) guías de redacción de informes de pruebas de penetración. Cuando el usuario pida "alinear con SANS", usa estos cuatro puntos y cita el curso/guía concreto solo si puedes verificarlo.
