# Matriz de mapeo cruzado

Generada desde `assets/data/mappings.json` (verificada el 2026-10-29). No la edites a mano: modifica el JSON y ejecuta `python scripts/build_cross_matrix.py`.

> Mapeos orientativos para trazabilidad. ASVS a nivel de capítulo. Antes de citar un ID concreto (ASVS, ATLAS, controles NIST, PCI, ISO) en un entregable formal, verifícalo en la fuente oficial (`references/00-versiones-y-fuentes.md`).

Columnas: CWE · ASVS 5.0 (capítulos) · NIST 800-53 r5 · tema NIST 800-228 · ATT&CK · ATLAS · PCI DSS 4.0.1 · ISO 27001:2022 · categorías OWASP relacionadas.

## OWASP API Security Top 10 — 2023

| Categoría | CWE | ASVS 5.0 | NIST 800-53 | NIST 800-228 (tema) | ATT&CK | ATLAS | PCI DSS 4.0.1 | ISO 27001:2022 | Relacionadas |
|---|---|---|---|---|---|---|---|---|---|
| **API1:2023** Broken Object Level Authorization | CWE-639, CWE-284, CWE-285 | V8 Authorization | AC-3, AC-6 | AuthN/AuthZ runtime; Pruebas de autorización en CI | T1190, T1078 | — | 6.2.4, 7.2 | 5.15, 5.18, 8.3 | API3:2023, API5:2023, LLM02:2026, ASI03:2026 |
| **API2:2023** Broken Authentication | CWE-287, CWE-306, CWE-307, CWE-798, CWE-613, CWE-347 | V6 Authentication; V7 Session Management; V9 Self-contained Tokens; V10 OAuth and OIDC | IA-2, IA-5, IA-8, SC-23 | AuthN/AuthZ runtime; Gestión de secretos | T1078, T1110, T1528, T1550, T1552 | — | 8.2, 8.3, 8.4, 8.6 | 5.16, 5.17, 8.5 | ASI03:2026 |
| **API3:2023** Broken Object Property Level Authorization | CWE-915, CWE-213, CWE-200 | V8 Authorization; V2 Validation and Business Logic; V14 Data Protection | AC-3, AC-6, SI-10, SI-15 | Validación de esquema; Protección de datos | T1190 | — | 3.4, 6.2.4, 7.2 | 8.3, 8.12 | API1:2023, LLM02:2026, LLM09:2026 |
| **API4:2023** Unrestricted Resource Consumption | CWE-770, CWE-400, CWE-799 | V2 Validation and Business Logic; V5 File Handling | SC-5, SC-6 | Protección de recursos (límites, cuotas) | T1499 | AML.T0029, AML.T0034 | 6.4.2 | 8.6 | LLM06:2026, ASI08:2026 |
| **API5:2023** Broken Function Level Authorization | CWE-862, CWE-863, CWE-285 | V8 Authorization; V4 API and Web Service | AC-3, AC-6, AC-2 | AuthN/AuthZ runtime | T1190, T1078 | — | 6.2.4, 7.2 | 5.15, 5.18, 8.2 | API1:2023, LLM03:2026, ASI02:2026, ASI03:2026 |
| **API6:2023** Unrestricted Access to Sensitive Business Flows | CWE-799, CWE-840, CWE-362 | V2 Validation and Business Logic; V15 Secure Coding and Architecture | SC-5, SI-4 | Protección de recursos; Monitoreo y detección | T1110, T1499 | — | 6.2.4, 10.4 | 8.16, 8.26 | API4:2023, ASI09:2026 |
| **API7:2023** Server Side Request Forgery | CWE-918 | V1 Encoding and Sanitization; V12 Secure Communication; V15 Secure Coding and Architecture | SC-7, SI-10, AC-4 | Control de salida (egress); Segmentación | T1190, T1530 | — | 1.4, 6.2.4 | 8.20, 8.22, 8.28 | API10:2023, ASI05:2026 |
| **API8:2023** Security Misconfiguration | CWE-16, CWE-942, CWE-209, CWE-319 | V13 Configuration; V12 Secure Communication; V3 Web Frontend Security; V16 Security Logging and Error Handling | CM-2, CM-6, CM-7, SC-8, SI-2 | Cifrado en tránsito; WAAP / API gateway; Configuración como código | T1190, T1530, T1552 | — | 2.2, 4.2, 6.4.1, 6.4.2 | 8.9, 8.20, 8.24 | API9:2023 |
| **API9:2023** Improper Inventory Management | — | V13 Configuration | CM-8, CM-2, RA-5 | Inventario y descubrimiento | T1595 | — | 6.3.2, 12.5.1 | 5.9, 8.8, 8.31 | ASI10:2026, LLM04:2026 |
| **API10:2023** Unsafe Consumption of APIs | CWE-20, CWE-345, CWE-918 | V15 Secure Coding and Architecture; V1 Encoding and Sanitization; V13 Configuration | SI-10, SR-3, SR-4, SA-9 | Validación de esquema; Control de salida (egress) | T1195, T1199 | AML.T0010 | 6.3.2, 12.8 | 5.19, 5.21, 8.28 | API7:2023, LLM04:2026, LLM10:2026, ASI04:2026 |

## OWASP Top 10 for LLM Applications — 2026

| Categoría | CWE | ASVS 5.0 | NIST 800-53 | NIST 800-228 (tema) | ATT&CK | ATLAS | PCI DSS 4.0.1 | ISO 27001:2022 | Relacionadas |
|---|---|---|---|---|---|---|---|---|---|
| **LLM01:2026** Prompt Injection | CWE-1427 | V1 Encoding and Sanitization; V2 Validation and Business Logic | SI-10, AC-6, SI-15 | Validación de esquema; AuthN/AuthZ runtime | T1190 | AML.T0051, AML.T0054 | 6.2.4 | 8.28, 8.29 | ASI01:2026, LLM03:2026, LLM08:2026 |
| **LLM02:2026** Sensitive Information Disclosure | CWE-200, CWE-359 | V14 Data Protection; V8 Authorization | AC-3, AC-4, SI-12, SC-28 | Protección de datos | T1567 | AML.T0057 | 3.4, 7.2 | 8.3, 8.12 | API1:2023, API3:2023, LLM09:2026 |
| **LLM03:2026** Excessive Agency | CWE-250, CWE-269, CWE-862 | V8 Authorization; V15 Secure Coding and Architecture | AC-6, AC-2, CM-7 | AuthN/AuthZ runtime; Segmentación | T1078, T1059 | AML.T0053 | 7.2, 8.6 | 5.15, 8.2 | API5:2023, ASI02:2026, ASI03:2026 |
| **LLM04:2026** Supply Chain | CWE-1357, CWE-829, CWE-494, CWE-502 | V13 Configuration; V15 Secure Coding and Architecture | SR-3, SR-4, SR-11, SA-9 | Análisis de dependencias (SCA/SBOM) | T1195 | AML.T0010 | 6.3.2, 12.8 | 5.19, 5.21, 8.28 | API10:2023, ASI04:2026 |
| **LLM05:2026** Data and Model Poisoning | CWE-345, CWE-20 | V15 Secure Coding and Architecture | SI-7, SR-4, SA-15 | — | T1195 | AML.T0020 | — | 8.28, 8.25 | LLM04:2026, LLM09:2026, ASI06:2026 |
| **LLM06:2026** Unbounded Consumption | CWE-400, CWE-770 | V2 Validation and Business Logic | SC-5, SC-6 | Protección de recursos (límites, cuotas) | T1499 | AML.T0029, AML.T0034 | 6.4.2 | 8.6 | API4:2023, ASI08:2026 |
| **LLM07:2026** Misinformation | CWE-1426 | V2 Validation and Business Logic | SI-10, SI-15 | — | — | — | — | 8.29 | ASI09:2026, LLM10:2026 |
| **LLM08:2026** Hidden Context Exposure | CWE-200, CWE-497 | V14 Data Protection; V13 Configuration | AC-3, SC-28, IA-5 | Gestión de secretos | T1552 | AML.T0056 | 3.4, 8.6 | 8.12 | LLM01:2026, LLM03:2026 |
| **LLM09:2026** Vector and Embedding Weaknesses | CWE-284, CWE-20, CWE-200 | V8 Authorization; V14 Data Protection | AC-3, AC-4, SI-10 | Segmentación | T1530 | AML.T0020 | 7.2 | 8.3, 8.31 | API1:2023, API3:2023, ASI06:2026 |
| **LLM10:2026** Improper Output Handling | CWE-79, CWE-89, CWE-78, CWE-94, CWE-116, CWE-1426 | V1 Encoding and Sanitization; V3 Web Frontend Security | SI-10, SI-15 | Validación de esquema; Control de salida (egress) | T1059, T1567 | AML.T0057 | 6.2.4 | 8.28 | API10:2023, ASI05:2026 |

## OWASP Top 10 for Agentic Applications — 2026

| Categoría | CWE | ASVS 5.0 | NIST 800-53 | NIST 800-228 (tema) | ATT&CK | ATLAS | PCI DSS 4.0.1 | ISO 27001:2022 | Relacionadas |
|---|---|---|---|---|---|---|---|---|---|
| **ASI01:2026** Agent Goal Hijack | CWE-1427 | V1 Encoding and Sanitization; V2 Validation and Business Logic | SI-10, AC-6 | AuthN/AuthZ runtime | T1190, T1567 | AML.T0051 | 6.2.4 | 8.28 | LLM01:2026, LLM03:2026 |
| **ASI02:2026** Tool Misuse & Exploitation | CWE-250, CWE-78, CWE-20 | V8 Authorization; V1 Encoding and Sanitization | AC-6, CM-7, SI-10 | AuthN/AuthZ runtime; Validación de esquema | T1059 | AML.T0053 | 6.2.4, 7.2 | 8.2, 8.28 | LLM03:2026, API5:2023 |
| **ASI03:2026** Identity & Privilege Abuse | CWE-269, CWE-287, CWE-250 | V8 Authorization; V10 OAuth and OIDC; V6 Authentication | AC-2, AC-6, IA-5 | AuthN/AuthZ runtime; Gestión de secretos | T1078, T1528 | — | 7.2, 8.6 | 5.16, 5.18, 8.2 | API2:2023, API5:2023, LLM03:2026 |
| **ASI04:2026** Agentic Supply Chain Vulnerabilities | CWE-1357, CWE-829, CWE-494 | V13 Configuration; V15 Secure Coding and Architecture | SR-3, SR-4, SR-11 | Análisis de dependencias (SCA/SBOM) | T1195 | AML.T0010 | 6.3.2, 12.8 | 5.19, 5.21 | LLM04:2026, API10:2023 |
| **ASI05:2026** Unexpected Code Execution (RCE) | CWE-94, CWE-78 | V1 Encoding and Sanitization; V15 Secure Coding and Architecture | SC-7, SI-10, CM-7, SC-39 | Control de salida (egress); Segmentación | T1059, T1190 | — | 1.4, 6.2.4 | 8.20, 8.22, 8.28 | LLM10:2026, API7:2023 |
| **ASI06:2026** Memory & Context Poisoning | CWE-345, CWE-20 | V2 Validation and Business Logic; V14 Data Protection | SI-10, SI-7, AC-4 | Segmentación | — | AML.T0020 | — | 8.28 | LLM09:2026, LLM05:2026 |
| **ASI07:2026** Insecure Inter-Agent Communication | CWE-306, CWE-345, CWE-319 | V12 Secure Communication; V6 Authentication; V9 Self-contained Tokens | IA-2, SC-8, SC-23 | Cifrado en tránsito; AuthN/AuthZ runtime | T1199 | — | 4.2, 8.2 | 8.20, 8.24 | API2:2023, API5:2023 |
| **ASI08:2026** Cascading Failures | CWE-400, CWE-770 | V15 Secure Coding and Architecture | SC-5, SC-7, CP-2 | Segmentación; Protección de recursos (límites, cuotas) | T1499 | AML.T0029 | 1.4 | 8.6, 8.31 | LLM06:2026, API4:2023 |
| **ASI09:2026** Human-Agent Trust Exploitation | CWE-1426 | V2 Validation and Business Logic | AC-6, AU-10 | Monitoreo y detección | — | — | — | 8.15 | LLM07:2026, API6:2023 |
| **ASI10:2026** Rogue Agents | — | V16 Security Logging and Error Handling | SI-4, AU-2, AU-6, AU-12 | Monitoreo y detección; Inventario y descubrimiento | T1078 | — | 10.4 | 8.15, 8.16 | API9:2023, LLM03:2026 |

## Cómo usar

1. Clasifica el hallazgo en la categoría OWASP más específica (puede tener varias: p. ej. una fuga entre tenants en un RAG es LLM02 + LLM09 + API1).
2. Pon como CWE principal la causa raíz más precisa, aunque no sea el primero de la lista.
3. Ejecuta `scripts/findings_matrix.py` para obtener la unión de mapeos de todas las categorías del hallazgo.
4. Para cumplimiento, redacta la **brecha** concreta; la tabla indica solo dónde mirar.
