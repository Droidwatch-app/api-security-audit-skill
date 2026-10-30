# CWE, CVSS v4.0, EPSS, KEV y ATT&CK

Contenido: [CWE](#cwe) · [CVSS v4.0](#cvss-v40) · [Ajuste contextual](#ajuste-contextual-de-severidad) · [EPSS y KEV](#epss-y-kev) · [ATT&CK](#mitre-attck) · [Ejemplos](#ejemplos-resueltos)

## CWE

Cada hallazgo lleva **un CWE principal** (la causa raíz más específica posible) y opcionalmente secundarios. Usa la edición más reciente del **CWE Top 25** como indicador de prioridad histórica, pero no fuerces un hallazgo a un CWE del Top 25 si hay uno más preciso.

CWE frecuentes por categoría (orientativos; verifica el ID y el nombre en cwe.mitre.org al citarlos):

| Problema | CWE |
|---|---|
| BOLA / IDOR | CWE-639 (autorización eludida mediante clave controlada por el usuario), CWE-284, CWE-285, CWE-862, CWE-863 |
| BFLA / falta de autorización | CWE-862 (falta de autorización), CWE-863 (autorización incorrecta), CWE-285 |
| Autenticación | CWE-287, CWE-306 (falta de autenticación para función crítica), CWE-307, CWE-798 (credenciales embebidas), CWE-613 (expiración de sesión insuficiente), CWE-347 (verificación de firma incorrecta), CWE-521 |
| BOPLA / mass assignment / exposición | CWE-915 (modificación de atributos dinámicos), CWE-213, CWE-200, CWE-359 |
| Consumo de recursos | CWE-400, CWE-770, CWE-799 (control insuficiente de frecuencia de interacción) |
| Lógica de negocio | CWE-840 (categoría de errores de lógica de negocio), CWE-362 (condición de carrera), CWE-841 |
| SSRF | CWE-918 |
| Configuración | CWE-16, CWE-942 (CORS permisivo), CWE-209 (error con datos sensibles), CWE-319, CWE-1004, CWE-614 |
| Inyección | CWE-89, CWE-78, CWE-79, CWE-94, CWE-611 (XXE), CWE-502 (deserialización), CWE-20 |
| Consumo inseguro | CWE-20, CWE-345 (autenticidad de datos insuficiente), CWE-918 |
| Prompt injection / salida de IA | CWE-1427 (neutralización incorrecta de entrada usada en prompts de LLM), CWE-1426 (validación incorrecta de salida de IA generativa) |
| Cadena de suministro | CWE-1357, CWE-829, CWE-494, CWE-502 |
| Privilegios excesivos | CWE-250, CWE-269 |
| Exposición de información | CWE-200, CWE-497, CWE-532 (información sensible en logs) |

## CVSS v4.0

Usa el vector CVSS v4.0 y la **calculadora oficial de FIRST** (https://www.first.org/cvss/calculator/4.0); no estimes puntuaciones "a ojo" ni las inventes: registra el vector y el valor que devuelve la calculadora. El script `findings_matrix.py` valida el formato del vector y la coherencia severidad–puntuación, pero **no calcula** la puntuación.

Formato del vector base:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

Métricas base: AV (vector de ataque: N red, A adyacente, L local, P físico), AC (complejidad: L/H), AT (requisitos de ataque: N/P), PR (privilegios requeridos: N/L/H), UI (interacción de usuario: N/P/A), VC/VI/VA (impacto en confidencialidad/integridad/disponibilidad del sistema vulnerable: H/L/N), SC/SI/SA (impacto en sistemas subsecuentes: H/L/N). Métricas adicionales opcionales: Threat (E: exploit maturity), Environmental (CR/IR/AR requisitos de seguridad, modificadas) y Supplemental.

Bandas de severidad (CVSS v4.0): 0.0 Ninguna · 0.1–3.9 Baja · 4.0–6.9 Media · 7.0–8.9 Alta · 9.0–10.0 Crítica.

Nomenclatura recomendada en informe: **CVSS-B** (solo base), **CVSS-BT** (base + amenaza), **CVSS-BE** (base + entorno) o **CVSS-BTE**. Si solo tienes el base, di CVSS-B.

Vectores base típicos de partida (confirma en la calculadora y ajusta a la realidad del hallazgo):

| Escenario | Vector orientativo |
|---|---|
| BOLA de lectura con PII entre usuarios autenticados | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| BFLA que permite acciones administrativas con usuario normal | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| Falta de autenticación en endpoint con datos sensibles | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Falta de límite de intentos en login (impacto depende de si hay cuentas comprometibles; calibrar en la calculadora) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` |
| Cabecera de seguridad ausente sin explotación | Informativo o Bajo; no inflar |

## Ajuste contextual de severidad

CVSS mide la vulnerabilidad en abstracto. Documenta el ajuste con estos factores y escribe el motivo:

| Factor | Sube severidad si… | Baja si… |
|---|---|---|
| Exposición | Internet/partners, sin WAF | Solo red interna segmentada con MFA |
| Datos | PII, financieros, secretos, datos de salud | Datos públicos o de prueba |
| Explotabilidad | Trivial con una sola petición; sin privilegios | Requiere condiciones raras o acceso previo elevado |
| Alcance | Cruza tenants / escala a toda la base de clientes | Un solo objeto del propio usuario |
| Explotación activa | EPSS alto o en KEV | Sin señales |
| Controles compensatorios | Ninguno | Detección y bloqueo efectivos verificados |
| Impacto de negocio | Fraude, regulatorio, reputacional | Mínimo |

Regla: el ajuste **no puede ocultar** un hallazgo; si reduces la severidad, el hallazgo se mantiene con la nota "mitigado parcialmente por X".

## EPSS y KEV

Aplican cuando el hallazgo se asocia a una CVE (componentes de terceros, gateways, frameworks, bibliotecas de IA):

- **EPSS**: probabilidad de explotación en los próximos 30 días; úsalo para ordenar el trabajo de parches (alto EPSS = priorizar).
- **CISA KEV**: si la CVE está en el catálogo, hay explotación activa conocida: tratar como urgente.
- Para fallos de lógica propios (BOLA, etc.) no hay EPSS: prioriza por el ajuste contextual.

## MITRE ATT&CK

Para modelado de amenazas y la columna "técnica adversaria" de la matriz. IDs frecuentes (verifica en attack.mitre.org):

| Técnica | ID | Se relaciona con |
|---|---|---|
| Explotar aplicación expuesta | T1190 | API1–API10 en general |
| Cuentas válidas | T1078 | API2, ASI03 |
| Robo de token de acceso a aplicación | T1528 | API2, ASI03 |
| Uso de material de autenticación alternativo | T1550 | API2 |
| Fuerza bruta / credential stuffing | T1110 | API2, API6 |
| Credenciales no protegidas | T1552 | API2, API8 |
| Escaneo activo | T1595 | API9 |
| Denegación de servicio de endpoint | T1499 | API4, LLM06 |
| Compromiso de la cadena de suministro | T1195 | API10, LLM04, ASI04 |
| Relación de confianza | T1199 | API10, ASI07 |
| Intérprete de comandos y scripts | T1059 | ASI05, LLM10 |
| Exfiltración por servicio web | T1567 | LLM02, LLM10, ASI01 |
| Datos de almacenamiento en la nube | T1530 | API8 |

## Ejemplos resueltos

**Ejemplo 1 — BOLA en `/accounts/{id}/statements`**: CWE-639; API1:2023; ASVS V8; NIST AC-3/AC-6; ATT&CK T1190; CVSS-B vector de lectura con PII (arriba) → típicamente Alta; sube a Crítica si el ID es secuencial (enumeración total) y los datos son financieros; PCI DSS Req. 7 si hay datos de cuenta.

**Ejemplo 2 — API sin límite de `max_tokens` controlable por el cliente**: CWE-770/CWE-400; LLM06:2026 + API4:2023; NIST SC-5; ATLAS AML.T0034; severidad por costo potencial; Media–Alta con evidencia del multiplicador de costo.

**Ejemplo 3 — Agente con token de repositorio de alcance amplio que ejecuta instrucciones leídas en issues**: CWE-250 + CWE-1427; LLM01 + LLM03 + ASI01 + ASI03; ATLAS AML.T0051.001; Crítica si permite exfiltrar repos privados; remediación: token por tarea, sin acceso a repos privados desde contexto con contenido público no confiable, aprobación de acciones.
