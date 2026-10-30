# NIST SP 800-228 y controles de arquitectura (800-53, CSF 2.0, 800-207)

Contenido: [SP 800-228](#nist-sp-800-228--protección-de-apis-en-sistemas-cloud-native) · [Patrones de despliegue](#patrones-de-despliegue-y-puntos-de-aplicación) · [Revisión de arquitectura](#lista-de-revisión-de-arquitectura) · [SP 800-53 rev. 5](#nist-sp-800-53-rev-5--familias-relevantes) · [CSF 2.0](#nist-csf-20) · [Zero Trust 800-207](#zero-trust-sp-800-207) · [CIS Controls](#cis-controls-v81-sucesor-de-los-sans-top-20)

> Esta referencia resume la **estructura y los temas** de SP 800-228 (final jun 2025, con actualización en 2026) para guiar una auditoría. No cites números de control internos de SP 800-228 sin abrir el documento: verifícalos en https://doi.org/10.6028/NIST.SP.800-228. Dónde diga "tema" no hay ID inventado.

## NIST SP 800-228 — Protección de APIs en sistemas cloud-native

Aplica a APIs **internas y externas** (clientes, partners, servicio-a-servicio). Se organiza en dos dimensiones:

1. **Fase del ciclo de vida**
   - **Pre-runtime** (diseño, desarrollo, pruebas, pre-despliegue): evitar vulnerabilidades antes de producción.
   - **Runtime**: protección activa y detección en operación.
2. **Madurez de controles**: **básicos** (línea base para todas las APIs) y **avanzados** (para APIs más sensibles o expuestas). La guía recomienda un enfoque incremental basado en riesgo: sube a avanzados cuando aumenta la sensibilidad de los datos, la exposición a internet o el impacto.

### Temas de controles pre-runtime (qué auditar)

| Tema | Qué buscar en la auditoría | Marco OWASP asociado |
|---|---|---|
| Inventario y descubrimiento | Catálogo completo y automático (incluye *shadow*/*zombie*/*rogue*) con propietario y versión | API9 |
| Diseño / especificación | Contrato OpenAPI/GraphQL/protobuf versionado; revisión de seguridad del diseño; modelado de amenazas | API1–API10 |
| Análisis estático y de dependencias | SAST, SCA, escaneo de secretos, SBOM en CI/CD | API8, API10, LLM04 |
| Validación de esquema | Rechazo de peticiones que no cumplen el contrato (tipos, longitudes, `additionalProperties`) | API3, API4, API8 |
| Pruebas | DAST/fuzzing de API, pruebas de autorización automatizadas en CI | API1, API3, API5 |
| Gestión de secretos y configuración | Sin secretos en repos/imágenes; IaC revisada | API2, API8 |

### Temas de controles runtime

| Tema | Qué buscar | Marco OWASP asociado |
|---|---|---|
| AuthN/AuthZ | Autenticación de cliente y servicio (OAuth 2.x/OIDC, mTLS), autorización por petición y por objeto, propagación de identidad entre servicios | API1, API2, API5 |
| Protección de recursos | Límites de tasa, cuotas, tamaños, timeouts, protección contra automatización | API4, API6 |
| Cifrado en tránsito | TLS moderno; mTLS interno donde proceda | API8 |
| Protección de datos | Minimización en respuestas, enmascaramiento, filtrado de salida | API3 |
| Monitoreo y detección | Logs de acceso y de decisiones de autorización, métricas, detección de anomalías, trazabilidad entre servicios | API9, ASI10 |
| WAAP / API gateway | Políticas centralizadas; WAF como defensa en profundidad (no sustituye autorización) | Todas |
| Control de salida (egress) | Allow-list de destinos de salida; protección SSRF | API7, API10, ASI05 |
| Segmentación | Aislamiento de servicios, micro-segmentación, políticas de red | API8, ASI08 |

## Patrones de despliegue y puntos de aplicación

SP 800-228 compara **dónde** aplicar los controles, con ventajas y costos de cada opción; úsalo para justificar recomendaciones:

| Patrón | Aplica bien a | Riesgo/limitación para auditar |
|---|---|---|
| **API gateway** (borde / norte-sur) | Autenticación, rate limiting, validación de esquema, WAAP, TLS en el perímetro | Si el tráfico interno (este-oeste) lo evita, las APIs internas quedan sin controles |
| **Malla de servicios / sidecars** | mTLS, autorización por servicio, telemetría uniforme | Complejidad operativa; políticas mal escritas → permisos amplios |
| **Gateway de salida (egress)** | Control de llamadas a terceros, SSRF, exfiltración | Falta de allow-list → agentes y servicios llaman a cualquier sitio |
| **Controles en la aplicación/librería** | Autorización por objeto/propiedad (no la puede hacer un gateway genérico) | Inconsistencia entre equipos; requiere pruebas en CI |

Idea clave para el informe: **el gateway no puede decidir si el usuario A puede ver el objeto 123**; BOLA/BFLA/BOPLA exigen lógica de negocio en el servicio.

## Lista de revisión de arquitectura

1. ¿Existe un único punto de aplicación de políticas por tipo de tráfico (norte-sur y este-oeste) o hay "caminos laterales"?
2. ¿La identidad se **propaga** hasta el servicio que accede a los datos (no se pierde en el gateway)?
3. ¿Las APIs internas tienen autenticación/autorización o confían en "estar en la red interna"? (Zero Trust: no.)
4. ¿Qué pasa si se compromete un servicio? ¿Qué alcanza (credenciales, red, datos)? Radio de impacto.
5. ¿Existe separación de entornos (dev/test/prod) en datos, credenciales y red?
6. ¿Hay límites de recursos en cada capa (gateway, servicio, base de datos, cola)?
7. ¿Los secretos tienen ciclo de vida (rotación, revocación) y gestor?
8. ¿La observabilidad permite reconstruir "quién hizo qué sobre qué objeto" de extremo a extremo?
9. ¿El egress está controlado?
10. Para IA: ¿el modelo/agente atraviesa las mismas políticas que cualquier cliente API, o es una puerta lateral con identidad de servicio privilegiada?

## NIST SP 800-53 rev. 5 — familias relevantes

| Control | Tema | Útil para |
|---|---|---|
| AC-2, AC-3, AC-6, AC-4 | Gestión de cuentas, aplicación de acceso, mínimo privilegio, flujo de información | API1, API3, API5, LLM03, ASI03 |
| IA-2, IA-5, IA-8 | Identificación/autenticación, gestión de autenticadores, usuarios no organizacionales | API2 |
| SC-5 | Protección contra denegación de servicio | API4, LLM06 |
| SC-7 | Protección de límites (boundary protection) | API7, API8, ASI05 |
| SC-8, SC-13, SC-23, SC-28 | Confidencialidad en tránsito, criptografía, autenticidad de sesión, protección en reposo | API2, API8 |
| SI-10, SI-15, SI-2 | Validación de entradas, filtrado de salidas, corrección de fallos | API3, API10, LLM10 |
| CM-2, CM-6, CM-7, CM-8 | Línea base, configuración, funcionalidad mínima, inventario de componentes | API8, API9 |
| AU-2, AU-3, AU-6, AU-12 | Eventos auditables, contenido, revisión, generación de registros | Detección |
| SI-4 | Monitoreo del sistema | ASI10 |
| RA-3, RA-5 | Evaluación de riesgo, escaneo de vulnerabilidades | Programa |
| SA-11, SA-15, SA-10 | Pruebas del desarrollador, proceso de desarrollo, gestión de configuración | Pre-runtime |
| SR-3, SR-4, SR-11 | Controles de cadena de suministro, procedencia, autenticidad de componentes | API10, LLM04, ASI04 |
| CA-8 | Pruebas de penetración | Alcance de la auditoría |

## NIST CSF 2.0

| Función | Categorías útiles | Aplicación a APIs |
|---|---|---|
| GOVERN (GV) | GV.SC (cadena de suministro), GV.RM (riesgo), GV.PO (políticas) | Propiedad de APIs, política de ciclo de vida, riesgo de terceros/IA |
| IDENTIFY (ID) | ID.AM (activos), ID.RA (evaluación de riesgos), ID.IM (mejora) | Inventario, modelado de amenazas, retest |
| PROTECT (PR) | PR.AA (identidad y acceso), PR.DS (datos), PR.PS (plataforma), PR.IR (resiliencia de infraestructura) | AuthN/Z, minimización de datos, configuración, límites |
| DETECT (DE) | DE.CM (monitoreo continuo), DE.AE (análisis de eventos) | Logs, anomalías, abuso de flujos |
| RESPOND (RS) / RECOVER (RC) | RS.MA, RS.AN, RC.RP | Plan de incidentes de API (PICERL de SANS), recuperación |

## Zero Trust (SP 800-207)

Principios aplicados a APIs: autenticar y autorizar **cada petición** (no confiar en la red), mínimo privilegio, políticas dinámicas basadas en contexto (dispositivo, riesgo, comportamiento), registrar y medir todo, tratar el tráfico interno como no confiable. Si una API interna "no necesita autenticación porque está en la VPC", es un hallazgo de arquitectura.

## CIS Controls v8.1 (sucesor de los SANS Top 20)

Línea base de higiene para el entorno que hospeda las APIs: inventario de activos y software (1, 2), protección de datos (3), configuración segura (4), gestión de cuentas y control de acceso (5, 6), gestión continua de vulnerabilidades (7), gestión de registros (8), seguridad de aplicaciones (16), gestión de proveedores de servicios (15), pruebas de penetración (18). Útil cuando el usuario pida "alineado con SANS/CIS".
