# Metodología por fases

Contenido: [Visión general](#visión-general) · [Fase 0](#fase-0--alcance-y-autorización) · [Fase 1](#fase-1--recolección-de-contexto) · [Fase 2](#fase-2--inventario-y-superficie) · [Fase 3](#fase-3--modelado-de-amenazas) · [Fase 4](#fase-4--revisión-estática) · [Fase 5](#fase-5--pruebas-dinámicas-guiadas) · [Fase 6](#fase-6--valoración-y-mapeo) · [Fase 7](#fase-7--reporte) · [Fase 8](#fase-8--remediación-y-retest) · [Bases metodológicas](#bases-metodológicas)

## Visión general

Combina NIST SP 800-115 (planificación → descubrimiento → ataque → reporte), el ciclo de vida de API de NIST SP 800-228 (pre-runtime y runtime), el flujo de pruebas de OWASP WSTG y las buenas prácticas de informes de pruebas de penetración de SANS. El modo por defecto es **híbrido**: revisión de especificaciones/código/configuración más pruebas activas guiadas y no destructivas.

Cada fase tiene criterio de salida. No saltes a la siguiente sin cumplirlo; si el usuario tiene prisa, di qué riesgo asume al saltarla.

## Fase 0 — Alcance y autorización

- **Entradas**: contacto del dueño, contrato/orden de trabajo o confirmación de propiedad.
- **Actividades**: completar `assets/templates/scope-roe.md`; acordar entornos, ventana, límites de tasa, cuentas de prueba, datos de prueba, canal de escalamiento, y qué se considera "parar y avisar".
- **Salida**: alcance firmado/confirmado. Sin esto, solo fases 1–4 (estáticas).
- **Error común**: probar el entorno equivocado (producción) o un host de terceros (CDN, IdP, API de proveedor). Los servicios de terceros consumidos por la API (API10) se evalúan como *consumo*, no se atacan.

## Fase 1 — Recolección de contexto

- **Actividades**: entender el negocio y los flujos críticos (pagos, onboarding, transferencias), clasificar datos (PII, financieros, credenciales, secretos de negocio), identificar actores y roles (cliente, partner, interno, servicio-a-servicio), consumidores (móvil, web, B2B, agentes de IA), dependencias externas y obligaciones regulatorias (PCI, protección de datos, banca abierta).
- **Salida**: mapa de activos y de datos sensibles; lista de "joyas de la corona" (qué sería catastrófico perder o alterar).
- **Pregunta guía**: "¿qué es lo peor que podría hacer un usuario autenticado de bajo privilegio con esta API?"

## Fase 2 — Inventario y superficie

Objetivo: lo que no está inventariado no se protege (API9:2023, NIST 800-228 inventario/descubrimiento).

- **Fuentes**: especificaciones OpenAPI/Swagger/Postman/GraphQL (introspección si está autorizada), configuración de API gateway/WAF/ingress, repositorios, DNS/subdominios del dominio en alcance, tráfico de aplicaciones móviles/web (proxy), logs de acceso, consola de la nube.
- **Clasificar** cada endpoint: expuesto a internet / partner / interno; autenticación requerida; datos que maneja; versión; estado (activo, obsoleto, huérfano).
- **Buscar**: APIs *shadow* (existen y no están documentadas), *zombie* (obsoletas pero activas), versiones antiguas (`/v1` con controles más débiles), entornos de prueba expuestos, endpoints de depuración/administración (`/actuator`, `/debug`, `/admin`, `/internal`, `/metrics`, `/swagger-ui`), diferencias entre la especificación y la realidad.
- **Herramienta**: `scripts/openapi_inventory.py` (estático). Para IA, listar además modelos, proveedores, herramientas, servidores MCP, índices vectoriales y fuentes de datos del RAG (un AIBOM mínimo).
- **Salida**: inventario con propietario, exposición, sensibilidad y estado.

## Fase 3 — Modelado de amenazas

- **Método**: STRIDE sobre un diagrama de flujo de datos (actores → gateway → servicios → datos → terceros), más las listas OWASP aplicables como "catálogo de escenarios". Para IA, marcar las **fronteras de confianza**: contenido no confiable que entra al contexto (usuario, documentos, web, correos, resultados de herramientas) y *sinks* que ejecutan o muestran salida del modelo (shell, SQL, navegador, plantillas, herramientas con efectos).
- **Mapeo a tácticas**: ATT&CK (acceso inicial T1190, credenciales T1078/T1528, exfiltración T1567, impacto T1499) y ATLAS para ML/LLM.
- **Salida**: lista priorizada de escenarios (probabilidad × impacto) con el dato/función en riesgo y el control que debería impedirlo. Esa lista guía la profundidad de la fase 5.

## Fase 4 — Revisión estática

- **Especificación**: autenticación declarada por operación, esquemas de seguridad (apiKey en query, basic, flujos OAuth obsoletos), parámetros de identificador de objeto, esquemas permisivos (`additionalProperties`), campos sensibles en respuestas, ausencia de paginación/límites, ausencia de 429, parámetros tipo URL.
- **Código** (si hay acceso): autorización por objeto en cada acceso a datos, comprobación de función/rol en el servidor (no solo en el cliente), validación de entrada con listas permitidas, serialización explícita de respuestas (DTO) en vez de volcar entidades, consumo seguro de APIs de terceros, manejo de errores, secretos en código, *sinks* de salida de LLM.
- **Configuración / IaC**: TLS y cifrados, CORS, cabeceras, límites de tamaño y tiempo, rate limiting en gateway, WAF/WAAP, segmentación, egress, permisos de identidad de servicio, logging.
- **Dependencias**: SCA, SBOM; para IA, artefactos de modelo y formato de serialización.
- **Salida**: candidatos a hallazgo con ubicación y checklist ID (p. ej. `AUTHZ-03`).

## Fase 5 — Pruebas dinámicas guiadas

Solo con autorización (fase 0). Principios: **no destructivo**, tasa baja, cuentas propias de prueba, evidencia mínima y enmascarada, parar ante datos reales.

Orden recomendado (mayor rendimiento primero):

1. **Autorización diferencial** (API1, API3, API5): para cada endpoint con identificador u objeto, probar con identidad A (dueño), identidad B (otro usuario, mismo rol), sin autenticación, y con rol inferior/superior. Incluir IDs en ruta, query, cuerpo, cabeceras y JSON anidado; GraphQL por alias y por `node(id:)`.
2. **Autenticación** (API2): política de contraseñas y bloqueo, enumeración de usuarios por mensajes/tiempos, ciclo de vida de tokens (expiración, revocación, rotación de refresh), validación de JWT (alg, firma, `aud`, `iss`, `exp`, `kid`), flujos de recuperación y OTP, claves de API por query.
3. **Propiedades y mass assignment** (API3): campos extra en escrituras (`role`, `is_admin`, `owner_id`, `price`, `status`), respuestas que devuelven más de lo necesario. Hacer en entorno de pruebas con datos propios.
4. **Recursos y flujos** (API4, API6): límites de paginación, tamaños de cuerpo, profundidad/complejidad de consultas (GraphQL), número de operaciones por lote, límites por usuario/IP/clave, abuso de flujos de negocio con efectos acotados (cupones, reservas, OTP) en cuentas de prueba.
5. **Entrada y salida** (API7, API10): parámetros tipo URL (SSRF contra recursos propios/colaborador controlado, nunca a la red interna de terceros), inyecciones con cargas inocuas de detección, deserialización, subida de archivos (tipos/tamaños), redirecciones, confianza en datos de terceros.
6. **Configuración** (API8): TLS, CORS, cabeceras, métodos, errores verbosos, endpoints de depuración, versiones antiguas.
7. **IA/agentes** (LLM01–10, ASI01–10): `assets/checklists/checklist-06-llm.md` y `checklist-07-agentes-mcp.md` con **canarios** (cadenas inofensivas que prueban que el contenido llegó o salió), no cargas que causen daño.

Para cada confirmación, guardar: petición, respuesta (recortada, enmascarada), identidad usada, fecha/hora UTC, versión/ruta y resultado esperado vs. observado. Distinguir **confirmado**, **probable** y **por validar**.

**Control de falsos positivos**: repetir al menos una vez, descartar caché/estado de sesión, confirmar con una segunda identidad, y verificar que la respuesta contiene datos del objeto ajeno (no solo un 200 con cuerpo vacío o genérico).

## Fase 6 — Valoración y mapeo

- Puntuar con **CVSS v4.0** (vector + puntuación de la calculadora de FIRST) y ajustar con contexto: exposición, datos, existencia de explotación (EPSS/KEV si hay CVE), controles compensatorios, facilidad. Ver `references/07-cwe-cvss-epss-attack.md` y `references/11-severidad-y-reporte.md`.
- Mapear a marcos con `scripts/findings_matrix.py` y `assets/data/mappings.json`.
- Consolidar causas raíz y hallazgos repetidos.

## Fase 7 — Reporte

- `assets/templates/informe-ejecutivo.md` y `informe-tecnico.md`. Ordenar por riesgo, no por orden de descubrimiento. Hoja de ruta 30/60/90 días. Lo no probado y por qué.
- Entregar en un canal seguro; los informes contienen la hoja de ruta de un atacante.

## Fase 8 — Remediación y retest

- Remediación en tres niveles: **correctivo** (arreglar la instancia), **preventivo** (patrón, librería, política de gateway, prueba automatizada en CI) y **detectivo** (log/alerta que lo verá la próxima vez).
- Retest con `assets/templates/retest.md`: repetir exactamente la reproducción original, probar variantes de evasión de la corrección y registrar estado (Cerrado / Parcial / Abierto / Riesgo aceptado con firma).
- Recomendar pruebas de regresión de autorización en CI (la causa de reaparición más común es que nadie volvió a probar).

## Bases metodológicas

- **NIST SP 800-115**: planificación, descubrimiento, ataque, reporte; uso de técnicas de revisión, identificación de objetivos y validación de vulnerabilidades.
- **NIST SP 800-228**: controles pre-runtime y runtime; maduración básica → avanzada según sensibilidad y exposición.
- **OWASP WSTG** (incluye pruebas de API/GraphQL) y **ASVS 5.0** como lista de requisitos verificables.
- **PTES / OSSTMM** como referencias complementarias de fases y rigor.
- **SANS**: redacción del informe (resumen ejecutivo, metodología, hallazgos con evidencia, remediación), y PICERL para el plan de respuesta que debe poder activarse si se encuentra un incidente real durante la auditoría.
