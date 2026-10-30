# OWASP API Security Top 10 — 2023

Contenido: API1 BOLA · API2 Autenticación rota · API3 BOPLA · API4 Consumo de recursos · API5 BFLA · API6 Flujos de negocio · API7 SSRF · API8 Configuración · API9 Inventario · API10 Consumo inseguro · [Plan de prueba GraphQL/gRPC/WebSocket](#particularidades-por-tecnología) · [Atajos de priorización](#atajos-de-priorización)

Cada categoría: **Qué es · Revisión estática · Pruebas dinámicas · Señales de fallo · Remediación · Severidad típica**. Los IDs de checklist (p. ej. `AUTHZ-01`) están en `assets/checklists/`. Mapeos cruzados completos en `references/09-matriz-cruzada.md`.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**Qué es**: el servidor no verifica que el usuario autenticado tenga derecho al **objeto concreto** que pide (IDs en ruta, query, cuerpo, cabeceras). Es el fallo más frecuente y de mayor impacto en APIs.

- **Estática**: cada acceso a datos por identificador debe incluir una comprobación de propiedad/permiso en el servidor (middleware, política, filtro por `tenant_id`/`owner_id` en la consulta). Sospecha de: `findById(id)` sin filtro de dueño, IDs secuenciales, endpoints `/users/{id}`, `/accounts/{id}/statements`, `/orders/{orderId}`, descargas de archivos por nombre, GraphQL `node(id:)`.
- **Dinámica** (`AUTHZ-01`, `AUTHZ-02`): crear un objeto con A; pedirlo con B y sin autenticación; repetir en lectura, escritura y borrado en el entorno de pruebas; probar IDs en cuerpo y cabeceras además de ruta; probar IDs predecibles vs. UUID (los UUID no son control de acceso); en GraphQL, alias y consultas anidadas (`user { friends { orders } }`).
- **Señal de fallo**: B recibe 200/2xx con datos de A, o modifica/borra el objeto de A. Un 404 uniforme también es válido si es consistente.
- **Remediación**: política de autorización centralizada por objeto; consultas siempre acotadas al principal; denegar por defecto; no confiar en IDs del cliente cuando el servidor puede derivarlos del token (`/me/...`); pruebas automáticas de autorización en CI.
- **Severidad típica**: Alta–Crítica (según sensibilidad y alcance de la enumeración).

## API2:2023 — Broken Authentication

**Qué es**: mecanismos de identidad débiles o mal implementados: credenciales, tokens, recuperación, MFA.

- **Estática**: algoritmo JWT (`none`, HS/RS confundidos), claves débiles/compartidas, validación de `iss/aud/exp/nbf`, `kid` sin control, tokens sin expiración, refresh sin rotación, API keys en query string, Basic Auth sobre canales no cifrados, flujos OAuth obsoletos (implicit, password), ausencia de PKCE, secretos en repositorio, comparación de secretos no constante, políticas de contraseña.
- **Dinámica** (`AUTHN-01…`): fuerza bruta/relleno de credenciales **a tasa baja y solo contra cuentas propias**, enumeración de usuarios (mensajes y tiempos), reutilización de tokens tras logout/cambio de contraseña, tokens expirados aceptados, manipulación de claims, recuperación de contraseña (tokens predecibles, sin expiración, enlace reutilizable), OTP sin límite de intentos, cambios sensibles sin reautenticación.
- **Señal de fallo**: acceso con token falsificado/expirado/revocado; sin límite de intentos; mensajes distintos para usuario existente/inexistente.
- **Remediación**: usar IdP/biblioteca probada, OAuth 2.0 BCP (RFC 9700) con Authorization Code + PKCE, JWT BCP (RFC 8725), expiraciones cortas + rotación de refresh con detección de reutilización, límite de intentos y alertas, MFA para operaciones sensibles, secretos en gestor de secretos, FAPI 2.0 en banca abierta.
- **Severidad típica**: Alta–Crítica.

## API3:2023 — Broken Object Property Level Authorization (BOPLA)

**Qué es**: fusiona *Excessive Data Exposure* y *Mass Assignment* de 2019. El usuario puede **ver** propiedades que no debería o **modificar** propiedades que no debería, aunque tenga derecho al objeto.

- **Estática**: serialización de entidades completas, DTOs sin lista permitida, `additionalProperties: true`, binding automático de cuerpo a modelo, campos sensibles en esquemas de respuesta (`password`, `hash`, `token`, `ssn`, `card`, `internal_*`), filtrado de campos solo en el cliente, GraphQL con campos sensibles sin autorización por campo.
- **Dinámica** (`AUTHZ-04`, `AUTHZ-05`, `DATA-01`): comparar la respuesta con lo que la UI muestra; enviar propiedades extra (`role`, `isAdmin`, `owner_id`, `price`, `balance`, `verified`, `status`) en PUT/PATCH/POST en pruebas con datos propios; verificar efecto en una lectura posterior; probar parámetros de expansión/campos (`?fields=`, `?expand=`, `include`).
- **Señal de fallo**: datos de más en la respuesta; propiedad modificada sin permiso.
- **Remediación**: DTOs explícitos de entrada y salida (lista permitida), validación de esquema estricta (`additionalProperties: false`), autorización por campo, nunca serializar entidades de BD directamente.
- **Severidad típica**: Media–Alta (Crítica si permite escalar privilegios o manipular saldos).

## API4:2023 — Unrestricted Resource Consumption

**Qué es**: sin límites de CPU, memoria, ancho de banda, tamaño, número de operaciones o gasto con terceros (SMS, correo, biometría, **tokens de LLM**). Se puede traducir en DoS o en costo económico.

- **Estática**: límites de paginación sin tope, tamaños máximos de cuerpo/archivo, timeouts, profundidad/complejidad de GraphQL, operaciones por lote, rate limiting en gateway, cuotas por clave, límites de memoria/contendor, cola de trabajos, llamadas a APIs de pago por uso sin tope.
- **Dinámica** (`RES-01…`): probar `limit=` grandes y negativos (esperar tope o 400), cuerpos grandes **moderados** (no saturar), consultas GraphQL anidadas y con alias de forma controlada, número de intentos por ventana (confirmar presencia del 429/`Retry-After`), trabajos asíncronos encadenables. No generar carga destructiva: acordar y medir con umbral bajo.
- **Señal de fallo**: sin tope de paginación; sin 429 tras exceder un umbral razonable; consumo desproporcionado por petición.
- **Remediación**: límites en gateway y aplicación (por IP, usuario, clave y por operación), topes server-side de todos los parámetros de tamaño, análisis de costo de consulta, timeouts, cuotas con alertas de gasto.
- **Severidad típica**: Media–Alta (Alta si hay impacto financiero directo o caída de servicio).

## API5:2023 — Broken Function Level Authorization (BFLA)

**Qué es**: el usuario accede a **funciones** (endpoints/métodos) reservadas a otros roles: administración, operaciones internas, métodos HTTP no esperados.

- **Estática**: rutas administrativas sin comprobación de rol en servidor; autorización solo en el front; mapa de roles vs. rutas inconsistente; métodos `PUT/DELETE` sin restricción; jerarquía de rutas (`/api/admin/*`) sin middleware común; GraphQL mutaciones sin control por rol.
- **Dinámica** (`AUTHZ-03`): ejecutar cada función con cada rol y sin autenticación; cambiar método HTTP (GET→PUT/DELETE); probar rutas descubiertas en JS/OpenAPI de roles superiores; sobreescritura de método (`X-HTTP-Method-Override`); versiones antiguas.
- **Señal de fallo**: rol bajo ejecuta función de rol alto.
- **Remediación**: autorización por función en una capa central, denegar por defecto, matriz rol×función revisada, pruebas de contrato de autorización.
- **Severidad típica**: Alta–Crítica.

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**Qué es**: flujos de negocio legítimos (compra, reserva, cupones, registro, votos, OTP, comentarios) expuestos sin controles contra abuso automatizado.

- **Estática/diseño**: identificar flujos sensibles en el modelado de amenazas; controles antiautomatización, límites por dispositivo/cuenta, detección de anomalías, validación de secuencia (el paso 3 no se llama sin el 2), idempotencia.
- **Dinámica** (`BIZ-01…`): repetir el flujo a baja escala con cuentas propias para ver si existen límites; saltar pasos; reutilizar tokens/cupones; condiciones de carrera con **pocas** peticiones paralelas en datos de prueba; manipular cantidades/precios/estados.
- **Señal de fallo**: se puede repetir el flujo sin fricción o fuera de secuencia; doble gasto/doble uso por condición de carrera.
- **Remediación**: límites de negocio (no solo técnicos), fricción proporcional al riesgo, detección de bots, bloqueos atómicos/transacciones idempotentes, monitoreo de patrones.
- **Severidad típica**: Media–Alta (depende del impacto de negocio; en pagos/fraude, Alta).

## API7:2023 — Server Side Request Forgery (SSRF)

**Qué es**: la API obtiene un recurso remoto a partir de una URL controlada por el usuario sin validarla, permitiendo alcanzar servicios internos/metadatos.

- **Estática**: parámetros `url`, `uri`, `callback`, `webhook`, `redirect`, `avatar_url`, `import_from`, importación de imágenes/documentos, previsualizaciones, conectores y proveedores personalizables; clientes HTTP que siguen redirecciones; resolución DNS y comprobación separadas (rebinding).
- **Dinámica** (`INPUT-05`): usar **un servidor colaborador controlado por el auditor** para confirmar que el servidor realiza la petición; probar esquemas y redirecciones; **no** escanear la red interna de terceros ni consultar metadatos de nube de producción salvo autorización expresa y específica.
- **Señal de fallo**: el servidor contacta destinos arbitrarios; diferencias de respuesta revelan alcance interno.
- **Remediación**: lista permitida de destinos, resolver y validar IP final (bloquear rangos privados, link-local y metadatos), desactivar redirecciones, aislar en red (egress deny-by-default), IMDSv2/equivalente, respuesta mínima al cliente.
- **Severidad típica**: Alta–Crítica en nube con metadatos accesibles.

## API8:2023 — Security Misconfiguration

**Qué es**: configuración insegura o incompleta en cualquier capa.

- **Estática/dinámica** (`CONF-01…`): TLS (versiones, cifrados, HSTS), CORS (origen reflejado + credenciales, `*` con datos sensibles), cabeceras de seguridad y `Cache-Control` en respuestas autenticadas, métodos HTTP innecesarios, errores verbosos/trazas, endpoints de depuración y documentación expuesta, credenciales por defecto, permisos excesivos de identidades de servicio, parches, contenedores y secretos en imágenes, diferencias entre entornos, falta de límites, falta de segmentación.
- **Señal de fallo**: cualquiera de los anteriores con impacto concreto.
- **Remediación**: línea base endurecida (CIS), IaC revisada y escaneada, configuración como código con pruebas, cabeceras estándar en gateway, tratamiento uniforme de errores (RFC 9457) sin detalle interno.
- **Severidad típica**: Baja–Alta (agrupa los menores en un hallazgo).

## API9:2023 — Improper Inventory Management

**Qué es**: no se sabe qué APIs, versiones, entornos y datos expuestos existen; versiones antiguas, endpoints de prueba y *shadow/zombie APIs* quedan sin parches ni controles.

- **Revisión** (`INV-01…`): comparar especificación vs. gateway vs. tráfico vs. DNS; versiones antiguas activas; entornos de prueba con datos reales; documentación pública que revela endpoints internos; falta de propietario, ciclo de vida o fecha de retiro; flujos de datos hacia terceros no documentados.
- **Señal de fallo**: endpoints activos no inventariados; versión antigua con controles más débiles.
- **Remediación**: inventario continuo y automático (descubrimiento), propietarios, política de ciclo de vida y retiro, gestión de versiones con paridad de controles, separación de entornos, clasificación de datos por endpoint.
- **Severidad típica**: Media–Alta (Alta si el activo olvidado expone datos).

## API10:2023 — Unsafe Consumption of APIs

**Qué es**: la API confía en datos o respuestas de APIs de terceros más que en la entrada del usuario y los procesa sin validar.

- **Estática** (`INPUT-06`): validación de esquema de respuestas externas, tamaños y tiempos, TLS verificado hacia terceros, seguimiento de redirecciones, inyecciones por datos de terceros (SQL/NoSQL/plantillas), deserialización, límites de recursos, manejo de errores y reintentos, credenciales de terceros con mínimo privilegio, evaluación de proveedores.
- **Dinámica**: con un tercero simulado/colaborador en entorno de pruebas, devolver respuestas malformadas, grandes, con redirecciones y caracteres especiales y observar el comportamiento. **Las salidas de LLM y de herramientas de agentes se tratan igual** (ver LLM10 y ASI02).
- **Remediación**: tratar todo dato externo como no confiable, validar contra esquema estricto, límites y timeouts, verificar certificados, aislar integraciones, monitorear.
- **Severidad típica**: Media–Alta.

---

## Particularidades por tecnología

**GraphQL**: introspección habilitada en producción (informativo/baja salvo que exponga esquema interno sensible), consultas anidadas y de alias para eludir rate limit y causar costo (API4), *batching* de consultas para fuerza bruta de OTP/credenciales (API2/API4), autorización por campo y por resolver (API1/API3/API5), sugerencias de campo ("Did you mean…") que filtran el esquema, mutaciones sin protección CSRF si usa cookies. Herramientas: InQL (Burp), clientes con introspección, límites de profundidad/costo.

**gRPC**: reflexión de servicios habilitada, autenticación/TLS/mTLS, autorización por método, límites de mensaje y *streaming*, metadatos como vector de inyección, validación de campos protobuf, deserialización.

**SOAP/XML**: XXE, expansión de entidades, WS-Security, esquemas sin límites, `wsdl` expuesto.

**WebSocket/SSE**: autenticación en el handshake y reautorización por mensaje, verificación de `Origin` (CSWSH), límites de mensajes y conexiones, validación por mensaje.

**REST**: negociación de contenido, verbos, versionado por ruta/cabecera, HATEOAS que revela rutas, herencia de permisos en rutas anidadas, `PATCH` con JSON Merge/JSON Patch (operaciones peligrosas como `replace /role`).

**Webhooks entrantes/salientes**: firmas HMAC y anti-replay (marca de tiempo + nonce), validación de destinos (SSRF), reintentos y límites.

## Atajos de priorización

1. API1 + API5 + API3 (autorización de objeto, función y propiedad) → mayor probabilidad y mayor impacto: prueba diferencial primero.
2. API2 en endpoints de emisión de tokens y recuperación.
3. API9 temprano: lo olvidado suele tener los peores fallos.
4. API4/API6 donde hay costo directo (SMS, pagos, LLM) o fraude.
5. API7/API10 donde la API integra terceros, importa contenido o llama a modelos y herramientas.
