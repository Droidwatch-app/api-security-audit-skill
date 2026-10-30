# Checklist 01 — Alcance, contexto e inventario (fases 0–2)

Leyenda de método: **E** estático (sin tráfico) · **D** dinámico (requiere autorización) · **P** proceso/entrevista. Estado: ✔ cumple · ✖ falla (abrir hallazgo) · N/A · ? por validar.

## Alcance y autorización (SCOPE)

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| SCOPE-01 | Autorización escrita del dueño con alcance, ventana y contacto de emergencia (`scope-roe.md` completado) | P | NIST 800-115 | |
| SCOPE-02 | Entornos en alcance definidos; producción excluida o con reglas especiales acordadas | P | — | |
| SCOPE-03 | Terceros (IdP, pasarelas, proveedores de modelos, CDN) marcados fuera de alcance salvo permiso expreso | P | API10 | |
| SCOPE-04 | Cuentas de prueba creadas: ≥2 usuarios del mismo rol, 1 rol bajo, 1 privilegiado, 1 de otro tenant | P | — | |
| SCOPE-05 | Límites técnicos acordados (tasa, tamaño, horarios) y criterio de "parar y avisar" | P | — | |
| SCOPE-06 | Marcos y niveles objetivo definidos (p. ej. ASVS L2, PCI DSS 4.0.1, ISO 27001:2022) | P | ASVS | |

## Contexto de negocio y datos (CTX)

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| CTX-01 | Flujos críticos identificados (pagos, onboarding, transferencias, KYC, recuperación) | P | API6 | |
| CTX-02 | Datos clasificados por endpoint (PII, financieros, secretos, salud, credenciales) | P/E | API3 · PCI 3 | |
| CTX-03 | Roles y matriz rol×función documentada | P/E | API5 · ASVS V8 | |
| CTX-04 | Consumidores identificados: móvil, web, B2B, servicio a servicio, agentes de IA | P | API9 | |
| CTX-05 | Dependencias de terceros y flujos de datos hacia ellos documentados | P/E | API10 · ISO 5.19–5.23 | |
| CTX-06 | Obligaciones regulatorias identificadas (PCI, protección de datos, banca abierta, DORA, EU AI Act) | P | Ref. 08 | |

## Inventario (INV)

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| INV-01 | Existe especificación (OpenAPI/GraphQL SDL/protobuf) y está versionada; se compara con lo desplegado | E | API9 · NIST 800-228 inventario | |
| INV-02 | Endpoints en gateway/WAF/ingress vs. spec: ¿hay endpoints no documentados (*shadow*)? | E | API9 | |
| INV-03 | Versiones antiguas (`/v1`, `/legacy`) activas y con paridad de controles; fecha de retiro | E/D | API9 | |
| INV-04 | Entornos de prueba/staging accesibles desde internet y con datos reales | E/D | API9 · ISO 8.31 | |
| INV-05 | Endpoints de depuración/administración expuestos (`/actuator`, `/debug`, `/admin`, `/metrics`, `/swagger-ui`, `/graphql` con introspección) | D | API8/API9 | |
| INV-06 | Cada API tiene propietario, clasificación de datos, exposición (internet/partner/interna) y ciclo de vida | P | API9 · CSF ID.AM | |
| INV-07 | Subdominios y hosts del dominio en alcance enumerados (DNS, certificados, repositorios) | D | API9 · ATT&CK T1595 | |
| INV-08 | Documentación pública revisada: ¿revela rutas internas, tokens de ejemplo, credenciales? | E | API8/API9 | |
| INV-09 | Inventario de componentes de IA: modelos, proveedores, herramientas, servidores MCP, índices vectoriales, fuentes RAG (AIBOM) | P/E | LLM04 · ASI04 | |
| INV-10 | Uso de APIs de terceros documentado (qué datos se envían, con qué credenciales) | E | API10 | |
| INV-11 | Mecanismo de descubrimiento continuo (no solo inventario manual) | P | NIST 800-228 · CIS 1/2 | |
