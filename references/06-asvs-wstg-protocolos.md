# ASVS 5.0, WSTG y protocolos de identidad (OAuth, OIDC, JWT, FAPI)

Contenido: [ASVS 5.0](#owasp-asvs-50) · [WSTG](#owasp-wstg) · [OAuth/OIDC](#oauth-20--oidc) · [JWT](#jwt) · [FAPI y banca abierta](#fapi-20-y-banca-abierta) · [mTLS y firmas](#mtls-firmas-de-mensaje-y-webhooks) · [Criptografía](#criptografía-y-transporte)

> Los capítulos de ASVS se citan a **nivel de capítulo**. Antes de citar un requisito concreto (p. ej. `v5.0.0-8.2.1`), ábrelo en la fuente oficial y copia su texto/ID; los números de requisito pueden diferir entre versiones.

## OWASP ASVS 5.0

Capítulos (estructura de ASVS 5.0) y su uso en esta auditoría:

| Capítulo | Relevancia API | Categorías relacionadas |
|---|---|---|
| V1 Encoding and Sanitization | Inyecciones, codificación de salida (incluye salida de LLM hacia sinks) | API10, LLM10 |
| V2 Validation and Business Logic | Validación de entrada, **lógica de negocio**, anti-automatización | API3, API4, API6 |
| V3 Web Frontend Security | Solo si hay cliente web (CORS, cabeceras, CSP) | API8 |
| V4 API and Web Service | Requisitos específicos de API REST/GraphQL/SOAP/WebSocket | Todas |
| V5 File Handling | Subida/descarga, límites, almacenamiento | API4, API8 |
| V6 Authentication | Contraseñas, MFA, recuperación, credenciales de servicio | API2 |
| V7 Session Management | Sesiones y ciclo de vida de tokens de sesión | API2 |
| V8 Authorization | **Autorización por función, por objeto y por propiedad**; principio de mínimo privilegio | API1, API3, API5 |
| V9 Self-contained Tokens | JWT y tokens autocontenidos | API2 |
| V10 OAuth and OIDC | Flujos, PKCE, validación, alcances, clientes | API2 |
| V11 Cryptography | Algoritmos, gestión de claves, aleatoriedad | API2, API8 |
| V12 Secure Communication | TLS/mTLS, comunicación interna | API8 |
| V13 Configuration | Configuración segura, secretos, dependencias | API8, API9 |
| V14 Data Protection | Clasificación, minimización, caché y almacenamiento | API3 |
| V15 Secure Coding and Architecture | Arquitectura, componentes, concurrencia, *race conditions* | API6, API10 |
| V16 Security Logging and Error Handling | Registros de seguridad, manejo de errores | API8 + detección |
| V17 WebRTC | Solo si hay WebRTC | — |

Niveles: L1 (mínimo/automatizable), L2 (la mayoría de aplicaciones con datos sensibles), L3 (alto valor/alta garantía). Para banca, pagos o salud, apunta a **L2 como mínimo y L3 para componentes críticos**; indica el nivel objetivo en el alcance.

Uso práctico: usa ASVS como **lista de verificación** de la fase 4–5 y cita el capítulo en la matriz; si el cliente exige verificación formal, abre el requisito concreto y reporta Cumple / No cumple / No aplica con evidencia.

## OWASP WSTG

Categorías (identificador de prueba `WSTG-<CAT>-NN`): INFO (recolección de información), CONF (configuración y despliegue), IDNT (gestión de identidad), ATHN (autenticación), ATHZ (autorización), SESS (sesiones), INPV (validación de entrada), ERRH (manejo de errores), CRYP (criptografía débil), BUSL (lógica de negocio), CLNT (lado cliente), APIT (pruebas de API; incluye GraphQL).

| Área de auditoría | Categoría WSTG |
|---|---|
| Inventario, descubrimiento de endpoints, huellas de tecnología | INFO |
| TLS, métodos HTTP, CORS, archivos expuestos, entornos | CONF |
| Registro, aprovisionamiento, enumeración de cuentas | IDNT |
| Credenciales, bloqueo, recuperación, MFA | ATHN |
| BOLA/BFLA/escalada, *path traversal*, referencias directas | ATHZ |
| Tokens, expiración, fijación, CSRF (con cookies) | SESS |
| Inyecciones, SSRF, deserialización, XXE | INPV |
| Mensajes de error y trazas | ERRH |
| Cifrado en tránsito/reposo, aleatoriedad | CRYP |
| Flujos de negocio, límites, subida de archivos, carreras | BUSL |
| GraphQL y otras API | APIT |

Cita el ID de prueba WSTG en la columna "cómo se probó" del hallazgo cuando coincida.

## OAuth 2.0 / OIDC

Checklist (OAuth 2.0 Security BCP, RFC 9700; PKCE, RFC 7636):

- **Authorization Code + PKCE** para clientes públicos y confidenciales; sin *implicit* ni *resource owner password credentials*.
- Redirect URIs con **coincidencia exacta**; sin comodines; sin redirecciones abiertas.
- Parámetro `state`/nonce correcto; validación de `iss` en la respuesta (mitigación de *mix-up*).
- Alcances (`scope`) mínimos; consentimiento significativo; *audience restriction* (`aud`) en tokens de acceso; **un recurso no acepta tokens emitidos para otro**.
- Tokens de acceso de vida corta; refresh tokens con **rotación y detección de reutilización**; revocación (RFC 7009) e introspección (RFC 7662) cuando aplique; sender-constrained tokens (mTLS o DPoP) en APIs sensibles.
- Tokens nunca en la URL; secretos de cliente fuera del código; clientes públicos sin secretos.
- Servidor de recursos: validar firma, `iss`, `aud`, `exp`, `nbf`, `scope`/`roles` en **cada** petición; no confiar en claims no verificados; evitar *token passthrough* a APIs aguas abajo (usar intercambio de tokens/on-behalf-of).
- OIDC: validar ID token (firma, `iss`, `aud`, `nonce`, `exp`); `userinfo` con token apropiado.

## JWT

Checklist (JWT BCP, RFC 8725): fijar algoritmo permitido en el verificador (rechazar `none` y confusión HS/RS), claves adecuadas y rotación (`kid` verificado contra *allow-list*/JWKS de confianza, sin cargar URLs arbitrarias en `jku`/`x5u`), validar `iss/aud/exp/nbf`, tamaño limitado, sin datos sensibles en el payload (está codificado, no cifrado; usar JWE si hace falta), revocación (lista de denegación o vida corta), `typ` explícito para evitar confusión entre tipos de token.

## FAPI 2.0 y banca abierta

Para banca/fintech y APIs de pagos (Open Banking/Open Finance), compara con el perfil **FAPI 2.0** de la OpenID Foundation: PAR (Pushed Authorization Requests), PKCE obligatorio, tokens con restricción de emisor (mTLS o DPoP), JARM/firmas de respuesta cuando aplique, y firma de mensajes para operaciones de pago. Si existe un esquema regulatorio local, cita su guía técnica (verifica la versión).

## mTLS, firmas de mensaje y webhooks

- **mTLS** servicio-a-servicio: verificar cadena y revocación, rotación de certificados, identidad en SAN (SPIFFE/SPIRE si aplica).
- **Firmas HMAC en webhooks**: comparar en tiempo constante, incluir marca de tiempo y *nonce*, ventana corta, rechazar repeticiones; documentar el secreto por cliente y su rotación.
- **Idempotencia** en operaciones monetarias (`Idempotency-Key`) para evitar doble ejecución y condiciones de carrera.

## Criptografía y transporte

TLS 1.2 como mínimo y preferentemente TLS 1.3, sin cifrados débiles, HSTS en endpoints con navegador, certificados válidos y renovación automatizada; datos sensibles cifrados en reposo con gestión de claves (KMS/HSM), sin algoritmos obsoletos (MD5, SHA-1 para firmas, DES/3DES, RC4), aleatoriedad criptográfica para tokens y claves. En PCI, ver `references/08-cumplimiento-pci-iso-regulacion.md`.
