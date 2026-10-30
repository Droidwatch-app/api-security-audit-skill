# Checklist 02 — Autenticación y autorización (fases 4–5)

Método: **E** estático · **D** dinámico (autorizado) · **P** proceso. Estado: ✔ · ✖ (abrir hallazgo) · N/A · ?.

## Autenticación (AUTHN) — API2:2023 · ASVS V6/V7/V9/V10 · PCI 8 · ISO 5.16/5.17/8.5

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| AUTHN-01 | Todos los endpoints no públicos exigen autenticación; la lista de públicos está justificada | E/D | API2 · CWE-306 | |
| AUTHN-02 | Emisión de tokens: Authorization Code + PKCE; sin implicit ni password; redirect URIs exactas | E/D | RFC 9700 · ASVS V10 | |
| AUTHN-03 | JWT: algoritmo fijado (rechaza `none`/confusión HS-RS), valida `iss`, `aud`, `exp`, `nbf`, firma; `kid`/`jku` no controlables | E/D | RFC 8725 · CWE-347 | |
| AUTHN-04 | Expiración corta de access tokens; refresh con rotación y detección de reutilización; revocación efectiva tras logout y cambio de contraseña | D | ASVS V7 · CWE-613 | |
| AUTHN-05 | Un recurso no acepta tokens emitidos para otra audiencia (`aud`); sin *token passthrough* | E/D | OAuth BCP | |
| AUTHN-06 | Límite de intentos/bloqueo y alertas en login, OTP, recuperación (cuentas propias, tasa baja) | D | CWE-307 · API4 | |
| AUTHN-07 | Sin enumeración de usuarios (mensajes y tiempos homogéneos) en login/registro/recuperación | D | WSTG-IDNT | |
| AUTHN-08 | Recuperación de contraseña: token impredecible, un solo uso, expiración corta, no filtra existencia de cuenta | D | ASVS V6 | |
| AUTHN-09 | MFA/reautenticación para operaciones sensibles (cambio de credenciales, pagos, datos personales) | D | PCI 8.4 | |
| AUTHN-10 | API keys: no en query string; con alcance, rotación, revocación y atribución; no embebidas en apps cliente | E | CWE-798 | |
| AUTHN-11 | Credenciales/secretos fuera del código, de imágenes y de logs; gestor de secretos con rotación | E | API8 · ATT&CK T1552 | |
| AUTHN-12 | Autenticación servicio-a-servicio (mTLS/identidad de carga de trabajo) en el tráfico interno | E | NIST 800-228 · SP 800-207 | |
| AUTHN-13 | Cookies de sesión (si existen): `Secure`, `HttpOnly`, `SameSite`, protección CSRF | E/D | ASVS V7 | |
| AUTHN-14 | Política de contraseñas y almacenamiento (hash con algoritmo adaptativo, no reversible) | E | ASVS V6 · PCI 8.3 | |
| AUTHN-15 | Cuentas por defecto/de prueba eliminadas; cuentas de servicio inventariadas | E/P | CIS 5 | |

## Autorización (AUTHZ) — API1/API3/API5:2023 · ASVS V8 · PCI 7 · ISO 5.15/5.18/8.3

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| AUTHZ-01 | **BOLA lectura**: usuario B no puede leer objetos de A (ruta, query, cuerpo, cabeceras, GraphQL `node(id:)`, alias, anidados); también sin autenticación | D | API1 · CWE-639 | |
| AUTHZ-02 | **BOLA escritura/borrado** (en entorno de pruebas, con objetos propios): B no puede modificar/borrar objetos de A | D | API1 | |
| AUTHZ-03 | **BFLA**: cada función se ejecuta solo con los roles previstos; cambiar método HTTP, rutas de roles superiores, versiones antiguas, `X-HTTP-Method-Override` | D | API5 · CWE-862 | |
| AUTHZ-04 | **BOPLA escritura (mass assignment)**: propiedades extra (`role`, `is_admin`, `owner_id`, `price`, `status`) no se aceptan ni modifican; esquema estricto | D/E | API3 · CWE-915 | |
| AUTHZ-05 | **BOPLA lectura**: la respuesta no devuelve propiedades que el rol no debe ver; `fields/expand/include` no las saltan | D/E | API3 · CWE-213 | |
| AUTHZ-06 | La autorización se aplica en el servidor en cada petición (no solo en el cliente/UI ni en el gateway) | E | ASVS V8 | |
| AUTHZ-07 | Política centralizada y deny-by-default; ausencia de rutas "olvidadas" sin middleware de autorización | E | NIST AC-3 | |
| AUTHZ-08 | Multi-tenancy: consultas siempre acotadas por `tenant_id` derivado del token; sin IDs de tenant aceptados del cliente | E/D | API1 · LLM09 | |
| AUTHZ-09 | Referencias a archivos/recursos (descargas por nombre, rutas) sin *path traversal* ni acceso a ajenos | D | WSTG-ATHZ | |
| AUTHZ-10 | IDs impredecibles *no* se usan como único control (UUID ≠ autorización) | E | API1 | |
| AUTHZ-11 | Alcances/roles de tokens mínimos y verificados por operación (`scope`, `roles`, `permissions` en el servidor de recursos) | E/D | OAuth BCP | |
| AUTHZ-12 | Escalada horizontal y vertical probadas con matriz rol×función (incluye rol inferior y usuario sin rol) | D | WSTG-ATHZ | |
| AUTHZ-13 | GraphQL: autorización por resolver y por campo; mutaciones y subscriptions protegidas | E/D | API1/3/5 | |
| AUTHZ-14 | Pruebas de regresión de autorización automatizadas en CI (dos identidades por endpoint) | P | NIST 800-228 pre-runtime | |
| AUTHZ-15 | Acciones de agentes/IA ejecutadas con la identidad y permisos del usuario (on-behalf-of), no con una cuenta de servicio privilegiada | E/D | LLM03 · ASI03 | |
