# Checklist 03 — Datos, entrada y salida (fases 4–5)

Método: **E** estático · **D** dinámico (autorizado) · **P** proceso. Estado: ✔ · ✖ (abrir hallazgo) · N/A · ?.

## Protección y minimización de datos (DATA) — API3 · ASVS V14 · PCI 3/4 · ISO 8.12

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| DATA-01 | Respuestas devuelven solo los campos necesarios (comparar respuesta real vs. UI/contrato); DTOs de salida explícitos | D/E | API3 · CWE-200 | |
| DATA-02 | Sin datos sensibles (contraseñas, hashes, tokens, claves, PAN completo, documentos) en respuestas, URLs, logs ni mensajes de error | D/E | CWE-532 · PCI 3.4 | |
| DATA-03 | Datos sensibles no viajan en query strings (quedan en logs/historial/Referer) | E/D | CWE-598 | |
| DATA-04 | Cifrado en tránsito (TLS ≥1.2) y en reposo con gestión de claves | E | ASVS V11/V12 · PCI 4.2 | |
| DATA-05 | `Cache-Control: no-store` en respuestas con datos personales/autenticadas; sin caché compartida de datos por usuario | D | ASVS V14 | |
| DATA-06 | Enmascaramiento/tokenización de datos de tarjeta y de identificación según política | E | PCI 3 | |
| DATA-07 | Retención y borrado definidos (incluye logs, conversaciones de LLM, índices vectoriales y memoria de agentes) | P | Protección de datos | |
| DATA-08 | Datos de producción no usados en pruebas/staging sin enmascarar | P | ISO 8.31 | |
| DATA-09 | Mensajes de error genéricos hacia el cliente (RFC 9457) con identificador de correlación; detalle solo en logs | D | API8 · CWE-209 | |

## Validación de entrada y salida (INPUT) — API3/API7/API8/API10 · ASVS V1/V2/V4/V5

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| INPUT-01 | Validación por esquema estricto (tipos, longitudes, rangos, patrón, enums, `additionalProperties:false`) en el servidor | E/D | API3/API4 · CWE-20 | |
| INPUT-02 | Inyección SQL/NoSQL/LDAP/OS/plantillas: consultas parametrizadas, sin concatenar entrada; pruebas con cargas inocuas de detección | E/D | CWE-89/78/94 | |
| INPUT-03 | XML/SOAP: XXE y expansión de entidades deshabilitados; esquemas con límites | E/D | CWE-611 | |
| INPUT-04 | Deserialización segura (sin formatos que ejecutan código; listas permitidas de tipos) | E | CWE-502 | |
| INPUT-05 | **SSRF**: parámetros/propiedades tipo URL con allow-list; resolución y validación de IP final; sin redirecciones; egress restringido (probar con colaborador propio) | E/D | API7 · CWE-918 | |
| INPUT-06 | **Consumo seguro de terceros**: validación de esquema de respuestas externas, TLS verificado, timeouts, límites de tamaño, sin confiar en redirecciones | E/D | API10 | |
| INPUT-07 | Subida de archivos: tipo por contenido, tamaño máximo, nombre sanitizado, almacenamiento fuera del webroot, escaneo, sin ejecución | E/D | ASVS V5 · API4 | |
| INPUT-08 | Redirecciones abiertas y `Location` controlado por entrada | D | CWE-601 | |
| INPUT-09 | Parámetros HTTP duplicados/ambiguos (HPP), tipos inesperados (array vs. string), JSON con claves duplicadas, números fuera de rango | D | ASVS V2 | |
| INPUT-10 | Negociación de contenido (`Content-Type`/`Accept`) estricta; sin aceptar formatos no previstos | D | ASVS V4 | |
| INPUT-11 | Salida codificada según contexto (HTML/JSON/CSV/SQL/shell); CSV injection en exportaciones | E/D | ASVS V1 | |
| INPUT-12 | GraphQL: límites de profundidad/complejidad/alias/lotes, introspección según política, sugerencias de campo deshabilitadas en producción | E/D | API4 · API8 | |
| INPUT-13 | Webhooks entrantes: firma HMAC verificada en tiempo constante, marca de tiempo y anti-replay | E/D | API2/API10 | |
| INPUT-14 | Salidas de LLM/herramientas tratadas como entrada no confiable antes de llegar a un sink (ver checklist 06) | E | API10 · LLM10 | |
