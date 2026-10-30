# Checklist 05 — Configuración, infraestructura y observabilidad (fases 4–5)

Método: **E** estático · **D** dinámico (autorizado) · **P** proceso. Estado: ✔ · ✖ · N/A · ?.

## Configuración (CONF) — API8:2023 · ASVS V3/V12/V13 · NIST CM · PCI 2.2/4.2/6.4 · ISO 8.9/8.20

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| CONF-01 | TLS 1.2+ (preferible 1.3), sin cifrados débiles, certificado válido y renovación automática; HSTS donde hay navegador | D | CWE-319 · PCI 4.2 | |
| CONF-02 | CORS: sin reflejar `Origin` arbitrario con credenciales, sin `*` con datos sensibles; lista de orígenes explícita | D | CWE-942 | |
| CONF-03 | Cabeceras de seguridad adecuadas (`X-Content-Type-Options`, `Cache-Control`, `Content-Security-Policy` si hay HTML, `Referrer-Policy`); sin `Server`/`X-Powered-By` verbosos | D | API8 | |
| CONF-04 | Métodos HTTP no necesarios deshabilitados (`TRACE`, `OPTIONS` ajustado); sin sobreescritura de método inesperada | D | API8 · API5 | |
| CONF-05 | Errores genéricos: sin trazas, rutas internas, versiones ni consultas SQL | D | CWE-209 | |
| CONF-06 | Sin endpoints de depuración/administración expuestos (`/actuator`, `/debug`, `/metrics`, consolas, documentación interna) | D | API8/API9 | |
| CONF-07 | Credenciales y valores por defecto cambiados; sin secretos en variables expuestas, imágenes o repositorios | E | CWE-798 | |
| CONF-08 | Contenedores/hosts endurecidos (usuario no root, FS de solo lectura donde proceda, sin puertos innecesarios) | E | CIS · NIST CM-7 | |
| CONF-09 | Permisos de identidades de servicio y roles cloud con mínimo privilegio; sin comodines (`*`) | E | NIST AC-6 | |
| CONF-10 | Segmentación de red y egress deny-by-default; metadatos de nube protegidos (IMDSv2 o equivalente) | E | API7 · PCI 1 | |
| CONF-11 | IaC y configuración del gateway/WAF bajo control de versiones, revisadas y escaneadas | E/P | NIST 800-228 pre-runtime | |
| CONF-12 | Gestión de parches: SO, runtime, frameworks, bibliotecas, gateway; CVE críticas con EPSS alto/KEV tratadas con prioridad | E/P | API8 · PCI 6.3 | |
| CONF-13 | Dependencias y SBOM: SCA en CI, versiones fijadas, procedencia verificada | E | API10 · LLM04 | |
| CONF-14 | WAF/WAAP presente como defensa en profundidad, no sustituto de autorización; reglas probadas | E/D | PCI 6.4.2 | |
| CONF-15 | Paridad de configuración entre entornos; sin diferencias que debiliten producción | P | API9 · ISO 8.31 | |
| CONF-16 | Documentación de la API (Swagger UI/Redoc) no expuesta públicamente si no corresponde | D | API9 | |
| CONF-17 | Gateway: políticas centralizadas (authN, rate limit, validación de esquema) aplicadas a **todo** el tráfico (norte-sur y este-oeste) | E | NIST 800-228 | |

## Registro, monitoreo y respuesta (LOG) — ASVS V16 · NIST AU/SI-4 · PCI 10 · ISO 8.15/8.16 · CSF DE

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| LOG-01 | Se registran autenticaciones (éxito/fallo), decisiones de autorización denegadas, cambios de privilegio y acciones sensibles con usuario, objeto, origen, hora y resultado | E | NIST AU-2/AU-3 | |
| LOG-02 | Los logs no contienen secretos, tokens ni PII innecesaria; protegidos contra alteración | E | CWE-532 | |
| LOG-03 | Trazabilidad extremo a extremo (ID de correlación) entre gateway, servicios y terceros | E | NIST 800-228 | |
| LOG-04 | Alertas para señales de abuso: enumeración de IDs, 401/403 en ráfaga, picos de 429, acceso a múltiples objetos por sesión, gasto anómalo | E/P | API1/API2/API4 | |
| LOG-05 | Retención y sincronización de reloj (NTP) conforme a política/regulación | P | PCI 10 | |
| LOG-06 | Procedimiento de respuesta a incidentes específico de API (revocar claves/tokens, bloquear, comunicar); PICERL | P | SANS · CSF RS | |
| LOG-07 | Línea base de comportamiento y detección de anomalías (especialmente agentes y servicios con identidad privilegiada) | P | ASI10 | |
| LOG-08 | Pruebas periódicas (pentest, red team, ejercicios de mesa) y retest de hallazgos | P | PCI 11.4 | |
