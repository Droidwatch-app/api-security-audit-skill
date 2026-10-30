# Checklist 07 — Agentes y servidores MCP (OWASP Agentic Top 10 2026)

Método: **E** estático/arquitectura · **D** dinámico (autorizado, entorno de pruebas, canarios) · **P** proceso. Estado: ✔ · ✖ · N/A · ?.
Combínala con `checklist-06-llm.md` (un agente es también una aplicación LLM). Detalle: `references/03-owasp-agentic-top10-2026.md`.

## Inventario del agente (AGT-INV)

| ID | Verificación | Método | Estado |
|---|---|---|---|
| AGT-INV-01 | Tabla de agentes: propósito, propietario, modelo/versión, expiración, kill switch | P | |
| AGT-INV-02 | Tabla de herramientas: permiso efectivo, efecto (lectura/escritura/irreversible), validación, aprobación | P/E | |
| AGT-INV-03 | Entradas no confiables que lee el agente y canales de salida disponibles (análisis de combinación datos privados + contenido no confiable + salida externa) | P | |
| AGT-INV-04 | Memoria y contexto persistentes: quién escribe, aislamiento, caducidad | P/E | |
| AGT-INV-05 | Sub-agentes y orquestación: ¿pueden crearse agentes no inventariados? | P/E | |

## Controles por categoría

| ID | Cat. | Verificación | Método | Estado |
|---|---|---|---|---|
| AGT-01 | ASI01 | Contenido recuperado aislado de las instrucciones; el agente no actúa sobre datos sensibles tras leer contenido no confiable sin barrera | E/D | |
| AGT-02 | ASI01 | Documento/correo canario con instrucción inofensiva no cambia el plan ni dispara herramientas (n/N) | D | |
| AGT-03 | ASI02 | Parámetros de herramienta validados **en el servidor de la herramienta** con esquema estricto y política por invocación | E/D | |
| AGT-04 | ASI02 | Sin herramientas con shell/`eval`/SQL libre; API parametrizadas | E | |
| AGT-05 | ASI02 | Descripciones y metadatos de herramientas tratados como no confiables; cambios detectados y versión fijada | E/D | |
| AGT-06 | ASI03 | Identidad por agente; credenciales de vida corta por tarea; alcance mínimo; atribución en logs | E | |
| AGT-07 | ASI03 | Un usuario de bajo privilegio no logra vía agente lo que su rol no permite (*confused deputy*) | D | |
| AGT-08 | ASI03 | Revisión periódica de permisos de identidades de agentes (misma cadencia que humanos) | P | |
| AGT-09 | ASI04 | AIBOM completo (agentes, modelos, frameworks, herramientas, servidores MCP); firmas y procedencia exigidas antes de cargar | P/E | |
| AGT-10 | ASI04 | Política de qué componentes puede descubrir/cargar el agente en ejecución (lista permitida) | E | |
| AGT-11 | ASI05 | Código generado se ejecuta en sandbox (contenedor/microVM) con mínimo privilegio, FS restringido, límites de recursos | E/D | |
| AGT-12 | ASI05 | **Egress denegado por defecto** desde el sandbox; prueba con archivo/callback canario | E/D | |
| AGT-13 | ASI06 | Escrituras a memoria/índice validadas; memoria inspeccionable y purgable; aislamiento por usuario y tarea | E/D | |
| AGT-14 | ASI06 | Recuerdo canario sembrado en una sesión no influye en otra sesión ni en otro usuario | D | |
| AGT-15 | ASI07 | Autenticación mutua y mensajes firmados con anti-replay entre agentes; lista permitida de delegaciones | E/D | |
| AGT-16 | ASI07 | Registro de descubrimiento de agentes/herramientas autenticado | E | |
| AGT-17 | ASI08 | Radio de impacto acotado: aislamiento entre agentes, entornos y datos; dev/prod separados técnicamente | E | |
| AGT-18 | ASI08 | Cortacircuitos y límites duros de pasos/gasto/tiempo; congelamientos aplicados técnicamente, no solo por instrucción | E/D | |
| AGT-19 | ASI09 | Aprobaciones humanas muestran la **acción cruda** (no el resumen del modelo); registro inmutable de lo mostrado vs. ejecutado | E/D | |
| AGT-20 | ASI09 | Medidas contra fatiga de aprobación (agrupación, riesgo, contexto) y contra lenguaje persuasivo en flujos sensibles | P | |
| AGT-21 | ASI10 | Línea base de comportamiento y alertas por desviación; logs inmutables de llamadas a herramientas y delegaciones | E/P | |
| AGT-22 | ASI10 | **Kill switch probado** (tiempo de efecto medido) y procedimiento de revocación de credenciales del agente | D/P | |

## Servidores MCP y conectores (MCP)

| ID | Verificación | Método | Estado |
|---|---|---|---|
| MCP-01 | Servidores remotos con autenticación/autorización (OAuth con PKCE); sin acceso anónimo a herramientas; sin *token passthrough* | E/D | |
| MCP-02 | Alcance mínimo por herramienta y por token; credenciales por tarea | E | |
| MCP-03 | Metadatos/descripciones de herramientas no confiables; detección de cambios y fijación de versión | E | |
| MCP-04 | Implementaciones locales: sin inyección de comandos (`exec`/shell/rutas) con parámetros controlados por el modelo | E/D | |
| MCP-05 | Procedencia, firma y versión fijada de servidores/paquetes; vigilancia de CVE | E/P | |
| MCP-06 | Transporte: TLS para remotos; servidores locales ligados a localhost, con verificación de `Origin` y protección contra DNS rebinding | E/D | |
| MCP-07 | Aislamiento entre servidores conectados al mismo agente (un servidor comprometido no influye en los demás) | E | |
| MCP-08 | Registro de invocaciones (herramienta, parámetros enmascarados, identidad, resultado) y alertas | E | |
| MCP-09 | Aprobación humana para herramientas con efectos; parámetros reales visibles | E/D | |
| MCP-10 | Límites de tasa, tamaño y costo por herramienta | E | |
