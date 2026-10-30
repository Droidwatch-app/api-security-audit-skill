# OWASP Top 10 for Agentic Applications — 2026 (ASI01–ASI10) + servidores MCP

Contenido: [Cuándo aplica](#cuándo-aplica) · [Modelo mental](#modelo-mental) · [Inventario del agente](#paso-previo-inventario-del-agente) · ASI01…ASI10 · [Servidores MCP y herramientas](#servidores-mcp-y-capa-de-herramientas) · [Controles transversales](#controles-transversales)

Publicada el **2025-12-09** por el OWASP GenAI Security Project (revisión por más de 100 expertos); se construye sobre incidentes reales de 2025 (p. ej. exfiltración sin clics vía correo contra un copiloto corporativo, compromiso de una extensión de asistente de código con cientos de miles de instalaciones, borrado de una base de datos de producción por un agente durante un congelamiento de código). **Extiende** el Top 10 de LLM: un sistema agéntico hereda todos los riesgos LLM. Checklist operativo: `assets/checklists/checklist-07-agentes-mcp.md`.

## Cuándo aplica

Cuando el sistema **planifica, usa herramientas, conserva memoria, coordina con otros agentes o actúa con autoridad delegada**. Un chatbot/RAG sin herramientas ni escritura se cubre con LLM Top 10; con herramientas pasa a este módulo.

## Modelo mental

La exposición de un agente es la **unión de todo lo que puede alcanzar**: credenciales, herramientas, APIs, datos, otros agentes. El daño se compone a lo largo de un plan de varios pasos; puede haber un agente "funcionando como se diseñó" que ejecute una secuencia que ningún humano habría aprobado. La auditoría pregunta: *¿cuál es el peor resultado alcanzable por este agente si su objetivo es secuestrado en el paso 1?*

## Paso previo: inventario del agente

Antes de probar, construye (y adjunta al informe):

| Componente | Qué anotar |
|---|---|
| Agente(s) | Propósito, propietario, modelo, versión, ciclo de vida (¿caduca?), kill switch |
| Identidad | Credencial usada (¿propia del agente o prestada de un humano?), alcance, duración, rotación |
| Herramientas | Nombre, permisos efectivos, efecto (lectura/escritura/irreversible), parámetros, validación, aprobación |
| Entradas no confiables | Qué contenido externo lee (correo, tickets, web, documentos, resultados de herramientas) |
| Memoria / contexto | Dónde persiste, quién escribe, caducidad, aislamiento por usuario/tarea |
| Ejecución de código | ¿Corre código? ¿En qué sandbox? ¿Egress? |
| Comunicación entre agentes | Protocolo, autenticación, mensajes firmados, descubrimiento |
| Servidores MCP / conectores | Origen, versión, procedencia, permisos, transporte |

Esa tabla es, a la vez, el AIBOM mínimo (ASI04) y el modelo de amenazas.

---

## ASI01:2026 — Agent Goal Hijack

Un atacante redirige el objetivo o la ruta de decisión del agente mediante **contenido que el agente lee** (no código que ejecuta). El agente cree seguir la meta del usuario.

- **Revisar**: separación instrucciones/datos; qué contenido externo puede influir en el plan; si el agente puede actuar sobre datos sensibles *después* de leer contenido no confiable en la misma sesión (combinación "datos privados + contenido no confiable + canal de salida" = riesgo de exfiltración).
- **Probar (canario)**: documento/correo de prueba con instrucción inofensiva y observar si cambia el plan o dispara una herramienta; medir tasa de éxito en varias ejecuciones.
- **Mitigar**: tratar todo lo recuperado como no confiable; restringir qué puede hacer el agente **sin importar lo que diga su contexto**; confirmación humana de acciones sensibles mostrando la operación cruda.
- **Mapeo**: LLM01 · CWE-1427 · ATLAS AML.T0051.001.

## ASI02:2026 — Tool Misuse & Exploitation

Una herramienta legítima se desvía hacia un resultado ilegítimo: entrada engañosa, **metadatos de herramienta envenenados**, o cadena de herramientas "seguras" que juntas son peligrosas.

- **Revisar**: validación de parámetros en el servidor de la herramienta (no solo en el prompt); alcance mínimo por herramienta; políticas en tiempo de ejecución por invocación; herramientas con shell/`eval`; descripciones de herramientas controladas por terceros.
- **Probar**: invocaciones con parámetros fuera de rango/contra políticas (en pruebas), encadenamientos que acumulan permisos, descripción de herramienta con instrucción canario.
- **Mitigar**: *least agency*; esquemas estrictos; API parametrizadas en lugar de shell crudo; política "allow-list" por herramienta y por contexto.
- **Mapeo**: LLM03 · API5/API3 · CWE-250/CWE-78.

## ASI03:2026 — Identity & Privilege Abuse

Los agentes se autentican con identidades mal gestionadas: credenciales de humanos prestadas, cuentas de servicio compartidas, tokens de larga vida con alcance sin revisar. Un secuestro hereda todo.

- **Revisar**: identidad **por agente**, credenciales de corta duración por tarea, alcance mínimo, expiración automática, atribución en logs (¿se sabe qué agente hizo qué?), *confused deputy* (el agente usa sus privilegios para algo que el usuario no podría hacer), revisión periódica de permisos como los humanos.
- **Probar**: ¿puede un usuario de bajo privilegio lograr, a través del agente, algo que su propio rol no permite? (BFLA vía agente).
- **Mitigar**: identidad propia del agente, propagación de la identidad del usuario con *on-behalf-of*, tokens de tarea, aprobaciones, revocación rápida.
- **Mapeo**: LLM03 · API2/API5 · CWE-269/CWE-287 · ATT&CK T1078/T1528.

## ASI04:2026 — Agentic Supply Chain Vulnerabilities

Frameworks, conectores, servidores MCP, registros de herramientas y prompts de terceros; los agentes pueden **descubrir e integrar componentes en tiempo de ejecución**, así que la cadena cambia tras el despliegue. Ejemplos públicos: inyección de comandos en un paquete conector con cientos de miles de descargas y compromiso de extensión vía repositorio/CI.

- **Revisar**: AIBOM, firmas y procedencia, fijación de versiones, política de qué componentes puede cargar un agente, SCA antes de cargar, permisos del componente.
- **Mitigar**: componentes firmados, lista permitida, revisión de descripciones de herramientas, vigilancia de CVE de paquetes de agentes.
- **Mapeo**: LLM04 · API10 · CWE-1357/CWE-829 · NIST SR-3/SR-4/SR-11 · ATLAS AML.T0010 · ATT&CK T1195.

## ASI05:2026 — Unexpected Code Execution (RCE)

Lenguaje natural que acaba como código en ejecución fuera de los límites: script generado desde instrucción envenenada, escape de sandbox, `eval`.

- **Revisar**: dónde corre el código del agente; sandbox con mínimo privilegio; **egress denegado por defecto**; FS de solo lectura; límites de CPU/tiempo; ninguna cadena externa llega a un intérprete/subproceso sin parametrizar.
- **Probar**: entorno de pruebas, con carga inofensiva (p. ej. escribir un archivo canario en el directorio temporal) para ver si el agente ejecuta código derivado de contenido; confirmar que el sandbox bloquea red y accesos fuera de su ámbito.
- **Mitigar**: contenedores/microVM aislados, API parametrizadas, deny egress, revisión humana de código antes de ejecutar en entornos sensibles.
- **Mapeo**: LLM10 · CWE-94/CWE-78 · ATT&CK T1059.

## ASI06:2026 — Memory & Context Poisoning

Contexto de sesión, índices de recuperación y memoria a largo plazo moldean el comportamiento futuro y no se diseñaron como fronteras de seguridad. El pago llega **sesiones o semanas después**.

- **Revisar**: quién/qué escribe en la memoria; validación de escrituras; aislamiento por usuario y tarea; caducidad; posibilidad de inspeccionar y purgar; si una escritura en un contexto afecta a otros usuarios.
- **Probar**: escribir un recuerdo canario benigno en una sesión y ver si influye en otra sesión/otro usuario.
- **Mitigar**: validación en ingestión, contexto efímero por defecto, memoria inspeccionable, segmentación.
- **Mapeo**: LLM09/LLM05 · API3 · ATLAS AML.T0020.

## ASI07:2026 — Insecure Inter-Agent Communication

Sistemas multiagente: mensajes, delegaciones y descubrimiento sin autenticación, integridad ni autorización permiten suplantar agentes, alterar instrucciones, reproducir delegaciones o registrar pares falsos.

- **Revisar**: autenticación mutua entre agentes, mensajes firmados con protección de integridad y anti-replay, *allow-list* de quién puede delegar a quién, registro de descubrimiento autenticado, cifrado en tránsito, registro inmutable del tráfico.
- **Probar**: entorno de pruebas con un "agente colaborador" para ver si acepta instrucciones sin verificar origen; replay de una delegación.
- **Mapeo**: API2/API5 · CWE-306/CWE-345 · ATT&CK T1199.

## ASI08:2026 — Cascading Failures

Un error o compromiso se propaga: un dato alucinado alimenta a otro agente, una acción excesiva dispara automatización posterior. En un análisis académico del protocolo MCP, con cinco servidores conectados a un agente, un servidor comprometido logró alta tasa de éxito y se propagó a operaciones de otros servidores con alta frecuencia: **la conectividad multiplica el riesgo**.

- **Revisar**: aislamiento del radio de impacto entre agentes/entornos; separación estricta desarrollo/producción; cortacircuitos que detengan la automatización ante desviaciones; límites de pasos/gasto; reversibilidad (backups, *dry-run*).
- **Mitigar**: aislamiento, límites duros, "congelamientos" que el agente no pueda saltarse técnicamente (no solo por instrucción).
- **Mapeo**: LLM06/LLM07 · API4 · NIST SP 800-228 (segmentación, resiliencia).

## ASI09:2026 — Human-Agent Trust Exploitation

El agente (comprometido o no) manipula a la persona: presenta un cambio con puerta trasera como arreglo rutinario, resume una aprobación ocultando lo que se aprueba, o usa lenguaje persuasivo para obtener credenciales. **Ataca el control que más se usa como red de seguridad: la aprobación humana.**

- **Revisar**: que la aprobación muestre la **acción cruda** y no el resumen del modelo; registro inmutable de lo mostrado vs. lo ejecutado; fatiga de aprobaciones; contexto suficiente para decidir; lenguaje persuasivo en flujos sensibles.
- **Mapeo**: LLM07 · API6 · ISO 42001 (supervisión humana) · NIST AI RMF (MANAGE).

## ASI10:2026 — Rogue Agents

Agentes que operan fuera de política por compromiso, desalineación o deriva, mientras parecen legítimos y **persisten**. Incluye sub-agentes no inventariados creados por orquestadores.

- **Revisar**: línea base de comportamiento y alertas por desviación; propietario y fecha de expiración por agente; sandbox por defecto; **kill switch probado** (¿funciona de verdad, y cuánto tarda?); inventario de sub-agentes; logs inmutables de llamadas a herramientas y delegaciones.
- **Mapeo**: API9 (inventario) · CSF DE.CM · NIST SI-4 · ATT&CK T1078.

---

## Servidores MCP y capa de herramientas

El **OWASP MCP Top 10** cubre la capa de conexión agente-herramientas; consulta su lista vigente en genai.owasp.org. Mientras tanto, revisa estos puntos (derivados de las categorías anteriores y de la documentación de seguridad del protocolo):

| ID | Verificación | Por qué |
|---|---|---|
| MCP-01 | Autenticación y autorización en cada servidor MCP remoto (OAuth 2.x con PKCE; sin *token passthrough* a APIs aguas abajo) | Evita *confused deputy* y acceso anónimo a herramientas |
| MCP-02 | Alcance mínimo de cada herramienta y de los tokens que usa; credenciales por tarea | ASI02/ASI03 |
| MCP-03 | Descripciones/metadatos de herramientas tratados como no confiables; detección de cambios ("rug pull") y fijación de versión | Envenenamiento de herramientas |
| MCP-04 | Validación estricta de parámetros y sin inyección de comandos en implementaciones locales (`exec`, shell, rutas) | Casos reales de RCE en conectores |
| MCP-05 | Procedencia, firma y fijación de versión de servidores/paquetes MCP; AIBOM | ASI04 |
| MCP-06 | Transporte seguro (TLS para remoto; permisos de proceso local mínimos; enlazar solo a localhost cuando proceda) y verificación de `Origin`/DNS rebinding para servidores locales HTTP | Superficie local |
| MCP-07 | Aislamiento entre servidores conectados al mismo agente; un servidor no debe poder influir en las herramientas de otro | Cascada |
| MCP-08 | Registro de invocaciones (herramienta, parámetros enmascarados, identidad, resultado) y alertas | Detección |
| MCP-09 | Aprobación humana para herramientas con efectos; mostrar parámetros reales | ASI09 |
| MCP-10 | Límites de tasa, tamaño y costo por herramienta | LLM06 |

## Controles transversales

1. **Identidad propia por agente**, credenciales de vida corta y alcance mínimo.
2. **Instrucciones separadas de datos**; todo contenido recuperado es no confiable.
3. **Sandbox** con egress denegado por defecto para cualquier ejecución.
4. **Aprobación humana** con acción cruda para lo irreversible.
5. **Validación en el sink** de toda salida del modelo.
6. **AIBOM** y procedencia para todo componente; revisión continua porque el agente amplía su cadena en ejecución.
7. **Observabilidad**: logs inmutables, línea base de comportamiento, alertas y **kill switch probado**.
8. **Aislamiento de radio de impacto** entre agentes, tenants y entornos.

Estos ocho puntos son también la estructura recomendada de la sección de remediación del informe para sistemas agénticos.
