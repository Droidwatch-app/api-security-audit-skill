# Checklist 06 — APIs y aplicaciones con LLM (OWASP LLM Top 10 2026)

Método: **E** estático/arquitectura · **D** dinámico (autorizado, solo cuentas y datos de prueba, **canarios** inofensivos) · **P** proceso. Estado: ✔ · ✖ · N/A · ?.

Reglas de prueba: sin contenido dañino, sin extraer datos reales, repetir cada prueba ≥5–10 veces (el modelo no es determinista) y reportar tasa de éxito (p. ej. 3/10). Un hallazgo debe nombrar **la acción o el dato alcanzado**. Detalle en `references/02-owasp-llm-top10-2026.md`.

## Mapa de confianza (LLM-MAP)

| ID | Verificación | Método | Estado |
|---|---|---|---|
| LLM-MAP-01 | Diagrama de flujo: entradas no confiables (usuario, documentos, web, correo, resultados de herramientas, memoria, RAG) → contexto → salidas → sinks | P | |
| LLM-MAP-02 | Lista de herramientas/acciones que el modelo puede invocar, con permiso efectivo e impacto máximo | P/E | |
| LLM-MAP-03 | Identidad con la que se ejecutan las acciones y las consultas del RAG (¿la del usuario o una de servicio?) | E | |
| LLM-MAP-04 | Proveedor(es) del modelo, región, retención de datos, uso de datos del cliente para entrenar | P | |

## Controles por categoría

| ID | Cat. | Verificación | Método | Estado |
|---|---|---|---|---|
| LLM-01 | LLM01 | Canal de sistema/desarrollador construido con plantillas estáticas; contenido de usuario y recuperado nunca se interpola en él | E | |
| LLM-02 | LLM01 | Contenido recuperado/externo delimitado y marcado como datos; instrucción canario en documento de prueba **no** altera el comportamiento ni dispara herramientas | D | |
| LLM-03 | LLM01 | Entradas multimodales (imagen, audio, PDF) inspeccionadas o tratadas como no confiables; canario oculto en imagen de prueba | D | |
| LLM-04 | LLM01 | Controles de entrada/salida (clasificadores, filtros) existen como defensa en profundidad, no como única barrera | E | |
| LLM-05 | LLM02 | Autorización **antes** de recuperar (ACL del usuario aplicada en el recuperador); dos usuarios con permisos distintos no ven contenido del otro | D/E | |
| LLM-06 | LLM02 | Sin secretos, claves ni datos personales innecesarios en prompts, herramientas o contexto | E | |
| LLM-07 | LLM02 | Registro y retención de conversaciones con minimización, enmascaramiento y acceso restringido | E/P | |
| LLM-08 | LLM03 | Cada herramienta con el mínimo permiso; credenciales de corta duración; sin acceso amplio "por si acaso" | E | |
| LLM-09 | LLM03 | Acciones irreversibles/costosas requieren aprobación humana que muestra la **operación cruda** | E/D | |
| LLM-10 | LLM03 | El modelo no puede obtener, vía herramientas, algo que el usuario no podría por su propio rol (BFLA vía LLM) | D | |
| LLM-11 | LLM04 | AIBOM: modelos, adaptadores, datasets, frameworks, conectores con versión y procedencia | P/E | |
| LLM-12 | LLM04 | Carga de artefactos con verificación de firma/hash; formatos de serialización sin ejecución de código | E | |
| LLM-13 | LLM04 | CVE de paquetes de IA/ML vigiladas (EPSS/KEV); versiones fijadas | E/P | |
| LLM-14 | LLM05 | Procedencia de datos de entrenamiento/afinado; control de acceso a pipelines y datasets; pruebas de regresión por cambio de modelo | P | |
| LLM-15 | LLM05 | Si el sistema aprende de datos de usuarios: no se puede inyectar contenido que altere el comportamiento para otros | P/D | |
| LLM-16 | LLM06 | Topes server-side de `max_tokens`, longitud de entrada, pasos/herramientas, tiempo y gasto; el cliente no puede subirlos | E/D | |
| LLM-17 | LLM06 | Presupuesto por tokens por usuario/tenant/sesión; cortacircuitos y alertas de gasto | E/P | |
| LLM-18 | LLM06 | Entradas largas/multimodales y bucles de herramientas con límite de pasos | D | |
| LLM-19 | LLM07 | Respuestas ancladas a fuentes (grounding/citas) donde corresponde; verificación antes de que la salida dispare una acción | E/D | |
| LLM-20 | LLM07 | Código generado: verificación de dependencias inexistentes ("paquetes alucinados") y revisión antes de ejecutar/mezclar | E/P | |
| LLM-21 | LLM08 | Ningún control de seguridad depende de que el prompt de sistema/esquemas de herramientas permanezcan ocultos; canario en el prompt no es extraíble con peticiones benignas… o se asume extraíble | D | |
| LLM-22 | LLM09 | Índice vectorial **por tenant y por tarea**; ACL a nivel de documento/fragmento | E/D | |
| LLM-23 | LLM09 | Escrituras al índice/memoria validadas; trazabilidad de quién escribió qué; caducidad | E | |
| LLM-24 | LLM09 | Documento canario de un tenant no aparece en respuestas de otro (varias consultas) | D | |
| LLM-25 | LLM10 | Salida del modelo codificada/validada en cada sink: shell, SQL, plantillas, HTML/Markdown, URLs | E/D | |
| LLM-26 | LLM10 | Clientes no autocargan imágenes/enlaces remotos desde la salida; secuencias ANSI neutralizadas en terminales/IDE | D | |
| LLM-27 | LLM10 | Consultas y comandos parametrizados; la salida del modelo nunca se ejecuta directamente | E | |

## Gobierno de IA (LLM-GOV) — NIST AI RMF · ISO 42001

| ID | Verificación | Método | Estado |
|---|---|---|---|
| LLM-GOV-01 | Propietario del sistema de IA, registro de casos de uso y evaluación de impacto | P | |
| LLM-GOV-02 | Evaluaciones/red teaming antes de liberar y tras cada cambio de modelo o prompt (regresión) | P | |
| LLM-GOV-03 | Monitoreo de abuso, deriva, costo y calidad; registro de incidentes de IA | P | |
| LLM-GOV-04 | Procedimiento de desactivación (kill switch) probado y supervisión humana en decisiones de alto impacto | P | |
| LLM-GOV-05 | Cumplimiento: EU AI Act / protección de datos / sectorial identificados | P | |

## Protocolo de canarios (resumen)

1. Genera cadenas únicas (`CANARIO-<ámbito>-<aleatorio>`).
2. Siembra: documento indexado de un tenant, memoria, prompt de sistema (si controlas el entorno), ticket/correo de prueba.
3. Consulta como otro usuario/tenant o como contenido indirecto.
4. Registra: entrada, salida recortada, canario observado, número de intentos y éxito (n/N).
5. Limpia: elimina los canarios sembrados al terminar.
