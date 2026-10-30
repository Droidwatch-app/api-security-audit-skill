# Gobierno y amenazas de IA: NIST AI RMF, AI 600-1, MITRE ATLAS, ISO/IEC 42001

Contenido: [Para qué sirve](#para-qué-sirve) · [NIST AI RMF](#nist-ai-rmf-10) · [AI 600-1 GenAI](#nist-ai-600-1--perfil-de-ia-generativa) · [MITRE ATLAS](#mitre-atlas) · [ISO/IEC 42001](#isoiec-42001) · [Preguntas de auditoría](#preguntas-de-auditoría-de-gobierno-de-ia) · [AIBOM](#aibom-mínimo)

## Para qué sirve

Los Top 10 de OWASP dicen **qué puede fallar** técnicamente. Estos marcos aportan **gobierno** (quién responde, cómo se mide y se gestiona el riesgo de IA) y **tácticas adversarias** (cómo atacan sistemas de ML/LLM). Se usan en la fase 3 (modelado de amenazas) y en el resumen ejecutivo.

## NIST AI RMF 1.0

Cuatro funciones; úsalas como estructura del apartado "gobierno de IA" del informe:

| Función | Pregunta de auditoría | Evidencia esperada |
|---|---|---|
| **GOVERN** | ¿Hay políticas, roles, rendición de cuentas y tolerancia al riesgo para IA? ¿Se gestiona el riesgo de terceros (modelos y datos)? | Política de IA, RACI, registro de proveedores, criterios de aceptación |
| **MAP** | ¿Se entiende el contexto, los usos previstos, impactos y las partes afectadas? ¿Se inventarían los componentes? | Descripción del caso de uso, clasificación de impacto, AIBOM |
| **MEASURE** | ¿Se prueban y monitorean riesgos (robustez, seguridad, privacidad, sesgo, confabulación) con métricas? | Resultados de *red teaming*, evaluaciones, métricas de incidentes |
| **MANAGE** | ¿Se priorizan, mitigan y comunican los riesgos? ¿Hay respuesta a incidentes y desactivación? | Plan de tratamiento, kill switch, procedimiento de incidentes |

## NIST AI 600-1 — Perfil de IA generativa

Identifica riesgos propios o agravados por la IA generativa. Los doce: CBRN (información de armas químicas, biológicas, radiológicas, nucleares), **confabulación**, contenido peligroso/violento/de odio, **privacidad de datos**, impacto ambiental, **configuración humano-IA**, **integridad de la información**, **seguridad de la información**, propiedad intelectual, contenido obsceno/degradante/abusivo, toxicidad/sesgo/homogeneización, e **integración de la cadena de valor y componentes**.

Mapa útil para auditoría de APIs con LLM:

| Riesgo AI 600-1 | OWASP LLM / ASI |
|---|---|
| Confabulación | LLM07 · ASI09 |
| Privacidad de datos | LLM02 · LLM09 |
| Seguridad de la información | LLM01 · LLM08 · LLM10 · ASI01/ASI05 |
| Cadena de valor y componentes | LLM04 · ASI04 |
| Configuración humano-IA | ASI09 · LLM03 |
| Integridad de la información | LLM05 · LLM07 · ASI06 |

## MITRE ATLAS

Matriz de tácticas y técnicas adversarias contra sistemas de IA (análoga a ATT&CK). **Los IDs cambian entre versiones: verifica en https://atlas.mitre.org/ antes de citarlos en un informe formal.** Técnicas más usadas aquí (IDs al momento de la verificación de la skill; marcar "por verificar" si no puedes contrastar):

| Técnica | ID | Relación |
|---|---|---|
| Inyección de prompt de LLM (directa/indirecta) | AML.T0051 (.000 / .001) | LLM01 · ASI01 |
| Jailbreak de LLM | AML.T0054 | LLM01 |
| Extracción de meta-prompt | AML.T0056 | LLM08 |
| Fuga de datos vía LLM | AML.T0057 | LLM02 · LLM10 |
| Envenenamiento de datos de entrenamiento | AML.T0020 | LLM05 · LLM09 · ASI06 |
| Compromiso de la cadena de suministro de ML | AML.T0010 | LLM04 · ASI04 |
| Compromiso de plugin/herramienta de LLM | AML.T0053 | LLM03 · ASI02 |
| Denegación de servicio de ML | AML.T0029 | LLM06 |
| Recolección de costo (cost harvesting) | AML.T0034 | LLM06 |

Uso: en la fase 3, para cada escenario añade la táctica ATT&CK o la técnica ATLAS correspondiente; en el informe, incluye la columna "Técnica adversaria" en la matriz.

## ISO/IEC 42001

Norma de **sistema de gestión de IA** (AIMS), certificable, análoga a ISO 27001. Áreas útiles: contexto y liderazgo, evaluación y tratamiento de riesgos de IA, evaluación de impacto del sistema de IA, controles del ciclo de vida del sistema de IA, datos para sistemas de IA, información para partes interesadas, uso responsable, relaciones con terceros y proveedores, monitoreo y mejora. En auditoría de API/LLM, úsala para evaluar: ¿existe un AIMS?, ¿se evalúa el impacto antes de exponer el modelo?, ¿están definidos supervisión humana y desactivación? **No afirmes conformidad**: señala evidencias y brechas; la certificación la emite un organismo acreditado.

Otras regulaciones a mencionar si aplican (sin dar asesoría legal): EU AI Act (clasificación por riesgo, transparencia, trazabilidad), DORA (resiliencia operativa en servicios financieros de la UE), y marcos locales de protección de datos y supervisión financiera.

## Preguntas de auditoría de gobierno de IA

1. ¿Quién es el dueño del sistema de IA y del riesgo? ¿Existe un registro de sistemas/casos de uso?
2. ¿Se clasificó el impacto (datos, decisiones automatizadas, derechos de personas)?
3. ¿Qué proveedores de modelos/datos se usan? ¿Qué cláusulas de datos, retención y entrenamiento con datos del cliente existen?
4. ¿Cómo se prueba antes de liberar (red teaming, evaluaciones de seguridad y de confabulación)? ¿Hay regresión por cada cambio de modelo/prompt?
5. ¿Hay monitoreo de uso, abuso, costo y deriva?
6. ¿Existe procedimiento de incidente específico de IA y **desactivación** (kill switch) probada?
7. ¿Hay supervisión humana definida donde la decisión es de alto impacto?
8. ¿Se registran las interacciones de forma que permita investigar sin violar privacidad?

## AIBOM mínimo

Lista viva de: modelos (nombre, versión, proveedor, formato, hash/firma), adaptadores/afinados, datasets de entrenamiento y de afinado (procedencia, licencia), frameworks y runtimes, índices vectoriales y fuentes de RAG, herramientas/conectores/servidores MCP (origen, versión, permisos), prompts de sistema versionados, dependencias de inferencia, propietario y fecha de revisión. Es el insumo de LLM04, ASI04 y de NIST SR-3/SR-4/SR-11.
