# Ética, autorización y reglas de compromiso

Contenido: [Por qué importa](#por-qué-importa) · [Condiciones previas](#condiciones-previas-obligatorias) · [Reglas de compromiso](#reglas-de-compromiso-por-defecto) · [Manejo de datos](#manejo-de-datos-y-evidencia) · [Cuándo parar](#cuándo-parar-y-escalar) · [Divulgación](#divulgación-responsable) · [Límites de esta skill](#límites-de-esta-skill) · [Laboratorios](#laboratorios-legales-para-practicar)

## Por qué importa

Sin autorización, una "prueba" es un acceso no autorizado, con consecuencias legales y daño potencial a terceros. Con autorización mal definida, es un incidente operativo. Estas reglas protegen al auditor, al cliente y a los usuarios finales, y hacen que la evidencia sea admisible y reproducible.

## Condiciones previas obligatorias

1. **Autorización escrita** del dueño del activo (contrato, SOW o carta) que cubra *qué*, *dónde* y *cuándo*.
2. **Alcance explícito**: dominios/IP/rutas/versiones y entornos incluidos y excluidos; terceros fuera de alcance salvo permiso expreso del tercero (proveedores de identidad, pasarelas, CDNs, modelos alojados).
3. **Ventana de pruebas** y contacto de emergencia 24/7 del cliente.
4. **Cuentas y datos de prueba** propios; ninguna prueba con cuentas de clientes reales.
5. **Límites técnicos** acordados: tasa máxima, tamaño máximo de petición, prohibiciones (DoS, ingeniería social, acceso físico, pruebas contra producción salvo acuerdo).
6. **Acuerdo de confidencialidad** y canal cifrado para entregar el informe.

## Reglas de compromiso por defecto

- **No destructivo**: sin borrado ni alteración de datos reales; escrituras solo en objetos de prueba creados por el auditor.
- **Sin DoS real**: las pruebas de consumo (API4/LLM06) son de **detección de ausencia de límites** con umbrales bajos acordados, no de saturación.
- **Tasa baja** y respeto de `429`/`Retry-After`; detener ante degradación visible.
- **Prueba mínima de datos**: si un fallo permite leer datos ajenos, demuéstralo con **un** registro de prueba o el mínimo necesario, enmascara y detente; no enumeres la base.
- **SSRF y callbacks**: usa un colaborador controlado por el auditor; no escanees redes internas ni consultes metadatos de nube sin autorización específica.
- **IA**: sin contenido dañino ni intentos de generar material ilegal; usa canarios; no entrenes ni "envenenes" modelos o índices compartidos de producción.
- **No ingeniería social** ni *phishing* a empleados salvo que el SOW lo incluya.
- **Sin persistencia ni movimiento lateral** fuera del objetivo de la prueba.
- **Cadena de custodia ligera**: registra hora UTC, origen, identidad de prueba y comando/petición de cada evidencia.

## Manejo de datos y evidencia

- Enmascara tokens, claves, contraseñas, PAN, documentos de identidad y cualquier PII en capturas e informes (`4111********1111`, `eyJhbG…[redactado]`).
- No almacenes cuerpos completos de respuesta con datos reales; guarda estado, tamaño, hash y un extracto sin PII.
- Cifra la evidencia en reposo, limita el acceso y define fecha de destrucción.
- Si encuentras secretos activos (claves cloud, tokens de producción), repórtalos de inmediato y no los uses más allá de comprobar que son válidos si el alcance lo permite; recomienda rotación.

## Cuándo parar y escalar

Detén las pruebas y avisa al contacto de emergencia si: (a) accedes a datos reales sensibles de forma inesperada; (b) observas degradación del servicio; (c) encuentras indicios de un **compromiso previo** o de un tercero atacando (activa el proceso de respuesta a incidentes del cliente; PICERL como referencia); (d) un hallazgo crítico es explotable a gran escala por cualquiera; (e) detectas que el objetivo no es del cliente o está fuera de alcance.

## Divulgación responsable

Informa primero al dueño; fija plazos razonables de remediación; no publiques detalles hasta que exista corrección o acuerdo. Si el hallazgo afecta a un producto de terceros (una biblioteca, un servidor MCP público), reporta al mantenedor por su canal de seguridad y coordina la divulgación (CVE si procede).

## Límites de esta skill

Claude **no** genera para esta skill: exploits armados ni cadenas de explotación listas para uso contra terceros, malware, herramientas de evasión de controles ajenos, ni material para atacar objetivos sin autorización. Sí describe cómo detectar y probar debilidades con cargas inocuas y de verificación, escribe herramientas de auditoría con salvaguardas, y ayuda a remediar. Si el usuario pide lo primero, explica el límite y redirige a pruebas autorizadas, configuración propia o laboratorios.

## Laboratorios legales para practicar

OWASP crAPI (API vulnerable), VAmPI, DVGA (GraphQL vulnerable), Damn Vulnerable RESTaurant, OWASP Juice Shop, WebGoat, laboratorios de PortSwigger Web Security Academy, y entornos propios aislados. Para IA: entornos de práctica de inyección de prompts con modelos propios o laboratorios que los proveedores permitan explícitamente. Útil para formación (cursos de hacking ético) sin riesgo legal.
