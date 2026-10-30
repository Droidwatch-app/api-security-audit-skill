# Checklist 04 — Recursos y flujos de negocio (fases 4–5)

Método: **E** estático · **D** dinámico (autorizado, **no destructivo**: detectar ausencia de límites con umbrales bajos, no saturar) · **P** proceso. Estado: ✔ · ✖ · N/A · ?.

## Consumo de recursos (RES) — API4:2023 · LLM06 · ASVS V2/V5 · NIST SC-5 · ISO 8.6

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| RES-01 | Rate limiting por IP, usuario, clave/cliente y por operación en gateway y/o servicio; respuesta 429 con `Retry-After` | E/D | API4 · CWE-770 | |
| RES-02 | Paginación obligatoria con tope server-side (`limit` grande, cero o negativo → clamp o 400) | D | API4 | |
| RES-03 | Tamaño máximo de cuerpo, de archivos, de campos y de arrays; límite de operaciones por lote | E/D | API4 · CWE-400 | |
| RES-04 | Timeouts y límites de memoria/CPU/conexiones por petición y por contenedor | E | API4 | |
| RES-05 | GraphQL/consultas complejas: límite de profundidad, costo, alias y *batching* | E/D | API4 | |
| RES-06 | Costos con terceros (SMS, correo, KYC/biometría, mapas, **tokens de LLM**) con cuotas, topes de gasto y alertas | E/P | API4 · LLM06 | |
| RES-07 | Tareas asíncronas/colas con límites y prioridades; sin encadenamiento ilimitado | E | API4 | |
| RES-08 | Expansión/relaciones (`expand`, `include`, joins) con límites; sin consultas N+1 explotables | E/D | API4 | |
| RES-09 | Parámetros que controlan el costo (p. ej. `max_tokens`, `temperature`, `n`, tamaño de imagen) no los fija el cliente sin tope server-side | E/D | LLM06 | |
| RES-10 | Presupuesto por **tokens/gasto** (no solo por peticiones) y cortacircuitos ante desviación | E/P | LLM06 · ASI08 | |
| RES-11 | Protección del gateway contra picos (autoscaling con tope, *load shedding*) sin amplificar costo | P | NIST 800-228 | |

## Flujos de negocio sensibles (BIZ) — API6:2023 · ASVS V2/V15 · PCI 6.2.4

| ID | Verificación | Método | Mapeo | Estado |
|---|---|---|---|---|
| BIZ-01 | Flujos sensibles inventariados (compra, transferencia, reserva, cupón, registro, OTP, KYC, referidos) con su riesgo de abuso | P | API6 | |
| BIZ-02 | Límites de negocio por cuenta/dispositivo/tiempo (no solo técnicos); verificación a baja escala con cuentas propias | D | API6 | |
| BIZ-03 | Validación de secuencia: no se puede saltar pasos ni llamar al paso N sin haber completado N-1 | D | CWE-841 | |
| BIZ-04 | Condiciones de carrera (doble gasto, doble canje) con **pocas** peticiones paralelas en datos de prueba; operaciones atómicas e idempotentes (`Idempotency-Key`) | D | CWE-362 | |
| BIZ-05 | Manipulación de valores (cantidad negativa, precio, moneda, descuento, estado) rechazada en servidor | D | API3/API6 | |
| BIZ-06 | Reutilización de tokens/cupones/enlaces de un solo uso | D | API6 | |
| BIZ-07 | Antiautomatización proporcional al riesgo (fricción, detección de bots, reputación) sin romper accesibilidad | E/P | API6 | |
| BIZ-08 | Detección de patrones de abuso y fraude (velocidad, geografía, dispositivo) con alerta y respuesta | P | PCI 10 · antifraude | |
| BIZ-09 | Controles de enumeración en flujos públicos (existencia de usuario/documento/cuenta) | D | API2/API6 | |
| BIZ-10 | Consistencia entre canales (web, móvil, B2B) en las reglas de negocio; versiones antiguas no eluden límites | E/D | API9 | |
