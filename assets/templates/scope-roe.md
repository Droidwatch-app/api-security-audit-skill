# Alcance y reglas de compromiso (Scope & RoE)

> Completar y firmar/confirmar antes de enviar tráfico. Sin este documento solo se realiza revisión estática.

## 1. Datos generales

| Campo | Valor |
|---|---|
| Cliente / dueño del activo | |
| Referencia de autorización (contrato, SOW, carta) | |
| Auditor/equipo | |
| Fecha de inicio / fin | |
| Ventana de pruebas (zona horaria) | |
| Contacto técnico del cliente | |
| **Contacto de emergencia 24/7** (para "parar y avisar") | |
| Canal seguro de entrega de resultados | |

## 2. Objetivo y alcance

| Elemento | En alcance | Fuera de alcance |
|---|---|---|
| Hosts / dominios | | |
| Rutas / versiones de API | | |
| Entornos (dev/staging/prod) | | |
| Terceros (IdP, pasarelas, proveedores de modelos, CDN) | Solo como *consumo*; no se atacan | Todo ataque directo salvo permiso expreso del tercero |
| Componentes de IA (modelos, RAG, agentes, MCP) | | |
| Tipo de pruebas | Revisión estática · Pruebas dinámicas guiadas no destructivas | DoS, ingeniería social, acceso físico, explotación destructiva |

## 3. Cuentas y datos de prueba

| Identidad | Rol | Tenant | Notas |
|---|---|---|---|
| A (dueño) | | | |
| B (mismo rol, otro usuario) | | | |
| LOW (rol inferior) | | | |
| ADMIN (privilegiado) | | | |
| Sin autenticación | — | — | |

Datos de prueba: objetos creados por el auditor; **ningún dato real de clientes** se modifica. Tokens en variables de entorno, nunca en documentos.

## 4. Límites técnicos

- Tasa máxima: ___ peticiones/segundo (por defecto 2).
- Máximo de peticiones por prueba/día: ___
- Tamaño máximo de cuerpo/archivo: ___
- Prohibido: DoS real, fuzzing masivo, fuerza bruta contra cuentas reales, SSRF hacia redes internas de terceros, extracción masiva de datos.
- Pruebas de IA: solo canarios inofensivos; sin contenido dañino; sin envenenar índices/memoria compartidos de producción.

## 5. Criterios para parar y avisar

Detener y llamar al contacto de emergencia si: se accede a datos reales sensibles de forma inesperada · se observa degradación del servicio · hay indicios de compromiso previo o de un tercero atacando · un hallazgo crítico es explotable a gran escala · se detecta que el objetivo no pertenece al cliente.

## 6. Manejo de datos y evidencia

Enmascarar datos sensibles; guardar solo estado/tamaño/hash/extractos sin PII; cifrar y limitar acceso a la evidencia; fecha de destrucción: ___.

## 7. Marcos y nivel objetivo

OWASP API Top 10 2023 · OWASP LLM Top 10 2026 · OWASP Agentic Top 10 2026 · ASVS 5.0 (nivel: L__) · NIST SP 800-228 · Otros (PCI DSS 4.0.1, ISO 27001:2022/42001, regulación local): ___

## 8. Confirmación

| | Nombre | Cargo | Fecha | Firma/confirmación |
|---|---|---|---|---|
| Cliente | | | | |
| Auditor | | | | |
