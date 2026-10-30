# Cumplimiento: PCI DSS 4.0.1, ISO/IEC 27001:2022 / 42001, regulación financiera

Contenido: [Principio](#principio-evidencias-y-brechas-no-certificación) · [PCI DSS 4.0.1](#pci-dss-401) · [ISO 27001:2022](#isoiec-270012022-anexo-a) · [ISO 42001](#isoiec-42001) · [Banca/fintech LatAm y open banking](#banca-fintech-y-banca-abierta) · [Protección de datos](#protección-de-datos-personales) · [Cómo reportar](#cómo-reportar-hallazgos-con-mapeo-de-cumplimiento)

## Principio: evidencias y brechas, no certificación

Una auditoría técnica de APIs **aporta evidencia** para PCI DSS, ISO 27001/42001 o regulación sectorial, pero no declara cumplimiento: eso lo hace un evaluador acreditado (QSA, organismo certificador, supervisor). Redacta "brecha respecto al requisito X" o "evidencia de control Y", nunca "cumple PCI". Los números de requisito de abajo son los de **PCI DSS 4.0.1** y los controles de **ISO 27001:2022**; verifica el texto exacto en la norma antes de citarlo en un entregable formal.

## PCI DSS 4.0.1

Aplica si la API almacena, procesa o transmite datos de tarjeta, o puede afectar la seguridad del entorno de datos de titulares (CDE). Los requisitos "futuros" de 4.0 son obligatorios desde el 31-mar-2025.

| Requisito | Tema | Categorías de la auditoría |
|---|---|---|
| 1 | Controles de seguridad de red (segmentación, egress) | API7, API8, ASI05 |
| 2.2 | Configuración segura, eliminación de valores por defecto | API8 |
| 3 | Protección de datos de cuenta almacenados (no almacenar SAD, enmascarar PAN, cifrar) | API3 |
| 4.2 | Criptografía fuerte en tránsito por redes públicas | API8 |
| 6.2 | Desarrollo seguro; **6.2.4**: técnicas de ingeniería de software para prevenir ataques de inyección, a datos y estructuras de datos, a criptografía, **a la lógica de negocio**, a mecanismos de control de acceso | API1–API10 |
| 6.3 | Identificar y gestionar vulnerabilidades; **6.3.2** inventario de software a medida y de terceros (SBOM) | API9, API10, LLM04 |
| 6.4 | Protección de aplicaciones web públicas; **6.4.1/6.4.2** solución técnica automatizada que detecte y prevenga ataques (WAF) | API4, API8 |
| 6.5 | Gestión de cambios | API9 |
| 7 | Restringir el acceso por necesidad de saber | API1, API3, API5 |
| 8 | Identificar usuarios y autenticar el acceso (MFA, contraseñas, cuentas de sistema) | API2 |
| 10 | Registro y monitoreo de accesos | Detección, ASI10 |
| 11.3 / 11.4 | Escaneos de vulnerabilidades / **pruebas de penetración** (a nivel de aplicación y de red; segmentación) | Alcance de esta auditoría |
| 12.8 | Gestión de riesgos con proveedores de servicios de terceros | API10, LLM04 |

Nota para APIs de pagos: los hallazgos de BOLA/BFLA/BOPLA sobre objetos de cuenta/tarjeta se mapean típicamente a **Req. 6.2.4 y Req. 7**; fallos de autenticación a **Req. 8**; falta de WAF/mitigación automatizada a **6.4.2**.

## ISO/IEC 27001:2022 Anexo A

Controles relevantes (numeración 2022):

| Control | Tema | Categorías |
|---|---|---|
| 5.9 | Inventario de información y otros activos | API9 |
| 5.15, 5.16, 5.17, 5.18 | Control de acceso, gestión de identidades, información de autenticación, derechos de acceso | API1, API2, API5 |
| 5.19–5.23 | Seguridad con proveedores y servicios en la nube | API10, LLM04 |
| 8.2, 8.3, 8.5 | Derechos de acceso privilegiado, restricción de acceso a la información, autenticación segura | API2, API5 |
| 8.6 | Gestión de la capacidad | API4 |
| 8.8 | Gestión de vulnerabilidades técnicas | API8, API9 |
| 8.9 | Gestión de la configuración | API8 |
| 8.12 | Prevención de fuga de datos | API3, LLM02 |
| 8.15, 8.16 | Registro y monitoreo de actividades | Detección |
| 8.20, 8.21, 8.22 | Seguridad de redes, servicios y segregación | API7, API8 |
| 8.24 | Uso de criptografía | API2, API8 |
| 8.25–8.29 | Ciclo de desarrollo seguro, requisitos de seguridad de aplicaciones, arquitectura segura, codificación segura, pruebas de seguridad | Todas |
| 8.31 | Separación de entornos | API9 |
| 8.32 | Gestión de cambios | API9 |

## ISO/IEC 42001

Para sistemas con IA: evalúa existencia de un sistema de gestión de IA, evaluación de riesgo e impacto, controles del ciclo de vida, gestión de datos de IA, relación con terceros, supervisión humana y mejora continua. Mapeos: LLM01–LLM10 y ASI01–ASI10 se relacionan con las áreas de evaluación de riesgos, ciclo de vida del sistema de IA, datos y terceros. Ver `references/05-ia-nist-airmf-atlas-iso42001.md`.

## Banca, fintech y banca abierta

- **FAPI 2.0** y perfiles regulatorios de banca abierta (Open Banking/Open Finance): requisitos de autenticación fuerte, firma de mensajes, consentimiento y trazabilidad (ver `references/06-asvs-wstg-protocolos.md`).
- **PSD2/SCA** (UE) como referencia internacional de autenticación fuerte en pagos.
- **DORA** (UE): resiliencia operativa digital, pruebas de resiliencia, gestión de riesgos de terceros TIC.
- **Regulación local** (supervisores bancarios, de valores y de protección de datos en cada país): identifica cuál aplica al cliente y pide la normativa técnica vigente; no la cites de memoria. Muchas exigen gestión de riesgos tecnológicos, pruebas de seguridad periódicas, reporte de incidentes y evaluación de proveedores críticos.
- **Prevención de fraude y AML**: las APIs de onboarding, transferencia y consulta de listas son objetivo de abuso de flujos de negocio (API6); documenta controles antifraude y límites operativos como parte de la evidencia.

## Protección de datos personales

Minimización (API3), finalidad y retención (logs de conversaciones LLM incluidos), derechos de acceso/borrado (¿se pueden ejercer sobre índices vectoriales y memoria?), transferencias internacionales (¿el proveedor del modelo procesa datos en otra jurisdicción?), notificación de brechas. Cita la ley local aplicable (verifica) y, si hay UE, RGPD.

## Cómo reportar hallazgos con mapeo de cumplimiento

En la matriz, columnas `PCI DSS 4.0.1` e `ISO 27001:2022` se rellenan automáticamente desde `assets/data/mappings.json` según la categoría OWASP. Añade manualmente en el hallazgo la **brecha** concreta ("el endpoint X permite acceso a datos de cuenta de otros clientes: brecha respecto a Req. 7.2 y 6.2.4"), la **evidencia** y la **acción correctiva**. Incluye una sección "Alcance de cumplimiento" que diga qué marcos pidió el cliente y qué requisitos no se evaluaron.
