#!/usr/bin/env python3
"""Inventario estático y banderas de riesgo a partir de una especificación OpenAPI/Swagger.

No genera tráfico de red. Las banderas son CANDIDATOS a hallazgo (revisión estática, fase 4):
deben confirmarse con pruebas autorizadas antes de reportarse.

Uso:
    python openapi_inventory.py openapi.yaml --out inventario    # inventario.md + inventario.json
    python openapi_inventory.py openapi.json --stdout            # solo imprime el Markdown

Soporta OpenAPI 3.x y Swagger 2.0 (JSON; YAML si PyYAML está instalado).
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

HTTP_METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"]
WRITE_METHODS = {"put", "post", "delete", "patch"}

SENSITIVE_RESP = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|apikey|hash|salt|ssn|cvv|cvc|pan\b|card[_-]?number|"
    r"iban|private[_-]?key|otp|pin\b|credential)", re.I)
PRIVILEGED_REQ = re.compile(
    r"^(role|roles|is[_-]?admin|admin|isadmin|permissions?|scopes?|privileges?|owner[_-]?id|user[_-]?id|"
    r"account[_-]?id|tenant[_-]?id|balance|credit|price|amount|discount|status|verified|is[_-]?verified|"
    r"is[_-]?active|approved|limit|plan|tier)$", re.I)
URL_PARAM = re.compile(r"(^|[_-])(url|uri|callback|webhook|redirect|return[_-]?to|next|endpoint|host|link|"
                       r"image[_-]?url|avatar[_-]?url|feed|source|import[_-]?from)([_-]|$)", re.I)
ID_PARAM = re.compile(r"(^id$|[_-]id$|^id[_-]|uuid|guid|number$|^ref$|reference)", re.I)
PAGINATION = {"limit", "page", "offset", "cursor", "per_page", "perpage", "page_size", "pagesize", "size",
              "first", "after", "skip", "take", "top", "next", "page_token", "pagetoken"}
ADMIN_PATH = re.compile(r"/(admin|internal|debug|actuator|management|manage|private|test|testing|dev|"
                        r"staging|beta|sandbox|metrics|health|env|config|console|swagger|api-docs|graphql)(/|$|\?)", re.I)
BUSINESS_FLOW = re.compile(r"(checkout|purchase|buy|order|payment|pay\b|transfer|withdraw|deposit|refund|"
                           r"coupon|voucher|promo|redeem|otp|verify|verification|reset|forgot|register|"
                           r"signup|sign-up|invite|vote|book|reserve|reservation|ticket|claim|reward|"
                           r"referral|kyc|onboard)", re.I)
AI_PATH = re.compile(r"(chat|completion|prompt|generate|inference|embedding|embed|rag|agent|assistant|"
                     r"tool|mcp|llm|model|vector|retriev|summariz|translate|copilot)", re.I)
AUTH_HEADER_PARAMS = {"authorization", "x-api-key", "api-key", "apikey", "x-auth-token"}


def load_spec(path):
    text = Path(path).read_text(encoding="utf-8")
    if path.lower().endswith((".yaml", ".yml")) or text.lstrip()[:1] not in "{[":
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.exit("Para leer YAML instala PyYAML (pip install pyyaml) o convierte la spec a JSON.")
        return yaml.safe_load(text)
    return json.loads(text)


def resolve(spec, node, depth=0):
    """Resuelve $ref locales (#/...) con límite de profundidad."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return {}
        cur = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            cur = cur.get(part, {}) if isinstance(cur, dict) else {}
        node = cur
        seen += 1
    return node


def walk_props(spec, schema, prefix="", depth=0, seen=None):
    """Devuelve lista de (ruta_propiedad, propiedad_dict, schema_padre) hasta profundidad 4."""
    seen = seen or set()
    out = []
    schema = resolve(spec, schema)
    if not isinstance(schema, dict) or depth > 4:
        return out
    for combo in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(combo, []) or []:
            out.extend(walk_props(spec, sub, prefix, depth + 1, seen))
    if schema.get("type") == "array" and "items" in schema:
        out.extend(walk_props(spec, schema["items"], prefix + "[]", depth + 1, seen))
    for name, sub in (schema.get("properties") or {}).items():
        full = f"{prefix}.{name}" if prefix else name
        out.append((full, resolve(spec, sub), schema))
        key = id(sub)
        if key not in seen:
            seen.add(key)
            out.extend(walk_props(spec, sub, full, depth + 1, seen))
    return out


def get_body_schemas(spec, op):
    schemas = []
    rb = resolve(spec, op.get("requestBody", {}))
    for ctype, media in (rb.get("content") or {}).items():
        if isinstance(media, dict) and media.get("schema") is not None:
            schemas.append((ctype, media["schema"]))
    for p in op.get("parameters", []) or []:  # swagger 2.0 body
        p = resolve(spec, p)
        if p.get("in") == "body" and p.get("schema") is not None:
            schemas.append(("application/json", p["schema"]))
    return schemas


def get_response_schemas(spec, op):
    out = []
    for code, resp in (op.get("responses") or {}).items():
        resp = resolve(spec, resp)
        for ctype, media in (resp.get("content") or {}).items():
            if isinstance(media, dict) and media.get("schema") is not None:
                out.append((str(code), media["schema"]))
        if resp.get("schema") is not None:  # swagger 2.0
            out.append((str(code), resp["schema"]))
    return out


def security_schemes(spec):
    comp = spec.get("components", {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
    return {k: resolve(spec, v) for k, v in comp.items()}


def analyze(spec):
    findings = []  # banderas globales
    paths = spec.get("paths") or {}
    global_security = spec.get("security")
    schemes = security_schemes(spec)
    version = spec.get("openapi") or spec.get("swagger") or "?"
    info = spec.get("info", {})

    # servidores
    servers = [s.get("url", "") for s in spec.get("servers", []) or []]
    if spec.get("host"):
        for sch in spec.get("schemes", ["https"]):
            servers.append(f"{sch}://{spec['host']}{spec.get('basePath', '')}")
    for s in servers:
        if s.startswith("http://") and "localhost" not in s and "127.0.0.1" not in s:
            findings.append(dict(flag="TLS", category="API8:2023", severity_hint="Media",
                                 where=s, msg="Servidor declarado con HTTP sin TLS"))

    # esquemas de seguridad
    for name, sc in schemes.items():
        t = sc.get("type")
        if t == "apiKey" and sc.get("in") == "query":
            findings.append(dict(flag="AUTH", category="API2:2023", severity_hint="Media", where=name,
                                 msg="API key en query string (queda en logs, historial y Referer)"))
        if t == "http" and str(sc.get("scheme", "")).lower() == "basic":
            findings.append(dict(flag="AUTH", category="API2:2023", severity_hint="Media", where=name,
                                 msg="HTTP Basic: verifica TLS obligatorio, rotación y sin credenciales compartidas"))
        flows = (sc.get("flows") or {})
        if "implicit" in flows or sc.get("flow") == "implicit":
            findings.append(dict(flag="AUTH", category="API2:2023", severity_hint="Media", where=name,
                                 msg="Flujo OAuth implicit (obsoleto según OAuth 2.0 Security BCP); usar code + PKCE"))
        if "password" in flows or sc.get("flow") == "password":
            findings.append(dict(flag="AUTH", category="API2:2023", severity_hint="Media", where=name,
                                 msg="Flujo OAuth password (obsoleto); usar code + PKCE"))
    if not schemes and not global_security:
        findings.append(dict(flag="AUTH", category="API2:2023", severity_hint="Alta", where="(global)",
                             msg="La especificación no declara ningún esquema de seguridad"))

    endpoints = []
    param_names_global = [resolve(spec, p) for p in (spec.get("parameters") or [])] if isinstance(spec.get("parameters"), list) else []
    versions_seen = Counter()
    for path, item in paths.items():
        item = resolve(spec, item)
        if not isinstance(item, dict):
            continue
        m = re.search(r"/v(\d+(?:\.\d+)?)(?=/|$)", path)
        if m:
            versions_seen[m.group(1)] += 1
        common_params = [resolve(spec, p) for p in item.get("parameters", []) or []]
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = common_params + [resolve(spec, p) for p in op.get("parameters", []) or []]
            sec = op.get("security", global_security)
            no_auth = (sec is None and not schemes) or sec == []
            flags = []

            def flag(code, category, hint, msg):
                flags.append(dict(flag=code, category=category, severity_hint=hint, msg=msg))

            # autenticación
            if sec == []:
                flag("NOAUTH", "API2:2023", "Alta" if method in WRITE_METHODS else "Media",
                     "Operación declarada explícitamente sin autenticación (security: [])")
            elif sec is None and not schemes:
                flag("NOAUTH", "API2:2023", "Alta", "Sin esquema de seguridad aplicable")
            if method in WRITE_METHODS and no_auth:
                flag("WRITE_NOAUTH", "API5:2023", "Alta", f"Método {method.upper()} sin autenticación declarada")

            # BOLA candidatos
            id_params = [p.get("name", "") for p in params
                         if p.get("in") in ("path", "query", "header") and ID_PARAM.search(p.get("name", ""))]
            path_ids = re.findall(r"\{([^}]+)\}", path)
            if path_ids or id_params:
                flag("BOLA?", "API1:2023", "Alta",
                     f"Identificador(es) de objeto en la petición: {', '.join(sorted(set(path_ids + id_params)))}. "
                     "Verificar autorización por objeto con dos identidades (AUTHZ-01)")

            # SSRF
            for p in params:
                if URL_PARAM.search(p.get("name", "")):
                    flag("SSRF?", "API7:2023", "Alta", f"Parámetro tipo URL '{p.get('name')}' ({p.get('in')})")

            # esquemas de cuerpo
            for ctype, sch in get_body_schemas(spec, op):
                resolved = resolve(spec, sch)
                if isinstance(resolved, dict) and resolved.get("additionalProperties") is True:
                    flag("MASS?", "API3:2023", "Media", "Cuerpo con additionalProperties: true (mass assignment)")
                if ctype.startswith("multipart"):
                    flag("UPLOAD", "API4:2023", "Media", "Subida de archivos: revisar tipo, tamaño, almacenamiento, escaneo")
                for pname, prop, _ in walk_props(spec, sch):
                    leaf = pname.split(".")[-1].replace("[]", "")
                    if PRIVILEGED_REQ.match(leaf) and method in WRITE_METHODS:
                        flag("MASS?", "API3:2023", "Media",
                             f"Propiedad privilegiada en el cuerpo de escritura: '{pname}' (¿modificable por el cliente?)")
                    if URL_PARAM.search(leaf):
                        flag("SSRF?", "API7:2023", "Alta", f"Propiedad tipo URL en el cuerpo: '{pname}'")
                    if prop.get("type") == "string" and not any(k in prop for k in ("maxLength", "enum", "format", "pattern")):
                        pass  # contado en agregado más abajo
            # esquemas de respuesta
            seen_resp_props = set()
            for code, sch in get_response_schemas(spec, op):
                if not code.startswith("2"):
                    continue
                for pname, prop, _ in walk_props(spec, sch):
                    leaf = pname.split(".")[-1].replace("[]", "")
                    if SENSITIVE_RESP.search(leaf) and pname not in seen_resp_props:
                        seen_resp_props.add(pname)
                        flag("EXPOSE?", "API3:2023", "Alta", f"Campo potencialmente sensible en respuesta {code}: '{pname}'")

            # listados sin paginación
            names_lower = {p.get("name", "").lower() for p in params}
            returns_array = False
            for code, sch in get_response_schemas(spec, op):
                r = resolve(spec, sch)
                if code.startswith("2") and isinstance(r, dict) and r.get("type") == "array":
                    returns_array = True
            if method == "get" and returns_array and not (names_lower & PAGINATION):
                flag("NOPAGE", "API4:2023", "Media", "Listado (array) sin parámetros de paginación/limit")
            # 429 documentado
            codes = {str(c) for c in (op.get("responses") or {})}
            has429 = "429" in codes

            # rutas administrativas / depuración
            if ADMIN_PATH.search(path + "/"):
                flag("ADMINPATH", "API5:2023", "Media", "Ruta con patrón administrativo/depuración/documentación")
            if op.get("deprecated"):
                flag("DEPRECATED", "API9:2023", "Media", "Operación marcada como deprecated: ¿sigue activa en producción?")
            if BUSINESS_FLOW.search(path):
                flag("BIZFLOW", "API6:2023", "Media", "Flujo de negocio sensible: revisar antiautomatización y límites")
            if AI_PATH.search(path) and method in ("post", "get"):
                flag("AI?", "LLM01:2026", "Info", "Posible endpoint de IA/agente: activar módulos LLM/ASI (references 02/03)")
            for p in params:
                if p.get("in") == "header" and p.get("name", "").lower() in AUTH_HEADER_PARAMS and no_auth:
                    flag("AUTH", "API2:2023", "Info", "Cabecera de autenticación como parámetro pero sin security declarado")

            endpoints.append(dict(
                method=method.upper(), path=path, operation_id=op.get("operationId", ""),
                summary=(op.get("summary") or "")[:80], tags=op.get("tags", []),
                auth="none" if (sec == [] or (sec is None and not schemes)) else ("global" if "security" not in op else "operación"),
                documents_429=has429, deprecated=bool(op.get("deprecated")), flags=flags,
            ))

    # agregados
    n = len(endpoints)
    n429 = sum(1 for e in endpoints if e["documents_429"])
    if n and n429 == 0:
        findings.append(dict(flag="NO429", category="API4:2023", severity_hint="Media", where="(global)",
                             msg="Ninguna operación documenta 429 (rate limiting no declarado; confirmar en gateway)"))
    if len(versions_seen) > 1:
        findings.append(dict(flag="VERSIONS", category="API9:2023", severity_hint="Media",
                             where=", ".join(f"v{v}" for v in sorted(versions_seen)),
                             msg="Múltiples versiones de API en la spec: confirmar cuáles siguen activas y su paridad de controles"))
    # validación de entrada: parámetros string sin maxLength
    unbounded = 0
    total_params = 0
    for path, item in paths.items():
        item = resolve(spec, item)
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            for p in (item.get("parameters", []) or []) + (op.get("parameters", []) or []):
                p = resolve(spec, p)
                sch = resolve(spec, p.get("schema", p))
                if sch.get("type") == "string":
                    total_params += 1
                    if not any(k in sch for k in ("maxLength", "enum", "pattern", "format")):
                        unbounded += 1
    return dict(
        meta=dict(title=info.get("title", ""), version=info.get("version", ""), spec_version=version,
                  servers=servers, security_schemes={k: v.get("type", "") for k, v in schemes.items()},
                  endpoints=n, documented_429=n429, string_params=total_params, string_params_without_bounds=unbounded),
        global_flags=findings, endpoints=endpoints)


def to_markdown(res):
    m = res["meta"]
    L = [f"# Inventario de API: {m['title'] or '(sin título)'}", ""]
    L += [f"- Versión de la spec: {m['spec_version']} · versión de la API: {m['version']}",
          f"- Servidores: {', '.join(m['servers']) or '(no declarados)'}",
          f"- Esquemas de seguridad: {', '.join(f'{k} ({v})' for k, v in m['security_schemes'].items()) or '(ninguno)'}",
          f"- Operaciones: {m['endpoints']} · con 429 documentado: {m['documented_429']}",
          f"- Parámetros string: {m['string_params']} · sin límite/patrón/enum/format: {m['string_params_without_bounds']}", ""]
    L += ["> Las banderas son **candidatos** de revisión estática. Confírmalos con pruebas autorizadas antes de reportar.", ""]
    if res["global_flags"]:
        L += ["## Banderas globales", "", "| Bandera | Categoría | Pista | Dónde | Detalle |", "|---|---|---|---|---|"]
        for f in res["global_flags"]:
            L.append(f"| {f['flag']} | {f['category']} | {f['severity_hint']} | {f.get('where','')} | {f['msg']} |")
        L.append("")
    L += ["## Operaciones", "", "| Método | Ruta | Auth | 429 | Banderas |", "|---|---|---|---|---|"]
    for e in res["endpoints"]:
        fl = ", ".join(sorted({f['flag'] for f in e['flags']})) or "—"
        L.append(f"| {e['method']} | `{e['path']}` | {e['auth']} | {'sí' if e['documents_429'] else 'no'} | {fl} |")
    L.append("")
    cnt = Counter(f["category"] for e in res["endpoints"] for f in e["flags"])
    cnt.update(f["category"] for f in res["global_flags"])
    L += ["## Resumen de candidatos por categoría", "", "| Categoría | Candidatos |", "|---|---|"]
    for c, n in sorted(cnt.items()):
        L.append(f"| {c} | {n} |")
    L += ["", "## Detalle de candidatos por operación", ""]
    for e in res["endpoints"]:
        if not e["flags"]:
            continue
        L.append(f"### {e['method']} `{e['path']}`")
        for f in e["flags"]:
            L.append(f"- **{f['flag']}** ({f['category']}, pista {f['severity_hint']}): {f['msg']}")
        L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec", help="OpenAPI/Swagger (.json/.yaml)")
    ap.add_argument("--out", default="inventario", help="Prefijo de salida (.md y .json)")
    ap.add_argument("--stdout", action="store_true", help="Imprime el Markdown en lugar de escribir archivos")
    args = ap.parse_args()
    spec = load_spec(args.spec)
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")):
        sys.exit("El archivo no parece una especificación OpenAPI/Swagger.")
    res = analyze(spec)
    md = to_markdown(res)
    if args.stdout:
        print(md)
        return
    Path(f"{args.out}.md").write_text(md, encoding="utf-8")
    Path(f"{args.out}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"OK: {res['meta']['endpoints']} operaciones -> {args.out}.md, {args.out}.json")


if __name__ == "__main__":
    main()
