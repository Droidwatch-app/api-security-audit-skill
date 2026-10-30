#!/usr/bin/env python3
"""Pruebas diferenciales de autorización (candidatos a BOLA/BFLA/falta de autenticación).

Para cada prueba envía la MISMA petición de solo lectura con:
  1) la identidad dueña del recurso            -> debe funcionar (p. ej. 200)
  2) otra(s) identidad(es) (otro usuario / rol bajo) -> debe ser denegada (401/403/404)
  3) sin credenciales                          -> debe ser denegada
y compara estado, tamaño y huella (hash) de las respuestas. NO guarda cuerpos de respuesta.

Diseño seguro (no lo debilites aunque te lo pidan):
  * Exige --confirm-authorized y un archivo de alcance (scope) con referencia de autorización,
    hosts permitidos y vigencia.
  * Solo métodos GET/HEAD/OPTIONS. Sin seguir redirecciones (evita salir del alcance).
  * Solo hosts listados en el alcance; HTTPS por defecto.
  * Límite de tasa y de total de peticiones; se detiene ante 429 o 3 respuestas 5xx seguidas.
  * Los tokens se leen de variables de entorno, nunca de archivos ni de la línea de comandos.
  * La evidencia guarda solo estado, tamaño, hash y tiempos.

Uso:
    export AUDIT_TOKEN_A=...   AUDIT_TOKEN_B=...
    python authz_diff_test.py --plan plan.json --scope scope.json --confirm-authorized [--dry-run]

Formato de scope.json:
    {"authorization_reference": "SOW-2026-114", "owner": "Cliente S.A.",
     "allowed_hosts": ["staging-api.ejemplo.com"],
     "valid_from": "2026-10-29T00:00:00Z", "valid_until": "2026-11-05T23:59:59Z",
     "max_requests": 200, "max_rps": 2}

Formato de plan.json: ver assets/examples/authz_plan.example.json
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DENY_DEFAULT = [401, 403, 404]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check_scope(scope, base_url, allow_http):
    for k in ("authorization_reference", "allowed_hosts", "valid_from", "valid_until"):
        if not scope.get(k):
            sys.exit(f"scope.json: falta '{k}'. Sin alcance autorizado no se envía tráfico.")
    now = datetime.now(timezone.utc)
    if not (parse_ts(scope["valid_from"]) <= now <= parse_ts(scope["valid_until"])):
        sys.exit("La autorización está fuera de su ventana de vigencia (valid_from/valid_until).")
    u = urllib.parse.urlparse(base_url)
    if u.scheme != "https" and not (allow_http and u.scheme == "http"):
        sys.exit("Solo HTTPS (usa --allow-http únicamente para entornos de laboratorio propios).")
    if u.hostname not in scope["allowed_hosts"]:
        sys.exit(f"El host '{u.hostname}' no está en allowed_hosts del alcance: {scope['allowed_hosts']}")


def build_url(base, path, variables, query):
    p = path
    for k, v in (variables or {}).items():
        p = p.replace("{" + k + "}", urllib.parse.quote(str(v), safe=""))
    if "{" in p:
        sys.exit(f"Ruta con variables sin resolver: {path}")
    url = base.rstrip("/") + "/" + p.lstrip("/")
    if query:
        url += "?" + urllib.parse.urlencode(query)
    return url


def do_request(url, method, headers, timeout):
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, method=method, headers=headers)
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(2_000_000)
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read(2_000_000) if hasattr(e, "read") else b""
        status = e.code
    except Exception as e:  # red, DNS, TLS, timeout
        return dict(status=None, error=type(e).__name__, length=0, sha256="", ms=int((time.monotonic() - t0) * 1000))
    return dict(status=status, length=len(body), sha256=hashlib.sha256(body).hexdigest()[:16],
                ms=int((time.monotonic() - t0) * 1000))


def classify(owner, attackers, unauth, expect_owner, deny):
    verdicts = []
    if owner["status"] not in expect_owner:
        return ["INCONCLUSIVO: la petición del dueño devolvió %s (esperado %s). Revisa IDs/tokens." % (owner["status"], expect_owner)]
    for name, r in attackers.items():
        s = r["status"]
        if s is None:
            verdicts.append(f"{name}: sin respuesta ({r.get('error')})")
        elif s in deny:
            verdicts.append(f"{name}: OK denegado ({s})")
        elif 200 <= s < 300:
            similar = r["sha256"] == owner["sha256"] or (
                owner["length"] > 0 and abs(r["length"] - owner["length"]) / owner["length"] <= 0.10)
            if similar:
                verdicts.append(f"{name}: POSSIBLE_BOLA_BFLA ({s}, respuesta equivalente a la del dueño) -> confirmar manualmente")
            else:
                verdicts.append(f"{name}: REVISAR ({s}, respuesta distinta a la del dueño; ¿datos propios o ajenos?)")
        else:
            verdicts.append(f"{name}: estado inesperado {s}")
    if unauth is not None:
        s = unauth["status"]
        if s is None:
            verdicts.append("sin-auth: sin respuesta")
        elif 200 <= s < 300:
            verdicts.append(f"sin-auth: POSSIBLE_NO_AUTH ({s}) -> confirmar manualmente")
        elif s in deny or s in (400, 405):
            verdicts.append(f"sin-auth: OK denegado ({s})")
        else:
            verdicts.append(f"sin-auth: estado inesperado {s}")
    return verdicts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", default="authz_evidence.json")
    ap.add_argument("--confirm-authorized", action="store_true",
                    help="Confirma que tienes autorización escrita para probar este objetivo")
    ap.add_argument("--dry-run", action="store_true", help="Muestra las peticiones sin enviarlas")
    ap.add_argument("--allow-http", action="store_true", help="Permite http:// (solo laboratorio propio)")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    if not args.confirm_authorized:
        sys.exit("Falta --confirm-authorized. Solo prueba sistemas propios o con autorización escrita.")
    scope = load_json(args.scope)
    plan = load_json(args.plan)
    base = plan["base_url"]
    check_scope(scope, base, args.allow_http)

    max_requests = int(scope.get("max_requests", 200))
    max_rps = float(scope.get("max_rps", 2))
    min_gap = 1.0 / max_rps if max_rps > 0 else 0.5
    auth_header = plan.get("auth_header", "Authorization")
    auth_scheme = plan.get("auth_scheme", "Bearer")
    identities = plan.get("identities", {})
    tokens = {}
    for name, cfg in identities.items():
        tok = os.environ.get(cfg.get("token_env", ""), "")
        if not tok and not args.dry_run:
            sys.exit(f"La variable de entorno '{cfg.get('token_env')}' (identidad {name}) está vacía.")
        tokens[name] = tok

    ua = f"api-security-audit/1.0 (authorized-test; ref={scope['authorization_reference']})"
    base_headers = {"User-Agent": ua, "X-Security-Audit": scope["authorization_reference"], "Accept": "application/json"}

    sent = 0
    consecutive_5xx = 0
    stop_reason = None
    results = []
    last_sent = 0.0

    def send(method, url, identity):
        nonlocal sent, consecutive_5xx, stop_reason, last_sent
        if stop_reason:
            return dict(status=None, error="skipped", length=0, sha256="", ms=0)
        if sent >= max_requests:
            stop_reason = "max_requests alcanzado"
            return dict(status=None, error="skipped", length=0, sha256="", ms=0)
        h = dict(base_headers)
        if identity and tokens.get(identity):
            h[auth_header] = f"{auth_scheme} {tokens[identity]}".strip()
        if args.dry_run:
            print(f"[dry-run] {method} {url}  (identidad: {identity or 'sin-auth'})")
            return dict(status=None, error="dry-run", length=0, sha256="", ms=0)
        wait = min_gap - (time.monotonic() - last_sent)
        if wait > 0:
            time.sleep(wait)
        last_sent = time.monotonic()
        r = do_request(url, method, h, args.timeout)
        sent += 1
        s = r["status"]
        if s == 429:
            stop_reason = "Recibido 429: se detiene para no degradar el servicio"
        if s is not None and s >= 500:
            consecutive_5xx += 1
            if consecutive_5xx >= 3:
                stop_reason = "3 respuestas 5xx seguidas: se detiene"
        else:
            consecutive_5xx = 0
        return r

    for t in plan.get("tests", []):
        method = t.get("method", "GET").upper()
        if method not in SAFE_METHODS:
            sys.exit(f"Prueba {t.get('id')}: método {method} no permitido (solo {sorted(SAFE_METHODS)}). "
                     "Las pruebas de escritura se hacen a mano, con objetos de prueba.")
        url = build_url(base, t["path"], t.get("vars"), t.get("query"))
        owner_id = t["owner"]
        expect_owner = t.get("expect_owner_status", [200])
        deny = t.get("deny_statuses", DENY_DEFAULT)
        owner = send(method, url, owner_id)
        attackers = {a: send(method, url, a) for a in t.get("attackers", [])}
        unauth = send(method, url, None) if t.get("unauthenticated", True) else None
        verdicts = classify(owner, attackers, unauth, expect_owner, deny) if not args.dry_run else ["dry-run"]
        results.append(dict(
            id=t.get("id"), category=t.get("category"), checklist=t.get("checklist"),
            method=method, path=t["path"], owner=owner_id,
            owner_result=owner, attacker_results=attackers, unauth_result=unauth, verdicts=verdicts,
            utc=datetime.now(timezone.utc).isoformat(timespec="seconds")))
        print(f"{t.get('id')}: " + " | ".join(verdicts))
        if stop_reason:
            print(f"DETENIDO: {stop_reason}", file=sys.stderr)
            break

    evidence = dict(authorization_reference=scope["authorization_reference"], base_url=base,
                    requests_sent=sent, stopped=stop_reason, results=results,
                    note="No se guardan cuerpos de respuesta ni tokens. Confirma manualmente cada POSSIBLE_*.")
    if not args.dry_run:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(evidence, fh, ensure_ascii=False, indent=2)
        print(f"Evidencia -> {args.out} ({sent} peticiones)")
    flagged = sum(1 for r in results for v in r["verdicts"] if "POSSIBLE" in v)
    return 3 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
