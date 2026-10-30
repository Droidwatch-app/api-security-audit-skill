#!/usr/bin/env python3
"""Genera la matriz de hallazgos con mapeo cruzado a partir de un findings.json.

Uso:
    python findings_matrix.py findings.json --out matriz     # matriz.md + matriz.csv
    python findings_matrix.py --example > findings.json      # esquema de ejemplo
    python findings_matrix.py --list-categories              # IDs de categoría válidos

Qué hace:
  * Valida campos obligatorios, IDs de categoría (OWASP API/LLM/ASI) y formato del vector CVSS v4.0.
  * Comprueba que la severidad declarada coincida con la banda de la puntuación CVSS
    (si difiere exige 'severity_justification').
  * Enriquece cada hallazgo con CWE, ASVS, NIST 800-53, ATT&CK/ATLAS, PCI DSS 4.0.1 e ISO 27001
    desde assets/data/mappings.json (unión de todas las categorías del hallazgo).
  * NO calcula la puntuación CVSS: usa la calculadora oficial de FIRST y registra vector y valor.

Solo usa la biblioteca estándar.
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_MAP = HERE.parent / "assets" / "data" / "mappings.json"

SEVERITIES = ["Crítica", "Alta", "Media", "Baja", "Informativa"]
SEV_ALIASES = {
    "critica": "Crítica", "crítica": "Crítica", "critical": "Crítica",
    "alta": "Alta", "high": "Alta",
    "media": "Media", "medium": "Media",
    "baja": "Baja", "low": "Baja",
    "informativa": "Informativa", "info": "Informativa", "informational": "Informativa", "none": "Informativa",
}
CONFIDENCE = ["Confirmado", "Probable", "Por validar"]
CONF_ALIASES = {
    "confirmado": "Confirmado", "confirmed": "Confirmado",
    "probable": "Probable",
    "por validar": "Por validar", "por_validar": "Por validar", "unverified": "Por validar",
}
STATUS = ["Abierto", "Parcial", "Cerrado", "Riesgo aceptado"]

# Métricas base de CVSS v4.0 (orden obligatorio) y valores permitidos
CVSS4_BASE = [
    ("AV", "NALP"), ("AC", "LH"), ("AT", "NP"), ("PR", "NLH"), ("UI", "NPA"),
    ("VC", "HLN"), ("VI", "HLN"), ("VA", "HLN"), ("SC", "HLN"), ("SI", "HLN"), ("SA", "HLN"),
]
CVSS4_RE = re.compile(
    r"^CVSS:4\.0/" + "/".join(f"{m}:[{v}]" for m, v in CVSS4_BASE) + r"(/[A-Za-z]{1,4}:[A-Za-z]{1,2})*$"
)

REQUIRED = ["id", "title", "categories", "severity", "affected", "description", "impact", "remediation"]

EXAMPLE = [
    {
        "id": "H-001",
        "title": "BOLA en GET /v2/accounts/{id}/statements permite leer extractos de otros clientes",
        "categories": ["API1:2023"],
        "cwe_primary": "CWE-639",
        "affected": ["GET /v2/accounts/{id}/statements (api.ejemplo.com, v2)"],
        "description": "El servicio devuelve el extracto del identificador solicitado sin verificar que pertenezca al principal autenticado.",
        "reproduction": "1) Autenticar como usuario A y obtener id de su cuenta (A-ID). 2) Autenticar como usuario B. 3) GET /v2/accounts/A-ID/statements con el token de B -> 200 con datos de A (enmascarados en evidencia).",
        "impact": "Lectura de extractos de cualquier cliente; IDs secuenciales facilitan la enumeración.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "cvss_score": 8.7,
        "severity": "Alta",
        "severity_justification": "",
        "confidence": "Confirmado",
        "remediation": "Correctiva: filtrar por principal en la consulta. Preventiva: política central de autorización por objeto + prueba de integración con dos usuarios en CI. Detectiva: alertar por accesos a >N IDs distintos por sesión.",
        "references": ["OWASP API1:2023", "ASVS V8"],
        "status": "Abierto",
        "evidence_ref": "evidencia/H-001/",
        "checklist_ids": ["AUTHZ-01", "AUTHZ-02"],
    }
]


def load_map(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def norm_sev(s):
    return SEV_ALIASES.get(str(s).strip().lower(), None)


def band(score):
    if score is None:
        return None
    if score == 0:
        return "Informativa"
    if score < 4.0:
        return "Baja"
    if score < 7.0:
        return "Media"
    if score < 9.0:
        return "Alta"
    return "Crítica"


def uniq(seq):
    out, seen = [], set()
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def validate(findings, cmap):
    errors, warnings = [], []
    ids = set()
    cats = cmap["categories"]
    for i, f in enumerate(findings):
        tag = f.get("id", f"#{i + 1}")
        for k in REQUIRED:
            if not f.get(k):
                errors.append(f"{tag}: falta el campo obligatorio '{k}'")
        if f.get("id") in ids:
            errors.append(f"{tag}: ID duplicado")
        ids.add(f.get("id"))
        for c in f.get("categories", []) or []:
            if c not in cats:
                errors.append(f"{tag}: categoría desconocida '{c}' (usa --list-categories)")
        sev = norm_sev(f.get("severity", ""))
        if f.get("severity") and not sev:
            errors.append(f"{tag}: severidad inválida '{f.get('severity')}' (usa {', '.join(SEVERITIES)})")
        conf = CONF_ALIASES.get(str(f.get("confidence", "Por validar")).strip().lower())
        if not conf:
            errors.append(f"{tag}: confianza inválida '{f.get('confidence')}' (usa {', '.join(CONFIDENCE)})")
        vec = f.get("cvss_vector")
        score = f.get("cvss_score")
        if vec:
            if not CVSS4_RE.match(vec):
                errors.append(f"{tag}: vector CVSS v4.0 con formato inválido: {vec}")
            if score is None:
                warnings.append(f"{tag}: hay vector pero falta 'cvss_score' (calcúlalo en la calculadora de FIRST)")
        else:
            warnings.append(f"{tag}: sin vector CVSS v4.0 (usa la matriz de riesgo de respaldo y justifícalo)")
        if score is not None:
            try:
                score = float(score)
                if not 0 <= score <= 10:
                    errors.append(f"{tag}: cvss_score fuera de rango 0-10")
                else:
                    b = band(score)
                    if sev and b and sev != b and not f.get("severity_justification"):
                        errors.append(
                            f"{tag}: severidad '{sev}' no coincide con la banda CVSS '{b}' ({score}); "
                            "añade 'severity_justification'")
            except (TypeError, ValueError):
                errors.append(f"{tag}: cvss_score no numérico")
        if f.get("status") and f["status"] not in STATUS:
            warnings.append(f"{tag}: estado '{f['status']}' no estándar ({', '.join(STATUS)})")
        if conf == "Confirmado" and not (f.get("reproduction") or f.get("evidence_ref")):
            warnings.append(f"{tag}: marcado Confirmado sin 'reproduction' ni 'evidence_ref'")
    return errors, warnings


def enrich(f, cmap):
    cats = cmap["categories"]
    agg = {k: [] for k in ["cwe", "asvs", "nist_800_53", "nist_800_228", "attack", "atlas", "pci_dss", "iso_27001"]}
    names = []
    for c in f.get("categories", []):
        m = cats.get(c)
        if not m:
            continue
        names.append(f"{c} {m['name']}")
        for k in agg:
            agg[k].extend(m.get(k, []))
    if f.get("cwe_primary"):
        agg["cwe"] = [f["cwe_primary"]] + agg["cwe"]
    return names, {k: uniq(v) for k, v in agg.items()}


def md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def build(findings, cmap):
    rows = []
    for f in findings:
        names, agg = enrich(f, cmap)
        sev = norm_sev(f.get("severity", "")) or f.get("severity", "")
        conf = CONF_ALIASES.get(str(f.get("confidence", "Por validar")).strip().lower(), f.get("confidence", ""))
        rows.append({
            "ID": f.get("id", ""),
            "Título": f.get("title", ""),
            "Severidad": sev,
            "CVSS v4.0": f"{f.get('cvss_score', '')}",
            "Vector": f.get("cvss_vector", ""),
            "Confianza": conf,
            "Estado": f.get("status", "Abierto"),
            "Categorías OWASP": "; ".join(names),
            "CWE": ", ".join(agg["cwe"]),
            "ASVS 5.0": "; ".join(agg["asvs"]),
            "NIST 800-53": ", ".join(agg["nist_800_53"]),
            "NIST 800-228 (tema)": "; ".join(agg["nist_800_228"]),
            "ATT&CK": ", ".join(agg["attack"]),
            "ATLAS": ", ".join(agg["atlas"]),
            "PCI DSS 4.0.1": ", ".join(agg["pci_dss"]),
            "ISO 27001:2022": ", ".join(agg["iso_27001"]),
            "Afectado": "; ".join(f.get("affected", [])),
            "Checklist": ", ".join(f.get("checklist_ids", [])),
        })
    return rows


def write_csv(rows, path):
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_md(rows, findings, cmap, path, errors, warnings):
    sev_count = Counter(r["Severidad"] for r in rows)
    cat_count = Counter()
    for f in findings:
        for c in f.get("categories", []):
            cat_count[c] += 1
    lines = ["# Matriz de hallazgos con mapeo cruzado", ""]
    lines.append(f"Mapeos verificados el {cmap['meta'].get('verified_on', '?')}. "
                 "Los IDs son orientativos: verifica en la fuente oficial antes de citar en un entregable formal.")
    lines.append("")
    lines.append("## Resumen por severidad")
    lines.append("")
    lines.append("| Severidad | Cantidad |")
    lines.append("|---|---|")
    for s in SEVERITIES:
        lines.append(f"| {s} | {sev_count.get(s, 0)} |")
    lines.append(f"| **Total** | **{len(rows)}** |")
    lines.append("")
    if cat_count:
        lines.append("## Cobertura por categoría")
        lines.append("")
        lines.append("| Categoría | Hallazgos |")
        lines.append("|---|---|")
        for c, n in sorted(cat_count.items()):
            lines.append(f"| {c} {cmap['categories'][c]['name'] if c in cmap['categories'] else ''} | {n} |")
        lines.append("")
    lines.append("## Matriz")
    lines.append("")
    cols = ["ID", "Título", "Severidad", "CVSS v4.0", "Confianza", "Estado", "Categorías OWASP", "CWE",
            "ASVS 5.0", "NIST 800-53", "ATT&CK", "ATLAS", "PCI DSS 4.0.1", "ISO 27001:2022"]
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + "|".join("---" for _ in cols) + "|")
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for r in sorted(rows, key=lambda r: (order.get(r["Severidad"], 99), r["ID"])):
        lines.append("| " + " | ".join(md_escape(r[c]) for c in cols) + " |")
    lines.append("")
    if warnings:
        lines.append("## Advertencias de calidad")
        lines.append("")
        lines.extend(f"- {w}" for w in warnings)
        lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", nargs="?", help="Ruta a findings.json (lista de hallazgos)")
    ap.add_argument("--out", default="matriz", help="Prefijo de salida (genera .md y .csv)")
    ap.add_argument("--map", default=str(DEFAULT_MAP), help="Ruta a mappings.json")
    ap.add_argument("--example", action="store_true", help="Imprime un findings.json de ejemplo")
    ap.add_argument("--list-categories", action="store_true", help="Lista los IDs de categoría válidos")
    ap.add_argument("--strict", action="store_true", help="Trata las advertencias como errores")
    args = ap.parse_args()

    if args.example:
        json.dump(EXAMPLE, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    cmap = load_map(args.map)
    if args.list_categories:
        for cid, m in cmap["categories"].items():
            print(f"{cid}\t{m['name']}")
        return 0
    if not args.findings:
        ap.error("indica la ruta a findings.json (o usa --example)")
    with open(args.findings, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data["findings"] if isinstance(data, dict) and "findings" in data else data
    if not isinstance(findings, list):
        print("findings.json debe ser una lista (o un objeto con la clave 'findings')", file=sys.stderr)
        return 2
    errors, warnings = validate(findings, cmap)
    if args.strict:
        errors, warnings = errors + warnings, []
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    for w in warnings:
        print(f"AVISO: {w}", file=sys.stderr)
    if errors:
        print(f"\n{len(errors)} error(es): corrige el findings.json y vuelve a ejecutar.", file=sys.stderr)
        return 1
    rows = build(findings, cmap)
    write_csv(rows, f"{args.out}.csv")
    write_md(rows, findings, cmap, f"{args.out}.md", errors, warnings)
    print(f"OK: {len(rows)} hallazgo(s) -> {args.out}.md, {args.out}.csv ({len(warnings)} aviso(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
