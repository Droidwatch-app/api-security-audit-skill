#!/usr/bin/env python3
"""Regenera references/09-matriz-cruzada.md desde assets/data/mappings.json.

Úsalo tras editar mappings.json para que la referencia legible y los datos no diverjan.
    python build_cross_matrix.py [--out ../references/09-matriz-cruzada.md]
"""
import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAP = HERE.parent / "assets" / "data" / "mappings.json"
OUT = HERE.parent / "references" / "09-matriz-cruzada.md"

GROUPS = [
    ("OWASP API Security Top 10 — 2023", "API"),
    ("OWASP Top 10 for LLM Applications — 2026", "LLM"),
    ("OWASP Top 10 for Agentic Applications — 2026", "ASI"),
]


def j(xs, sep=", "):
    return sep.join(xs) if xs else "—"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    data = json.loads(MAP.read_text(encoding="utf-8"))
    cats = data["categories"]
    L = ["# Matriz de mapeo cruzado", "",
         f"Generada desde `assets/data/mappings.json` (verificada el {data['meta']['verified_on']}). "
         "No la edites a mano: modifica el JSON y ejecuta `python scripts/build_cross_matrix.py`.", "",
         "> Mapeos orientativos para trazabilidad. ASVS a nivel de capítulo. Antes de citar un ID concreto "
         "(ASVS, ATLAS, controles NIST, PCI, ISO) en un entregable formal, verifícalo en la fuente oficial "
         "(`references/00-versiones-y-fuentes.md`).", "",
         "Columnas: CWE · ASVS 5.0 (capítulos) · NIST 800-53 r5 · tema NIST 800-228 · ATT&CK · ATLAS · PCI DSS 4.0.1 · ISO 27001:2022 · categorías OWASP relacionadas.", ""]
    for title, prefix in GROUPS:
        L += [f"## {title}", "",
              "| Categoría | CWE | ASVS 5.0 | NIST 800-53 | NIST 800-228 (tema) | ATT&CK | ATLAS | PCI DSS 4.0.1 | ISO 27001:2022 | Relacionadas |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for cid, m in cats.items():
            if not cid.startswith(prefix):
                continue
            L.append("| **{id}** {name} | {cwe} | {asvs} | {n53} | {n228} | {att} | {atl} | {pci} | {iso} | {rel} |".format(
                id=cid, name=m["name"], cwe=j(m["cwe"]), asvs=j(m["asvs"], "; "), n53=j(m["nist_800_53"]),
                n228=j(m["nist_800_228"], "; "), att=j(m["attack"]), atl=j(m["atlas"]), pci=j(m["pci_dss"]),
                iso=j(m["iso_27001"]), rel=j(m["related"])))
        L.append("")
    L += ["## Cómo usar", "",
          "1. Clasifica el hallazgo en la categoría OWASP más específica (puede tener varias: p. ej. una fuga entre tenants en un RAG es LLM02 + LLM09 + API1).",
          "2. Pon como CWE principal la causa raíz más precisa, aunque no sea el primero de la lista.",
          "3. Ejecuta `scripts/findings_matrix.py` para obtener la unión de mapeos de todas las categorías del hallazgo.",
          "4. Para cumplimiento, redacta la **brecha** concreta; la tabla indica solo dónde mirar.", ""]
    Path(args.out).write_text("\n".join(L), encoding="utf-8")
    print(f"OK -> {args.out}")


if __name__ == "__main__":
    main()
