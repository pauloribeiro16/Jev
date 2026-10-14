"""Build the shortlist-filter prompts for the big model on Deucalion.

Parses the AEGIS Phase 1 / Phase 3 documents for one case and turns each use
case into a single filtering prompt carrying the context that decides the
answer: the use case itself, the STRIDE/LINDDUN threat hypotheses that target
it, the trust boundaries it crosses, and the assets at stake.

Two prompt sets are produced:

  cwe_<case>.json    — one prompt per use case, carrying the entire CWE
                       catalogue. Every CWE is offered; none is pre-filtered.
  d3fend_<case>.json — one prompt per ATT&CK technique, carrying that
                       technique's D3FEND defences. This is where the candidate
                       space explodes (median 7, max 27), which is why the big
                       model is needed there and nowhere else in the chain.

Run with --dry-run first: it prints prompt sizes and token estimates without
calling any model, which is the local preflight before an sbatch submission.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from frameworks.stores import FederatedStore  # noqa: E402

CASE_ROOT = Path(
    "/home/paulinho/Work/aegis-mvp/cases/Case_01_TinyTask_SaaS/03_PHASE3_SPEC"
)
USE_CASES = "part1_security_privacy/v2_security_privacy_synthesis/Doc02_System_Use_Cases.md"
SYSTEM_MODEL = "part2_threat_risk/01_SYSTEM_MODEL_ASSETS_AND_BOUNDARIES.md"
THREATS = "part2_threat_risk/02_TECHNICAL_THREATS_STRIDE.md"
PRIVACY = "part2_threat_risk/03_PRIVACY_THREATS_LINDDUN.md"

DEFAULT_DESC_CHARS = 200


# --------------------------------------------------------------------- parsing

def sections(text: str, pattern: str):
    """[(heading_line, body)] for every markdown heading matching `pattern`.

    The whole line is kept, not just the matched prefix — the heading pattern
    only covers the id, and the title sits after it.
    """
    out, current, buf = [], None, []
    rx = re.compile(pattern)
    for line in text.splitlines():
        if rx.match(line):
            if current:
                out.append((current, "\n".join(buf)))
            current, buf = line, []
        elif current is not None:
            buf.append(line)
    if current:
        out.append((current, "\n".join(buf)))
    return out


def field(body: str, name: str) -> str:
    """Value of a `- **Field:** value` bullet, including indented continuation."""
    rx = re.compile(r"^(\s*)[-*]\s*\*\*{0}\s*:?\s*\*\*".format(re.escape(name)), re.I)
    lines = body.splitlines()
    for i, line in enumerate(lines):
        m = rx.match(line)
        if not m:
            continue
        base = len(m.group(1))
        inline = line[m.end():].lstrip()
        inline = inline.split("**", 1)[0] if inline.startswith("**") else inline
        if not inline:
            inline = re.sub(r"^\**\s*", "", line[m.end():]).strip()
        out = [inline] if inline else []
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                break
            cur = len(nxt) - len(nxt.lstrip())
            if cur <= base:
                break
            out.append(nxt.strip())
        return " ".join(x for x in out if x).strip()
    return ""


def ids_in(text: str, prefix: str):
    """Every {U.C. x.y} / TM-... / TB-... / AST-... referenced in `text`."""
    return re.findall(r"\{?" + re.escape(prefix) + r"[^`\s,)]*\}?", text)


def parse_use_cases(path: Path):
    """The `#### {U.C. x.y}` entries only — `### {U.C. x}` are package groupings,
    not use cases, and including them double-counts every threat."""
    out = []
    for heading, body in sections(path.read_text(encoding="utf-8"),
                                  r"^####\s+\{U\.C\.\s*[\d.]+\}"):
        uc = re.search(r"\{U\.C\.\s*([\d.]+)\}", heading).group(1)
        title = re.sub(r"^#+\s*\{U\.C\.\s*[\d.]+\}\s*", "", heading).strip()
        if not title:
            continue
        happy = ""
        m = re.search(r"\*\*Main Success Scenario.*?\*\*:\s*(.*?)(?=\n\s*[-*]\s*\*\*|\Z)",
                      body, re.S)
        if m:
            happy = " ".join(m.group(1).split())[:600]
        out.append({
            "id": f"U.C. {uc}",
            "title": title,
            "actor": field(body, "Primary Actor"),
            "trigger": field(body, "Trigger"),
            "happy_path": happy,
            "requirements": re.findall(r"`(R[\d.]+)`", field(body, "Traceability")),
            "_raw": body,
        })
    return out


def parse_threats(paths):
    cards = []
    for path in paths:
        # Loud on a missing file: a silently empty threat set would produce
        # context-free prompts that still look valid.
        if not path.exists():
            raise FileNotFoundError(f"threat document not found: {path}")
        for heading, body in sections(path.read_text(encoding="utf-8"),
                                      r"^####\s+TM-[A-Z0-9.\-]+:"):
            tid = re.match(r"^####\s+(TM-[A-Z0-9.\-]+):", heading).group(1)
            cards.append({
                "id": tid,
                "title": heading.split(":", 1)[1].strip(),
                "stride": field(body, "STRIDE Category"),
                "linddun": field(body, "LINDDUN Category"),
                "hypothesis": field(body, "Adversary Threat Hypothesis")
                             or field(body, "Privacy Threat Hypothesis"),
                "interaction": field(body, "Target Interaction & Boundary"),
                "target_flow": field(body, "Target Data Flow"),
                "cwe": field(body, "Root Weakness (CWE)"),
                "capec": field(body, "Attack Pattern (CAPEC)"),
                "attack": field(body, "Adversary TTP (ATT&CK)"),
                "constraints": field(body, "Active Mitigating Constraints")
                               or field(body, "Active Mitigating Constraint"),
                "_raw": body,
            })
    return cards


def parse_assets_and_boundaries(path: Path):
    text = path.read_text(encoding="utf-8")
    assets = {}
    for line in text.splitlines():
        m = re.match(r"^\|\s*\*\*(AST-\d+)\*\*\s*\|\s*(.+?)\s*\|", line)
        if m:
            assets[m.group(1)] = m.group(2).replace("**", "").strip()
    boundaries = []
    for heading, body in sections(text, r"^####\s+TB-\d+:"):
        tid = re.match(r"^####\s+(TB-\d+):", heading).group(1)
        boundaries.append({
            "id": tid,
            "title": heading.split(":", 1)[1].strip(),
            "type": field(body, "Boundary Type"),
            "exposure": field(body, "Threat Exposure"),
            "constraints": field(body, "Mitigating Constraints in Baseline"),
            "use_cases": re.findall(r"\{U\.C\.\s*[\d.]+\}", field(body, "Target Use Cases")),
            "_raw": body,
        })
    return assets, boundaries


# ------------------------------------------------------------------- catalogue

def cwe_catalogue(store, desc_chars: int):
    return [
        {"id": e.id, "name": e.name,
         "description": (e.description or "")[:desc_chars]}
        for e in store.cwe.entities.values()
    ]


def d3fend_prompts(store):
    """One prompt per ATT&CK technique that actually has defences."""
    out = []
    for eid, ent in store.attack.entities.items():
        measures = []
        for l in store.crosswalk.get_crosswalk_links(eid):
            if l.direction == "OUTGOING" and l.rel_type == "DEFENDED_BY" \
                    and l.target_id.startswith("D3"):
                d = store.d3fend.get_entity(l.target_id)
                if d is not None:
                    measures.append({"id": d.id, "name": d.name,
                                     "description": (d.description or "")[:200]})
        if measures:
            out.append({"technique_id": eid, "technique": ent.name,
                        "description": (ent.description or "")[:300],
                        "defences": measures})
    return out


# --------------------------------------------------------------------- prompts

CWE_INSTRUCTION = """\
You are filtering MITRE CWE weaknesses for a specific adversary goal.

Goal: {title}
{context}

From the FULL catalogue of {n} CWE entries below, select the {k} to {k2} whose
absence would make this goal achievable, or whose presence the adversary would
exploit. Prefer weaknesses that are specific to this goal over broadly
applicable ones.

Rules:
- Do not invent identifiers. Only use ids present in the catalogue.
- Every entry must be a weakness an adversary exploits, not a mitigation.
- If the catalogue genuinely contains no good match, return an empty list.

Return ONLY this JSON object:
{{"candidates": [{{"id": "CWE-xxx", "why": "one sentence, in English"}}]}}
"""

D3FEND_INSTRUCTION = """\
An adversary uses the technique "{technique}" ({technique_id}).
{description}

From the defensive techniques below, select the {k} to {k2} that most directly
answer this specific technique — the ones that would break the path an
adversary takes, not generic hardening.

Rules:
- Do not invent identifiers. Only use ids present in the list.
- Prefer techniques that neutralise the mechanism rather than detect it after
  the fact.

Return ONLY this JSON object:
{{"candidates": [{{"id": "D3-xxx", "why": "one sentence, in English"}}]}}
"""


def use_case_context(uc, threats, boundaries, assets):
    lines = [f"Use case: {uc['id']} {uc['title']}"]
    if uc["actor"]:
        lines.append(f"Primary actor: {uc['actor']}")
    if uc["trigger"]:
        lines.append(f"Trigger: {uc['trigger']}")
    if uc["happy_path"]:
        lines.append(f"What the actor does: {uc['happy_path']}")
    if uc["requirements"]:
        lines.append(f"Requirements: {', '.join(uc['requirements'])}")

    mine = [t for t in threats if f"{{U.C. {uc['id'].replace('U.C. ', '')}}}" in t["_raw"]]
    for t in mine:
        lines.append(f"\nThreat hypothesis {t['id']}: {t['title']}")
        if t["stride"] or t["linddun"]:
            lines.append(f"  Category: {t['stride'] or t['linddun']}")
        if t["hypothesis"]:
            lines.append(f"  {t['hypothesis']}")
        if t["interaction"]:
            lines.append(f"  Boundary crossed: {t['interaction'][:300]}")

    for b in boundaries:
        if any(u.replace(" ", "") in f"{{U.C. {uc['id'].replace('U.C. ', '')}}}"
               for u in b["use_cases"]):
            lines.append(f"\nTrust boundary {b['id']} {b['title']} ({b['type']})")
            if b["exposure"]:
                lines.append(f"  Exposure: {b['exposure'][:300]}")
            if b["constraints"]:
                lines.append(f"  Baseline constraints: {b['constraints'][:200]}")

    referenced = set(re.findall(r"AST-\d+", " ".join(t["interaction"] for t in mine)))
    for a in sorted(referenced):
        if a in assets:
            lines.append(f"Asset {a}: {assets[a][:220]}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--case-root", type=Path, default=CASE_ROOT)
    ap.add_argument("--case", default="tinytask")
    ap.add_argument("--out", type=Path, default=Path("prompts"))
    ap.add_argument("--keep", type=int, default=8,
                    help="how many candidates the model should return (min), and one more")
    ap.add_argument("--desc-chars", type=int, default=DEFAULT_DESC_CHARS)
    ap.add_argument("--dry-run", action="store_true",
                    help="report prompt sizes only; write nothing and call no model")
    args = ap.parse_args()

    root = args.case_root
    ucs = parse_use_cases(root / USE_CASES)
    threats = parse_threats([root / THREATS, root / PRIVACY])
    assets, boundaries = parse_assets_and_boundaries(root / SYSTEM_MODEL)
    store = FederatedStore.get_instance()

    cwes = cwe_catalogue(store, args.desc_chars)
    d3 = d3fend_prompts(store)

    print(f"parsed {len(ucs)} use cases, {len(threats)} threat cards, "
          f"{len(assets)} assets, {len(boundaries)} boundaries")
    print(f"catalogue: {len(cwes)} CWEs, {len(d3)} ATT&CK techniques with defences")

    cwe_prompts = []
    for uc in ucs:
        ctx = use_case_context(uc, threats, boundaries, assets)
        cwe_prompts.append({
            "use_case": uc["id"],
            "title": uc["title"],
            "messages": [
                {"role": "system", "content":
                 "You are a cybersecurity analyst working on MITRE ATT&CK for a "
                 "formally specified system. Answer with JSON only."},
                {"role": "user", "content": CWE_INSTRUCTION.format(
                    title=f"{uc['id']} {uc['title']}", context=ctx,
                    n=len(cwes), k=args.keep, k2=args.keep + 2)
                 + "\n\nCATALOGUE (JSON):\n" + json.dumps(cwes)},
            ],
        })

    d3_prompts = []
    for item in d3:
        d3_prompts.append({
            "technique_id": item["technique_id"],
            "technique": item["technique"],
            "messages": [
                {"role": "system", "content":
                 "You are a cybersecurity analyst specialising in MITRE D3FEND. "
                 "Answer with JSON only."},
                {"role": "user", "content": D3FEND_INSTRUCTION.format(
                    technique=item["technique"], technique_id=item["technique_id"],
                    description=item.get("description", ""), k=args.keep, k2=args.keep + 2)
                 + "\n\nDEFENCES (JSON):\n" + json.dumps(item["defences"])},
            ],
        })

    def tokens(prompts):
        chars = sum(len(m["content"]) for p in prompts for m in p["messages"])
        return chars // 4

    print(f"\nCWE prompts   : {len(cwe_prompts)} x ~{tokens(cwe_prompts)//max(1,len(cwe_prompts)):,} tokens")
    print(f"D3FEND prompts: {len(d3_prompts)} x ~{tokens(d3_prompts)//max(1,len(d3_prompts)):,} tokens")

    if args.dry_run:
        p = cwe_prompts[0]["messages"][1]["content"]
        print("\n--- first CWE prompt, context only (catalogue elided) ---\n")
        print(p[:p.index("CATALOGUE")].strip())
        print(f"\n[...catalogue of {len(cwes)} entries elided...]")
        return

    args.out.mkdir(parents=True, exist_ok=True)
    for name, prompts in ((f"cwe_{args.case}.json", cwe_prompts),
                          (f"d3fend_{args.case}.json", d3_prompts)):
        path = args.out / name
        path.write_text(json.dumps(prompts, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        print(f"wrote {path} ({path.stat().st_size / 1024 / 1024:.2f} MB)")


if __name__ == "__main__":
    main()