"""Download, version and refresh the official MITRE/CISA ontologies.

Live data stays in data/official/ because the domain stores hardcode that path.
Previous bytes are archived under data/versions/<date>/ only when content
actually changes, and every fetch is recorded in a sha256 manifest so an
experiment can be tied to the exact ontology revision it ran against.

    python scripts/fetch_official_data.py              # download what is missing
    python scripts/fetch_official_data.py --check      # what changed upstream?
    python scripts/fetch_official_data.py --update     # refresh + archive old
    python scripts/fetch_official_data.py --rollback 2026-10-13
"""

import argparse
import hashlib
import json
import shutil
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "data" / "official"
VERSION_DIR = ROOT / "data" / "versions"
MANIFEST = VERSION_DIR / "manifest.jsonl"

DATA_DIR.mkdir(parents=True, exist_ok=True)
VERSION_DIR.mkdir(parents=True, exist_ok=True)

SOURCES = {
    "capec": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
        "filename": "capec.json",
        "description": "MITRE CAPEC (STIX 2.1 JSON)"
    },
    "attack": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "filename": "enterprise-attack.json",
        "description": "MITRE Enterprise ATT&CK (STIX 2.1 JSON)"
    },
    "attack_mobile": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
        "filename": "mobile-attack.json",
        "description": "MITRE Mobile ATT&CK (Android/iOS STIX 2.1 JSON)"
    },
    "attack_ics": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
        "filename": "ics-attack.json",
        "description": "MITRE ICS/OT/IoT ATT&CK (Embedded & Industrial STIX 2.1 JSON)"
    },
    "d3fend": {
        "url": "https://d3fend.mitre.org/ontologies/d3fend.json",
        "filename": "d3fend.json",
        "description": "MITRE D3FEND (JSON Matrix)"
    },
    "d3fend_mappings": {
        "url": "https://d3fend.mitre.org/resources/d3fend-full-mappings.csv",
        "filename": "d3fend-full-mappings.csv",
        "description": "MITRE D3FEND Full Mappings (CSV)"
    },
    "atlas": {
        "url": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.09.yaml",
        "filename": "atlas.yaml",
        "description": "MITRE ATLAS (YAML Matrix)"
    },
    "cwe": {
        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "filename": "cwec_latest.xml.zip",
        "description": "MITRE CWE Catalog (XML Zip)"
    },
}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest() -> list:
    if not MANIFEST.exists():
        return []
    out = []
    for line in MANIFEST.read_text(errors="ignore").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def last_entry(key: str):
    """Most recent manifest record for a source, or None."""
    entries = [e for e in read_manifest() if e.get("key") == key]
    return entries[-1] if entries else None


def log(entry: dict) -> None:
    with MANIFEST.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def fetch(key: str, info: dict, force: bool = False):
    """Download one source. Returns a status dict describing what happened."""
    dest = DATA_DIR / info["filename"]
    prev = last_entry(key)
    has_local = dest.exists() and dest.stat().st_size > 0

    if has_local and not force:
        return {"key": key, "status": "present", "file": info["filename"]}

    headers = {"User-Agent": UA}
    if prev and not force:
        if prev.get("etag"):
            headers["If-None-Match"] = prev["etag"]
        if prev.get("last_modified"):
            headers["If-Modified-Since"] = prev["last_modified"]

    req = urllib.request.Request(info["url"], headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            content = resp.read()
            etag = resp.headers.get("ETag")
            last_mod = resp.headers.get("Last-Modified")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return {"key": key, "status": "unchanged", "file": info["filename"]}
        raise
    except Exception as e:
        return {"key": key, "status": f"error: {e}", "file": info["filename"]}

    new_hash = hashlib.sha256(content).hexdigest()
    old_hash = sha256(dest) if has_local else None

    if has_local and old_hash == new_hash:
        log({"ts": datetime.now(timezone.utc).timestamp(), "iso": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "key": key, "filename": info["filename"], "url": info["url"], "sha256": new_hash,
             "bytes": len(content), "etag": etag, "last_modified": last_mod, "changed": False})
        return {"key": key, "status": "unchanged", "file": info["filename"], "sha256": new_hash}

    archived = None
    if has_local:
        stamp = today()
        archive_dir = VERSION_DIR / stamp
        archive_dir.mkdir(parents=True, exist_ok=True)
        archived = archive_dir / info["filename"]
        shutil.copy2(dest, archived)

    dest.write_bytes(content)
    entry = {
        "ts": datetime.now(timezone.utc).timestamp(),
        "iso": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "key": key, "filename": info["filename"], "url": info["url"],
        "sha256": new_hash, "bytes": len(content),
        "etag": etag, "last_modified": last_mod,
        "changed": True,
    }
    log(entry)
    out = {"key": key, "status": "updated" if has_local else "downloaded",
           "file": info["filename"], "sha256": new_hash, "bytes": len(content)}
    if archived:
        out["archived_to"] = str(archived.relative_to(ROOT))
    return out


def extract_cwe_zip(zip_path: Path):
    xml_dest = DATA_DIR / "cwec.xml"
    if xml_dest.exists() and xml_dest.stat().st_size > 0:
        return xml_dest
    with zipfile.ZipFile(zip_path, "r") as z:
        for fname in z.namelist():
            if fname.endswith(".xml") and "cwec" in fname:
                with z.open(fname) as source, xml_dest.open("wb") as target:
                    target.write(source.read())
                return xml_dest
    return None


def do_check():
    """Conditional GET against upstream: 304 means nothing to do."""
    print("=== Verificar novidades a montante (ETag / Last-Modified) ===")
    for key, info in SOURCES.items():
        dest = DATA_DIR / info["filename"]
        if not (dest.exists() and dest.stat().st_size > 0):
            print(f"  [MISSING] {key:16s} {info['description']}")
            continue
        res = fetch(key, info, force=False)
        mark = {"unchanged": "igual", "updated": "NOVO", "present": "igual"}.get(res["status"], res["status"])
        print(f"  [{mark:7s}] {key:16s} {info['filename']}")
    print("\nNada foi transferido. Use --update para trazer as novidades.")


def do_rollback(date: str):
    src = VERSION_DIR / date
    if not src.is_dir():
        print(f"ERRO: não existe versão arquivada em {src}", file=sys.stderr)
        return
    print(f"=== Repor versão {date} ===")
    for archived in sorted(src.iterdir()):
        if archived.is_file():
            shutil.copy2(archived, DATA_DIR / archived.name)
            print(f"  {archived.name}")
    print("Reposto. Regenera o snapshot: python scripts/export_canonical_graph.py")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="report upstream changes without downloading")
    ap.add_argument("--update", action="store_true", help="re-download and archive changed files")
    ap.add_argument("--rollback", metavar="YYYY-MM-DD", help="restore an archived version")
    args = ap.parse_args()

    if args.check:
        do_check()
        return
    if args.rollback:
        do_rollback(args.rollback)
        return

    print("=== Descarregar / atualizar datasets oficiais ===")
    for key, info in SOURCES.items():
        try:
            res = fetch(key, info, force=args.update)
            extra = f"  sha={res.get('sha256', '')[:12]}"
            if res.get("archived_to"):
                extra += f"  arquivado em {res['archived_to']}"
            print(f"  [{res['status']:10s}] {key:16s} {info['filename']}{extra}")
            if key == "cwe" and res["status"] in ("updated", "downloaded"):
                extract_cwe_zip(DATA_DIR / info["filename"])
        except Exception as e:
            print(f"  [erro      ] {key:16s} {e}", file=sys.stderr)

    print(f"\nFicheiros em {DATA_DIR}")
    print(f"Manifesto   {MANIFEST}")


if __name__ == "__main__":
    main()