"""
Downloads official canonical cybersecurity ontologies from MITRE/CISA
and stores them in data/official/ for native decoupled domain stores.
"""

import os
import sys
import zipfile
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data" / "official"
DATA_DIR.mkdir(parents=True, exist_ok=True)

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
    }
}


def download_file(name: str, info: dict) -> Path:
    dest = DATA_DIR / info["filename"]
    if dest.exists() and dest.stat().st_size > 0:
        print(f"[{name.upper()}] Already downloaded: {dest.name} ({dest.stat().st_size / 1024 / 1024:.2f} MB)")
        return dest

    print(f"[{name.upper()}] Downloading {info['description']}...")
    req = urllib.request.Request(info["url"], headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as out:
        content = resp.read()
        out.write(content)
    
    print(f"[{name.upper()}] Downloaded: {dest.name} ({dest.stat().st_size / 1024 / 1024:.2f} MB)")
    return dest


def extract_cwe_zip(zip_path: Path):
    xml_dest = DATA_DIR / "cwec.xml"
    if xml_dest.exists() and xml_dest.stat().st_size > 0:
        return xml_dest
    
    print("[CWE] Extracting cwec.xml from zip...")
    with zipfile.ZipFile(zip_path, "r") as z:
        for fname in z.namelist():
            if fname.endswith(".xml") and "cwec" in fname:
                with z.open(fname) as source, open(xml_dest, "wb") as target:
                    target.write(source.read())
                print(f"[CWE] Extracted {xml_dest.name} ({xml_dest.stat().st_size / 1024 / 1024:.2f} MB)")
                return xml_dest
    return None


def main():
    print("=== Baixar Datasets Oficiais de Cibersegurança ===")
    for key, info in SOURCES.items():
        try:
            path = download_file(key, info)
            if key == "cwe" and path.name.endswith(".zip"):
                extract_cwe_zip(path)
        except Exception as e:
            print(f"ERRO ao descarregar {key}: {e}", file=sys.stderr)
            
    print("\nTodos os ficheiros estão em:", DATA_DIR)


if __name__ == "__main__":
    main()
