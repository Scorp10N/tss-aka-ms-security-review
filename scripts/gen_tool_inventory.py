# Requires the extracted TSS.zip archive contents at ./extracted (not included in this
# repo — download from the URL in bom.json's resolved_url, verify against archive_sha256,
# and unzip to ./extracted before running).
import json, os, re, glob

with open("bom.json") as f:
    bom = json.load(f)
pe = [r for r in bom["files"] if r.get("is_pe")]

script_files = glob.glob("extracted/**/*.ps1", recursive=True) + glob.glob("extracted/**/*.psm1", recursive=True)
script_text = {}
for sf in script_files:
    with open(sf, "r", encoding="utf-8", errors="ignore") as fh:
        script_text[sf] = fh.readlines()

def find_refs(basename_noext, max_refs=3):
    pat = re.compile(re.escape(basename_noext), re.IGNORECASE)
    refs = []
    for sf, lines in script_text.items():
        rel = os.path.relpath(sf, "extracted")
        for i, line in enumerate(lines, 1):
            if pat.search(line):
                refs.append(f"{rel}:{i}: {line.strip()[:160]}")
                if len(refs) >= max_refs:
                    return refs
    return refs

rows = []
for r in pe:
    path = r["path"]
    base = os.path.basename(path)
    noext = os.path.splitext(base)[0]
    refs = find_refs(noext)
    rows.append({"path": path, "basename": base, "refs": refs, "sha256": r["sha256"]})

with open("tool_inventory.json", "w") as f:
    json.dump(rows, f, indent=2)

referenced = [r for r in rows if r["refs"]]
not_referenced = [r for r in rows if not r["refs"]]
print(f"Total PE: {len(rows)}  Referenced in TSS.ps1/psm1: {len(referenced)}  Not directly referenced by basename: {len(not_referenced)}")
print("\nNot referenced (may be invoked indirectly, via config data, or by other bundled tools):")
for r in not_referenced:
    print(f"  {r['path']}")
