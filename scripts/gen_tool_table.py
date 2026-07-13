import json, csv, sys
sys.path.insert(0, ".")
from tool_purposes import PURPOSES

inv = json.load(open("tool_inventory.json"))
bom = json.load(open("bom.json"))
by_path = {r["path"]: r for r in bom["files"]}

rows = []
for r in inv:
    path = r["path"]
    signed_row = by_path.get(path, {})
    rows.append({
        "path": path,
        "signed": signed_row.get("signed", False),
        "digest_match": signed_row.get("digest_match"),
        "purpose": PURPOSES[path],
        "invocation_evidence": r["refs"][0] if r["refs"] else "No direct reference found in bundled scripts (695 .ps1/.psm1 files searched)",
    })

rows.sort(key=lambda r: r["path"])

with open("tool_inventory_final.json", "w") as f:
    json.dump(rows, f, indent=2)

with open("tool_inventory.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["path", "signed", "digest_match", "purpose", "invocation_evidence"])
    for r in rows:
        w.writerow([r["path"], r["signed"], r["digest_match"], r["purpose"], r["invocation_evidence"]])

print(f"Wrote {len(rows)} rows to tool_inventory_final.json / tool_inventory.csv")
