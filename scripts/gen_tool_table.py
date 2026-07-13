import json, csv, sys
sys.path.insert(0, ".")
from tool_purposes import PURPOSES

# Manual overrides for cases where the automated scorer still can't surface the
# correct line — typically because the basename is an extremely common English
# substring (e.g. "SAN" also matches "instance", "constant", etc.) so the
# candidate cap fills with noise before reaching the real reference. Verified
# by direct manual grep; see the corresponding purpose text for the citation.
MANUAL_EVIDENCE_OVERRIDES = {
    "psSDP/Diag/global/SAN.exe": (
        "DC_SanStorageInfo.ps1:16: $CommandToExecute = \"cmd.exe /c SAN.exe $CommandToAdd\" "
        "[inside a commented-out <# ... #> block under '#region Old Code' — legacy/dead code, "
        "not the active execution path; automated scorer could not surface this line because "
        "\"SAN\" is too common a substring across the 695 scripts for the 40-candidate cap to "
        "reach it — manually verified instead]"
    ),
}

inv = json.load(open("tool_inventory.json"))
bom = json.load(open("bom.json"))
by_path = {r["path"]: r for r in bom["files"]}

rows = []
for r in inv:
    path = r["path"]
    signed_row = by_path.get(path, {})
    if path in MANUAL_EVIDENCE_OVERRIDES:
        evidence = MANUAL_EVIDENCE_OVERRIDES[path]
    elif r["refs"]:
        evidence = r["refs"][0]
    else:
        evidence = "No direct reference found in bundled scripts (695 .ps1/.psm1 files searched)"
    rows.append({
        "path": path,
        "signed": signed_row.get("signed", False),
        "digest_match": signed_row.get("digest_match"),
        "purpose": PURPOSES[path],
        "invocation_evidence": evidence,
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
