import json, csv, sys
sys.path.insert(0, ".")
from tool_purposes import PURPOSES

# Manual overrides for cases where the automated scorer's top-ranked candidate is
# still not the most informative line to show — e.g. a genuine reference to the
# binary ties in score against unrelated same-word collisions (SAN.exe: the real
# "SAN.exe" reference ties against "san" the DiskPart command and "SAN" the X.509
# Subject Alternative Name field), or the tie-break happens to land on a
# comment-fragment sibling line rather than the clean active-code line right next
# to it (cdb.exe: line 53 is a commented-out remnant, line 54 immediately below it
# is the real active reference). Verified by direct manual grep; see the
# corresponding purpose text for the citation.
MANUAL_EVIDENCE_OVERRIDES = {
    "psSDP/Diag/global/SAN.exe": (
        "DC_SanStorageInfo.ps1:16: $CommandToExecute = \"cmd.exe /c SAN.exe $CommandToAdd\" "
        "[inside a commented-out <# ... #> block under '#region Old Code' — legacy/dead code, "
        "not the active execution path; the automated scorer ranks this line no higher than "
        "unrelated same-word collisions elsewhere (the DiskPart \"san\" command, the X.509 "
        "\"SAN\" field) — manually verified and selected instead]"
    ),
    "psSDP/Diag/global/cdb.exe": (
        "TS_DumpCollector.ps1:54: $ScriptArguments += \"/cdbpath:$Global:ToolsPath\\cdb.exe /debuginfo\" "
        "[active code, passed as a debug-info-collection argument; the automated scorer ties this "
        "line with the commented-out remnant immediately above it (line 53) and the stable sort "
        "displays the comment fragment first — manually selected the active line instead]"
    ),
    "BIN/handle.exe": (
        "TSS_SHA.psm1:1295: \"$global:ScriptFolder\\BIN\\handle.exe -a /AcceptEula | Out-File "
        "${LogFolder}\\${Env:COMPUTERNAME}_handle.txt\" "
        "[the actual invocation; ties in score with TSS_SHA.psm1:1292 ($LogFolder=...\\handle, a "
        "log-folder path string that happens to also match \"handle\" but isn't an invocation) — "
        "manually selected the real invocation line instead]"
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
