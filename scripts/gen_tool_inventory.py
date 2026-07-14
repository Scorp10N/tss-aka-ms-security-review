# Requires the extracted TSS.zip archive contents at ./extracted (not included in this
# repo — download from the URL in bom.json's resolved_url, verify against archive_sha256,
# and unzip to ./extracted before running).
import json, os, re

with open("bom.json") as f:
    bom = json.load(f)
pe = [r for r in bom["files"] if r.get("is_pe")]

# Case-insensitive discovery (os.walk + lower().endswith), not glob("*.ps1"), because
# a handful of bundled scripts use uppercase ".PS1" (e.g. scripts/KipG-Scripts/*.PS1)
# and a case-sensitive glob on a case-sensitive filesystem silently drops them. Check
# #4's independent critique caught this: an earlier version of this script searched
# and reported "695 scripts" while actually only reading 692.
script_files = []
for root, _dirs, files in os.walk("extracted"):
    for fn in files:
        if fn.lower().endswith((".ps1", ".psm1")):
            script_files.append(os.path.join(root, fn))

script_text = {}
for sf in script_files:
    with open(sf, "r", encoding="utf-8", errors="ignore") as fh:
        script_text[sf] = fh.readlines()

INVOCATION_MARKERS = (
    ".exe", ".dll", ".sys", "start-process", "-filepath", "cmd.exe", "& $", '& "',
    "join-path", "| out-file", "get-command", "run-diagexpression", "commandname",
    "test-path", "$global:", "$script:",
)

def is_comment(stripped):
    return stripped.startswith("#") or stripped.startswith("::") or stripped.startswith("<#")

def looks_like_encoded_blob(stripped):
    # long line, no whitespace, mostly base64-ish charset -> likely an obfuscated/encoded blob
    body = stripped.replace(" ", "")
    if len(body) < 60:
        return False
    non_b64 = sum(1 for c in body if not re.match(r"[A-Za-z0-9+/=]", c))
    return non_b64 / max(len(body), 1) < 0.05

def score(line, matched_word_boundary):
    stripped = line.strip()
    s = 0
    if matched_word_boundary:
        s += 3
    if not is_comment(stripped):
        s += 2
    if looks_like_encoded_blob(stripped):
        s -= 5
    low = stripped.lower()
    if any(m in low for m in INVOCATION_MARKERS):
        s += 2
    return s

def find_refs(basename_noext, max_refs=3):
    # Score EVERY substring match, not just the first N found — check #4's critique
    # found that an earlier version capped candidate collection at 40 *before*
    # scoring/sorting, so high-frequency basenames (du, tmq) never had their real
    # invocation line seen by the scorer at all if it happened to occur after the
    # 40th incidental substring hit. No cap here: collect all matches, then sort.
    sub_pat = re.compile(re.escape(basename_noext), re.IGNORECASE)
    wb_pat = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(basename_noext) + r"(?![A-Za-z0-9_])", re.IGNORECASE)
    candidates = []
    for sf, lines in script_text.items():
        rel = os.path.relpath(sf, "extracted")
        for i, line in enumerate(lines, 1):
            if sub_pat.search(line):
                wb = bool(wb_pat.search(line))
                candidates.append((score(line, wb), rel, i, line.strip()[:160]))
    # Secondary sort key (rel path, then line number) makes tie-breaking deterministic
    # regardless of os.walk()/dict traversal order, which Python does not guarantee
    # stable across filesystems or runs. Check #5's critique proved that without this,
    # 62 of 115 binaries' displayed evidence line could change under a different
    # (equally valid) traversal order, even though the underlying data was correct.
    candidates.sort(key=lambda c: (-c[0], c[1], c[2]))
    top = candidates[:max_refs]
    return [f"{rel}:{i}: {text}" for _, rel, i, text in top]

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
print(f"Scripts searched: {len(script_files)}")
print(f"Total PE: {len(rows)}  Referenced in TSS.ps1/psm1: {len(referenced)}  Not directly referenced by basename: {len(not_referenced)}")
print("\nNot referenced (may be invoked indirectly, via config data, or by other bundled tools):")
for r in not_referenced:
    print(f"  {r['path']}")
