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

INVOCATION_MARKERS = (
    ".exe", ".dll", ".sys", "start-process", "-filepath", "cmd.exe", "& $", '& "',
    "join-path", "| out-file", "get-command", "run-diagexpression", "commandname",
    "test-path",
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

def find_refs(basename_noext, max_refs=3, max_candidates=40):
    # substring pattern (broad net) and word-boundary pattern (high-confidence signal)
    sub_pat = re.compile(re.escape(basename_noext), re.IGNORECASE)
    wb_pat = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(basename_noext) + r"(?![A-Za-z0-9_])", re.IGNORECASE)
    candidates = []
    for sf, lines in script_text.items():
        rel = os.path.relpath(sf, "extracted")
        for i, line in enumerate(lines, 1):
            if sub_pat.search(line):
                wb = bool(wb_pat.search(line))
                candidates.append((score(line, wb), rel, i, line.strip()[:160]))
                if len(candidates) >= max_candidates:
                    break
        if len(candidates) >= max_candidates:
            break
    candidates.sort(key=lambda c: -c[0])
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
print(f"Total PE: {len(rows)}  Referenced in TSS.ps1/psm1: {len(referenced)}  Not directly referenced by basename: {len(not_referenced)}")
print("\nNot referenced (may be invoked indirectly, via config data, or by other bundled tools):")
for r in not_referenced:
    print(f"  {r['path']}")
