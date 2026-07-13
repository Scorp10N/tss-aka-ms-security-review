import os, hashlib, json, subprocess, re

ROOT = "extracted"
OUT_JSON = "bom.json"
OUT_CSV = "bom.csv"

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def osslsigncode_info(path):
    """Real Authenticode verification via osslsigncode: confirms the embedded
    digest matches a freshly recomputed PE hash (proves the signed bytes are
    what's on disk), and separately reports whether the certificate chain
    verifies to a trusted root in the local trust store. Subject/issuer are
    parsed from the leaf signer block, not merely grepped from anywhere in
    the PKCS#7 blob."""
    info = {
        "is_pe": False,
        "signed": False,
        "digest_match": None,
        "chain_verified": None,
        "signer": None,
        "issuer": None,
    }
    result = subprocess.run(["osslsigncode", "verify", path], capture_output=True, text=True)
    out = result.stdout
    if "No signature found" in out or ("Subject:" not in out and "PE checksum" not in out):
        if "PE checksum" not in out and "Subject:" not in out and result.returncode not in (0, 1):
            return info  # not a PE osslsigncode could parse at all
    info["is_pe"] = "PE checksum" in out or "MSI" in out
    if not info["is_pe"]:
        return info

    digest_lines = re.findall(r"(?:Current|Calculated) message digest\s*:\s*([0-9A-Fa-f]+)", out)
    if len(digest_lines) >= 2:
        info["signed"] = True
        info["digest_match"] = (digest_lines[0].strip() == digest_lines[1].strip())

    m = re.search(r"Signer #0:\s*\n\s*Subject:\s*(.+)\n\s*Issuer\s*:\s*(.+)", out)
    if m:
        info["signer"] = m.group(1).strip()
        info["issuer"] = m.group(2).strip()

    if "Signature verification: ok" in out or "Signature verification: succeeded" in out:
        info["chain_verified"] = True
    elif "Signature verification: failed" in out:
        info["chain_verified"] = False

    return info

rows = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        full = os.path.join(dirpath, fn)
        rel = os.path.relpath(full, ROOT)
        size = os.path.getsize(full)
        digest = sha256(full)
        ext = os.path.splitext(fn)[1].lower()
        row = {"path": rel, "size_bytes": size, "sha256": digest, "extension": ext}
        if ext in (".exe", ".dll", ".sys", ".ocx"):
            row.update(osslsigncode_info(full))
        rows.append(row)

rows.sort(key=lambda r: r["path"])

with open(OUT_JSON, "w") as f:
    json.dump({
        "component": "TSS (TroubleShootingScript toolset)",
        "source_url": "https://aka.ms/gettss",
        "resolved_url": "https://download.microsoft.com/download/53c578ea-5649-4fdb-b949-0529ebb643ab/TSS.zip",
        "archive_sha256": sha256("TSS.zip"),
        "file_count": len(rows),
        "verification_method": "osslsigncode verify (PE digest recomputed and compared to embedded signed "
                                "digest = digest_match; full chain-to-root verification = chain_verified, "
                                "requires local Microsoft root CA trust store which was not configured, so "
                                "chain_verified is expected to read false/failed even for genuine binaries)",
        "files": rows,
    }, f, indent=2)

import csv
with open(OUT_CSV, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["path", "size_bytes", "sha256", "extension", "is_pe", "signed", "digest_match",
                "chain_verified", "signer", "issuer"])
    for r in rows:
        w.writerow([r["path"], r["size_bytes"], r["sha256"], r["extension"],
                    r.get("is_pe", ""), r.get("signed", ""), r.get("digest_match", ""),
                    r.get("chain_verified", ""), r.get("signer", ""), r.get("issuer", "")])

pe_rows = [r for r in rows if r.get("is_pe")]
signed = [r for r in pe_rows if r.get("signed")]
unsigned = [r for r in pe_rows if not r.get("signed")]
digest_ok = [r for r in signed if r.get("digest_match")]
digest_bad = [r for r in signed if r.get("digest_match") is False]

print(f"Total files: {len(rows)}")
print(f"PE binaries: {len(pe_rows)}  signed(has cert): {len(signed)}  unsigned: {len(unsigned)}")
print(f"Digest match (integrity confirmed): {len(digest_ok)}  digest MISMATCH: {len(digest_bad)}")
if unsigned:
    print("Unsigned PE files:")
    for r in unsigned:
        print(f"  {r['path']}")
if digest_bad:
    print("DIGEST MISMATCH (possible tampering) — investigate immediately:")
    for r in digest_bad:
        print(f"  {r['path']}")
