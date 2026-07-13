import os, hashlib, json, struct, subprocess, sys
import pefile

ROOT = "extracted"
OUT_JSON = "bom.json"
OUT_CSV = "bom.csv"

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def pe_info(path):
    info = {"is_pe": False, "signed": False, "signer": None, "product_version": None, "company_name": None}
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return info
    info["is_pe"] = True
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                for entry in fi:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            d = {k.decode(errors="ignore"): v.decode(errors="ignore") for k, v in st.entries.items()}
                            info["product_version"] = d.get("ProductVersion") or info["product_version"]
                            info["company_name"] = d.get("CompanyName") or info["company_name"]
    except Exception:
        pass
    try:
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if dir_entry.VirtualAddress and dir_entry.Size:
            with open(path, "rb") as f:
                f.seek(dir_entry.VirtualAddress)
                cert_table = f.read(dir_entry.Size)
            length, revision, certtype = struct.unpack_from('<IHH', cert_table, 0)
            der = cert_table[8:length]
            tmp = "/tmp/_sig.p7"
            with open(tmp, "wb") as sf:
                sf.write(der)
            result = subprocess.run(['openssl', 'pkcs7', '-inform', 'DER', '-in', tmp, '-print_certs', '-noout'],
                                     capture_output=True, text=True)
            subjects = [l for l in result.stdout.splitlines() if l.startswith('subject=')]
            if subjects:
                info["signed"] = True
                info["signer"] = subjects[0].replace("subject=", "").strip()
    except Exception:
        pass
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
            row.update(pe_info(full))
        rows.append(row)

rows.sort(key=lambda r: r["path"])

with open(OUT_JSON, "w") as f:
    json.dump({"component": "TSS (TroubleShootingScript toolset)",
               "source_url": "https://aka.ms/gettss",
               "resolved_url": "https://download.microsoft.com/download/53c578ea-5649-4fdb-b949-0529ebb643ab/TSS.zip",
               "archive_sha256": sha256("TSS.zip"),
               "file_count": len(rows),
               "files": rows}, f, indent=2)

import csv
with open(OUT_CSV, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["path", "size_bytes", "sha256", "extension", "is_pe", "signed", "signer", "product_version", "company_name"])
    for r in rows:
        w.writerow([r["path"], r["size_bytes"], r["sha256"], r["extension"],
                    r.get("is_pe", ""), r.get("signed", ""), r.get("signer", ""),
                    r.get("product_version", ""), r.get("company_name", "")])

pe_rows = [r for r in rows if r.get("is_pe")]
signed = [r for r in pe_rows if r.get("signed")]
unsigned = [r for r in pe_rows if not r.get("signed")]
print(f"Total files: {len(rows)}")
print(f"PE binaries: {len(pe_rows)}  signed: {len(signed)}  unsigned: {len(unsigned)}")
if unsigned:
    print("Unsigned PE files:")
    for r in unsigned:
        print(f"  {r['path']}")
