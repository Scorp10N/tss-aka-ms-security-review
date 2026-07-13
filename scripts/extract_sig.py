import pefile, sys, struct, subprocess, os, tempfile

# NOTE: this extracts and prints the leaf certificate SUBJECT only — it does
# NOT cryptographically verify the signature (no digest recomputation, no
# chain validation). For real Authenticode verification (digest match +
# chain-to-root), use `osslsigncode verify <file>` instead, as gen_bom.py
# now does. This script is kept as a lightweight standalone inspector.

targets = sys.argv[1:]
for path in targets:
    name = os.path.basename(path)
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception as e:
        print(f"{name}: PARSE ERROR {e}")
        continue
    try:
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    except Exception as e:
        print(f"{name}: no security directory index ({e})")
        continue
    if dir_entry.VirtualAddress == 0 or dir_entry.Size == 0:
        print(f"{name}: NO EMBEDDED SIGNATURE (unsigned)")
        continue
    with open(path, 'rb') as f:
        f.seek(dir_entry.VirtualAddress)
        cert_table = f.read(dir_entry.Size)
    # WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2) bCertificate[]
    off = 0
    found = False
    while off + 8 <= len(cert_table):
        length, revision, certtype = struct.unpack_from('<IHH', cert_table, off)
        if length == 0:
            break
        der = cert_table[off+8: off+length]
        with tempfile.NamedTemporaryFile(suffix=".p7") as sf:
            sf.write(der)
            sf.flush()
            result = subprocess.run(['openssl', 'pkcs7', '-inform', 'DER', '-in', sf.name,
                                      '-print_certs', '-noout'],
                                     capture_output=True, text=True)
        subjects = [l for l in result.stdout.splitlines() if l.startswith('subject=')]
        print(f"{name}: cert blob present, certs found: {len(subjects)} (subject presence only, not verified)")
        for s in subjects:
            print(f"   {s}")
        found = True
        off += length
        off = (off + 7) & ~7  # 8-byte align
    if not found:
        print(f"{name}: security dir present but no cert parsed")
