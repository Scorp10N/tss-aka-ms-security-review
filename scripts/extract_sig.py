import pefile, sys, struct, subprocess, os

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
        sig_path = f"/tmp/claude-1000/-home-yarin-Projects/8eb9bcaa-a105-4e06-a715-4bb256cf86c4/scratchpad/tss/{name}.p7"
        with open(sig_path, 'wb') as sf:
            sf.write(der)
        result = subprocess.run(['openssl','pkcs7','-inform','DER','-in',sig_path,'-print_certs','-noout'],
                                 capture_output=True, text=True)
        subjects = [l for l in result.stdout.splitlines() if l.startswith('subject=')]
        print(f"{name}: SIGNED, certs found: {len(subjects)}")
        for s in subjects:
            print(f"   {s}")
        found = True
        off += length
        off = (off + 7) & ~7  # 8-byte align
    if not found:
        print(f"{name}: security dir present but no cert parsed")
