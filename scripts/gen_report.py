from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
import json, datetime

with open("bom.json") as f:
    bom = json.load(f)
with open("tool_inventory_final.json") as f:
    tool_rows = json.load(f)

doc = Document()

title = doc.add_heading("Security Architecture Review: aka.ms/gettss (TSS Toolkit)", level=0)
sub = doc.add_paragraph()
sub.add_run(f"Prepared: {datetime.date.today().isoformat()}    |    Reviewer: Claude Code (security architect review)").italic = True

doc.add_heading("1. Executive Summary", level=1)
doc.add_paragraph(
    "The short link https://aka.ms/gettss is a live, first-party Microsoft alias that 301-redirects to "
    "download.microsoft.com and delivers TSS.zip (~35.5 MB), the \"TroubleShootingScript\" (TSS / TSSv2) "
    "diagnostic toolkit used by Microsoft Customer Support Services (CSS) engineers. It is a real, publicly "
    "circulated Microsoft support tool: a curated bundle of Sysinternals-class tracing and diagnostic "
    "binaries (Procmon, Sysmon, procdump, xperf, wpr, packet capture, RPC enumeration) wrapped in "
    "PowerShell modules that CSS engineers and administrators run to collect Windows troubleshooting data "
    "for a support case."
)
doc.add_paragraph(
    "The archive bundles 1,531 files, including 115 native PE binaries (Sysinternals-class tools: Procmon, "
    "Sysmon, procdump, xperf, wpr, psping, rpcdump, rpccfg, etc.) alongside PowerShell modules for ETW "
    "tracing, packet capture, and log collection across many Windows subsystems. 114 of 115 PE binaries "
    "carry Microsoft Authenticode signatures; for all 114, the PE digest was cryptographically recomputed "
    "and confirmed to match the embedded signed digest (zero mismatches — no evidence of tampering). Of "
    "those 114, 113 chain-verify to a trusted public Microsoft root CA including the RFC3161 timestamp "
    "countersignature (see 3.3); one (SQLCheck.exe) is signed with Microsoft's internal-only corporate PKI "
    "rather than the public code-signing chain, so it cannot be chain-verified against a public root by "
    "design — its digest still matches, but this is flagged as a notable outlier (see 3.3.3). The one "
    "unsigned PE is a resource-only icon DLL with no executable code, which is normal and low-risk."
)
doc.add_paragraph(
    "Primary risk is CAPABILITY, not AUTHENTICITY: this is a legitimately signed, high-privilege diagnostic "
    "kit (kernel ETW tracing, process dumping, packet capture, RPC enumeration) that is attractive for abuse "
    "if delivered to a target under pretext (a 'living-off-the-land'-style social engineering vector), "
    "precisely because its binaries are trusted, first-party Microsoft signed executables unlikely to trip "
    "standard AV/EDR signature heuristics."
)

doc.add_heading("2. Scope and Method", level=1)
for line in [
    "Resolved the aka.ms/gettss short link and captured the full HTTP redirect chain.",
    "Downloaded the resolved archive directly from download.microsoft.com and computed its SHA-256.",
    "Extracted and enumerated all 1,531 files; computed SHA-256 for every file (full BOM, attached separately).",
    "Verified embedded Authenticode signatures on all 115 PE binaries via osslsigncode: recomputed each "
    "binary's PE digest and compared it to the digest embedded in the signature (proves the signed bytes "
    "match what's on disk) — not merely checking for the presence of a certificate subject string.",
    "Fetched Microsoft's root and intermediate CA certificates from the Authority Information Access (AIA) "
    "URLs embedded in the binaries' own certificates (not guessed), and re-ran verification with full "
    "chain-to-root validation plus RFC3161 timestamp-countersignature validation, closing the gap left by "
    "the initial digest-only pass (see ms-roots/README.md in the repository for exact provenance).",
]:
    doc.add_paragraph(line, style="List Bullet")

doc.add_heading("3. Findings", level=1)

doc.add_heading("3.1 Link resolution", level=2)
table = doc.add_table(rows=1, cols=2)
table.style = "Light Grid Accent 1"
hdr = table.rows[0].cells
hdr[0].text, hdr[1].text = "Property", "Value"
rows_311 = [
    ("Short link", "https://aka.ms/gettss"),
    ("HTTP status", "301 Moved Permanently"),
    ("Redirect target", bom["resolved_url"]),
    ("Redirect host", "download.microsoft.com (Microsoft-owned CDN, Kestrel/Azure)"),
    ("Archive size", "37,178,473 bytes (~35.5 MB)"),
    ("Archive SHA-256", bom["archive_sha256"]),
]
for k, v in rows_311:
    row = table.add_row().cells
    row[0].text, row[1].text = k, v

doc.add_heading("3.2 Archive contents overview", level=2)
doc.add_paragraph(
    "Top-level structure: TSS.ps1 / TSSGUI.ps1 (main entry points), 19 TSS_*.psm1 feature modules "
    "(ADS, AUT, CRM, DND, INT, ITN, MCM, NET, PRF, SDP, SHA, SPS, UEX...), and BIN / BINx64 / BINx86 / "
    "BINARM directories bundling third-party diagnostic executables (Procmon, Sysmon, procdump, xperf, "
    "wpr, psping, rpcdump, rpccfg, WinHTTPDiag, poolmon, etc.), plus scripts/, config/, help/, xray/ and "
    "psSDP/ support directories. A complete per-binary inventory of all 115 PE files — purpose and how "
    "each is invoked by TSS's PowerShell layer, with file:line evidence — is provided in section 7."
)

doc.add_heading("3.3 Authenticode signature verification", level=2)
pe_rows = [r for r in bom["files"] if r.get("is_pe")]
signed = [r for r in pe_rows if r.get("signed")]
unsigned = [r for r in pe_rows if not r.get("signed")]
digest_ok = [r for r in signed if r.get("digest_match")]
digest_bad = [r for r in signed if r.get("digest_match") is False]
chain_ok = [r for r in signed if r.get("chain_verified") is True]
chain_bad = [r for r in signed if r.get("chain_verified") is False]
doc.add_paragraph(
    f"PE binaries found: {len(pe_rows)}  |  Signed (certificate present): {len(signed)}  |  "
    f"Unsigned: {len(unsigned)}  |  Digest verified match: {len(digest_ok)}  |  Digest mismatch: {len(digest_bad)}  |  "
    f"Full chain-to-root verified: {len(chain_ok)}  |  Chain verification failed: {len(chain_bad)}"
)
doc.add_paragraph(
    "Verification method: osslsigncode verify was run against all 115 PE binaries. For each signed binary, "
    "this recomputes the Authenticode PE hash from the file's actual bytes (excluding the checksum and "
    "certificate table fields, per the Authenticode spec) and compares it to the digest embedded inside the "
    "PKCS#7 signature. A match cryptographically proves the file has not been altered since it was signed. "
    "This is a materially stronger check than earlier tooling in this review's history that only confirmed "
    "a certificate subject string was present in the signature blob without verifying the digest — that "
    "weaker method has been superseded."
)
table2 = doc.add_table(rows=1, cols=4)
table2.style = "Light Grid Accent 1"
hdr2 = table2.rows[0].cells
hdr2[0].text, hdr2[1].text, hdr2[2].text, hdr2[3].text = "Binary (sample)", "Certificate Subject", "Digest Match", "Chain Verified"
samples = ["BIN/xperf.exe", "BIN/wpr.exe", "BIN/Procmon.exe", "BIN/Sysmon.exe",
           "BIN/procdump.exe", "BIN/psping.exe", "BIN/rpcdump.exe", "BIN/rpccfg.exe"]
by_path = {r["path"]: r for r in bom["files"]}
for s in samples:
    r = by_path.get(s)
    if r:
        row = table2.add_row().cells
        row[0].text = s
        row[1].text = r.get("signer") or "N/A"
        row[2].text = "Yes" if r.get("digest_match") else str(r.get("digest_match"))
        row[3].text = "Yes" if r.get("chain_verified") else str(r.get("chain_verified"))

doc.add_paragraph(
    f"All {len(signed)} signed binaries carry Microsoft Corporation leaf certificates, and all "
    f"{len(digest_ok)} of them passed digest verification (0 mismatches). No evidence of tampering, "
    "spoofed, self-signed, or third-party-substituted certificates was found."
)
doc.add_paragraph(
    "Chain-to-root validation was initially deferred because the local OpenSSL trust store did not include "
    "Microsoft's code-signing root CAs. This gap has since been closed: the exact root and intermediate "
    "(PCA) certificates were identified from the Authority Information Access (AIA) 'CA Issuers' URL "
    "embedded in the binaries' own certificates (not guessed or fetched from an unrelated source), and "
    "verification was re-run with the full chain plus the RFC3161 timestamp countersignature validated "
    f"against those same roots (Microsoft's own timestamp authority chains to them). Result: {len(chain_ok)} "
    f"of {len(signed)} signed binaries pass full chain-to-root verification against a trusted public "
    f"Microsoft root. The remaining {len(chain_bad)} (SQLCheck.exe) is signed with a different, "
    "internal-only Microsoft PKI chain that cannot be verified against a public root by design — see "
    "3.3.3. Provenance of each certificate (exact AIA URL, subject) is recorded in ms-roots/README.md in "
    "the accompanying repository, and the certificates themselves (ms-roots/*.pem) are included so this "
    "is independently re-checkable without re-fetching from Microsoft."
)
doc.add_heading("3.3.1 Unsigned PE finding", level=3)
table_unsigned = doc.add_table(rows=1, cols=4)
table_unsigned.style = "Light Grid Accent 1"
hu = table_unsigned.rows[0].cells
hu[0].text, hu[1].text, hu[2].text, hu[3].text = "Path", "Signed", "PE Sections", "Assessment"
unsigned_row = by_path.get("config/GUI/tssGUI-icons.dll")
ru = table_unsigned.add_row().cells
ru[0].text = "config/GUI/tssGUI-icons.dll"
ru[1].text = "No"
ru[2].text = ".rdata, .rsrc (no .text/code section)"
ru[3].text = "Resource-only icon library for the TSSGUI front-end; contains no executable code. " \
             "Unsigned status is expected/normal for this file type and is not an indicator of tampering."
if unsigned_row:
    ru2 = table_unsigned.add_row().cells
    ru2[0].text = "SHA-256"
    ru2[1].text = ""
    ru2[2].text = ""
    ru2[3].text = unsigned_row["sha256"]
doc.add_paragraph(
    "This is the only unsigned PE binary out of 115 found in the archive (114/115 signed). It was manually "
    "inspected and contains only .rdata and .rsrc sections — no .text/code section — confirming it is a "
    "resource-only icon library for the GUI, not a functional executable or DLL. This is a common, "
    "low-risk pattern and does not indicate tampering."
)
doc.add_paragraph(
    "Leaf certificate validity windows on sampled binaries are in the past relative to the review date — "
    "expected/normal for Authenticode, since the RFC3161 timestamp countersignature (independently validated "
    "as part of the chain-to-root verification in 3.3, not merely assumed) is what keeps the signature valid "
    "past the leaf certificate's own expiry, and is not itself an indicator of tampering. CRL revocation "
    "checking was also performed live: osslsigncode connected to Microsoft's actual CRL distribution points "
    "(e.g. crl.microsoft.com) over the network during verification and reported 'CRL verification: ok' for "
    "the sampled binaries, meaning none of the checked certificates have been revoked. OCSP was not "
    "separately checked (osslsigncode's revocation checking here is CRL-based, not OCSP-based)."
)

doc.add_heading("3.3.2 Weak-link analysis: could the unsigned DLL compromise the solution?", level=3)
doc.add_paragraph(
    "Question examined: since config/GUI/tssGUI-icons.dll is the one unsigned PE in the archive, could it "
    "serve as the weakest link and lead to compromise of the broader toolkit? Verified against the actual "
    "call site in TSSGUI.ps1 rather than the file's properties alone."
)
doc.add_paragraph(
    "TSSGUI.ps1 loads the file exclusively via a P/Invoke call to Shell32!ExtractIconEx (line ~230-249): "
    "[System.IconExtractor]::Extract(\"$tssGuiPath\\config\\GUI\\tssGUI-icons.dll\", $i, $true). This is the "
    "same Win32 API Windows Explorer uses to render file-type icons for arbitrary, untrusted files. It loads "
    "the target strictly as an image resource (LOAD_LIBRARY_AS_IMAGE_RESOURCE semantics) and does not invoke "
    "DllMain or execute any code the file might contain — consistent with the file having no .text "
    "section to execute in the first place. The path is also hardcoded/explicit rather than resolved via "
    "DLL search order, so classic DLL search-order hijacking does not apply."
)
table_weak = doc.add_table(rows=1, cols=2)
table_weak.style = "Light Grid Accent 1"
hw = table_weak.rows[0].cells
hw[0].text, hw[1].text = "Angle", "Verdict"
weak_rows = [
    ("Code execution via current call site", "No — icon extraction does not execute module code by design; this is why icon previews are considered safe for untrusted files."),
    ("Integrity / tamper-detection", "Yes, this is the real gap: it is the only file in the archive where Authenticode/WDAC give no cryptographic assurance the bytes are unmodified. Every other binary would fail signature validation if swapped; this one would not."),
    ("Resource-parser exploitation", "Narrow, non-zero, OS-side surface: Windows icon/cursor resource parsers have had historical memory-corruption CVEs (e.g., animated-cursor-class bugs). A maliciously crafted icon resource could theoretically exploit an unpatched parser bug, independent of the DLL's own code."),
    ("Future-proofing / design fragility", "If a future version or a different script loads this same filename via a normal LoadLibrary/Add-Type instead of ExtractIconEx, any embedded code would then execute. No current code path does this, but an unsigned file in the tree is one careless change away from becoming a real execution path."),
    ("AppLocker/WDAC bypass angle", "Most signed-binary allow-list policies enforce on EXE launch, not DLL load, by default (DLL rule enforcement is off by default for performance reasons). This DLL would load without friction even under a signed-only policy — not because of exploitation, but because the control does not inspect it."),
]
for a, b in weak_rows:
    row = table_weak.add_row().cells
    row[0].text, row[1].text = a, b
doc.add_paragraph(
    "Conclusion: not a live path to full-solution compromise today, given its actual usage is resource-only "
    "icon extraction. It is correctly identified as the single point in the archive with no cryptographic "
    "tamper-evidence, and should be treated as the artifact to re-verify by hash (SHA-256 recorded in the "
    "BOM) on any future download, rather than as an active code-execution risk under the current call site."
)

doc.add_heading("3.3.3 SQLCheck.exe: internal-only Microsoft certificate", level=3)
doc.add_paragraph(
    "One binary, BIN/SQLCheck.exe, is a notable outlier among the 114 signed PE files. Its digest matches "
    "(no tampering), but its certificate chain is entirely different from every other signed binary in the "
    "archive:"
)
sql_row = by_path.get("BIN/SQLCheck.exe", {})
table_sql = doc.add_table(rows=1, cols=2)
table_sql.style = "Light Grid Accent 1"
hs = table_sql.rows[0].cells
hs[0].text, hs[1].text = "Property", "Value"
sql_facts = [
    ("Leaf certificate subject", sql_row.get("signer") or "CN=Microsoft Corporation (Internal Use Only), O=Microsoft Corporation, L=Redmond, ST=Washington, C=US"),
    ("Issuer", sql_row.get("issuer") or "CN=MSIT CA Z1"),
    ("Root", "CN=Microsoft Internal Corporate Root (not a public root — not present in ms-roots/, not published outside Microsoft's internal network)"),
    ("Digest match", "Yes — file integrity confirmed, no tampering"),
    ("Chain-to-root verified", "No — cannot be, by design: the issuing root is Microsoft's internal corporate PKI, never published for external validation"),
]
for k, v in sql_facts:
    row = table_sql.add_row().cells
    row[0].text, row[1].text = k, v
doc.add_paragraph(
    "Every other signed binary in the archive (113 of 114) is signed under Microsoft's public code-signing "
    "PKI (Code Signing PCA 2010/2011/2024 or Windows Production PCA 2011), the same infrastructure used to "
    "sign publicly-distributed Windows components and Sysinternals tools. SQLCheck.exe instead carries a "
    "certificate whose own Common Name is literally 'Microsoft Corporation (Internal Use Only)', issued by "
    "an internal certificate authority ('MSIT CA Z1') that chains to Microsoft's internal corporate root, "
    "not a public one. This was only discovered because an independent code-review pass (see "
    ".devils-advocate/ check #6 in the accompanying repository) caught a parsing bug in an earlier version "
    "of this verification script that was silently misreporting this binary's chain status as verified; "
    "fixing that parsing bug surfaced this finding."
)
doc.add_paragraph(
    "Assessment: most likely an internal Microsoft support/build tool that was bundled into this "
    "publicly-distributed diagnostic toolkit without being re-signed under the public code-signing "
    "pipeline used for the rest of the archive — an operational-hygiene lapse rather than evidence of "
    "tampering (the digest still matches its own signature). It is not independently verifiable against a "
    "public trust root by any third party, which is a meaningfully different assurance level than the "
    "other 113 signed binaries in this archive, and is worth being aware of if this specific binary is "
    "relied upon."
)

doc.add_heading("4. Risk Assessment", level=1)
table3 = doc.add_table(rows=1, cols=3)
table3.style = "Light Grid Accent 1"
h3 = table3.rows[0].cells
h3[0].text, h3[1].text, h3[2].text = "Risk", "Rating", "Rationale"
risks = [
    ("Malicious/tampered download", "Low", "First-party host, valid Microsoft signatures on all functional binaries, ZIP integrity confirmed."),
    ("Capability abuse if misdelivered", "Medium-High (contextual)", "Bundles kernel ETW tracing, process dumping, and packet capture tools; valuable to an attacker via pretext/social engineering precisely because binaries are trusted and signed."),
    ("Supply-chain provenance", "Low-Medium", "No single canonical public source repo identified; distribution relies on community mirrors and an internal Microsoft alias rather than a versioned, auditable release channel."),
]
for a, b, c in risks:
    row = table3.add_row().cells
    row[0].text, row[1].text, row[2].text = a, b, c

doc.add_heading("5. Recommendations", level=1)
for line in [
    "Restrict deployment/execution of the TSS toolkit to authorized admin/support workstations under change control; treat it as a high-privilege diagnostic kit, not a general utility.",
    "Pin and verify the archive SHA-256 (recorded in this report and the accompanying BOM) for any future re-download, rather than trusting the aka.ms redirect blindly each time.",
    "If TSS output/traces are received from an unsolicited or unverified source, apply the same scrutiny as any unverified executable bundle, despite the presence of valid Microsoft signatures.",
    "For a stronger provenance guarantee, obtain TSS through Microsoft Support/CSS engagement channels or Microsoft Learn documentation referencing it, rather than via a bare short link.",
]:
    doc.add_paragraph(line, style="List Bullet")

doc.add_heading("6. Appendix", level=1)
doc.add_paragraph(f"Archive SHA-256: {bom['archive_sha256']}")
doc.add_paragraph(f"Total files in archive: {bom['file_count']}")
doc.add_paragraph(f"PE binaries: {len(pe_rows)} (signed: {len(signed)}, unsigned: {len(unsigned)})")
doc.add_paragraph("Full file-level Bill of Materials (path, size, SHA-256, signer) is provided in bom.csv / bom.json in the accompanying repository.")

doc.add_heading("7. Bundled Tool Inventory (complete, all 115 PE binaries)", level=1)
doc.add_paragraph(
    "This is a complete, per-binary inventory of every PE file in the archive: what it is, and where/how "
    "TSS's own PowerShell layer invokes it. Evidence was gathered by searching all 695 .ps1/.psm1 files in "
    "the archive (not just the 19 top-level TSS_*.psm1 modules) for each binary's filename, scoring "
    "candidate matches (word-boundary match, non-comment line, presence of invocation syntax such as "
    "Start-Process/.exe/cmd.exe) and citing the highest-scoring lines found — not simply the first matches "
    "encountered. Important caveats:"
)
for line in [
    "An earlier version of this table selected the first 1-3 substring matches per binary without this "
    "scoring, which produced a false NEGATIVE for handle.exe (the first matches found were unrelated GUI "
    "comments, so a genuinely-invoked tool was reported as unconfirmed) and misleading evidence lines for "
    "Pstat.exe/latte.exe (a substring match inside an unrelated word — \"pStat\" inside \"HttpStatusCode\", "
    "\"latte\" inside \"latter\" — was cited as if it were the real invocation). That fix (check #3) turned "
    "out to be incomplete: it corrected the specific entries found but not the root cause, which was that "
    "candidate collection was capped at 40 matches *before* scoring — so any basename common enough to "
    "produce more than 40 incidental substring hits (e.g. \"du\", \"tmq\") could still have its real, active "
    "invocation line invisible to the scorer, and in both cases the entry was then wrongly written up as a "
    "confirmed false positive. Independent critique (check #4) caught this. The cap has since been removed "
    "entirely — every substring match across all 695 scripts is now scored, not just the first 40 — and the "
    "du.exe, tmq.exe, and cdb.exe purpose descriptions below have been corrected to their actual (active, "
    "confirmed) invocations. Full history in this repository's .devils-advocate/ directory.",
    "Automated substring matching can still produce false positives on short/common names (e.g. \"kd\" "
    "colliding with \"kdbgctrl\"/\"chkdsk\"). Those remaining cases are explicitly flagged below as "
    "unconfirmed rather than presented as verified instrumentation. Two entries (SAN.exe, cdb.exe) needed a "
    "manually-verified evidence override because the automated scorer ties a genuine reference against "
    "unrelated same-word collisions or an adjacent comment-fragment sibling line — SAN.exe's real reference "
    "additionally sits inside a commented-out ('dead') code block rather than the active execution path, "
    "which is called out explicitly rather than treated as either a clean confirmation or a false positive.",
    "\"Purpose\" descriptions for well-known public Microsoft/Sysinternals/WDK tools (Procmon, Sysmon, "
    "procdump, PsPing, AccessChk, etc.) draw on their established public documentation. For TSS-internal or "
    "less-documented tools, purpose is stated only as far as the script context found actually supports — "
    "entries marked \"not independently confirmed\" are inference from naming/bundling convention, not "
    "verified fact.",
]:
    doc.add_paragraph(line, style="List Bullet")

tool_table = doc.add_table(rows=1, cols=4)
tool_table.style = "Light Grid Accent 1"
th = tool_table.rows[0].cells
th[0].text, th[1].text, th[2].text, th[3].text = "Path", "Signed / Digest OK", "Purpose", "Invocation evidence (file:line)"
for r in tool_rows:
    row = tool_table.add_row().cells
    row[0].text = r["path"]
    if r["signed"] is True and r["digest_match"] is True:
        sig_status = "Yes / Yes"
    elif r["signed"] is True and r["digest_match"] is False:
        sig_status = "Yes / MISMATCH"
    elif r["signed"] is False:
        sig_status = "No (unsigned)"
    else:
        sig_status = "N/A"
    row[1].text = sig_status
    row[2].text = r["purpose"]
    row[3].text = r["invocation_evidence"]

doc.add_heading("8. Official References", level=1)
doc.add_paragraph(
    "Sources for further reading and authoritative usage guidance on TSS, limited to official/first-party "
    "Microsoft sources — no third-party or community mirrors:"
)
for line in [
    "TSS's own built-in help — the most authoritative and complete source: run \".\\TSS.ps1 -Help\" or "
    "\"Get-Help .\\TSS.ps1 -full\" after extracting the archive, or \".\\TSS.ps1 -Search <keyword>\" for "
    "topic-specific guidance. This is what was used during this review to understand TSS's own scenarios "
    "and switches.",
    "TSSGUI.ps1 — the bundled GUI front-end, for browsing available scenarios/switches interactively.",
    "https://aka.ms/TssInfo — Microsoft's own \"Introduction to TroubleShootingScript toolset\" landing "
    "page, referenced directly in TSSGUI.ps1's own help-link table.",
    "The help/ directory inside the extracted archive.",
    "https://aka.ms/gettss — the official Microsoft distribution short link for the toolkit itself "
    "(analyzed in section 3.1 of this report).",
]:
    doc.add_paragraph(line, style="List Bullet")

doc.save("TSS_Security_Review.docx")
print("saved TSS_Security_Review.docx")
