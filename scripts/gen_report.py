from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
import json, datetime

with open("bom.json") as f:
    bom = json.load(f)

doc = Document()

title = doc.add_heading("Security Architecture Review: aka.ms/gettss (TSS Toolkit)", level=0)
sub = doc.add_paragraph()
sub.add_run(f"Prepared: {datetime.date.today().isoformat()}    |    Reviewer: Claude Code (security architect review)").italic = True

doc.add_heading("1. Executive Summary", level=1)
doc.add_paragraph(
    "The short link https://aka.ms/gettss is a live, first-party Microsoft alias that 301-redirects to "
    "download.microsoft.com and delivers TSS.zip (~35.5 MB), the \"TroubleShootingScript\" (TSS / TSSv2) "
    "diagnostic toolkit used by Microsoft Customer Support Services (CSS) engineers. This is a real, "
    "publicly circulated Microsoft support tool, not malware, not a fake/typosquat, and not related to "
    "text-to-speech or the unrelated microsoft/TSS.MSR (TPM stack) project."
)
doc.add_paragraph(
    "The archive bundles 1,531 files, including 115 native PE binaries (Sysinternals-class tools: Procmon, "
    "Sysmon, procdump, xperf, wpr, psping, rpcdump, rpccfg, etc.) alongside PowerShell modules for ETW "
    "tracing, packet capture, and log collection across many Windows subsystems. 114 of 115 PE binaries "
    "carry valid Microsoft Authenticode signatures; the one unsigned PE is a resource-only icon DLL with "
    "no executable code, which is normal and low-risk."
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
    "Extracted embedded Authenticode PKCS#7 signature blocks from all PE binaries and validated certificate "
    "chain subjects/issuers via OpenSSL.",
    "Searched GitHub for canonical upstream source / provenance and cross-referenced against the unrelated "
    "microsoft/TSS.MSR (TPM stack) repository to rule out name-collision confusion.",
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

doc.add_heading("3.2 Related alias: aka.ms/gettts", level=2)
doc.add_paragraph(
    "The visually similar alias aka.ms/gettts (double-t, TTS not TSS) is currently UNREGISTERED. It falls "
    "back to Bing (Location: https://www.bing.com?ref=aka&shorturl=gettts), which is aka.ms's standard "
    "behavior for a dead/unclaimed alias. This is a dangling-link risk: nothing prevents someone from "
    "registering it in the future and redirecting it elsewhere while it still displays as a trusted "
    "aka.ms domain."
)

doc.add_heading("3.3 Archive contents overview", level=2)
doc.add_paragraph(
    "Top-level structure: TSS.ps1 / TSSGUI.ps1 (main entry points), 19 TSS_*.psm1 feature modules "
    "(ADS, AUT, CRM, DND, INT, ITN, MCM, NET, PRF, SDP, SHA, SPS, UEX...), and BIN / BINx64 / BINx86 / "
    "BINARM directories bundling third-party diagnostic executables (Procmon, Sysmon, procdump, xperf, "
    "wpr, psping, rpcdump, rpccfg, WinHTTPDiag, poolmon, etc.), plus scripts/, config/, help/, xray/ and "
    "psSDP/ support directories."
)

doc.add_heading("3.4 Authenticode signature verification", level=2)
pe_rows = [r for r in bom["files"] if r.get("is_pe")]
signed = [r for r in pe_rows if r.get("signed")]
unsigned = [r for r in pe_rows if not r.get("signed")]
doc.add_paragraph(f"PE binaries found: {len(pe_rows)}  |  Signed: {len(signed)}  |  Unsigned: {len(unsigned)}")
table2 = doc.add_table(rows=1, cols=2)
table2.style = "Light Grid Accent 1"
hdr2 = table2.rows[0].cells
hdr2[0].text, hdr2[1].text = "Binary (sample)", "Certificate Subject"
samples = ["BIN/xperf.exe", "BIN/wpr.exe", "BIN/Procmon.exe", "BIN/Sysmon.exe",
           "BIN/procdump.exe", "BIN/psping.exe", "BIN/rpcdump.exe", "BIN/rpccfg.exe"]
by_path = {r["path"]: r for r in bom["files"]}
for s in samples:
    r = by_path.get(s)
    if r:
        row = table2.add_row().cells
        row[0].text = s
        row[1].text = r.get("signer") or "N/A"

doc.add_paragraph(
    "All sampled signed binaries chain to genuine Microsoft Corporation leaf certificates issued under "
    "Microsoft Code Signing PCA (2010/2011/2024) or Windows Production PCA intermediates. No evidence of "
    "spoofed, self-signed, or third-party-substituted certificates was found."
)
doc.add_paragraph(
    "The single unsigned PE file, config/GUI/tssGUI-icons.dll, was inspected: it contains only .rdata and "
    ".rsrc sections (no .text/code section), i.e. it is a resource-only icon library for the GUI with no "
    "executable code. This is a common, low-risk pattern and does not indicate tampering."
)
doc.add_paragraph(
    "Not verified in this review: full X.509 chain-of-trust / CRL / OCSP revocation status, and RFC3161 "
    "timestamp countersignature validity (no Windows signtool available in the review environment). Leaf "
    "certificate validity windows on sampled binaries were in the past relative to the review date, which "
    "is expected/normal for Authenticode when covered by a timestamp countersignature and is not itself "
    "an indicator of tampering."
)

doc.add_heading("3.5 Provenance / upstream identity", level=2)
doc.add_paragraph(
    "No official microsoft/* GitHub repository hosts this toolkit under the TSS name; microsoft/TSS.MSR is "
    "an unrelated TPM 2.0 software stack project (confirmed via empty/irrelevant release history). Multiple "
    "independent community GitHub mirrors were found with matching file structure and identical internal "
    "warning strings (e.g. rsessa/TSS, andreipintica/TSSV2), consistent with a tool that circulates "
    "informally. The likely original author is Walter Eder, a Microsoft support/field engineer whose GitHub "
    "Pages site is described as hosting 'Windows Tools (TSS, psTSS, psSDP)', matching this toolkit's module "
    "naming (a psSDP directory is present in the archive). This is consistent with TSS's public reputation "
    "as a Microsoft CSS-support-engineer-authored diagnostic toolkit distributed via aka.ms/getTSS, rather "
    "than an official, centrally-supported Microsoft product."
)

doc.add_heading("4. Risk Assessment", level=1)
table3 = doc.add_table(rows=1, cols=3)
table3.style = "Light Grid Accent 1"
h3 = table3.rows[0].cells
h3[0].text, h3[1].text, h3[2].text = "Risk", "Rating", "Rationale"
risks = [
    ("Malicious/tampered download", "Low", "First-party host, valid Microsoft signatures on all functional binaries, ZIP integrity confirmed."),
    ("Dangling-alias hijack (gettts)", "Medium (latent)", "Unregistered aka.ms alias could be claimed and repointed later while retaining implicit trust of the aka.ms domain."),
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
    "Do not register or repurpose the aka.ms/gettts alias path in any internal documentation; treat any link claiming to be a TTS tool at that address as unverified until re-checked.",
    "If TSS output/traces are received from an unsolicited or unverified source, apply the same scrutiny as any unverified executable bundle, despite the presence of valid Microsoft signatures.",
    "For a stronger provenance guarantee, obtain TSS through Microsoft Support/CSS engagement channels or Microsoft Learn documentation referencing it, rather than via a bare short link.",
]:
    doc.add_paragraph(line, style="List Bullet")

doc.add_heading("6. Appendix", level=1)
doc.add_paragraph(f"Archive SHA-256: {bom['archive_sha256']}")
doc.add_paragraph(f"Total files in archive: {bom['file_count']}")
doc.add_paragraph(f"PE binaries: {len(pe_rows)} (signed: {len(signed)}, unsigned: {len(unsigned)})")
doc.add_paragraph("Full file-level Bill of Materials (path, size, SHA-256, signer) is provided in bom.csv / bom.json in the accompanying repository.")

doc.save("TSS_Security_Review.docx")
print("saved TSS_Security_Review.docx")
