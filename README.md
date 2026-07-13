# Security Review: aka.ms/gettss

Security architecture review of the Microsoft short link `https://aka.ms/gettss`, which resolves to the **TSS
(TroubleShootingScript / TSSv2)** diagnostic toolkit used by Microsoft Customer Support Services (CSS)
engineers.

**Verdict:** a legitimate, Authenticode-signed first-party Microsoft distribution — a Microsoft
CSS-support-engineer-authored bundle of Sysinternals-class diagnostic and tracing tools (Procmon, Sysmon,
procdump, xperf, wpr, packet capture, RPC enumeration) wrapped in PowerShell modules for collecting
Windows troubleshooting data. Primary residual risk is *capability*: a bundled high-privilege
diagnostic/tracing kit is attractive for social-engineering abuse precisely because it's trusted and signed.

See [`TSS_Security_Review.docx`](TSS_Security_Review.docx) for the full report.

## Contents

- `TSS_Security_Review.docx` — full report: link resolution, archive contents, Authenticode verification,
  provenance research, risk assessment, and recommendations.
- `bom.json` / `bom.csv` — full file-level Bill of Materials for the 1,531-file archive: path, size,
  SHA-256, and (for PE binaries) signed status, **digest-match verification**, certificate signer/issuer.
- `scripts/gen_bom.py` — script used to generate the BOM (walks the extracted archive, hashes every file,
  and verifies each PE binary's Authenticode signature via `osslsigncode verify` — cryptographically
  recomputing the PE digest and comparing it to the embedded signed digest, not just checking for a
  certificate subject string).
- `scripts/gen_report.py` — script used to generate the DOCX report from `bom.json`.
- `scripts/extract_sig.py` — lightweight standalone leaf-certificate-subject inspector (does not verify
  the signature cryptographically; use `gen_bom.py`/`osslsigncode` for real verification).
- `tool_inventory.csv` / `tool_inventory_final.json` — complete per-binary inventory of all 115 PE files:
  purpose and, where found, the exact file:line in TSS's own PowerShell scripts that invokes it. Generated
  by `scripts/gen_tool_inventory.py` (grep-based evidence gathering across all 695 bundled `.ps1`/`.psm1`
  files) and `scripts/gen_tool_table.py` (merges evidence with hand-authored purpose descriptions). Also
  reproduced in full as section 7 of the DOCX report. See that section for caveats on false-positive
  matches (short names like `du`/`kd`/`SAN`) and on confidence level for less-documented internal tools.

## Key facts

| Property | Value |
|---|---|
| Short link | `https://aka.ms/gettss` |
| Resolves to | `https://download.microsoft.com/download/53c578ea-5649-4fdb-b949-0529ebb643ab/TSS.zip` |
| Archive size | 37,178,473 bytes (~35.5 MB) |
| Archive SHA-256 | see `bom.json` → `archive_sha256` |
| Files in archive | 1,531 |
| PE binaries | 115 (114 signed by Microsoft Corporation with digest verified — 0 mismatches; 1 unsigned resource-only icon DLL — no code) |

Chain-to-root / CRL / OCSP / timestamp-countersignature validation was not completed (no local Microsoft
root CA trust store or Windows `signtool` in the review environment) — see the report's §3.3 for what that
does and doesn't mean for the digest-match result.

## What is intentionally NOT included in this repo

The actual `TSS.zip` archive and its extracted binaries are **not republished here** — they are Microsoft's
and third-party (Sysinternals-class) redistributable tools under their own licensing terms. This repo
contains only the analysis artifacts (hashes, signatures, structure) needed to independently verify a
future download against what was reviewed here.
