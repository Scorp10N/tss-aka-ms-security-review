# Security Review: aka.ms/gettss

Security architecture review of the Microsoft short link `https://aka.ms/gettss`, which resolves to the **TSS
(TroubleShootingScript / TSSv2)** diagnostic toolkit used by Microsoft Customer Support Services (CSS)
engineers.

**Verdict:** legitimate, Authenticode-signed first-party Microsoft distribution. Not malware, not a
typosquat, not related to text-to-speech or the unrelated `microsoft/TSS.MSR` (TPM stack) project. Primary
residual risk is *capability* (a bundled high-privilege diagnostic/tracing kit is attractive for social
engineering abuse), not authenticity.

See [`TSS_Security_Review.docx`](TSS_Security_Review.docx) for the full report.

## Contents

- `TSS_Security_Review.docx` — full report: link resolution, archive contents, Authenticode verification,
  provenance research, risk assessment, and recommendations.
- `bom.json` / `bom.csv` — full file-level Bill of Materials for the 1,531-file archive: path, size,
  SHA-256, and (for PE binaries) signed status, certificate signer, product version.
- `scripts/gen_bom.py` — script used to generate the BOM (walks the extracted archive, hashes every file,
  extracts embedded Authenticode PKCS#7 signatures via `pefile` + `openssl`).
- `scripts/gen_report.py` — script used to generate the DOCX report from `bom.json`.
- `scripts/extract_sig.py` — standalone Authenticode signature extraction/inspection utility.

## Key facts

| Property | Value |
|---|---|
| Short link | `https://aka.ms/gettss` |
| Resolves to | `https://download.microsoft.com/download/53c578ea-5649-4fdb-b949-0529ebb643ab/TSS.zip` |
| Archive size | 37,178,473 bytes (~35.5 MB) |
| Archive SHA-256 | see `bom.json` → `archive_sha256` |
| Files in archive | 1,531 |
| PE binaries | 115 (114 signed by Microsoft Corporation, 1 unsigned resource-only icon DLL — no code) |

## Note on the similar alias `aka.ms/gettts`

`aka.ms/gettts` (double-T, TTS not TSS) is **currently unregistered** and falls back to Bing
(`aka.ms`'s standard dead-alias behavior). This is a latent dangling-link risk: nothing prevents future
registration and repointing while the domain still reads as trusted `aka.ms`.

## What is intentionally NOT included in this repo

The actual `TSS.zip` archive and its extracted binaries are **not republished here** — they are Microsoft's
and third-party (Sysinternals-class) redistributable tools under their own licensing terms. This repo
contains only the analysis artifacts (hashes, signatures, structure) needed to independently verify a
future download against what was reviewed here.
