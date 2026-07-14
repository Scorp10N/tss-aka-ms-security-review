# Microsoft CA certificates for chain-to-root verification

These certificates close the "chain-to-root not verified" gap noted in earlier
versions of this report (section 3.3). They were fetched from the Authority
Information Access (AIA) "CA Issuers" URL embedded in the TSS binaries' own
certificates — not guessed or downloaded from a generic search — by extracting
each binary's PKCS#7 signature (`osslsigncode extract-signature`) and reading
the `CA Issuers` extension with `openssl x509 -text`.

## Provenance

| File | Subject | Fetched from (AIA URL in the child cert) |
|---|---|---|
| `MicRooCerAut_2010-06-23.pem` | Microsoft Root Certificate Authority 2010 (self-signed root) | `http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt` |
| `root2011.pem` | Microsoft Root Certificate Authority 2011 (self-signed root) | `http://www.microsoft.com/pki/certs/MicRooCerAut2011_2011_03_22.crt` |
| `intermed_codesign2010.pem` | Microsoft Code Signing PCA 2010 | `http://www.microsoft.com/pki/certs/MicCodSigPCA_2010-07-06.crt` |
| `intermed_codesign2011.pem` | Microsoft Code Signing PCA 2011 | `http://www.microsoft.com/pkiops/certs/MicCodSigPCA2011_2011-07-08.crt` |
| `intermed_codesign2024.pem` | Microsoft Code Signing PCA 2024 | `http://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt` |
| `intermed_winprod2011.pem` | Microsoft Windows Production PCA 2011 | `http://www.microsoft.com/pkiops/certs/MicWinProPCA2011_2011-10-19.crt` |

`ms_roots_ca.pem` = the two root certs concatenated (used as `osslsigncode verify -CAfile` and also `-TSA-CAfile`, since Microsoft's timestamp authority certificates chain to the same roots).
`ms_intermediates.pem` = the four intermediate (PCA) certs concatenated (used as `-untrusted`).

## Why `-TSA-CAfile` matters

Each binary's Authenticode signature carries an RFC3161 timestamp countersignature.
Without validating that countersignature's own certificate chain, `osslsigncode`
falls back to checking the leaf certificate's expiry against the *current* wall-clock
time — which fails for every binary here, since their code-signing certs expired
years ago (normal for old binaries; the timestamp is what's supposed to keep the
signature valid). Pointing `-TSA-CAfile` at these same roots lets `osslsigncode`
validate the timestamp and use its asserted signing time instead, which is the
semantically correct behavior for Authenticode.

## Reproducing

```
osslsigncode verify -CAfile ms-roots/ms_roots_ca.pem \
  -untrusted ms-roots/ms_intermediates.pem \
  -TSA-CAfile ms-roots/ms_roots_ca.pem \
  <path-to-binary>
```
