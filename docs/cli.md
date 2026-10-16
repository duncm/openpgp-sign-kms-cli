# Command reference

## Signing and export

Use one input file, `-`, or omitted input for stdin. Stdin defaults to stdout.
Use `-o -` to select stdout explicitly. Named output is staged before publication;
input/output aliases and symlink output destinations are rejected.

| Option | Meaning |
| --- | --- |
| `-s`, `--sign` | Attached signed message |
| `-b`, `--detach-sign` | Detached signature |
| `--clear-sign`, `--clearsign` | Clear-signed text; always armored |
| `-u`, `--local-user ARN` | Concrete KMS key ARN, not an alias or email |
| `-a`, `--armor` | ASCII output |
| `-o`, `--output PATH` | Destination, or `-` for stdout |
| `--digest-algo SHA256/SHA384/SHA512` | RSA digest; Ed25519 requires SHA512 |
| `--yes`, `--no` | Allow/refuse overwriting; refusal is the default |
| `--batch`, `--no-tty` | Accepted; signing never prompts |
| `--quiet`, `--verbose` | Accepted compatibility flags; errors remain visible |
| `--status-fd N` | GPG status records on an inherited descriptor |
| `--git-metadata off/auto` | Optional Git audit fields; default off |
| `--description TEXT` | CloudTrail User-Agent annotation |
| `--export` | Export a public certificate, requiring name and email |
| `--export-name`, `--export-email`, `--export-comment` | Certificate identity |

Short flags may be combined (`-bsau ARN`), and `--` ends option parsing.
Clear signing takes precedence over sign/detach flags, as in GPG.
Unknown options, multiple input files, and multiple signing keys are errors.

## Certificate identity

The certificate is a v4 primary signing/certification key. Its timestamp is the
KMS key creation time rounded down to seconds. RSA uses SHA256 by default;
Ed25519 uses the legacy OpenPGP EdDSA encoding with SHA512.

Export creates a user-ID self-signature and requires one KMS signing operation.
Ordinary signing does not repeat this certification. Fingerprints stay stable
when re-exporting the same KMS key with the same public material and timestamp.
Retain the certificate you distribute. This is not an importer for existing
OpenPGP certificates; imported KMS keys and multi-region replicas may have
different OpenPGP identities. Subkeys and v6 output are not supported yet.

## Failure and compatibility behavior

The target verifiers are GnuPG 2.2 and 2.4. Attached messages are uncompressed.
Cleartext signing normalizes line endings and whitespace; it is not a reversible
encoding of arbitrary files. Use attached or detached signing for exact bytes.

The SDK permits up to three attempts per operation with a 60-second operation
timeout. A failed or timed-out request may already have used the key. Exactly-once
signing is not guaranteed. Local verification rejects malformed KMS signatures.

Status output must not share stdout with signature data. The process returns 2
on operation failure. Diagnostics go to stderr; `SIG_CREATED` is emitted only
after output completes. A status failure after publishing output still fails the
command, so callers must always check the exit status.

This executable does not provide encryption, keyring management, local private-key
signing, fingerprint lookup, or arbitrary GPG command compatibility.

## Google provider

`--local-user` also accepts an explicit Google CryptoKeyVersion resource name.
Google versions fix the digest algorithm; incompatible `--digest-algo` values fail.
Identity uses the version creation time, not its parent key creation time.
See [Google algorithms, credentials and identity](google-cloud.md).
