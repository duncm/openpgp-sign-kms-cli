# OpenPGP Sign with AWS KMS

Create GPG-compatible signatures without exporting your private key from AWS KMS.
Supports RSA and Ed25519 on Linux x86_64 and ARM64.

> Initial release preparation: binaries are published only after live AWS integration passes.

## Get started

You need an enabled KMS signing key and AWS credentials with `kms:DescribeKey`,
`kms:GetPublicKey`, and `kms:Sign`. [Create a key](docs/aws.md) if needed.

1. Download the archive for your architecture from [Releases](https://github.com/duncm/openpgp-sign-kms-cli/releases).
2. Verify its checksum against `SHA256SUMS`, extract it, and place `openpgp-sign-kms` on your PATH.
3. Configure AWS credentials using your usual profile, environment, or workload role.

```sh
export KEY_ARN='arn:aws:kms:REGION:ACCOUNT:key/KEY-ID'

# Export once, then distribute this certificate to verifiers.
openpgp-sign-kms --export -u "$KEY_ARN" --armor \
  --export-name 'Release signer' --export-email 'release@example.com' \
  --output public.asc

# Sign and verify a file.
openpgp-sign-kms --detach-sign -u "$KEY_ARN" artifact.tar.gz
gpg --import public.asc
gpg --verify artifact.tar.gz.sig artifact.tar.gz
```

Replace the ARN, identity, and input filename with your values.
A valid signature does not automatically establish trust in its identity.

## Choose an output

| Command | Output |
| --- | --- |
| `--sign file` | Attached signed message: `file.gpg` |
| `--detach-sign file` | Detached signature: `file.sig` |
| `--clear-sign file` | Readable signed text: `file.asc` |

Add `--armor` for ASCII output (`.asc`) or `--output PATH` to choose a filename.
An existing output is refused unless `--yes` is supplied.

## Sign Git commits and tags

```sh
export OPENPGP_SIGN_KMS_GPG=/usr/bin/gpg
git config gpg.format openpgp
git config gpg.openpgp.program /absolute/path/to/openpgp-sign-kms
git config user.signingkey "$KEY_ARN"
git commit -S -m 'Signed change'
git tag -s v1.0.0 -m 'Signed release'
git verify-commit HEAD
```

Verification is delegated to GPG, using its existing keyring and trust settings.
[Git and audit details](docs/git.md) · [Command reference](docs/cli.md)

## Use in GitHub Actions

Use the separate [OpenPGP signing action](https://github.com/duncm/openpgp-sign-kms).

## Further reading

- [AWS setup](docs/aws.md)
- [Compatibility and certificate identity](docs/cli.md)
- [Build and test](docs/contributing.md)
- [Release procedures](docs/releases.md)
