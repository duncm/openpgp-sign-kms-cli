# OpenPGP Sign with Cloud KMS

Create GPG-compatible signatures without exporting your private key from AWS KMS or Google Cloud KMS.
Supports RSA and Ed25519 on Linux x86_64 and ARM64 (glibc 2.35+, including Ubuntu 22.04/24.04).

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

## Google Cloud quick start

Use Application Default Credentials and an enabled, explicit key version.
[Create a key and grant access](docs/google-cloud.md) first.

```sh
gcloud auth application-default login
export KEY='projects/PROJECT/locations/us-central1/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/1'
openpgp-sign-kms --export -u "$KEY" --armor \
  --export-name 'Release signer' --export-email 'release@example.com' -o google-public.asc
openpgp-sign-kms -b -u "$KEY" artifact.tar.gz
gpg --import google-public.asc
gpg --verify artifact.tar.gz.sig artifact.tar.gz
```

Replace `PROJECT`, `RING`, `KEY`, the version, and input filename. The same Git setup
below works with `user.signingkey` set to `$KEY`.

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

Optional `OPENPGP_SIGN_KMS_GIT_METADATA=auto` adds commit/tag context to the provider’s audit logs.
Verification is delegated to GPG, using its existing keyring and trust settings.
[Git and audit details](docs/git.md) · [Command reference](docs/cli.md)

## Use in GitHub Actions

Use the separate [OpenPGP signing action](https://github.com/duncm/openpgp-sign-kms).

## Further reading

- [AWS setup](docs/aws.md) · [Google Cloud setup](docs/google-cloud.md)
- [Dedicated Google integration project](docs/google-integration.md)
- [Compatibility and certificate identity](docs/cli.md)
- [Build and test](docs/contributing.md)
- [Release procedures](docs/releases.md)
