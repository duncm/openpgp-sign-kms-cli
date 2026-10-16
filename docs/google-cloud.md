# Google Cloud KMS

The CLI uses Application Default Credentials (ADC) and an explicit key version.
For this project's test infrastructure, use the separate
[integration project guide](google-integration.md).

## Create a signing key

Authenticate as an administrator and replace the project and identity placeholders.
These commands create a software-backed RSA-3072 key with one enabled version.
Production keys should retain a suitable recovery window; the 24-hour test setting
is deliberately absent here.

```sh
export PROJECT_ID='YOUR_PROJECT_ID'
export LOCATION='us-central1'
gcloud auth login
gcloud services enable cloudkms.googleapis.com --project="$PROJECT_ID"
gcloud kms keyrings create signing --project="$PROJECT_ID" --location="$LOCATION"
gcloud kms keys create releases --project="$PROJECT_ID" --location="$LOCATION" \
  --keyring=signing --purpose=asymmetric-signing \
  --default-algorithm=rsa-sign-pkcs1-3072-sha256 --protection-level=software
```

Use `--protection-level=hsm` for supported RSA keys. For software Ed25519, use
`--default-algorithm=ec-sign-ed25519`. Do not enable automatic rotation: changing
versions changes the OpenPGP identity and requires distributing a new certificate.

## Grant signing access

Create a custom role from [the production signer role](gcp/openpgpSigner.json)
and bind it on the specific CryptoKey:

```sh
gcloud iam roles create openpgpSigner --project="$PROJECT_ID" \
  --file=docs/gcp/openpgpSigner.json
gcloud kms keys add-iam-policy-binding releases --project="$PROJECT_ID" \
  --location="$LOCATION" --keyring=signing \
  --member='serviceAccount:SIGNER@YOUR_PROJECT_ID.iam.gserviceaccount.com' \
  --role="projects/$PROJECT_ID/roles/openpgpSigner"
```

The role contains only version metadata, public-key retrieval, and signing.
No `useToVerify`, KMS Admin, or private-key export permission is needed.

For local development, run `gcloud auth application-default login` with a suitably
restricted identity. In GitHub Actions, establish ADC with OIDC; see the
[action guide](https://github.com/duncm/openpgp-sign-kms/blob/main/docs/google-oidc.md).
There is no production endpoint override or fallback signer.

## Export, sign, and verify

```sh
export KEY="projects/$PROJECT_ID/locations/$LOCATION/keyRings/signing/cryptoKeys/releases/cryptoKeyVersions/1"
openpgp-sign-kms --export -u "$KEY" --armor \
  --export-name 'Release signer' --export-email 'release@example.com' -o public.asc
openpgp-sign-kms -b -u "$KEY" artifact.tar.gz
gpg --import public.asc
gpg --verify artifact.tar.gz.sig artifact.tar.gz
```

An enabled version is required. An unversioned CryptoKey is rejected; the CLI never
resolves a primary or latest version. The immutable version creation timestamp
(truncated to seconds), public key, and OpenPGP v4 encoding determine its fingerprint.
Repeated exports preserve it. Imported-key OpenPGP identity preservation is not supported.

## Algorithms and digest selection

| Algorithm | Digest | Protection |
| --- | --- | --- |
| `RSA_SIGN_PKCS1_2048_SHA256` | SHA-256 | Software, HSM |
| `RSA_SIGN_PKCS1_3072_SHA256` | SHA-256 | Software, HSM |
| `RSA_SIGN_PKCS1_4096_SHA256` | SHA-256 | Software, HSM |
| `RSA_SIGN_PKCS1_4096_SHA512` | SHA-512 | Software, HSM |
| `EC_SIGN_ED25519` | SHA-512 | Software |

Unlike AWS RSA keys, Google key versions fix their signing digest. The CLI chooses
that digest by default and rejects incompatible `--digest-algo` values before signing.
For Ed25519, the OpenPGP SHA-512 digest is signed as raw data with PureEdDSA, using
legacy OpenPGP EdDSA packets for GnuPG compatibility.

RSA-PSS, ECDSA, external KMS and single-tenant HSM are not supported.
See [Google's algorithm table](https://docs.cloud.google.com/kms/docs/algorithms).

## Integrity, retries, and audit descriptions

The CLI sends CRC32C checksums and checks returned checksums, key identity,
algorithm/protection metadata, and request-checksum acknowledgement. It also verifies
every signature locally before finalizing output.

Each SDK operation has a 60-second deadline and at most three attempts. Only
transient failures are retried; access denial and integrity failures fail closed.
Retries can repeat a signing request. Metadata lookup and certificate export also
make API requests; an export creates a self-signature.

`--description` and Git metadata use the same base64url User-Agent component as AWS.
The complete client-supplied header is limited to 1,024 bytes. Find it in
`protoPayload.requestMetadata.callerSuppliedUserAgent` in Cloud Audit Logs.
Descriptions are caller-provided context, not an authentication claim.

Enable KMS `DATA_READ` audit logging to record signing. Data Access logging is not
implicitly enabled by the CLI. [Google audit documentation](https://docs.cloud.google.com/kms/docs/audit-logging)

[Git metadata and privacy](git.md) · [Integration project](google-integration.md)
