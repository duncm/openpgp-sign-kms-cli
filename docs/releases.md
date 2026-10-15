# CI and releases

## Workflows

- **CI:** pull requests, main pushes and manual dispatch; read-only, no AWS.
- **AWS integration:** manual or called by release; GitHub OIDC, environment `integration`.
- **Release:** `v*` tags; validates version/main ancestry and publishes only after tests.
- **Maintenance:** weekly/manual dependency checks and external links.

External actions are pinned by SHA. Dependabot updates dependencies and action
pins through ordinary pull requests. Set `CI / required` as a required check.
Protect `main` from direct updates and limit version-tag creation to maintainers.

## Integration environment

Create the GitHub environment `integration` restricted to main and release tags.
Set these environment variables:

| Variable | Meaning |
| --- | --- |
| `AWS_ROLE_ARN` | OIDC role trusted for this repository/environment |
| `AWS_REGION` | Region containing both test keys |
| `KMS_RSA_KEY_ARN` | Enabled RSA signing key |
| `KMS_ED25519_KEY_ARN` | Enabled Ed25519 signing key |

Grant the role DescribeKey, GetPublicKey and Sign on those test keys, plus
`cloudtrail:LookupEvents` on `*` for the audit check. No key creation/deletion
permissions are needed. Missing configuration fails integration and blocks release.
CloudTrail may take several minutes; the test uses a unique description and a
bounded polling window. It fails if the expected event never appears.

## Publish

1. Update the package version and release notes in a normal main-branch change.
2. Run offline CI and manual AWS integration.
3. Create and push the matching `vVERSION` tag. Prerelease versions include a suffix.
4. The release workflow tests candidates and publishes the same verified artifacts.

Existing published releases are never overwritten. A failed run leaves no public
release; inspect logs and rerun the workflow after addressing external failures.
For code changes, make a new version/tag rather than moving a versioned tag.

CLI archives are built on Ubuntu 22.04 for x86_64 and ARM64. The source bundle
contains this project, vendored Cargo dependency sources, Cargo configuration,
license files and rebuild instructions. `dependencies.json` and a CycloneDX SBOM
record the locked packages. Build provenance is attached through GitHub attestations.

Consumers can use `gh attestation verify ARCHIVE --repo duncm/openpgp-sign-kms-cli`.
The release pipeline does not depend on using this signer to sign its own release.

Rehearse with a prerelease tag before publishing the first stable CLI release.
The action must be pinned to a published CLI release afterward.
