# CI and releases

## Workflows

- **CI:** pull requests, main pushes and manual dispatch; read-only, no AWS.
- **AWS integration:** manual or called by release; GitHub OIDC, environment `integration`.
- **Release:** `v*` tags; validates version/main ancestry and publishes only after tests.
- **Orphan key cleanup:** daily/manual; retires expired temporary integration keys.
- **Maintenance:** weekly/manual dependency checks and external links.

External actions are pinned by SHA. Dependabot updates dependencies and action
pins through ordinary pull requests. Set the CI job named `required` as a required check.
Protect `main` from direct updates and limit version-tag creation to maintainers.

## Integration environment

Create the GitHub environment `integration` restricted to main and release tags.
Set these environment variables:

| Variable | Meaning |
| --- | --- |
| `AWS_ROLE_ARN` | OIDC role trusted for this repository/environment |
| `AWS_REGION` | Region in which temporary test keys are created |

Each matrix job creates its own temporary keys and schedules their deletion after
use. A daily workflow recovers expired keys from interrupted jobs. Review and apply
the [temporary-key IAM policy and lifecycle setup](temporary-test-keys.md) before
enabling these workflows. Permanent key-ARN variables are no longer configured.
Missing configuration fails integration and blocks release.
CloudTrail may take several minutes; the test uses a unique description and a
bounded polling window. It fails if the expected event never appears.

## Immutable publication

Enable release immutability in each repository before publishing stable versions:

```sh
gh api --method PUT repos/OWNER/REPO/immutable-releases
```

Replace OWNER/REPO with the repository name. The GitHub CLI creates an asset-bearing
release as a draft, uploads its files, and then publishes it. Published assets and
the version tag are locked. See [GitHub's release guide](https://cli.github.com/manual/gh_release_create).
Do not create a release for the action's moving major tag; only semantic-version
tags receive releases.

## Release credentials

The publishing job uses the protected `release` environment and a repository-scoped
GitHub App token. Configure the [release App](release-app.md) before merging the
App-authentication change. The built-in workflow token remains read-only in that
job; attestation continues to use its existing narrowly scoped permissions.

## Publish

1. Update the package version and release notes in a normal main-branch change.
2. Run offline CI and manual AWS integration.
3. Create and push the matching `vVERSION` tag. Prerelease versions include a suffix.
4. The release workflow tests candidates and publishes the same verified artifacts.

Existing published releases are never overwritten. A failed build or integration run publishes nothing. If an upload fails after
GitHub creates a draft, inspect it and delete only that incomplete draft before
retrying. Never delete or replace a published release. Rerun after resolving
external failures.
For code changes, make a new version/tag rather than moving a versioned tag.

CLI archives are built on Ubuntu 22.04 for x86_64 and ARM64. The source bundle
contains this project, vendored Cargo dependency sources, Cargo configuration,
license files and rebuild instructions. Every binary archive also includes full
dependency notices and its dependency inventory. `dependencies.json` and a CycloneDX SBOM
record the locked packages. Build provenance is attached through GitHub attestations.

Consumers can use `gh attestation verify ARCHIVE --repo duncm/openpgp-sign-kms-cli`.
The release pipeline does not depend on using this signer to sign its own release.

Rehearse with a prerelease tag before publishing the first stable CLI release.
The action must be pinned to a published CLI release afterward.

## Initial release rehearsal

The [0.1.0-rc.1 rehearsal](https://github.com/duncm/openpgp-sign-kms-cli/actions/runs/38806205307)
passed the four-runner offline matrix, candidate-binary live AWS tests on both
architectures, packaging, attestation, and publication.
The [intentional version-mismatch test](https://github.com/duncm/openpgp-sign-kms-cli/actions/runs/38808161422)
failed validation and skipped integration, attestation, and publication.
Its `v0.0.0-rehearsal-invalid` tag is retained as a test record and has no release.

Create release tags with `git tag -s vVERSION -m 'Release VERSION'` and verify
with `git verify-tag vVERSION` before pushing. Contributor commits must also be
GPG signed as described in the contributor guide.
