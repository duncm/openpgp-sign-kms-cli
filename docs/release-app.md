# Release App setup

A dedicated GitHub App lets the release workflows publish releases and update
moving major-version tags while tag rules restrict other writers. Its bypass is
limited to major-tag creation and updates; it cannot bypass `main` protections,
rewrite semantic-version tags, or delete release tags.

GitHub's built-in `GITHUB_TOKEN` cannot use this ruleset bypass. Isolated workflow
tests confirmed that adding `github-actions[bot]` as a user bypass does not work,
even though the API accepts that configuration. GitHub also rejects the built-in
Actions integration as an integration bypass actor.

## Configure the App

1. [Create a GitHub App](https://github.com/settings/apps/new) owned by `duncm`.
   Use an available name such as `duncm-openpgp-releases` and either project
   repository as its homepage. Disable the webhook; no OAuth callback is needed.
2. Grant only repository **Contents: Read and write**. Metadata read access is
   automatic. No organization/account permissions or event subscriptions are needed.
3. Limit installation to this account. Install the App on these two selected repositories:
   - `duncm/openpgp-sign-kms`
   - `duncm/openpgp-sign-kms-cli`
4. Generate a private key in the App settings. In the existing `release` environment
   of **each** repository, configure:

   | Setting | Type | Value |
   | --- | --- | --- |
   | `RELEASE_APP_ID` | Variable | Numeric App ID; used to configure the tag ruleset |
   | `RELEASE_APP_CLIENT_ID` | Variable | App Client ID; used to mint installation tokens |
   | `RELEASE_APP_PRIVATE_KEY` | Secret | Entire generated PEM private key |

Keep the private key only in the protected `release` environment, with no
repository-level copy. The two non-secret variables may also be configured at
repository scope. Do not paste the key into chat, commit it, or reuse a personal
access token. The release job requests a token for only its own
repository, with Contents write permission. The token action revokes it after use.

Environment settings:

- [Action release environment](https://github.com/duncm/openpgp-sign-kms/settings/environments)
- [CLI release environment](https://github.com/duncm/openpgp-sign-kms-cli/settings/environments)

The environments allow only `main` and `v*.*.*` tags. Admin bypass is disabled.
This keeps App secrets out of fork PRs and arbitrary development branches.

## Activate the tag restriction

After both environments are configured:

1. Confirm the App is installed on both repositories and its IDs match the variables.
2. Merge the release-authentication PRs after their required CI passes.
3. Prepare isolated `__release_hardening_version` and `__release_hardening_major`
   refs/rules (the signed version probe must point to current `main`) and dispatch
   **Release permission verification** on `main` in both
   repositories. This verifies App-authenticated tag creation/update and draft-release
   operations, while rejecting version-tag rewrites and tag deletion. Remove the
   temporary rules and refs afterward; do not publish a test release.
4. Enable the major-tag creation/update ruleset with this bypass actor:

   ```json
   {"actor_type":"Integration","actor_id":123456,"bypass_mode":"always"}
   ```

   Replace `123456` with the numeric App ID. Do not grant this bypass to the `main`
   ruleset or the immutable-version-tag/deletion rulesets.

Activation completed on 16 October 2026 using App `openpgp-sign-kms-releases`
(ID `5338261`). Both publishing workflows now use App installation tokens.
The [action permission test](https://github.com/duncm/openpgp-sign-kms/actions/runs/38825066339)
and [CLI permission test](https://github.com/duncm/openpgp-sign-kms-cli/actions/runs/38825069627)
verified tag creation/force-update and draft release creation, asset upload, and
editing. Version-tag rewrites and tag deletion were rejected. The temporary
rules, tags, and draft releases were removed; existing releases were unchanged.

The CLI currently publishes immutable version releases; the action also advances
its major convenience tag. Both publishing jobs use the same App setup.

## Current repository hardening

Both repositories require PRs, verified commit signatures, and the up-to-date
`required` CI check on `main`, without bypass actors. Force pushes and deletion
of `main` are blocked. Merged PR head branches are automatically deleted.

All external contributors require approval for fork workflow runs. Third-party
actions must use full commit SHAs and match the explicit action allowlist, which
includes the nested attestation actions and `actions/create-github-app-token`.
Dependabot alerts/security updates and private vulnerability reporting are enabled.
Secret scanning, push protection, and immutable releases remain enabled.

Version tags (`v*.*.*`) can be created only by `duncm`, and cannot be updated or
deleted. Major tags match `v[0-9]*`, excluding dots and prerelease hyphens; their
deletion is blocked. Only the release App can create or update major tags. Its
bypass applies only to those two operations; all other protections remain active.

## References

- [Creating a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)
- [Installation token action](https://github.com/actions/create-github-app-token)
- [Repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository)
