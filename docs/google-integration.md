# Dedicated Google integration project

This guide provisions test infrastructure for both repositories in an **existing
Google Cloud organization**, using `us-central1`. Run administrator commands yourself;
GitHub workflows cannot provision projects or change IAM.

**Rollout status:** policy templates and workflows are prepared. They have not yet
been applied or verified against a live Google project. Record successful run links
in the validation section after setup; offline tests do not prove cloud permissions.

## Prerequisites and identifiers

Use an existing organization administrator identity with MFA. Obtain approval for
project creation, billing attachment, custom-role and federation administration,
KMS provisioning, IAM deny administration, and organization-policy administration.
Do not grant those administration roles to workflow service accounts.
Deny-policy creation specifically requires an organization-level `roles/iam.denyAdmin`
grant; see [temporary deny administration](google-guardrails.md#grant-deny-policy-administration).

Choose a project ID, organization/folder, billing account, and recovery group whose
members can administer this project. The group must belong to the organization.
Confirm its membership before applying deny policies; an exception does not grant access.

```sh
export PROJECT_ID='YOUR_UNIQUE_PROJECT_ID'
export ORG_ID='YOUR_ORGANIZATION_ID'
export BILLING_ACCOUNT='AAAAAA-BBBBBB-CCCCCC'
export ADMIN_GROUP='gcp-admins@YOUR_DOMAIN'
export LOCATION='us-central1'
gcloud auth login
gcloud organizations list
gcloud billing accounts list
```

Inspect the parent organization/folder IAM policies and effective constraints first.
Keep their output outside the repository. Check inherited location, protection-level,
minimum-destruction-delay, domain-sharing, and service restrictions.

```sh
gcloud organizations get-iam-policy "$ORG_ID"
gcloud org-policies describe gcp.resourceLocations --organization="$ORG_ID" --effective
gcloud org-policies describe cloudkms.minimumDestroyScheduledDuration --organization="$ORG_ID" --effective
gcloud org-policies describe iam.managed.allowedPolicyMembers --organization="$ORG_ID" --effective
```

An absent explicit policy can produce `NOT_FOUND`; distinguish that from lack of
permission. If using a folder, inspect its effective policies too. Do not weaken
an inherited policy to make these examples work. Resolve conflicts with the owner.

## Create the empty project

```sh
gcloud projects create "$PROJECT_ID" --organization="$ORG_ID" \
  --name='OpenPGP KMS integration'
# If using an existing folder, use --folder=FOLDER_ID instead of --organization.
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
export PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
gcloud services enable --project="$PROJECT_ID" \
  cloudkms.googleapis.com iam.googleapis.com iamcredentials.googleapis.com \
  sts.googleapis.com logging.googleapis.com cloudresourcemanager.googleapis.com \
  serviceusage.googleapis.com orgpolicy.googleapis.com cloudbilling.googleapis.com \
  billingbudgets.googleapis.com monitoring.googleapis.com
```

Create a project-scoped budget (example: USD 5/month):

```sh
gcloud billing budgets create --billing-account="$BILLING_ACCOUNT" \
  --display-name='OpenPGP integration' --budget-amount=5USD \
  --filter-projects="projects/$PROJECT_NUMBER" \
  --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1
```

By default, budget notifications go to billing administrators/users. To send them
to a specific recipient, create and verify a Cloud Monitoring email notification
channel, then add `--notifications-rule-monitoring-notification-channels=CHANNEL_NAME`.
[Recipient setup](https://docs.cloud.google.com/billing/docs/how-to/budgets-notification-recipients)
Budget alerts **do not cap spending**; keep an eye on version counts and cleanup failures.

## Render and review the configuration

From the CLI checkout, copy [project.example.json](gcp/project.example.json) outside
the repository. Replace the project ID/number, organization ID, and administrator
group. Verify repository IDs against GitHub before using the supplied values.

```sh
cp docs/gcp/project.example.json /tmp/openpgp-google-project.json
# Edit /tmp/openpgp-google-project.json with your values.
python3 scripts/gcp-project.py --config /tmp/openpgp-google-project.json \
  --output /tmp/openpgp-google-review
bash -n /tmp/openpgp-google-review/provision-runtime.sh
```

Rendering is offline: it creates review files and never calls Google APIs.
Review the generated roles, providers, deny policy, Organization Policies, and shell
commands. Checked-in examples are illustrative, not applied configuration.

Then run the one-time runtime provisioning commands:

```sh
bash /tmp/openpgp-google-review/provision-runtime.sh
```

The script stops on errors. If interrupted, inspect resources and resume the remaining
commands individually; do not delete/recreate the project or suppress arbitrary errors.

If an older generated script stopped because provider ID `hsm` was too short,
regenerate the files with your original project configuration using the fixed
renderer. Keep the existing pool and `software` provider. Resume at `hsm-smoke`:

```sh
cd /tmp/openpgp-google-review
sed -n '/^gcloud iam workload-identity-pools providers create-oidc hsm-smoke /,$p' \
  provision-runtime.sh > resume-runtime.sh
test -s resume-runtime.sh
bash -euo pipefail resume-runtime.sh
```

Regeneration also corrects the HSM audience and `github-environments.json`; use
those updated values when configuring GitHub. Key protection levels, key-ring
names, and the `gcp-hsm` environment keep their existing names.

It creates:

- One dedicated workload pool with providers `software` and `hsm-smoke`.
  Provider IDs require 4–32 characters; `hsm` alone is too short.
- Four service accounts: software and HSM for each repository.
- Four test key rings, scoped by repository and protection level.
- Five software key containers for CLI tests; two for action tests.
- One RSA-3072 HSM container per repository.
- No initial key versions, no static service-account keys, and no rotation schedule.

See [the role templates](gcp/openpgpIntegration.json) and
[cleanup-only permissions](gcp/openpgpCleanup.json). Roles are bound to named keys,
not every key in the project. Audit-read permissions are project-scoped because
this project contains only test infrastructure.

## Enable signing audit logs

Preserve the current project policy and its `etag`; merge KMS `DATA_READ` logging
rather than replacing unrelated bindings or audit settings:

```sh
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/openpgp-google-iam-before.json
python3 scripts/gcp-enable-audit.py /tmp/openpgp-google-iam-before.json /tmp/openpgp-google-iam-audit.json
# Review the diff before applying.
diff -u /tmp/openpgp-google-iam-before.json /tmp/openpgp-google-iam-audit.json || true
gcloud projects set-iam-policy "$PROJECT_ID" /tmp/openpgp-google-iam-audit.json
```

The helper refuses existing KMS or all-services DATA_READ exemptions so they cannot
silently exclude test signers. Review exemptions with your administrator instead.
Admin Activity logging remains enabled. The normal Logging retention policy applies;
these guides do not create extra log buckets or exports.

## Apply guardrails

Follow [Google guardrails](google-guardrails.md) to inspect inherited settings,
validate policy files, apply only this project's enforcement, and test recovery.
Do this before enabling release integration. Custom constraint definitions belong
to the organization; their enforcement is restricted to this project.

## Configure GitHub environments

Both repositories now have `gcp-integration` and `gcp-hsm` environments. The software
environment allows `main` and version tags; HSM allows `main` with owner approval.
Administrator bypass is disabled. Their Google variables are not set yet. Copy the
values from generated `github-environments.json`:

| Variable | Meaning |
| --- | --- |
| `GCP_PROJECT_ID` | Dedicated project ID |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Software or HSM provider resource name |
| `GCP_SERVICE_ACCOUNT` | Corresponding repository/protection service account |

Populate the variables from the reviewed generated file (requires GitHub administration):

```sh
python3 - <<'PYCODE'
import json, subprocess
from pathlib import Path
values = json.loads(Path('/tmp/openpgp-google-review/github-environments.json').read_text())
repos = {'cli': 'duncm/openpgp-sign-kms-cli', 'action': 'duncm/openpgp-sign-kms'}
for repo, environments in values.items():
    for environment, variables in environments.items():
        for name, value in variables.items():
            subprocess.run(['gh', 'variable', 'set', name, '--repo', repos[repo],
                            '--env', environment, '--body', value], check=True)
PYCODE
```

No Google secret is needed. For other deployments, restrict `gcp-integration` to `main` and release tags
matching `v*.*.*`; restrict `gcp-hsm` to `main`. Use manual approval for HSM tests where available and disable administrator bypass. Do not require a
human approval for each scheduled cleanup job.

Federation independently checks numeric repository/owner IDs, environment, workflow,
and event. Software release calls require the release workflow and its reusable Google
integration workflow. HSM requires a manual dispatch. Neither provider accepts PR events.
Service-account bindings also include repository ID **and** environment, so the two
providers cannot impersonate each other's service accounts.

The `google.subject` mapping preserves the actual customized `assertion.sub`.
Do not reset either repository's OIDC subject template.

## Run and record verification

After trusted changes are merged, run Google software integration and cleanup in
both repositories. Run cleanup with `dry_run=true` first, then `false`.
Run **Google HSM smoke** manually if you want live HSM verification.

```sh
gh workflow run gcp-integration.yml --repo duncm/openpgp-sign-kms-cli --ref main
gh workflow run gcp-cleanup.yml --repo duncm/openpgp-sign-kms-cli --ref main -f dry_run=true
# Repeat for duncm/openpgp-sign-kms after its CLI pin has been updated.
```

The CLI tests five algorithms on both architectures. The action tests RSA-3072 and
Ed25519 on both architectures. All jobs create fresh versions, sign/verify, inspect
Google audit descriptions, and clean up in `always()` steps.

Record the successful integration, cleanup, optional HSM, and separate guardrail
validation evidence here. **No live Google validation has been recorded yet.**

## Lifecycle and cost

Versions are journaled before readiness checks. Creation is not automatically
retried. An ambiguous response is recovered by the daily sweeper, which visits only
the fixed parent-key allowlist and checks metadata before acting.

Cleanup disables versions and requests destruction. The configured delay is 24 hours;
versions remain billable during that delay. Daily sweepers destroy abandoned versions
older than 24 hours. A run with no key creation adds no active-version rental.
Destroyed metadata is retained, but is not billed as active key material.
[Pricing](https://cloud.google.com/kms/pricing)

Manual cleanup defaults to dry-run. For a failed job that left recent versions,
provide `recover_versions` as a JSON array of their exact resource names when
dispatching `gcp-cleanup.yml`. Read them from the job's uploaded version journal.
Review with `dry_run=true`, then use `dry_run=false` for that same selection.
Only explicitly selected versions bypass the 24-hour threshold; the normal sweeper
still requires expiry. Every selected version must pass the same fixed parent-key
allowlist and metadata checks. No additional IAM permissions are needed.

Sweepers process software and HSM containers for their own repository only. Software accounts have cleanup-only access to HSM keys.
Failures remain visible and do not stop attempts to clean up other eligible versions.

## Recovery and teardown

For an orphan-cleanup failure, inspect the uploaded report, reauthenticate, and
rerun cleanup. Do not restore versions or reuse them as permanent signing identities.
A malformed journal or unexpected parent configuration requires administrator review.

To suspend access, disable the dedicated workload providers first. Leave cleanup
credentials available until all remaining versions are scheduled for destruction.
For full teardown, stop workflows, inspect all test versions, schedule their destruction,
then remove project resources or delete the dedicated project through your normal
administrative process. Remove only this project's policy enforcement; do not delete
organization custom constraints while other projects still use them.
