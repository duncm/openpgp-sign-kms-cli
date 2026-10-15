# Temporary integration keys

Both repositories create test keys inside each integration matrix job. Permanent
keys are no longer required by the current workflows.

| Repository | Keys created by each job | Keys per complete run |
| --- | --- | --- |
| Action | One RSA-3072 or Ed25519 key | 4 |
| CLI | One RSA-3072 and one Ed25519 key | 4 |

The role and region still come from the `integration` environment's
`AWS_ROLE_ARN` and `AWS_REGION` variables. The helper supplies generated key ARNs
through `GITHUB_ENV`; the action and CLI signing interfaces are unchanged.

## Lifecycle and cleanup

1. Create single-region, AWS-generated `SIGN_VERIFY` keys with ownership tags.
2. Save each ARN in a job-local journal before checking readiness or creating
   another key. Wait for key/tag visibility and public-key access before testing.
3. Run the existing signing, verification, Git, and CloudTrail tests.
4. Refresh OIDC credentials and schedule deletion in an `always()` cleanup step.
   Cleanup attempts every recorded key and fails visibly if any attempt fails.

Deletion uses KMS's minimum seven-day waiting period. Scheduling makes the key
unusable immediately. Already-pending keys are treated as successfully cleaned up.
No deletion is cancelled, and existing permanent keys are not retired by this change.

`CreateKey` is not idempotent, so creation has automatic retries disabled. A lost
response can still leave a key without a local journal entry. Tags are attached
in the creation request so daily cleanup can find that key.

## Daily orphan cleanup

Each repository has an **Orphan key cleanup** workflow that runs daily on `main`
and uses the protected `integration` environment. It can also be dispatched
manually; manual runs default to a dry run. Set `dry_run=false` to schedule deletion.

The action runs at 04:19 UTC and the CLI at 04:49 UTC. Each sweeper handles only
its own repository's keys. Cleanup reports are uploaded as workflow artifacts.

The sweeper requires all of these conditions:

- `Project=openpgp-sign-kms`, `Purpose=integration-temporary`, and
  `ManagedBy=openpgp-sign-kms-ci`.
- `Repository` matches the running repository, with run, attempt, and job tags.
- `ExpiresAt` is an expired Unix timestamp and the key is at least 24 hours old.
- The key is in the configured account/region, customer-managed, single-region,
  AWS-generated, and a supported RSA-3072 or Ed25519 signing key.

The helper sets expiry to 24 hours after creation. Invalid ownership or metadata
never authorizes deletion. Malformed eligible records and AWS errors are reported;
other eligible keys are still processed. AWS CLI automatic pagination scans all keys.

`always()` cannot guarantee cleanup after runner loss, a job timeout, or forced
cancellation. The daily workflow handles those cases, normally scheduling deletion
within 24–48 hours of creation. An expiry tag does not itself trigger AWS deletion.

## IAM change for review

**Prepared only; not applied.** Replace the `openpgp-sign-kms-integration` inline
policy on role `openpgp-sign-kms-github-integration` after review:

- [Proposed complete policy](iam/integration-role-policy.json)
- [Previous policy snapshot](iam/integration-role-policy-before.json)

The proposal targets account `889580843530`, region `ap-southeast-2`, and the two
`duncm` repositories. Other deployments must substitute their account, region,
repository names, and permanent-key protection list.

| Permission change | Scope |
| --- | --- |
| Create keys | Required tags; RSA-3072/Ed25519; `SIGN_VERIFY`; AWS-generated; single-region |
| Tag keys at creation | Exact allowed tag names and required ownership values |
| List keys, read metadata/tags | Account/region discovery for orphan cleanup |
| Get public keys and sign | Temporary-key ownership tags and supported key properties |
| Schedule deletion | Same restrictions; exactly seven days |
| Existing key validation | Preserved so previously published workflows still work |
| Explicit denial | Tagging, untagging, disabling, or scheduling deletion of the two existing permanent test keys |

There is no new permission to cancel deletion, change key policies, create grants,
or manage IAM. The OIDC trust policy and environment restrictions stay unchanged.
The existing local provisioning user's permissions already permit replacing this
role's inline policy; no additional local-user policy is proposed.

### Tagging permission boundary

KMS requires `kms:TagResource` on all keys in the account/region to tag keys during
creation. That permission can also authorize retagging existing keys; request-tag
conditions alone are not a creation-only boundary.

This policy is intended for the dedicated test account. It explicitly protects the
two existing permanent test keys. Any additional long-lived keys must receive
corresponding explicit-deny protection (or a key policy denying this role access)
before being placed in this account. Do not reuse the policy unchanged in a
production account. Both repositories share the role; repository filtering in the
helper prevents accidental cross-repository cleanup, not access by hostile code
already authorized to assume that shared role.

### Apply after review

From the CLI repository:

```sh
aws --profile openpgp-sign-kms-testing iam put-role-policy \
  --role-name openpgp-sign-kms-github-integration \
  --policy-name openpgp-sign-kms-integration \
  --policy-document file://docs/iam/integration-role-policy.json
```

Apply the reviewed policy before merging/enabling the new workflows. Then run
manual integration in both repositories and confirm every created ARN reaches
`PendingDeletion`. Dispatch orphan cleanup in dry-run mode, then exercise recovery
with an expired temporary fixture. Ordinary PR CI remains independent of AWS.

The old `KMS_RSA_KEY_ARN` and `KMS_ED25519_KEY_ARN` environment variables may remain
for historical release workflows; the updated workflows ignore them. Before
rolling back the IAM policy, clean up outstanding temporary keys so the daily
workflow does not lose permission to retire them.

## Development and verification

`scripts/kms-test-keys.py` uses Python's standard library and AWS CLI v2. Keep it
and `scripts/tests/test_kms_test_keys.py` identical in both repositories; this guide
and the policy files have their authoritative home in the CLI repository.

```sh
python3 -m unittest discover -s scripts/tests -v
```

Tests cover partial creation, lost responses, readiness failures, cleanup retries,
malformed journals, ownership/account/region guards, expiry, pagination settings,
dry runs, and idempotence. Both CI workflows run them without AWS credentials.

The proposed policy passed AWS IAM Access Analyzer `ValidatePolicy` with no findings.
Nine IAM custom-policy simulations confirmed the intended allows and denials,
including explicit protection of permanent keys and rejection of missing ownership
tags, other repositories, unsupported key types, multi-region keys, and non-seven-day
deletion windows. These simulations cover the identity policy, not full live KMS
resource-policy evaluation.

Read-only sweeps against the test account found its two permanent keys and selected
neither. Live creation/deletion validation remains pending policy review and application.

## AWS references

- [Creating and tagging keys](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html)
- [Tagging permissions](https://docs.aws.amazon.com/kms/latest/developerguide/add-tags.html)
- [Scheduling deletion](https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html)
