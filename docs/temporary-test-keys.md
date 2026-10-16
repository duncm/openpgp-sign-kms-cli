# Temporary integration keys

Both repositories create test keys inside each integration matrix job. Permanent
keys are no longer required by the current workflows.

| Repository | Keys created by each job | Keys per complete run |
| --- | --- | --- |
| Action | One RSA-3072 or Ed25519 key | 4 |
| CLI | One RSA-3072 and one Ed25519 key | 4 |

The role and region still come from the `integration` environment's
`AWS_ROLE_ARN` and `AWS_REGION` variables. The target test region is `us-west-2`;
follow the [policy and region cutover](aws-guardrails.md) before changing an existing
environment. The helper supplies generated key ARNs
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
No deletion is cancelled.

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

## Integration role policy

The role `openpgp-sign-kms-github-integration` uses the customer-managed policy
`arn:aws:iam::889580843530:policy/openpgp-sign-kms-integration`. It has no inline
policy. The bootstrap IAM user and its local static-credential profile have been
removed; administration uses IAM Identity Center or an organization administration
role. GitHub workflows continue to authenticate through OIDC.

The files below are review drafts for the region change and additional guardrails.
Preparing or merging them does not update AWS policies or GitHub environment variables.

| Policy | Purpose |
| --- | --- |
| [Managed policy](iam/integration-role-policy.json) | Existing permissions retargeted to `us-west-2` |
| [Integration-role SCP](iam/integration-role-scp.json) | Deny unexpected operations, other regions, and other key resources |
| [KMS RCP](iam/integration-kms-rcp.json) | Restrict access to this account’s customer-managed keys |

The drafts target account `889580843530` and the two `duncm` repositories.
Other deployments must substitute their account, role ARN, region, and repository
names. See [guardrail scope, validation, and application](aws-guardrails.md).

| Managed-policy permission | Scope |
| --- | --- |
| Create keys | Required tags; RSA-3072/Ed25519; `SIGN_VERIFY`; AWS-generated; single-region |
| Tag keys at creation | Exact allowed tag names and required ownership values |
| List keys, read metadata/tags | Account/region discovery for orphan cleanup |
| Get public keys and sign | Temporary-key ownership tags and supported key properties |
| Schedule deletion | Same restrictions; exactly seven days |
| Look up CloudTrail events | `us-west-2`; used to verify audit descriptions |

The managed-policy action set is unchanged. It does not add permissions to cancel
deletion, change existing key policies, create grants, or manage IAM. However,
`CreateKey` can supply an initial key policy; the [SCP and RCP](aws-guardrails.md)
address limits that an identity-policy allow list alone cannot enforce. The OIDC
trust policy and GitHub environment branch restrictions do not change.

### Tagging permission boundary

KMS requires `kms:TagResource` on all keys in the account/region to tag keys during
creation. That permission can also authorize retagging existing keys; request-tag
conditions alone are not a creation-only boundary.

This policy is intended for the dedicated test account. Any long-lived keys must
receive explicit-deny protection (or a key policy denying this role access) before
being placed in this account. Do not reuse the policy unchanged in a
production account. Both repositories share the role; repository filtering in the
helper prevents accidental cross-repository cleanup, not access by hostile code
already authorized to assume that shared role.

### Apply after review

Use the [managed-policy update and cutover procedure](aws-guardrails.md#cutover-order).
Create a new default version of the existing managed policy; do not recreate an
inline policy or a bootstrap IAM user.

No permanent key-ARN GitHub variables are needed. Current workflows receive their
generated key ARNs through job-local environment variables. Historical workflows
that require permanent key variables cannot be rerun successfully.

## Permanent key retirement

The original RSA-3072 and Ed25519 test keys were scheduled for deletion on
16 October 2026, with deletion scheduled for 23 October. Both entered
`PendingDeletion`, ending their use for signing. Their key-specific deny and legacy-access
statements were removed from the integration role policy, and the old key-ARN
variables were removed from both GitHub environments.

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

The previous managed-policy contents passed IAM Access Analyzer validation and live
integration. The new-region policy and organization guardrails require fresh
validation; prior results do not validate the SCP/RCP or their combined effects.
The [guardrail guide](aws-guardrails.md#validation-before-application) includes
Access Analyzer commands and the live acceptance checks to run after review.

Offline lifecycle tests remain credential-free. Integration and daily cleanup use
the GitHub OIDC role, not a local profile.

## AWS references

- [Creating and tagging keys](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html)
- [Tagging permissions](https://docs.aws.amazon.com/kms/latest/developerguide/add-tags.html)
- [Scheduling deletion](https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html)
