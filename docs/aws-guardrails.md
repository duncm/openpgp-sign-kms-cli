# Test-account policies

The move to `us-west-2` completed on **16 October 2026**. Both repositories use
that region for integration and orphan cleanup. The customer-managed IAM policy
is applied to `openpgp-sign-kms-github-integration`, and the SCP and KMS RCP are
attached to member account `889580843530`.

## Verified rollout

All runs below passed on `main`. Baseline runs verified the region change with the
updated managed policy; the subsequent runs verified required workflow operations
with the managed policy, SCP, and RCP applied together.

| Repository | Permissions | Integration | Orphan cleanup |
| --- | --- | --- | --- |
| Action | Managed-policy baseline | [Passed](https://github.com/duncm/openpgp-sign-kms/actions/runs/38842112721) | [Passed](https://github.com/duncm/openpgp-sign-kms/actions/runs/38842377830) |
| CLI | Managed-policy baseline | [Passed](https://github.com/duncm/openpgp-sign-kms-cli/actions/runs/38842124275) | [Passed](https://github.com/duncm/openpgp-sign-kms-cli/actions/runs/38842773953) |
| Action | Managed policy + SCP + RCP | [Passed](https://github.com/duncm/openpgp-sign-kms/actions/runs/38843115614) | [Passed](https://github.com/duncm/openpgp-sign-kms/actions/runs/38843375946) |
| CLI | Managed policy + SCP + RCP | [Passed](https://github.com/duncm/openpgp-sign-kms-cli/actions/runs/38843118774) | [Passed](https://github.com/duncm/openpgp-sign-kms-cli/actions/runs/38843563041) |

Integration covered RSA-3072 and Ed25519 on x86_64 and ARM64, signing modes, GPG
verification, and CloudTrail descriptions. CLI integration also covered Git signing.
The runs with all policies applied created eight distinct test keys in `us-west-2`;
job cleanup scheduled all eight for seven-day deletion.

Both subsequent orphan sweeps used `dry_run=false`. The action scanned 12 keys
(eight owned by that repository); the CLI scanned 16 (eight owned by that repository).
Neither found an expired candidate. Actual deletion scheduling was exercised by
job cleanup; these sweeps verified discovery and filtering, not expired-key recovery.

These results establish compatibility for the required workflow operations. They
do not exhaustively test denied actions, external principals, or direct AWS service
requests. The RCP warning and future-change checks below remain relevant.

All test keys in the previous region were already `PendingDeletion` before the
switch, so no dual-region permission period was needed. Scheduled deletion continues
without workflow access to that region. See
[AWS key deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html).

## Policy files and scope

| File | Applied configuration |
| --- | --- |
| [integration-role-policy.json](iam/integration-role-policy.json) | Default version of the customer-managed integration IAM policy |
| [integration-role-scp.json](iam/integration-role-scp.json) | Organizations SCP attached only to this member account |
| [integration-kms-rcp.json](iam/integration-kms-rcp.json) | Organizations RCP attached only to this member account |

The IAM policy update changed only the region. It retained the existing actions,
required tags, key types, and seven-day deletion window. Its statement responsibilities are
listed in the [temporary-key guide](temporary-test-keys.md#integration-role-policy).

### Integration-role SCP

The SCP has three explicit-deny statements:

| Statement | Effect |
| --- | --- |
| `DenyUnexpectedIntegrationOperations` | Caps this role at the eight existing KMS actions, CloudTrail lookup, and STS identity lookup |
| `DenyIntegrationOperationsOutsideTestRegion` | Denies this role’s KMS requests and CloudTrail lookups outside `us-west-2` |
| `DenyIntegrationAccessToOtherKeyResources` | Denies its key-specific operations on resources outside this account’s `us-west-2` key ARNs |

All three statements match the exact role through `aws:PrincipalArn`, which uses
the IAM role ARN for assumed-role requests. STS is excluded from the region deny
so identity lookup does not depend on a regional endpoint. These statements do
not restrict the account’s SSO/organization administration roles.

The SCP grants nothing. Keep the existing SCP allow baseline at every applicable
organization level; adding a separate `Allow` cannot override these denies.
Do not attach this account-specific policy to the organization root. See
[SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
and [principal ARN semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalarn).

The cap denies operations such as IAM changes, role assumption, key grants,
cancelling deletion, and changes to existing key policies even if another policy
later grants them. `CreateKey` can still set an initial key policy. Keep the helper’s
default key policy and lockout safety check, which passed actual key creation under
the applied SCP. Repeat that check after future permission changes. Do not work
around a failure by disabling the safety check or adding key-administration
permissions without a separate review.

### KMS RCP

The RCP applies to this account’s customer-managed key ARNs in **all regions**,
including keys pending deletion. It has two explicit-deny statements:

| Statement | Effect |
| --- | --- |
| `DenyExternalPrincipalsOnTestAccountKeys` | Denies non-service callers whose principal account is different or missing |
| `DenyServiceRequestsWithoutLocalSourceAccount` | Denies direct AWS service callers whose `aws:SourceAccount` is different or missing |

GitHub OIDC sessions assume a role in this account, so they satisfy the account
restriction. Administrators from another organization account must first assume
an administration role **in this member account**; direct cross-account KMS calls
are denied, including calls from the management account.

The service restriction deliberately fails closed when `aws:SourceAccount` is
absent. These disposable signing keys have no required direct AWS-service use.
Review this restriction before adding a service integration that omits that key;
do not reuse the policy unchanged for general-purpose production keys.

Access Analyzer reported `RCP_MISSING_SERVICE_CONDITION_KEY_NULL_CHECK` for
`DenyServiceRequestsWithoutLocalSourceAccount`. The applied statement intentionally
denies direct AWS service requests when `aws:SourceAccount` is missing. Adding
`"Null": {"aws:SourceAccount": "false"}` would make that deny skip missing-key
requests.

The warning was retained with the reviewed strict behavior; successful GitHub-role tests do not establish compatibility with future service integrations.
See the [AWS warning reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html).

Keep `RCPFullAWSAccess`; the policy supplies additional denies. RCPs do not restrict
service-linked roles or AWS-managed KMS keys, and KMS `RetireGrant` has an RCP
exception. The SCP separately denies grant-management operations for the integration
role. See [RCP scope and exceptions](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
and [confused-deputy controls](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

### Limits of these policies

- Tagging permission can retag existing keys. Keep this account dedicated to
  disposable tests; the shared role is not an isolation boundary between repositories.
- IAM allow conditions still control key properties and ownership tags. The SCP is
  an action/resource/region cap, not a duplicate of every IAM condition.
- Key creation and signing can incur costs. Expiry tags and the daily sweeper do
  not impose a hard budget or constrain malicious code that already has the role.
- Organization-wide logging, detection, root-access, and administrator protections
  remain separate controls. These account-specific policies do not replace them.

## Validation before future changes

The bootstrap IAM user and local static-credential profile have been removed.
Use an existing IAM Identity Center account-administration profile. Replace both
profile placeholders below with profiles configured on your own machine:

```sh
ACCOUNT_ADMIN_PROFILE=your-member-account-sso-profile
ORG_ADMIN_PROFILE=your-organization-admin-profile
aws sso login --profile "$ACCOUNT_ADMIN_PROFILE"
aws --profile "$ACCOUNT_ADMIN_PROFILE" sts get-caller-identity
```

Confirm that the returned account is `889580843530`. Organization policy creation
and attachment use the separate organization-administration profile with the
necessary Organizations permissions.

From this repository, validate all three documents and review **every finding**:

```sh
aws --profile "$ACCOUNT_ADMIN_PROFILE" accessanalyzer validate-policy \
  --region us-west-2 --policy-type IDENTITY_POLICY \
  --policy-document file://docs/iam/integration-role-policy.json
aws --profile "$ACCOUNT_ADMIN_PROFILE" accessanalyzer validate-policy \
  --region us-west-2 --policy-type SERVICE_CONTROL_POLICY \
  --policy-document file://docs/iam/integration-role-scp.json
aws --profile "$ACCOUNT_ADMIN_PROFILE" accessanalyzer validate-policy \
  --region us-west-2 --policy-type RESOURCE_CONTROL_POLICY \
  --policy-document file://docs/iam/integration-kms-rcp.json
```

These are read-only validation calls. A successful API exit does not mean there
are no findings. Validation checks policy syntax and policy issues; it does not
prove combined IAM/SCP/RCP/KMS behavior or inspect inherited organization policies.
See [ValidatePolicy](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html).

## Future changes and cutover order

The initial rollout is complete; the commands below are an administration and
rollback reference. Do not recreate the existing policies or repeat the migration
for routine workflow runs. For another region change, review all region-specific
policy values and commands first.

1. **Review and validate** the updated policy documents. Repository changes do not
   apply AWS permissions or change GitHub environment variables.
2. **Quiesce AWS workflows** in both repositories: let active integration/release/
   cleanup jobs finish and avoid new dispatches or release tags during the update.
   Before removing access to a region, schedule deletion of its outstanding test
   keys. If the change overlaps daily cleanup schedules, temporarily disable only
   those workflows and re-enable them immediately afterward.
3. **Record rollback values:** both environment regions, the managed-policy default
   version, and the existing SCP/RCP IDs and contents. Keep the organization
   administration session available for rollback.
4. **Apply reviewed changes together:** update the managed policy and any affected
   existing SCP/RCP, then change both `AWS_REGION` values if needed. The already
   attached SCP must agree with the selected region before workflows resume.
   The integration role attachment and OIDC trust do not need replacement.
5. **Verify the combined configuration** after propagation: run manual integration
   and orphan cleanup in both repositories. Check signing, CloudTrail visibility,
   and successful key-deletion scheduling.
6. Restore normal scheduling and confirm every newly created test key has reached
   `PendingDeletion`.

The original rollout tested the new region before attaching the SCP/RCP, then
repeated the tests with both attached. Future updates must account for the active
guardrails; changing only IAM permissions or `AWS_REGION` can leave them inconsistent.

### Update the existing managed policy

Record the current region before changing it:

```sh
PREVIOUS_REGION=$(gh variable get AWS_REGION --env integration --repo duncm/openpgp-sign-kms-cli)
POLICY_ARN=arn:aws:iam::889580843530:policy/openpgp-sign-kms-integration
PREVIOUS_POLICY_VERSION=$(aws --profile "$ACCOUNT_ADMIN_PROFILE" iam get-policy \
  --policy-arn "$POLICY_ARN" --query Policy.DefaultVersionId --output text)
aws --profile "$ACCOUNT_ADMIN_PROFILE" iam list-policy-versions --policy-arn "$POLICY_ARN"
aws --profile "$ACCOUNT_ADMIN_PROFILE" iam create-policy-version \
  --policy-arn "$POLICY_ARN" \
  --policy-document file://docs/iam/integration-role-policy.json \
  --set-as-default
```

IAM permits five managed-policy versions. If all slots are occupied, explicitly
review and delete an unused **non-default** version first. Retain the previous
default version for rollback. Do not attach a second copy or create an inline policy.

### Change the GitHub environments

Run only after the managed-policy update:

```sh
gh variable set AWS_REGION --env integration --repo duncm/openpgp-sign-kms --body us-west-2
gh variable set AWS_REGION --env integration --repo duncm/openpgp-sign-kms-cli --body us-west-2
```

`AWS_ROLE_ARN` and the release-App configuration do not change. Confirm both values
with `gh variable get AWS_REGION --env integration --repo OWNER/REPOSITORY`.
Historical workflow logs and immutable releases retain their original contents.

### Update existing organization policies

Both policies are already created and attached for this account. Set `SCP_ID` and
`RCP_ID` to their recorded Organizations policy IDs, save their current contents,
and update those policies rather than creating duplicates:

```sh
aws --profile "$ORG_ADMIN_PROFILE" organizations update-policy \
  --policy-id "$SCP_ID" --content file://docs/iam/integration-role-scp.json
aws --profile "$ORG_ADMIN_PROFILE" organizations update-policy \
  --policy-id "$RCP_ID" --content file://docs/iam/integration-kms-rcp.json
```

### Fresh deployments only: create and attach organization policies

The creation commands below are for a new deployment, not this completed rollout.

First confirm that the organization has all features and that the SCP and RCP
policy types are enabled at its root. Retain existing allow baselines. If a type is
not enabled, review that organization-level change with its administrator before
proceeding; these commands do not enable it automatically.

```sh
SCP_ID=$(aws --profile "$ORG_ADMIN_PROFILE" organizations create-policy \
  --name openpgp-sign-kms-integration-scp \
  --description 'Restrict the test integration role to its reviewed operations and region' \
  --type SERVICE_CONTROL_POLICY \
  --content file://docs/iam/integration-role-scp.json \
  --query Policy.PolicySummary.Id --output text)
RCP_ID=$(aws --profile "$ORG_ADMIN_PROFILE" organizations create-policy \
  --name openpgp-sign-kms-test-keys-rcp \
  --description 'Restrict access to the dedicated test account KMS keys' \
  --type RESOURCE_CONTROL_POLICY \
  --content file://docs/iam/integration-kms-rcp.json \
  --query Policy.PolicySummary.Id --output text)
aws --profile "$ORG_ADMIN_PROFILE" organizations attach-policy \
  --policy-id "$SCP_ID" --target-id 889580843530
aws --profile "$ORG_ADMIN_PROFILE" organizations attach-policy \
  --policy-id "$RCP_ID" --target-id 889580843530
```

For later edits, update the recorded policy IDs instead of creating duplicate
policies. Keep the IDs with the change record for rollback.

### Acceptance and rollback

Run **AWS integration** on `main` in both repositories. Check all signing modes,
both key types/architectures, CloudTrail checks, and successful cleanup steps. Run
**Orphan key cleanup** with its default dry-run setting, then verify a reviewed
expired fixture through the normal cleanup procedure if testing recovery.

Review denied-operation cases too: unexpected actions for the integration role,
key access outside the account/region, and external-principal KMS access under the
RCP. Access Analyzer alone is not an enforcement test. Do not issue destructive
API calls merely to test a deny; use policy evaluation or disposable fixtures.

If a policy update blocks valid integration, stop new AWS jobs and restore the
saved SCP/RCP contents using their existing IDs from the organization admin session.
For a newly introduced policy in a fresh deployment, roll back only that new
account attachment. Keep existing and inherited organization protections in place.

For a region rollback, first schedule deletion of any new-region test keys while
permissions still allow cleanup. Restore the previous region-specific SCP contents,
the previous managed-policy default, and both environment regions. Restore the
previous RCP contents too if they changed:

```sh
aws --profile "$ACCOUNT_ADMIN_PROFILE" iam set-default-policy-version \
  --policy-arn "$POLICY_ARN" --version-id "$PREVIOUS_POLICY_VERSION"
gh variable set AWS_REGION --env integration --repo duncm/openpgp-sign-kms --body "$PREVIOUS_REGION"
gh variable set AWS_REGION --env integration --repo duncm/openpgp-sign-kms-cli --body "$PREVIOUS_REGION"
```

Changing only `AWS_REGION` is not a rollback: the managed policy and SCP must agree
with the selected region. Resume scheduling only after that consistency is restored.
