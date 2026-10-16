# Test-account policies and region cutover

**Review drafts — not applied by a repository change.** The target account is
`889580843530`, the test region is `us-west-2`, and the integration role is
`openpgp-sign-kms-github-integration`.

The account owner confirmed that all test keys in the previous region are already
`PendingDeletion`. No dual-region permission period or seven-day wait is needed.
KMS completes scheduled deletion without further workflow access. See
[AWS key deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html).

Apply the managed policy before changing `AWS_REGION`. Avoid running integration,
release, or cleanup jobs while permissions and environment variables disagree.

## Policy files and scope

| File | Where it belongs |
| --- | --- |
| [integration-role-policy.json](iam/integration-role-policy.json) | New default version of the existing customer-managed IAM policy |
| [integration-role-scp.json](iam/integration-role-scp.json) | Organizations SCP attached only to this member account |
| [integration-kms-rcp.json](iam/integration-kms-rcp.json) | Organizations RCP attached only to this member account |

The IAM policy changes only the region. It retains the existing actions, required
tags, key types, and seven-day deletion window. Its statement responsibilities are
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
Do not attach this account-specific draft to the organization root. See
[SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
and [principal ARN semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalarn).

The cap denies operations such as IAM changes, role assumption, key grants,
cancelling deletion, and changes to existing key policies even if another policy
later grants them. `CreateKey` can still set an initial key policy. Keep the helper’s
default key policy and lockout safety check; exercise actual key creation under the
SCP before declaring it compatible. Do not work around a failure by disabling the
safety check or adding key-administration permissions without a separate review.

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
do not reuse the draft unchanged for general-purpose production keys.

Keep `RCPFullAWSAccess`; the draft supplies additional denies. RCPs do not restrict
service-linked roles or AWS-managed KMS keys, and KMS `RetireGrant` has an RCP
exception. The SCP separately denies grant-management operations for the integration
role. See [RCP scope and exceptions](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
and [confused-deputy controls](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

### Limits these drafts do not solve

- Tagging permission can retag existing keys. Keep this account dedicated to
  disposable tests; the shared role is not an isolation boundary between repositories.
- IAM allow conditions still control key properties and ownership tags. The SCP is
  an action/resource/region cap, not a duplicate of every IAM condition.
- Key creation and signing can incur costs. Expiry tags and the daily sweeper do
  not impose a hard budget or constrain malicious code that already has the role.
- Organization-wide logging, detection, root-access, and administrator protections
  remain separate controls. These account-specific drafts do not replace them.

## Validation before application

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

## Cutover order

1. **Review and validate** the three policies. Merge the documentation/fixture PRs
   after ordinary CI; merging does not apply AWS permissions or change the region.
2. **Quiesce AWS workflows** in both repositories: let active integration/release/
   cleanup jobs finish and avoid new dispatches or release tags during the switch.
   If the change overlaps the daily cleanup schedules, temporarily disable only
   those cleanup workflows and re-enable them immediately afterward.
3. **Record rollback values** and update the managed policy using the command below.
   The role attachment and OIDC trust stay unchanged.
4. **Change both environment variables** to `us-west-2` using the commands below.
   Once both are updated and IAM propagation completes, test manual integration in
   both repositories. Verify signing, CloudTrail visibility, and key cleanup.
5. **Attach the reviewed SCP and RCP** to this account. Rerun manual integration and
   cleanup in both repositories to check the combined controls. Keep the organization
   administration session available for rollback.
6. Confirm that normal workflow scheduling is restored and all newly created test
   keys have reached `PendingDeletion`.

The region change needs one coordinated policy-first cutover, not an intermediate
policy granting access to two regions. Testing the new region before attaching
organization guardrails separates region problems from guardrail problems.

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

### Create and attach organization policies

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

If a guardrail blocks valid integration, stop new AWS jobs and detach only the
new account-level SCP/RCP using their recorded IDs from the organization admin
session. Keep normal inherited organization protections in place.

For a region rollback, first schedule deletion of any new-region test keys while
permissions still allow cleanup. Reconcile or detach the new region-specific SCP,
restore the previous managed-policy default, and restore both environment regions:

```sh
aws --profile "$ACCOUNT_ADMIN_PROFILE" iam set-default-policy-version \
  --policy-arn "$POLICY_ARN" --version-id "$PREVIOUS_POLICY_VERSION"
gh variable set AWS_REGION --env integration --repo duncm/openpgp-sign-kms --body "$PREVIOUS_REGION"
gh variable set AWS_REGION --env integration --repo duncm/openpgp-sign-kms-cli --body "$PREVIOUS_REGION"
```

Changing only `AWS_REGION` is not a rollback: the managed policy and SCP must agree
with the selected region. Resume scheduling only after that consistency is restored.
