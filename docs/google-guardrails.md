# Google integration guardrails

Apply these controls only to the dedicated project. The
[project guide](google-integration.md) owns provisioning, OIDC and runtime access.

These files are prepared for administrator review; no live policy enforcement or
negative-test result is claimed yet.

## What each control does

| Control | Protection | Limit |
| --- | --- | --- |
| Key-scoped custom roles | CI can manage versions only in fixed test containers | An allow policy is not a permissions ceiling |
| Signing IAM deny | Blocks `useToSign` except designated signers/recovery group | Exceptions still need an allow grant; does not protect resources in other projects |
| Workflow administration deny | Prevents specified IAM, federation, key-template and service changes | IAM deny supports an explicit set of permissions; it is not universal AWS `NotAction` |
| Allowed policy members | Prevents new external/public IAM grants | Existing/inherited grants require separate review |
| Key creation/upload constraints | Prevents long-lived service-account keys | Existing keys require inspection and removal |
| GitHub provider allowlist | Restricts configured federation issuers | Provider conditions enforce repository/environment/workflow identity |
| Resource locations | Restricts KMS resources to `us-central1` | Applies only to supported resource types; global IAM control-plane resources remain available |
| Custom KMS constraint | Fixes allowed algorithms, purpose, protection and 24-hour destruction delay | Applies to supported CryptoKey create/update operations |
| Resource service allowlist | Blocks supported unrelated resource services | IAM, Logging and Monitoring are excluded essential dependencies |

Unlike an AWS SCP/RCP pair, these controls do not establish a universal organization-wide
ceiling on the integration identities. Do not grant them roles in other projects.
VPC Service Controls and Principal Access Boundaries are deferred; this setup is not
a network perimeter. Administrators able to change these policies remain trusted.

Sources: [IAM deny](https://docs.cloud.google.com/iam/docs/deny-overview),
[supported deny permissions](https://docs.cloud.google.com/iam/docs/deny-permissions-support),
[domain-restricted sharing](https://docs.cloud.google.com/organization-policy/restrict-domains),
[service restrictions](https://docs.cloud.google.com/organization-policy/restrict-services).

## Review and inspect before applying

The renderer writes JSON accepted by `gcloud`; JSON also avoids YAML boolean ambiguity.
Review the generated account IDs and group carefully. Keep an authenticated recovery
administrator session and verify membership of the exception group.

```sh
gcloud projects get-iam-policy "$PROJECT_ID" --format=json
gcloud iam service-accounts list --project="$PROJECT_ID"
gcloud iam workload-identity-pools providers list --project="$PROJECT_ID" \
  --location=global --workload-identity-pool=openpgp-github

gcloud org-policies list --project="$PROJECT_ID"
for file in /tmp/openpgp-google-review/policy-*.json; do
  constraint=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"].split("/")[-1])' "$file")
  gcloud org-policies describe "$constraint" --project="$PROJECT_ID" --effective
 done
```

Some policies/custom constraints do not exist yet; `NOT_FOUND` is expected for those.
Do not ignore permission errors. Review effective parent policies and resolve any
conflicting stronger restriction with the organization owner. In particular:

- A minimum destruction duration above 24 hours conflicts with this test design.
- A policy requiring disable-before-destroy is supported: cleanup disables first.
- A policy restricting all keys to HSM conflicts with software integration.
- The organization principal set must include the pool/service accounts and recovery group.
- Do not add `global` to resource locations merely to make an unrelated operation work;
  that would also permit global KMS keys.

The generated policies are proposals for this new project, not a merge engine for
arbitrary inherited constraints. Do not bulk-apply them until that review is complete.

Validate local syntax and inspect the generated command script without executing it:

```sh
python3 -m json.tool /tmp/openpgp-google-review/deny-policy.json > /dev/null
bash -n /tmp/openpgp-google-review/provision-runtime.sh
python3 -m unittest discover -s scripts/tests -p 'test_gcp_project.py' -v
```

For Organization Policies supporting dry-run, place the proposed `spec` under
`dryRunSpec` while preserving any enforced policy and its etag. Evaluate Policy
Simulator/dry-run findings before enforcement. Dry-run is not available for IAM deny;
use the dedicated project and recovery identity for its staged validation.
[Testing policies](https://docs.cloud.google.com/organization-policy/test-organization-policies)

## Grant deny-policy administration

Creating an IAM deny policy requires `roles/iam.denyAdmin`. Google allows this role
to be granted on the **organization**, even when the policy is attached to a project.
Project Owner and Organization Policy Administrator do not provide deny-policy
creation permission. [Required role](https://docs.cloud.google.com/iam/docs/deny-access#required_roles)

An administrator who can modify the organization's IAM allow policy can grant it
temporarily to your human administrator identity. Replace `YOUR_ADMIN_EMAIL`:

```sh
export ADMIN_EMAIL='YOUR_ADMIN_EMAIL'
DENY_ADMIN_UNTIL=$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')
gcloud organizations add-iam-policy-binding "$ORG_ID" \
  --member="user:$ADMIN_EMAIL" \
  --role=roles/iam.denyAdmin \
  --condition="expression=request.time < timestamp('$DENY_ADMIN_UNTIL'),title=openpgp-deny-setup"
```

This grants organization-wide deny-policy administration for one hour through an
IAM **allow-policy binding**. It does not change the scope of our project-attached
deny policy. Do not grant this role to the workflow accounts. After IAM propagation,
retry the failed `gcloud iam policies create` command; already-applied Organization
Policies do not need to be reapplied.

The time condition stops this binding from granting access after expiry. To remove
the binding earlier, run the equivalent `gcloud organizations remove-iam-policy-binding`
command with the same member, role, and condition. Do not remove another existing
administrative binding. If the grant command is denied, use an organization IAM
administrator; project ownership alone is insufficient for that grant.

## Apply the reviewed policies

Create the custom constraint definition at organization scope; enforcement below is
project-scoped. If the definition already exists, inspect it first and coordinate changes
with any other users instead of overwriting it.

```sh
gcloud org-policies set-custom-constraint \
  /tmp/openpgp-google-review/custom-kms-constraint.json

# Apply individually after reviewing inheritance/conflicts for each file.
for file in /tmp/openpgp-google-review/policy-*.json; do
  gcloud org-policies set-policy "$file"
done

gcloud iam policies create openpgp-integration-guardrails \
  --attachment-point="cloudresourcemanager.googleapis.com/projects/$PROJECT_NUMBER" \
  --kind=denypolicies --policy-file=/tmp/openpgp-google-review/deny-policy.json
```

Policy propagation is asynchronous. Inspect the actual stored/effective policies
before concluding a validation failure means the policy is ineffective.

```sh
gcloud iam policies get openpgp-integration-guardrails \
  --attachment-point="cloudresourcemanager.googleapis.com/projects/$PROJECT_NUMBER" \
  --kind=denypolicies
```

For future updates, retrieve the current deny policy/etag and use `gcloud iam policies
update`; do not delete/recreate an enforcement policy as the normal update procedure.

## Validate positive and negative behavior

Run software integration and cleanup in both repositories. Optional manual HSM tests
validate the HSM credentials and same API contract. Runtime permission checks use
`testIamPermissions` to confirm required permissions and absence of IAM/template,
restoration, verification, cross-repository, and software-to-HSM signing access.
These are non-mutating checks; they do not prove a deny overrides an accidental grant.

Also validate the federation policies using real GitHub tokens from deliberately
unapproved workflows/environments/repositories: token exchange must fail. Do not
print tokens. Routine PR CI has no OIDC permissions and never runs privileged tests.

As an administrator, test public/external IAM grant rejection against a temporary
probe service account or test key. Use a read-only role for the attempted grant;
confirm `PERMISSION_DENIED`/Organization Policy violation, and remove it immediately
if the test unexpectedly succeeds. Authentication, syntax, and missing-resource
errors do not demonstrate guardrail enforcement.

To prove the **signing deny** overrides an allow:

1. Create a temporary probe service account in this project, outside all deny exceptions.
2. Grant it the key-scoped `openpgpSigner` role on an allowlisted software test key.
3. Grant your administrator temporary impersonation access to that probe only.
4. Create a test version as administrator; try signing as the probe.
5. Require an explicit IAM deny result. Use Policy Troubleshooter to confirm the deny
   rule, rather than accepting an arbitrary failed request.
6. Remove the probe grants, destroy the test version, and delete the probe account in
   cleanup even if a check fails.

[Administrator probe commands](google-probe.md) implement that sequence with cleanup.
Never put the probe in the recovery group or run it with CI credentials.

Test KMS configuration constraints with an administrator's attempted creation of an
AES encryption key in a test ring: creation must be denied. If it unexpectedly succeeds,
schedule destruction of its version and investigate before enabling releases. The
normal CI identities cannot run this test because their allow policies already prohibit
parent-key creation.

Record positive workflow links and negative probe evidence separately in the
[rollout record](google-integration.md#run-and-record-verification).

## Recovery

Use the administrator recovery identity to inspect allow/deny decisions. The recovery
exception only covers signing; it does not itself grant IAM administration or sign access.
Do not exempt all organization principals or all service agents to resolve a test failure.

If a policy needs correction, change only this project's policy using its current etag,
retain the previous reviewed file for comparison, and rerun positive/negative checks.
Never disable organization-wide constraints or remove unrelated project bindings.
