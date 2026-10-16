# Administrator signing-deny probe

Run only after [applying the reviewed guardrails](google-guardrails.md). This test
creates a short-lived probe account and software key version. It deliberately grants
a signer role, then expects the project IAM deny to block signing.

Use an administrator in the recovery group. Set `ADMIN_MEMBER` to that authenticated
identity (for example `user:admin@example.com`), not a workflow account.
The probe must never be added to a deny exception or recovery group.

First create the production signer custom role if it does not already exist:

```sh
gcloud iam roles create openpgpSigner --project="$PROJECT_ID" \
  --file=docs/gcp/openpgpSigner.json
```

Review and run this Bash block. Its cleanup attempts each operation independently;
retain the reported identifiers if cleanup fails.

```bash
set -euo pipefail
: "${PROJECT_ID:?}" "${ADMIN_MEMBER:?}"
probe_id="openpgp-probe-$(date +%s)"
probe="$probe_id@$PROJECT_ID.iam.gserviceaccount.com"
probe_dir=$(mktemp -d)
version=''
created=false
bound=false
cleanup() {
  set +e
  failed=0
  if [[ -n "$version" ]]; then
    gcloud kms keys versions disable "$version" --project="$PROJECT_ID" \
      --location=us-central1 --keyring=openpgp-cli-software --key=rsa3072 || failed=1
    gcloud kms keys versions destroy "$version" --project="$PROJECT_ID" \
      --location=us-central1 --keyring=openpgp-cli-software --key=rsa3072 --quiet || failed=1
  fi
  if [[ "$bound" == true ]]; then
    gcloud kms keys remove-iam-policy-binding rsa3072 --project="$PROJECT_ID" \
      --location=us-central1 --keyring=openpgp-cli-software \
      --member="serviceAccount:$probe" --role="projects/$PROJECT_ID/roles/openpgpSigner" || failed=1
  fi
  if [[ "$created" == true ]]; then
    gcloud iam service-accounts delete "$probe" --project="$PROJECT_ID" --quiet || failed=1
  fi
  if [[ "$failed" != 0 ]]; then
    printf 'Cleanup needs attention: probe=%s version=%s reports=%s\n' "$probe" "$version" "$probe_dir" >&2
  fi
  return "$failed"
}
trap 'result=$?; cleanup || result=1; exit "$result"' EXIT

gcloud iam service-accounts create "$probe_id" --project="$PROJECT_ID"
created=true
gcloud iam service-accounts add-iam-policy-binding "$probe" --project="$PROJECT_ID" \
  --member="$ADMIN_MEMBER" --role=roles/iam.serviceAccountTokenCreator
gcloud kms keys add-iam-policy-binding rsa3072 --project="$PROJECT_ID" \
  --location=us-central1 --keyring=openpgp-cli-software \
  --member="serviceAccount:$probe" --role="projects/$PROJECT_ID/roles/openpgpSigner"
bound=true
name=$(gcloud kms keys versions create --project="$PROJECT_ID" --location=us-central1 \
  --keyring=openpgp-cli-software --key=rsa3072 --format='value(name)')
version=${name##*/}
printf 'IAM deny probe\n' > "$probe_dir/input"

# Wait for generation before testing permissions.
state=''
for attempt in {1..60}; do
  state=$(gcloud kms keys versions describe "$version" --project="$PROJECT_ID" \
    --location=us-central1 --keyring=openpgp-cli-software --key=rsa3072 --format='value(state)')
  [[ "$state" == ENABLED ]] && break
  [[ "$state" == PENDING_GENERATION ]] || exit 1
  sleep 5
done
[[ "$state" == ENABLED ]]

if gcloud kms asymmetric-sign --project="$PROJECT_ID" --location=us-central1 \
  --keyring=openpgp-cli-software --key=rsa3072 --version="$version" \
  --digest-algorithm=sha256 --input-file="$probe_dir/input" \
  --signature-file="$probe_dir/signature" --impersonate-service-account="$probe" \
  2> "$probe_dir/sign-error.txt"; then
  echo 'FAIL: unexpected successful signing; inspect the deny policy.' >&2
  exit 1
fi
cat "$probe_dir/sign-error.txt"
grep -F 'cloudkms.cryptoKeyVersions.useToSign' "$probe_dir/sign-error.txt"
grep -Ei 'PERMISSION_DENIED|denied' "$probe_dir/sign-error.txt"
# Save/inspect a Policy Troubleshooter explanation before this account is deleted.
# Enable policytroubleshooter.googleapis.com as administrator first if needed.
gcloud policy-intelligence troubleshoot-policy iam \
  "//cloudkms.googleapis.com/projects/$PROJECT_ID/locations/us-central1/keyRings/openpgp-cli-software/cryptoKeys/rsa3072" \
  --principal-email="$probe" --permission=cloudkms.cryptoKeyVersions.useToSign \
  --format=json > "$probe_dir/troubleshooter.json"
printf 'Review deny explanation: %s\n' "$probe_dir/troubleshooter.json"
```

Require a denial of `cloudkms.cryptoKeyVersions.useToSign`. A failed impersonation,
unready version, or syntax error is not a successful test. Allow for IAM propagation
and repeat with a new probe if necessary. Do not print access tokens.

While the probe/grant still exists, Policy Troubleshooter can identify the deny rule
(use a separate administrator terminal before leaving the test block if needed):

```sh
gcloud policy-intelligence troubleshoot-policy iam \
  "//cloudkms.googleapis.com/projects/$PROJECT_ID/locations/us-central1/keyRings/openpgp-cli-software/cryptoKeys/rsa3072" \
  --principal-email="$probe" --permission=cloudkms.cryptoKeyVersions.useToSign
```

The administrator may need the Policy Troubleshooter API and viewer permissions.
Save its explanation with the effective deny-policy revision and successful positive
workflow links. Remove the temporary reports when no longer needed.
