# AWS KMS setup

## Create a signing key

Choose your AWS region and run one command:

```sh
aws kms create-key --region REGION --key-usage SIGN_VERIFY --key-spec RSA_3072
# Or:
aws kms create-key --region REGION --key-usage SIGN_VERIFY --key-spec ECC_NIST_EDWARDS25519
```

Copy `KeyMetadata.Arn`. Supported types are RSA_2048, RSA_3072, RSA_4096 and
ECC_NIST_EDWARDS25519. Key state must be Enabled.

## Authorize the signer

Add this statement to the existing key policy, substituting your signing-role ARN.
Preserve existing administrator statements; do not replace the policy with this
statement alone.

```json
{
  "Sid": "AllowOpenPgpSigner",
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/ROLE"},
  "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
  "Resource": "*"
}
```

Within a KMS key policy, this resource refers to the key whose policy is edited.
For cross-account use, also grant these actions on the exact key ARN in the
role's identity policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
    "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
  }]
}
```

Public-key verification occurs locally; no `kms:Verify` grant is needed.
Credentials come from the standard AWS SDK chain, including environment,
profiles, web identity and workload roles. Region comes from the key ARN.

For GitHub repository restrictions, follow the action's
[OIDC setup guide](https://github.com/duncm/openpgp-sign-kms/blob/main/docs/aws-oidc.md).

## Export and distribute

Follow the [CLI quick start](../README.md#get-started) to export `public.asc`.
Publish that certificate through your release or project documentation.
Keep it available so historical signatures can still be verified.
