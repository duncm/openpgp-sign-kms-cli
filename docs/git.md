# Git and audit logging

Configure `gpg.openpgp.program` and `user.signingkey` as shown in the README.
Git sends the exact payload on stdin using `--status-fd=2 -bsau KEY`.
The CLI returns an armored detached signature and accurate GPG status records.

## Verification

Set `OPENPGP_SIGN_KMS_GPG` to an absolute GPG executable path, or use
`--gpg-program PATH --verify SIGNATURE DATA` directly. Arguments, streams and exit
status are preserved. Delegation runs before AWS initialization and rejects
recursive invocation and mixed signing/verification commands.

Import the exported certificate into GPG. For GitHub's Verified indicator,
[add the public key to the relevant account](https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account)
and ensure its email matches the commit identity requirements.

## CloudTrail descriptions

Set `OPENPGP_SIGN_KMS_DESCRIPTION`, or pass `--description` directly. CLI values
win over the environment. The KMS Sign request User-Agent contains
`description/BASE64URL`, encoding the UTF-8 description without padding.
Descriptions are audit context, not an authorization mechanism.

The complete custom User-Agent is capped at 1,024 bytes. Oversized descriptions
fail before signing. CloudTrail does not provide a native Sign description field.

## Optional Git metadata

Enable enrichment when signing commits or tags:

```sh
export OPENPGP_SIGN_KMS_GIT_METADATA=auto
export OPENPGP_SIGN_KMS_DESCRIPTION='Release signing'
git commit -S -m 'Signed change'
```

The default is `off`. `--git-metadata=off|auto` overrides the environment.
Recognized payloads append these fields to the explicit description:

| Field | Meaning |
| --- | --- |
| `git_type` | `commit` or `tag` |
| `payload_sha256` | SHA-256 of the exact unsigned input bytes |
| `tree`, repeated `parent` | Commit tree and parent object IDs |
| `target_id`, `target_type`, `tag` | Tag target and tag name |

Tag names use UTF-8 percent encoding. Identities and message text are omitted.
The explicit description and payload digest take priority; optional fields are
added in table order when space permits within the 1,024-byte User-Agent limit.
If the description plus required fields cannot fit, signing fails before AWS
calls. Shorten the description or disable enrichment.

The parser examines at most 64 KiB of headers, handles continuation headers,
root/merge commits, and SHA-1/SHA-256 object IDs. Unrecognized input is signed
normally. Recognized payloads are spooled to a temporary file so their digest
is available before signing; signed bytes and signing-call counts are unchanged.
Export and verification do not enrich descriptions.

Recognition is a heuristic, not proof that Git invoked the command. The payload
digest is **not the final signed Git object ID**. No repository, branch, checkout
ID, or `HEAD` is inferred. Post-signing correlation remains outside this tool.

## Google Cloud audit records

The same Git invocation and opt-in metadata work with an explicit Google key-version
resource name as `user.signingkey`. Descriptions appear in Cloud Audit Logs under
`protoPayload.requestMetadata.callerSuppliedUserAgent`; enable KMS DATA_READ logging.
Encoding, privacy, size limits, payload hashing and caller-trust limitations are
unchanged. [Google setup and audit details](google-cloud.md#integrity-retries-and-audit-descriptions)
