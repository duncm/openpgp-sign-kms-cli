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

## Deferred metadata enrichment

Git-payload metadata enrichment is deliberately deferred until baseline live AWS
validation and release rehearsal pass. The future opt-in `--git-metadata=auto`
will add tag target/name or commit tree/parents plus an unsigned-payload SHA256.
It will never label that digest as the final signed Git object ID.
