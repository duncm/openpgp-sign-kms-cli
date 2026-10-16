# Build and test

Install Rust through rustup, plus a C compiler, make, Perl, pkg-config, clang,
libclang development files, Python 3, OpenSSL CLI, Git and GnuPG. Ubuntu packages:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config clang libclang-dev perl python3 openssl git gnupg
cargo build --locked
bash scripts/check.sh
```

The checked-in toolchain file pins Rust. Sequoia uses vendored OpenSSL and no
compression backend. Cargo.lock pins transitive dependencies.

`examples/offline-signer.rs` is an explicitly test-only local-key provider used
by interoperability tests. It exercises the same adapter and application code;
it is never included in release archives or selected by the production CLI.

## Architecture

- `args`: GPG argument compatibility and verification delegation.
- `provider`: key identifiers, shared material/capabilities, audit headers and dispatch.
- `kms`, `gcp`: provider metadata, algorithm mapping and remote requests.
- `pgp`: external signer adapter, local verification and OpenPGP serialization.
- `app`, `output`, `status`: orchestration, staged output and machine status.

Run `cargo fmt` before submitting. CI covers Ubuntu 22.04/24.04 on x86_64/ARM64.
PR tests require no AWS/Google credentials or cloud access.

`examples/gcp-protocol-signer.rs` is a second test-only executable, exercising the
real Google SDK against the local HTTP server in `scripts/gcp-sdk-test.py`. Its
anonymous credentials and endpoint are never selected by the production CLI.
Google protocol tests include all five algorithms, metadata/checksum rejection,
HSM response variants, audit headers, retries and timeouts.

Google infrastructure helpers use Python’s standard library and the gcloud access
token established by OIDC. Unit tests fake the API; they do not contact Google.

## Commit signatures

All commits must be OpenPGP/GPG signed. Configure your signing key and use
`git commit -S`; verify with `git log --show-signature`. Do not disable commit
signing when preparing changes or releases.
