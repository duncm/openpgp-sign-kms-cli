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
- `kms`: AWS metadata, algorithm mapping, requests and audit headers.
- `pgp`: external signer adapter, local verification and OpenPGP serialization.
- `app`, `output`, `status`: orchestration, staged output and machine status.

Run `cargo fmt` before submitting. CI covers Ubuntu 22.04/24.04 on x86_64/ARM64.
PR tests require neither AWS credentials nor production keys.
