#!/usr/bin/env bash
set -euo pipefail
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --example offline-signer --bin openpgp-sign-kms
python3 -m unittest discover -s scripts/tests -v
python3 scripts/interop.py
python3 scripts/sdk-test.py
python3 scripts/notices.py > /dev/null
python3 scripts/check-docs.py
