# Supplemental dependency notices

These crates omit their repository license file from the crates.io package.
The files here are copied unchanged from these pinned upstream revisions:

- [base64-simd-0.8.0.txt](https://raw.githubusercontent.com/Nugine/simd/d74c030d9dc4f3cae02146d1f497ff62726ef09a/LICENSE)
- [vsimd-0.8.0.txt](https://raw.githubusercontent.com/Nugine/simd/d74c030d9dc4f3cae02146d1f497ff62726ef09a/LICENSE)
- [difflib-0.4.0.txt](https://raw.githubusercontent.com/DimaKudosh/difflib/f035fb8e656f27119e23eca9d5b996df14f3885e/LICENSE)

Review these files when updating the corresponding dependencies. Release packaging
fails if any dependency has neither packaged notices nor a versioned supplement.

The Google SDK adds `webpki-root-certs`, whose root-certificate dataset uses
CDLA-Permissive-2.0. That license is allowed in `deny.toml`; its packaged license
notice is included in the release notices and corresponding source archive.

Additional pinned upstream notices for Google SDK dependencies:

- [google-cloud-auth-1.17.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE)
- [google-cloud-gax-1.15.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE)
- [google-cloud-gax-internal-0.7.20.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/2a03d923a0d56114e15cc7404de33992111c854b/LICENSE)
- [google-cloud-iam-v1-1.13.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE)
- [google-cloud-kms-v1-1.15.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE)
- [google-cloud-location-1.12.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE)
- [google-cloud-longrunning-1.14.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE)
- [google-cloud-lro-1.11.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/373bb9cc698f45e1f63e41beef090924af2ac2a4/LICENSE)
- [google-cloud-rpc-1.6.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/544a5d8f29117f2611aeadc4b3d30843710371e2/LICENSE)
- [google-cloud-type-1.6.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/544a5d8f29117f2611aeadc4b3d30843710371e2/LICENSE)
- [google-cloud-wkt-1.9.0.txt](https://raw.githubusercontent.com/googleapis/google-cloud-rust/2a03d923a0d56114e15cc7404de33992111c854b/LICENSE)
- [jni-0.22.4.txt](https://raw.githubusercontent.com/jni-rs/jni-rs/5ae9458a4ec44c5318f37ddc7569c1d4ae8a69e7/LICENSE-APACHE)
- [jni-macros-0.22.4.txt](https://raw.githubusercontent.com/jni-rs/jni-rs/33045a124105c939d1e2cbdcb5a39e5d868ffa03/LICENSE-APACHE)
- [jni-sys-macros-0.4.1.txt](https://raw.githubusercontent.com/jni-rs/jni-sys/64d77b7a5f119d7b55b4e2c169a4668067ff59e6/LICENSE-APACHE)
- [opentelemetry-0.33.1.txt](https://raw.githubusercontent.com/open-telemetry/opentelemetry-rust/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/LICENSE)
- [opentelemetry-semantic-conventions-0.33.1.txt](https://raw.githubusercontent.com/open-telemetry/opentelemetry-rust/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/LICENSE)
- [opentelemetry_sdk-0.33.1.txt](https://raw.githubusercontent.com/open-telemetry/opentelemetry-rust/372ebbc74d4dba71bb9820732f57f7316b4e7a1e/LICENSE)
- [rustls-platform-verifier-android-0.2.0.txt](https://raw.githubusercontent.com/rustls/rustls-platform-verifier/252e25161a91af476cbea620e29d277592d27ec7/LICENSE-APACHE)
- [tonic-prost-0.14.6.txt](https://raw.githubusercontent.com/hyperium/tonic/6cb6056b5a748bc5a29bd48f4602dbc4e552bb7d/LICENSE)
- [valuable-0.1.1.txt](https://raw.githubusercontent.com/tokio-rs/valuable/9efc29b6e58cef28f6566a47aa7e142a55fead77/LICENSE)
