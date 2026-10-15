use anyhow::Result;
use openpgp_sign_kms::{
    args::Mode,
    kms::{Kind, Material, RemoteSigner},
    pgp::SignerAdapter,
};
use openssl::{
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use sequoia_openpgp::{crypto::Signer, types::HashAlgorithm};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
struct Remote {
    key: PKey<Private>,
    calls: Arc<AtomicUsize>,
    corrupt: bool,
    fail: bool,
}
impl RemoteSigner for Remote {
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            anyhow::bail!("AccessDeniedException")
        }
        let mut signature = if self.key.id() == openssl::pkey::Id::ED25519 {
            openssl::sign::Signer::new_without_digest(&self.key)?.sign_oneshot_to_vec(digest)?
        } else {
            let mut c = PkeyCtx::new(&self.key)?;
            c.sign_init()?;
            c.set_rsa_padding(Padding::PKCS1)?;
            c.set_signature_md(match hash {
                HashAlgorithm::SHA256 => Md::sha256(),
                HashAlgorithm::SHA384 => Md::sha384(),
                HashAlgorithm::SHA512 => Md::sha512(),
                _ => unreachable!(),
            })?;
            let mut v = Vec::new();
            c.sign_to_vec(digest, &mut v)?;
            v
        };
        if self.corrupt {
            signature[0] ^= 1;
        }
        Ok(signature)
    }
}
fn signer(kind: Kind, corrupt: bool, fail: bool) -> (SignerAdapter<Remote>, Arc<AtomicUsize>) {
    let key = match kind {
        Kind::Rsa(bits) => PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap(),
        Kind::Ed25519 => PKey::generate_ed25519().unwrap(),
    };
    let material = Material {
        der: key.public_key_to_der().unwrap(),
        created: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
        kind,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    (
        SignerAdapter::new(
            material,
            Remote {
                key,
                calls: calls.clone(),
                corrupt,
                fail,
            },
        )
        .unwrap(),
        calls,
    )
}
#[test]
fn one_remote_call_per_output() {
    for kind in [Kind::Rsa(2048), Kind::Ed25519] {
        for mode in [Mode::Attached, Mode::Detached, Mode::Clear] {
            let (s, c) = signer(kind, false, false);
            let hash = s.default_hash();
            let mut out = Vec::new();
            openpgp_sign_kms::pgp::sign(
                &mut &b"hello\n"[..],
                &mut out,
                s,
                mode,
                true,
                hash,
                std::time::SystemTime::now(),
            )
            .unwrap();
            assert_eq!(c.load(Ordering::SeqCst), 1);
            assert!(!out.is_empty());
        }
    }
}
#[test]
fn bad_remote_signatures_and_errors_rejected() {
    for kind in [Kind::Rsa(2048), Kind::Ed25519] {
        for (corrupt, fail) in [(true, false), (false, true)] {
            let (mut s, c) = signer(kind, corrupt, fail);
            let h = s.default_hash();
            assert!(s.sign(h, &vec![0; h.digest_size().unwrap()]).is_err());
            assert_eq!(c.load(Ordering::SeqCst), 1);
        }
    }
}
#[test]
fn incompatible_hash_rejected_without_call() {
    let (mut s, c) = signer(Kind::Ed25519, false, false);
    assert!(s.sign(HashAlgorithm::SHA256, &[0; 32]).is_err());
    assert_eq!(c.load(Ordering::SeqCst), 0);
}
#[test]
fn declared_key_size_checked() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let material = Material {
        der: key.public_key_to_der().unwrap(),
        created: std::time::SystemTime::now(),
        kind: Kind::Rsa(4096),
    };
    assert!(
        SignerAdapter::new(
            material,
            Remote {
                key,
                calls: Arc::default(),
                corrupt: false,
                fail: false
            }
        )
        .is_err()
    );
}

#[test]
fn sequoia_verifies_exported_certificates_and_every_format() {
    use sequoia_openpgp::{
        Cert, KeyHandle,
        parse::{
            Parse,
            stream::{
                DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
                VerifierBuilder,
            },
        },
        policy::StandardPolicy,
    };
    use std::io::Read;
    struct Helper(Cert);
    impl VerificationHelper for Helper {
        fn get_certs(&mut self, _: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
            Ok(vec![self.0.clone()])
        }
        fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
            let mut valid = false;
            for layer in structure.iter() {
                if let MessageLayer::SignatureGroup { results } = layer {
                    anyhow::ensure!(
                        !results.is_empty() && results.iter().all(Result::is_ok),
                        "invalid signature group"
                    );
                    valid = true;
                }
            }
            anyhow::ensure!(valid, "no verified signature");
            Ok(())
        }
    }
    for kind in [Kind::Rsa(2048), Kind::Ed25519] {
        for mode in [Mode::Attached, Mode::Detached, Mode::Clear] {
            let (mut signer, calls) = signer(kind, false, false);
            let hash = signer.default_hash();
            let mut certificate = Vec::new();
            openpgp_sign_kms::pgp::export(
                &mut signer,
                "Test",
                "test@example.com",
                None,
                &mut certificate,
                true,
                hash,
            )
            .unwrap();
            let certificate = Cert::from_bytes(&certificate).unwrap();
            calls.store(0, Ordering::SeqCst);
            let mut output = Vec::new();
            let input = b"verify this\n";
            openpgp_sign_kms::pgp::sign(
                &mut &input[..],
                &mut output,
                signer,
                mode,
                true,
                hash,
                std::time::SystemTime::now(),
            )
            .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let policy = StandardPolicy::new();
            if mode == Mode::Detached {
                let mut verifier = DetachedVerifierBuilder::from_bytes(&output)
                    .unwrap()
                    .with_policy(&policy, None, Helper(certificate))
                    .unwrap();
                verifier.verify_bytes(input).unwrap();
            } else {
                let mut verifier = VerifierBuilder::from_bytes(&output)
                    .unwrap()
                    .with_policy(&policy, None, Helper(certificate))
                    .unwrap();
                let mut recovered = Vec::new();
                verifier.read_to_end(&mut recovered).unwrap();
                if mode == Mode::Attached {
                    assert_eq!(recovered, input);
                }
            }
        }
    }
}
