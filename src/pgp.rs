use crate::{
    args::Mode,
    kms::{Kind, Material, RemoteSigner},
};
use anyhow::{Result, ensure};
use openssl::{
    md::Md,
    pkey::{PKey, Public},
    pkey_ctx::PkeyCtx,
    rsa::Padding,
};
use pgp::{
    Packet,
    crypto::{Signer as CryptoSigner, mpi},
    packet::{
        Key, Signature, UserID,
        key::{Key4, PublicParts, UnspecifiedRole},
        signature::SignatureBuilder,
    },
    serialize::{
        Serialize,
        stream::{Armorer, LiteralWriter, Message, Signer},
    },
    types::{HashAlgorithm, KeyFlags, SignatureType},
};
use sequoia_openpgp as pgp;
use std::{
    io::{Read, Write},
    time::SystemTime,
};

pub struct SignerAdapter<R: RemoteSigner> {
    pub key: Key<PublicParts, UnspecifiedRole>,
    remote: R,
    public: PKey<Public>,
    kind: Kind,
}
impl<R: RemoteSigner> SignerAdapter<R> {
    pub fn new(material: Material, remote: R) -> Result<Self> {
        let public = PKey::public_key_from_der(&material.der)?;
        let key = match material.kind {
            Kind::Rsa(bits) => {
                let rsa = public.rsa()?;
                ensure!(
                    rsa.n().num_bits() == bits as i32,
                    "RSA key size disagrees with KMS metadata"
                );
                Key4::import_public_rsa(&rsa.e().to_vec(), &rsa.n().to_vec(), material.created)?
                    .into()
            }
            Kind::Ed25519 => {
                ensure!(
                    public.id() == openssl::pkey::Id::ED25519,
                    "expected Ed25519 public key"
                );
                Key4::import_public_ed25519(&public.raw_public_key()?, material.created)?.into()
            }
        };
        Ok(Self {
            key,
            remote,
            public,
            kind: material.kind,
        })
    }
    pub fn default_hash(&self) -> HashAlgorithm {
        if self.kind == Kind::Ed25519 {
            HashAlgorithm::SHA512
        } else {
            HashAlgorithm::SHA256
        }
    }
}
impl<R: RemoteSigner> CryptoSigner for SignerAdapter<R> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.key
    }
    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        if self.kind == Kind::Ed25519 {
            &[HashAlgorithm::SHA512]
        } else {
            &[
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA512,
            ]
        }
    }
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> pgp::Result<mpi::Signature> {
        crate::kms::algorithm(self.kind, hash)?;
        ensure!(
            digest.len() == hash.digest_size()?,
            "invalid OpenPGP digest length"
        );
        let bytes = self.remote.sign(hash, digest)?;
        match self.kind {
            Kind::Rsa(bits) => {
                ensure!(
                    bytes.len() == bits as usize / 8,
                    "invalid RSA signature size"
                );
                let mut ctx = PkeyCtx::new(&self.public)?;
                ctx.verify_init()?;
                ctx.set_rsa_padding(Padding::PKCS1)?;
                ctx.set_signature_md(match hash {
                    HashAlgorithm::SHA256 => Md::sha256(),
                    HashAlgorithm::SHA384 => Md::sha384(),
                    HashAlgorithm::SHA512 => Md::sha512(),
                    _ => unreachable!(),
                })?;
                ensure!(
                    ctx.verify(digest, &bytes)?,
                    "KMS RSA signature failed local verification"
                );
                Ok(mpi::Signature::RSA {
                    s: mpi::MPI::new(&bytes),
                })
            }
            Kind::Ed25519 => {
                ensure!(bytes.len() == 64, "invalid Ed25519 signature size");
                let mut verifier = openssl::sign::Verifier::new_without_digest(&self.public)?;
                ensure!(
                    verifier.verify_oneshot(&bytes, digest)?,
                    "KMS Ed25519 signature failed local verification"
                );
                Ok(mpi::Signature::EdDSA {
                    r: mpi::MPI::new(&bytes[..32]),
                    s: mpi::MPI::new(&bytes[32..]),
                })
            }
        }
    }
}
pub fn sign<R: RemoteSigner>(
    input: &mut dyn Read,
    output: &mut (dyn Write + Send + Sync),
    signer: SignerAdapter<R>,
    mode: Mode,
    armor: bool,
    hash: HashAlgorithm,
    time: SystemTime,
) -> Result<()> {
    let message = Message::new(output);
    let message = if armor && mode != Mode::Clear {
        Armorer::new(message)
            .kind(if mode == Mode::Detached {
                pgp::armor::Kind::Signature
            } else {
                pgp::armor::Kind::Message
            })
            .build()?
    } else {
        message
    };
    let builder = Signer::new(message, signer)?
        .hash_algo(hash)?
        .creation_time(time);
    match mode {
        Mode::Attached => {
            let mut writer = LiteralWriter::new(builder.build()?).build()?;
            std::io::copy(input, &mut writer)?;
            writer.finalize()?;
        }
        Mode::Detached => {
            let mut writer = builder.detached().build()?;
            std::io::copy(input, &mut writer)?;
            writer.finalize()?;
        }
        Mode::Clear => {
            let mut writer = builder.cleartext().build()?;
            std::io::copy(input, &mut writer)?;
            writer.finalize()?;
        }
        Mode::Export => anyhow::bail!("export is not a document signature"),
    }
    Ok(())
}
pub fn export<R: RemoteSigner>(
    signer: &mut SignerAdapter<R>,
    name: &str,
    email: &str,
    comment: Option<&str>,
    output: &mut dyn Write,
    armor: bool,
    hash: HashAlgorithm,
) -> Result<()> {
    ensure!(
        !name.contains(['\n', '\r'])
            && !email.contains(['\n', '\r'])
            && !comment.unwrap_or("").contains(['\n', '\r']),
        "identity must be a single line"
    );
    let uid = UserID::from_unchecked_address(Some(name), comment, email)?;
    let signature: Signature = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(hash)
        .set_signature_creation_time(SystemTime::now())?
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())?
        .set_preferred_hash_algorithms(vec![signer.default_hash()])?
        .sign_userid_binding(signer, None, &uid)?;
    let packets = vec![
        Packet::PublicKey(signer.key.clone().role_into_primary()),
        Packet::UserID(uid),
        Packet::Signature(signature),
    ];
    let cert = pgp::Cert::from_packets(packets.into_iter())?;
    if armor {
        cert.armored().serialize(output)?;
    } else {
        cert.serialize(output)?;
    }
    Ok(())
}
