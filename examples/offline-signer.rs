//! Test-only signing executable. Never included in a release or selected by the production CLI.
use anyhow::Result;
use clap::Parser;
use openpgp_sign_kms::{
    args::Args,
    kms::{Kind, Material, RemoteSigner},
    status::Status,
};
use openssl::{
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::Padding,
};
use sequoia_openpgp::types::HashAlgorithm;
struct Local(PKey<Private>);
impl RemoteSigner for Local {
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>> {
        if self.0.id() == openssl::pkey::Id::ED25519 {
            return Ok(
                openssl::sign::Signer::new_without_digest(&self.0)?.sign_oneshot_to_vec(digest)?
            );
        }
        let mut ctx = PkeyCtx::new(&self.0)?;
        ctx.sign_init()?;
        ctx.set_rsa_padding(Padding::PKCS1)?;
        ctx.set_signature_md(match hash {
            HashAlgorithm::SHA256 => Md::sha256(),
            HashAlgorithm::SHA384 => Md::sha384(),
            HashAlgorithm::SHA512 => Md::sha512(),
            _ => anyhow::bail!("bad hash"),
        })?;
        let mut out = Vec::new();
        ctx.sign_to_vec(digest, &mut out)?;
        Ok(out)
    }
}
fn main() -> Result<()> {
    let args = Args::parse();
    let mut status = Status::new(args.status_fd)?;
    openpgp_sign_kms::app::run(args, &mut status, |_, _| {
        let key = PKey::private_key_from_pem(&std::fs::read(std::env::var("TEST_SIGNING_PEM")?)?)?;
        let kind = if key.id() == openssl::pkey::Id::ED25519 {
            Kind::Ed25519
        } else {
            Kind::Rsa(key.rsa()?.n().num_bits() as u32)
        };
        let m = Material {
            der: key.public_key_to_der()?,
            created: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
            kind,
        };
        Ok((Local(key), m))
    })
}
