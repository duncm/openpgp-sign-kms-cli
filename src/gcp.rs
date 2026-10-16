//! Google Cloud KMS. Explicit versions keep the OpenPGP identity stable.
use crate::provider::{Kind, Material, RemoteSigner, google_version};
use anyhow::{Context, Result, bail, ensure};
use google_cloud_gax::{
    options::RequestOptions,
    retry_policy::{Aip194Strict, RetryPolicyExt},
};
use google_cloud_kms_v1::{
    client::KeyManagementService,
    model::{
        self, ProtectionLevel,
        crypto_key_version::{
            CryptoKeyVersionAlgorithm as Algorithm, CryptoKeyVersionState as State,
        },
    },
};
use sequoia_openpgp::types::HashAlgorithm;
use std::time::{Duration, UNIX_EPOCH};

const DEADLINE: Duration = Duration::from_secs(60);
// REST RequestOptions overrides User-Agent; protocol tests enforce the full-header limit.
pub const USER_AGENT_BUDGET: usize = 1024;

pub fn capabilities(algorithm: &Algorithm) -> Result<(Kind, HashAlgorithm)> {
    Ok(match algorithm {
        Algorithm::RsaSignPkcs12048Sha256 => (Kind::Rsa(2048), HashAlgorithm::SHA256),
        Algorithm::RsaSignPkcs13072Sha256 => (Kind::Rsa(3072), HashAlgorithm::SHA256),
        Algorithm::RsaSignPkcs14096Sha256 => (Kind::Rsa(4096), HashAlgorithm::SHA256),
        Algorithm::RsaSignPkcs14096Sha512 => (Kind::Rsa(4096), HashAlgorithm::SHA512),
        Algorithm::EcSignEd25519 => (Kind::Ed25519, HashAlgorithm::SHA512),
        _ => bail!("unsupported Google signing algorithm: {algorithm:?}"),
    })
}
fn crc32c(bytes: &[u8]) -> u32 {
    crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum(bytes)
}
fn checksum(bytes: &[u8], checksum: Option<i64>) -> Result<()> {
    ensure!(
        checksum == Some(i64::from(crc32c(bytes))),
        "Google KMS CRC32C integrity check failed"
    );
    Ok(())
}
fn material(
    name: &str,
    version: &model::CryptoKeyVersion,
    public: &model::PublicKey,
) -> Result<Material> {
    ensure!(
        version.name == name && public.name == name,
        "Google KMS returned a different key version"
    );
    ensure!(
        version.state == State::Enabled,
        "Google key version must be ENABLED"
    );
    ensure!(
        matches!(
            version.protection_level,
            ProtectionLevel::Software | ProtectionLevel::Hsm
        ),
        "unsupported Google protection level"
    );
    ensure!(
        public.algorithm == version.algorithm
            && public.protection_level == version.protection_level,
        "inconsistent Google public-key metadata"
    );
    let (kind, hash) = capabilities(&version.algorithm)?;
    ensure!(
        kind != Kind::Ed25519 || version.protection_level == ProtectionLevel::Software,
        "Ed25519 requires SOFTWARE protection"
    );
    checksum(public.pem.as_bytes(), public.pem_crc32c)?;
    let seconds = version
        .create_time
        .as_ref()
        .context("missing Google key-version creation time")?
        .seconds();
    ensure!(
        (0..=u32::MAX as i64).contains(&seconds),
        "key creation time is outside OpenPGP v4 range"
    );
    Ok(Material {
        der: openssl::pkey::PKey::public_key_from_pem(public.pem.as_bytes())
            .context("invalid Google public key")?
            .public_key_to_der()?,
        created: UNIX_EPOCH + Duration::from_secs(seconds as u64),
        kind,
        hashes: vec![hash],
    })
}
fn options(ua: &str) -> RequestOptions {
    let mut options = RequestOptions::default();
    options.set_user_agent(ua);
    // Retrying signs is permitted, but is not an exactly-once guarantee.
    options.set_idempotency(true);
    options.set_retry_policy(Aip194Strict.with_attempt_limit(3).with_time_limit(DEADLINE));
    options.set_attempt_timeout(DEADLINE);
    options
}
pub struct Kms {
    client: KeyManagementService,
    runtime: tokio::runtime::Runtime,
    name: String,
    kind: Kind,
    hash: HashAlgorithm,
    protection: ProtectionLevel,
    ua: String,
}
impl Kms {
    pub fn connect(name: &str, ua: String) -> Result<(Self, Material)> {
        google_version(name)?;
        ensure!(
            ua.len() <= USER_AGENT_BUDGET,
            "description exceeds the 1024-byte encoded User-Agent budget"
        );
        let runtime = tokio::runtime::Runtime::new()?;
        let client = runtime.block_on(async {
            tokio::time::timeout(DEADLINE, KeyManagementService::builder().build()).await
        })??;
        Self::connect_client(name, ua, runtime, client)
    }
    /// Also used by the offline protocol harness with a local endpoint and anonymous credentials.
    pub fn connect_client(
        name: &str,
        ua: String,
        runtime: tokio::runtime::Runtime,
        client: KeyManagementService,
    ) -> Result<(Self, Material)> {
        google_version(name)?;
        ensure!(
            ua.len() <= USER_AGENT_BUDGET,
            "Google User-Agent budget exceeded"
        );
        let (version, public) = runtime.block_on(async {
            tokio::time::timeout(DEADLINE, async {
                let version = client
                    .get_crypto_key_version()
                    .set_name(name)
                    .with_options(options(&ua))
                    .send()
                    .await
                    .context("Google GetCryptoKeyVersion failed")?;
                ensure!(
                    version.name == name && version.state == State::Enabled,
                    "Google key version is disabled or mismatched"
                );
                capabilities(&version.algorithm)?;
                let public = client
                    .get_public_key()
                    .set_name(name)
                    .with_options(options(&ua))
                    .send()
                    .await
                    .context("Google GetPublicKey failed")?;
                Ok::<_, anyhow::Error>((version, public))
            })
            .await
            .context("Google metadata operation timed out")?
        })?;
        let material = material(name, &version, &public)?;
        let signer = Self {
            client,
            runtime,
            name: name.to_owned(),
            kind: material.kind,
            hash: material.hashes[0],
            protection: version.protection_level,
            ua,
        };
        Ok((signer, material))
    }
}
impl RemoteSigner for Kms {
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            hash == self.hash && digest.len() == hash.digest_size()?,
            "digest does not match Google key version algorithm"
        );
        let crc = i64::from(crc32c(digest));
        let request = self
            .client
            .asymmetric_sign()
            .set_name(&self.name)
            .with_options(options(&self.ua));
        let request = if self.kind == Kind::Ed25519 {
            request.set_data(digest.to_vec()).set_data_crc32c(crc)
        } else {
            let digest = match hash {
                HashAlgorithm::SHA256 => model::Digest::new().set_sha256(digest.to_vec()),
                HashAlgorithm::SHA512 => model::Digest::new().set_sha512(digest.to_vec()),
                _ => bail!("unsupported Google RSA digest"),
            };
            request.set_digest(digest).set_digest_crc32c(crc)
        };
        let response = self
            .runtime
            .block_on(async { tokio::time::timeout(DEADLINE, request.send()).await })
            .context("Google signing operation timed out")?
            .context("Google AsymmetricSign failed")?;
        ensure!(
            response.name == self.name && response.protection_level == self.protection,
            "inconsistent Google signature metadata"
        );
        ensure!(
            if self.kind == Kind::Ed25519 {
                response.verified_data_crc32c
            } else {
                response.verified_digest_crc32c
            },
            "Google did not verify the request checksum"
        );
        checksum(&response.signature, response.signature_crc32c)?;
        Ok(response.signature.to_vec())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn algorithms() {
        for (algorithm, bits, hash) in [
            (
                Algorithm::RsaSignPkcs12048Sha256,
                2048,
                HashAlgorithm::SHA256,
            ),
            (
                Algorithm::RsaSignPkcs13072Sha256,
                3072,
                HashAlgorithm::SHA256,
            ),
            (
                Algorithm::RsaSignPkcs14096Sha256,
                4096,
                HashAlgorithm::SHA256,
            ),
            (
                Algorithm::RsaSignPkcs14096Sha512,
                4096,
                HashAlgorithm::SHA512,
            ),
        ] {
            assert_eq!(capabilities(&algorithm).unwrap(), (Kind::Rsa(bits), hash));
        }
        assert_eq!(
            capabilities(&Algorithm::EcSignEd25519).unwrap(),
            (Kind::Ed25519, HashAlgorithm::SHA512)
        );
        assert!(capabilities(&Algorithm::RsaSignPss2048Sha256).is_err());
    }
    #[test]
    fn integrity() {
        let crc = i64::from(crc32c(b"payload"));
        assert!(checksum(b"payload", Some(crc)).is_ok());
        for c in [None, Some(-1), Some(crc + 1), Some(i64::MAX)] {
            assert!(checksum(b"payload", c).is_err());
        }
    }
}
