use anyhow::{Context, Result, bail, ensure};
use aws_sdk_kms::{
    Client,
    config::{Region, retry::RetryConfig, timeout::TimeoutConfig},
    primitives::Blob,
    types::{KeySpec, KeyState, KeyUsageType, MessageType, SigningAlgorithmSpec},
};
use sequoia_openpgp::types::HashAlgorithm;
use std::time::{Duration, UNIX_EPOCH};

use crate::provider::{Kind, Material, RemoteSigner};
pub fn region(arn: &str) -> Result<String> {
    let p: Vec<_> = arn.split(':').collect();
    ensure!(
        p.len() == 6
            && p[0] == "arn"
            && matches!(p[1], "aws" | "aws-cn" | "aws-us-gov")
            && p[2] == "kms"
            && !p[3].is_empty()
            && p[4].len() == 12
            && p[4].bytes().all(|c| c.is_ascii_digit()),
        "expected a concrete AWS KMS key ARN"
    );
    let id = p[5]
        .strip_prefix("key/")
        .context("aliases are not supported; supply a key ARN")?;
    let id = id.strip_prefix("mrk-").unwrap_or(id);
    ensure!(
        matches!(id.len(), 32 | 36) && id.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-'),
        "invalid KMS key ID"
    );
    Ok(p[3].to_owned())
}
pub fn algorithm(kind: Kind, hash: HashAlgorithm) -> Result<(SigningAlgorithmSpec, MessageType)> {
    Ok(match (kind, hash) {
        (Kind::Rsa(_), HashAlgorithm::SHA256) => (
            SigningAlgorithmSpec::RsassaPkcs1V15Sha256,
            MessageType::Digest,
        ),
        (Kind::Rsa(_), HashAlgorithm::SHA384) => (
            SigningAlgorithmSpec::RsassaPkcs1V15Sha384,
            MessageType::Digest,
        ),
        (Kind::Rsa(_), HashAlgorithm::SHA512) => (
            SigningAlgorithmSpec::RsassaPkcs1V15Sha512,
            MessageType::Digest,
        ),
        (Kind::Ed25519, HashAlgorithm::SHA512) => {
            (SigningAlgorithmSpec::Ed25519Sha512, MessageType::Raw)
        }
        _ => bail!("unsupported digest for this key"),
    })
}
pub struct Kms {
    client: Client,
    runtime: tokio::runtime::Runtime,
    arn: String,
    kind: Kind,
    ua: String,
}
impl Kms {
    pub fn connect(arn: &str, ua: String) -> Result<(Self, Material)> {
        let region = region(arn)?;
        let runtime = tokio::runtime::Runtime::new()?;
        let config = runtime.block_on(
            aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(Region::new(region))
                .retry_config(RetryConfig::standard().with_max_attempts(3))
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_timeout(Duration::from_secs(60))
                        .build(),
                )
                .load(),
        );
        let client = Client::new(&config);
        let desc = runtime
            .block_on(client.describe_key().key_id(arn).send())
            .context("KMS DescribeKey failed")?;
        let m = desc.key_metadata.context("KMS returned no key metadata")?;
        ensure!(
            m.arn.as_deref() == Some(arn),
            "KMS returned a different key ARN"
        );
        ensure!(
            m.key_usage == Some(KeyUsageType::SignVerify) && m.key_state == Some(KeyState::Enabled),
            "key must be enabled with SIGN_VERIFY usage"
        );
        let kind = match m.key_spec {
            Some(KeySpec::Rsa2048) => Kind::Rsa(2048),
            Some(KeySpec::Rsa3072) => Kind::Rsa(3072),
            Some(KeySpec::Rsa4096) => Kind::Rsa(4096),
            Some(KeySpec::EccNistEdwards25519) => Kind::Ed25519,
            _ => bail!("supported key types: RSA_2048/3072/4096 and ECC_NIST_EDWARDS25519"),
        };
        let seconds = m.creation_date.context("missing key creation date")?.secs();
        ensure!(
            seconds >= 0 && seconds <= u32::MAX as i64,
            "key creation time is outside OpenPGP v4 range"
        );
        let public = runtime
            .block_on(client.get_public_key().key_id(arn).send())
            .context("KMS GetPublicKey failed")?;
        ensure!(
            public.key_id.as_deref() == Some(arn)
                && public.key_spec == m.key_spec
                && public.key_usage == Some(KeyUsageType::SignVerify),
            "inconsistent KMS public-key metadata"
        );
        let expected = algorithm(
            kind,
            if kind == Kind::Ed25519 {
                HashAlgorithm::SHA512
            } else {
                HashAlgorithm::SHA256
            },
        )?
        .0;
        ensure!(
            public.signing_algorithms().contains(&expected),
            "KMS does not advertise the required signing algorithm"
        );
        let material = Material {
            der: public
                .public_key
                .context("missing public key")?
                .into_inner(),
            created: UNIX_EPOCH + Duration::from_secs(seconds as u64),
            kind,
            hashes: if kind == Kind::Ed25519 {
                vec![HashAlgorithm::SHA512]
            } else {
                vec![
                    HashAlgorithm::SHA256,
                    HashAlgorithm::SHA384,
                    HashAlgorithm::SHA512,
                ]
            },
        };
        Ok((
            Self {
                client,
                runtime,
                arn: arn.to_owned(),
                kind,
                ua,
            },
            material,
        ))
    }
}
impl RemoteSigner for Kms {
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>> {
        let (algorithm, message_type) = algorithm(self.kind, hash)?;
        ensure!(digest.len() == hash.digest_size()?, "wrong digest size");
        let ua = self.ua.clone();
        let response = self
            .runtime
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.arn)
                    .signing_algorithm(algorithm.clone())
                    .message_type(message_type)
                    .message(Blob::new(digest))
                    .customize()
                    .mutate_request(move |r| {
                        r.headers_mut().insert("user-agent", ua.clone());
                    })
                    .send(),
            )
            .context("KMS Sign failed")?;
        ensure!(
            response.key_id.as_deref() == Some(&self.arn)
                && response.signing_algorithm == Some(algorithm),
            "KMS returned inconsistent signing metadata"
        );
        Ok(response
            .signature
            .context("KMS returned no signature")?
            .into_inner())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::user_agent;
    #[test]
    fn validate_arn() {
        assert_eq!(
            region("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
                .unwrap(),
            "us-east-1"
        );
        for a in [
            "alias/test",
            "arn:aws:kms:us-east-1:123456789012:alias/test",
            "arn:evil:kms:r:123456789012:key/abc",
        ] {
            assert!(region(a).is_err());
        }
    }
    #[test]
    fn mapping() {
        assert_eq!(
            algorithm(Kind::Ed25519, HashAlgorithm::SHA512).unwrap(),
            (SigningAlgorithmSpec::Ed25519Sha512, MessageType::Raw)
        );
        assert!(algorithm(Kind::Ed25519, HashAlgorithm::SHA256).is_err());
        for hash in [
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            assert_eq!(
                algorithm(Kind::Rsa(2048), hash).unwrap().1,
                MessageType::Digest
            );
        }
    }
    #[test]
    fn header_encoding() {
        let ua = user_agent(Some("release\n✓")).unwrap();
        assert!(ua.is_ascii());
        assert!(!ua.contains('\n'));
        assert!(user_agent(Some(&"x".repeat(1024))).is_err());
    }
}
