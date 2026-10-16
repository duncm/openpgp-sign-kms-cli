//! Provider-independent key capabilities and dispatch. The first hash is the default.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sequoia_openpgp::types::HashAlgorithm;
use std::time::SystemTime;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rsa(u32),
    Ed25519,
}
pub struct Material {
    pub der: Vec<u8>,
    pub created: SystemTime,
    pub kind: Kind,
    pub hashes: Vec<HashAlgorithm>,
}
pub trait RemoteSigner: Send + Sync {
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>>;
}
impl RemoteSigner for Box<dyn RemoteSigner> {
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>> {
        (**self).sign(hash, digest)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Provider {
    Aws,
    Google,
}
pub fn identify(key: &str) -> Result<Provider> {
    if key.starts_with("arn:") {
        crate::kms::region(key)?;
        Ok(Provider::Aws)
    } else {
        google_version(key)?;
        Ok(Provider::Google)
    }
}
pub fn google_version(key: &str) -> Result<()> {
    let p: Vec<_> = key.split('/').collect();
    ensure!(
        p.len() == 10
            && p[0] == "projects"
            && p[2] == "locations"
            && p[4] == "keyRings"
            && p[6] == "cryptoKeys"
            && p[8] == "cryptoKeyVersions",
        "expected a concrete AWS key ARN or Google CryptoKeyVersion resource name"
    );
    for i in [1, 3, 5, 7] {
        ensure!(
            !p[i].is_empty()
                && p[i].len() <= 63
                && p[i]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || (i >= 5 && b == b'_')),
            "invalid Google resource identifier"
        );
    }
    ensure!(
        p[9].parse::<u64>().is_ok_and(|n| n > 0)
            && !p[9].starts_with('0')
            && p[9].bytes().all(|b| b.is_ascii_digit()),
        "Google key requires an explicit positive numeric version"
    );
    Ok(())
}
pub fn connect(key: &str, ua: String) -> Result<(Box<dyn RemoteSigner>, Material)> {
    match identify(key)? {
        Provider::Aws => {
            let (s, m) = crate::kms::Kms::connect(key, ua)?;
            Ok((Box::new(s), m))
        }
        Provider::Google => {
            let (s, m) = crate::gcp::Kms::connect(key, ua)?;
            Ok((Box::new(s), m))
        }
    }
}
pub fn user_agent(description: Option<&str>) -> Result<String> {
    let mut ua = format!("openpgp-sign-kms/{}", env!("CARGO_PKG_VERSION"));
    if let Some(d) = description.filter(|d| !d.is_empty()) {
        ua.push_str(" description/");
        ua.push_str(&URL_SAFE_NO_PAD.encode(d));
    }
    ensure!(
        ua.len() <= 1024,
        "description exceeds the 1024-byte encoded User-Agent budget"
    );
    Ok(ua)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_version_required() {
        let name = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/rsa/cryptoKeyVersions/1";
        assert_eq!(identify(name).unwrap(), Provider::Google);
        for bad in [
            name.replace("/1", "/0"),
            name.replace("/1", "/primary"),
            name.replace("/1", "/01"),
            format!("https://cloudkms.googleapis.com/v1/{name}"),
            name.replace("/cryptoKeyVersions/1", ""),
            name.replace("test-project", "test%2fproject"),
        ] {
            assert!(identify(&bad).is_err(), "{bad}");
        }
    }
}
