use crate::{
    args::{Args, Mode},
    kms::user_agent,
    output::Output,
    pgp::{self, SignerAdapter},
    status::Status,
};
use anyhow::{Context, Result, ensure};
use sequoia_openpgp::{crypto::Signer, types::HashAlgorithm};
use std::{
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn run<R: crate::kms::RemoteSigner>(
    args: Args,
    status: &mut Status,
    connect: impl FnOnce(&str, String) -> Result<(R, crate::kms::Material)>,
) -> Result<()> {
    let mode = args.mode()?;
    let arn = args
        .key
        .as_deref()
        .context("--local-user requires a concrete KMS key ARN")?;
    crate::kms::region(arn)?;
    let ua = user_agent(args.description.as_deref())?;
    let output_path = args.output_path(mode);
    ensure!(
        !(output_path.is_none() && args.status_fd == Some(1)),
        "status-fd=1 would corrupt stdout signature output"
    );
    let mut input: Box<dyn Read> =
        if let Some(p) = args.input.as_deref().filter(|p| p.as_os_str() != "-") {
            let f = std::fs::File::open(p).context("opening input")?;
            ensure!(f.metadata()?.is_file(), "input must be a regular file");
            Box::new(f)
        } else {
            Box::new(std::io::stdin())
        };
    let mut output = Output::prepare(output_path, args.input.as_deref(), args.yes)?;
    let (remote, material) = connect(arn, ua)?;
    let mut signer = SignerAdapter::new(material, remote)?;
    let hash = match args
        .digest_algo
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("SHA256") => HashAlgorithm::SHA256,
        Some("SHA384") => HashAlgorithm::SHA384,
        Some("SHA512") => HashAlgorithm::SHA512,
        _ => signer.default_hash(),
    };
    ensure!(
        signer.acceptable_hashes().contains(&hash),
        "digest is unsupported by this key"
    );
    let fingerprint = signer.public().fingerprint().to_hex();
    let algo = u8::from(signer.public().pk_algo());
    let time = SystemTime::now();
    status.emit("BEGIN_SIGNING")?;
    if mode == Mode::Export {
        pgp::export(
            &mut signer,
            args.export_name.as_deref().unwrap(),
            args.export_email.as_deref().unwrap(),
            args.export_comment.as_deref(),
            output.writer(),
            args.armor,
            hash,
        )?;
    } else {
        pgp::sign(
            &mut *input,
            output.writer(),
            signer,
            mode,
            args.armor,
            hash,
            time,
        )?;
    }
    output.finish()?;
    if mode != Mode::Export {
        let (kind, class) = match mode {
            Mode::Attached => ("S", "00"),
            Mode::Detached => ("D", "00"),
            Mode::Clear => ("C", "01"),
            _ => unreachable!(),
        };
        status.emit(&format!(
            "SIG_CREATED {kind} {algo} {} {class} {} {fingerprint}",
            u8::from(hash),
            time.duration_since(UNIX_EPOCH)?.as_secs()
        ))?;
    }
    Ok(())
}
