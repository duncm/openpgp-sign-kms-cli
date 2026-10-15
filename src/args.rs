use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Attached,
    Detached,
    Clear,
    Export,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum GitMetadata {
    #[default]
    Off,
    Auto,
}

/// Sign OpenPGP messages using an AWS KMS key. Compatible with Git's GPG signer invocation.
#[derive(Debug, Parser)]
#[command(version, disable_help_subcommand = true)]
pub struct Args {
    #[arg(short = 's', long)]
    pub sign: bool,
    #[arg(short = 'b', long = "detach-sign")]
    pub detach: bool,
    #[arg(long = "clear-sign", alias = "clearsign")]
    pub clear: bool,
    #[arg(long)]
    pub export: bool,
    #[arg(short = 'u', long = "local-user")]
    pub key: Option<String>,
    #[arg(short = 'a', long)]
    pub armor: bool,
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    #[arg(long, value_parser = ["SHA256", "SHA384", "SHA512"], ignore_case = true)]
    pub digest_algo: Option<String>,
    #[arg(long)]
    pub batch: bool,
    #[arg(long)]
    pub no_tty: bool,
    #[arg(long, conflicts_with = "no")]
    pub yes: bool,
    #[arg(long)]
    pub no: bool,
    #[arg(short = 'q', long)]
    pub quiet: bool,
    #[arg(short = 'v', long)]
    pub verbose: bool,
    #[arg(long)]
    pub status_fd: Option<i32>,
    #[arg(long, env = "OPENPGP_SIGN_KMS_DESCRIPTION")]
    pub description: Option<String>,
    #[arg(
        long,
        env = "OPENPGP_SIGN_KMS_GIT_METADATA",
        value_enum,
        default_value = "off"
    )]
    pub git_metadata: GitMetadata,
    #[arg(long)]
    pub export_name: Option<String>,
    #[arg(long)]
    pub export_email: Option<String>,
    #[arg(long)]
    pub export_comment: Option<String>,
    pub input: Option<PathBuf>,
}
impl Args {
    pub fn mode(&self) -> Result<Mode> {
        if self.export {
            if self.sign || self.detach || self.clear || self.input.is_some() {
                bail!("--export cannot be combined with signing or input files")
            }
            if self.export_name.as_deref().is_none_or(str::is_empty)
                || self.export_email.as_deref().is_none_or(str::is_empty)
            {
                bail!("--export requires --export-name and --export-email")
            }
            return Ok(Mode::Export);
        }
        if !self.sign && !self.detach && !self.clear {
            bail!("specify --sign, --detach-sign, --clear-sign, or --export")
        }
        // GPG's clear-sign command wins over sign/detach modifiers.
        Ok(if self.clear {
            Mode::Clear
        } else if self.detach {
            Mode::Detached
        } else {
            Mode::Attached
        })
    }
    pub fn output_path(&self, mode: Mode) -> Option<PathBuf> {
        if let Some(p) = &self.output {
            return (p.as_os_str() != "-").then(|| p.clone());
        }
        if mode == Mode::Export {
            return None;
        }
        self.input
            .as_ref()
            .filter(|p| p.as_os_str() != "-")
            .map(|p| {
                let suffix = if self.armor || mode == Mode::Clear {
                    ".asc"
                } else if mode == Mode::Detached {
                    ".sig"
                } else {
                    ".gpg"
                };
                let mut name = p.as_os_str().to_os_string();
                name.push(suffix);
                PathBuf::from(name)
            })
    }
}

/// Extract our delegation option before passing GPG's own arguments through unchanged.
pub fn delegation(raw: &[OsString]) -> Result<Option<(PathBuf, Vec<OsString>)>> {
    let mut args = Vec::new();
    let mut program = std::env::var_os("OPENPGP_SIGN_KMS_GPG").map(PathBuf::from);
    let mut verify = false;
    let mut options = true;
    let mut i = 0;
    while i < raw.len() {
        let s = raw[i].to_string_lossy();
        if options && s == "--" {
            options = false;
        } else if options && s == "--verify" {
            verify = true;
        } else if options && s == "--gpg-program" {
            i += 1;
            program =
                Some(PathBuf::from(raw.get(i).ok_or_else(|| {
                    anyhow::anyhow!("--gpg-program needs a path")
                })?));
            i += 1;
            continue;
        } else if options && s.starts_with("--gpg-program=") {
            program = Some(PathBuf::from(&s[14..]));
            i += 1;
            continue;
        }
        args.push(raw[i].clone());
        i += 1;
    }
    if !verify {
        return Ok(None);
    }
    // Do not delegate any invocation that also requests private-key operations.
    for a in &args {
        let s = a.to_string_lossy();
        if matches!(
            s.as_ref(),
            "--sign" | "--detach-sign" | "--clear-sign" | "--clearsign" | "--export"
        ) || (s.starts_with('-')
            && !s.starts_with("--")
            && s != "-"
            && s[1..].chars().any(|c| matches!(c, 's' | 'b')))
        {
            bail!("verification cannot be combined with signing")
        }
    }
    let p = program.ok_or_else(|| {
        anyhow::anyhow!("verification requires --gpg-program or OPENPGP_SIGN_KMS_GPG")
    })?;
    if !p.is_absolute() {
        bail!("GPG delegate must be an absolute path")
    }
    let p = std::fs::canonicalize(p)?;
    use std::os::unix::fs::MetadataExt;
    let a = std::fs::metadata(&p)?;
    let b = std::fs::metadata(std::env::current_exe()?)?;
    if (a.dev(), a.ino()) == (b.dev(), b.ino())
        || std::env::var_os("OPENPGP_SIGN_KMS_DELEGATING").is_some()
    {
        bail!("recursive GPG delegation refused")
    }
    Ok(Some((p, args)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn git_cluster() {
        let a = Args::try_parse_from(["kms", "--status-fd=2", "-bsau", "arn"]).unwrap();
        assert_eq!(a.mode().unwrap(), Mode::Detached);
        assert!(a.armor);
        assert_eq!(a.key.as_deref(), Some("arn"));
    }
    #[test]
    fn modes_and_paths() {
        for (flag, suffix) in [
            ("--sign", ".gpg"),
            ("--detach-sign", ".sig"),
            ("--clear-sign", ".asc"),
        ] {
            let a = Args::try_parse_from(["kms", flag, "file"]).unwrap();
            assert_eq!(
                a.output_path(a.mode().unwrap()).unwrap(),
                PathBuf::from(format!("file{suffix}"))
            );
        }
    }
    #[test]
    fn unknown_and_duplicate_key() {
        assert!(Args::try_parse_from(["kms", "--encrypt"]).is_err());
        assert!(Args::try_parse_from(["kms", "-u", "one", "-u", "two", "-s"]).is_err());
    }
}
