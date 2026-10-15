use clap::Parser;
use openpgp_sign_kms::{
    args::{Args, delegation},
    status::Status,
};
fn main() {
    let raw: Vec<_> = std::env::args_os().skip(1).collect();
    match delegation(&raw) {
        Ok(Some((program, args))) => {
            use std::os::unix::process::CommandExt;
            let error = std::process::Command::new(program)
                .args(args)
                .env("OPENPGP_SIGN_KMS_DELEGATING", "1")
                .exec();
            eprintln!("openpgp-sign-kms: GPG delegation failed: {error}");
            std::process::exit(2)
        }
        Err(e) => {
            eprintln!("openpgp-sign-kms: {e:#}");
            std::process::exit(2)
        }
        Ok(None) => {}
    }
    let args = Args::parse();
    let mut status = match Status::new(args.status_fd) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("openpgp-sign-kms: status descriptor: {e:#}");
            std::process::exit(2)
        }
    };
    if let Err(e) =
        openpgp_sign_kms::app::run(args, &mut status, openpgp_sign_kms::kms::Kms::connect)
    {
        eprintln!("openpgp-sign-kms: {e:#}");
        let _ = status.emit("FAILURE sign 1");
        std::process::exit(2)
    }
}
