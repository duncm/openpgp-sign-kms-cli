//! Offline SDK harness only. Never packaged or selected by the production CLI.
use clap::Parser;
use openpgp_sign_kms::{args::Args, status::Status};
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut status = Status::new(args.status_fd)?;
    openpgp_sign_kms::app::run(args, &mut status, |name, ua| {
        let runtime = tokio::runtime::Runtime::new()?;
        let client = runtime.block_on(
            google_cloud_kms_v1::client::KeyManagementService::builder()
                .with_endpoint(std::env::var("TEST_GOOGLE_ENDPOINT")?)
                .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
                .build(),
        )?;
        openpgp_sign_kms::gcp::Kms::connect_client(name, ua, runtime, client)
    })
}
