use std::process::ExitCode;

use assam::cli::Cli;
use clap::Parser;
use tracing::{Level, subscriber};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = init_logging(cli.verbose) {
        eprintln!("Failed to initialize logging: {e}");
        return ExitCode::FAILURE;
    }

    match cli.execute().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(verbose: u8) -> anyhow::Result<()> {
    let level = match verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    // Allow RUST_LOG env var to override verbosity flag
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(verbose >= 2)
        .with_thread_ids(verbose >= 3)
        .with_file(verbose >= 3)
        .with_line_number(verbose >= 3)
        .compact()
        .finish();

    subscriber::set_global_default(subscriber)?;

    Ok(())
}
