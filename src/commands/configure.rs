use anyhow::Result;
use clap::Args;

use crate::config;

#[derive(Debug, Clone, Args)]
pub struct ConfigureCommand {}

impl ConfigureCommand {
    pub async fn execute(self, profile: &str) -> Result<()> {
        config::configure_interactive(profile).await
    }
}
