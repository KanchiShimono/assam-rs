use anyhow::Result;
use clap::Args;

use crate::config;

#[derive(Debug, Default, Clone, Args)]
pub(crate) struct ConfigCommand {}

impl ConfigCommand {
    pub(crate) async fn execute(self, profile: &str) -> Result<()> {
        config::configure_interactive(profile).await
    }
}
