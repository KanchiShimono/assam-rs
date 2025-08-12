use anyhow::Result;
use clap::Args;

use crate::aws;

#[derive(Debug, Clone, Args)]
pub struct WebCommand {}

impl WebCommand {
    pub async fn execute(self, profile: &str) -> Result<()> {
        aws::console::open_console(profile).await
    }
}
