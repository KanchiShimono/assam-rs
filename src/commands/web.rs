use anyhow::Result;
use clap::Args;

use crate::aws;

#[derive(Debug, Default, Clone, Args)]
pub(crate) struct WebCommand {}

impl WebCommand {
    pub(crate) async fn execute(self, profile: &str) -> Result<()> {
        aws::console::open_console(profile).await
    }
}
