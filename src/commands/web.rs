use anyhow::{Result, bail};
use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct WebCommand {}

impl WebCommand {
    pub async fn execute(self, profile: &str) -> Result<()> {
        bail!(
            "AWS Management Console access not yet implemented for profile: {}",
            profile
        )
    }
}
