use anyhow::{Context, Result};
use aws_smithy_types::date_time::Format;
use clap::Args;
use tracing::info;

use crate::{aws, browser, config, saml};

#[derive(Debug, Clone, Args)]
pub struct AuthCommand {
    #[arg(short = 'r', long, help = "AWS IAM role name to assume")]
    pub role: Option<String>,
}

impl AuthCommand {
    pub async fn execute(self, profile: &str) -> Result<()> {
        info!("Starting authentication for profile: {}", profile);

        // Load configuration
        let config = config::load(profile)
            .await
            .with_context(|| format!("Failed to load configuration for profile '{profile}'. Please run 'assam configure' first."))?;

        // Generate SAML request
        let saml_request =
            saml::create_request(&config.app_id_uri).context("Failed to create SAML request")?;

        info!("Opening browser for Azure Entra ID authentication...");
        println!("Please complete authentication in the browser window.");

        // Authenticate via browser
        let saml_response = browser::authenticate(
            &saml_request,
            &config.azure_tenant_id,
            &config.chrome_user_data_dir,
        )
        .await
        .context("Failed to complete browser authentication")?;

        // Extract role information from SAML response
        let (role_arn, principal_arn) =
            saml::extract_role_from_response(&saml_response, self.role.as_deref())
                .context("Failed to extract role information from SAML response")?;

        info!("Requesting AWS credentials for role: {}", role_arn);

        // Get AWS credentials
        let credentials = aws::assume_role_with_saml(
            profile,
            &saml_response,
            &role_arn,
            &principal_arn,
            i32::from(config.default_session_duration_hours) * 3600,
        )
        .await
        .context("Failed to assume AWS role with SAML")?;

        // Save credentials
        aws::save_credentials(profile, &credentials)
            .await
            .context("Failed to save AWS credentials")?;

        println!("\nAWS credentials saved to {profile} profile.");
        println!(
            "Credentials will expire at: {}",
            credentials
                .expiration
                .fmt(Format::DateTime)
                .unwrap_or_else(|_| "unknown".to_string())
        );

        Ok(())
    }
}
