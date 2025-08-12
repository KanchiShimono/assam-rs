use anyhow::{Context, Result};
use aws_smithy_types::date_time::Format;
use clap::Args;
use tracing::info;

use crate::{
    aws::{self, AvailableRoles},
    browser::{BrowserAutomation, ChromeBrowser},
    config,
    idp::{IdentityProvider, azure::AzureProvider},
    saml::{SamlRequest, SamlResponse},
};

/// AWS SAML endpoint URL (where SAML response is posted)
const AWS_SAML_ENDPOINT: &str = "https://signin.aws.amazon.com/saml";

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
            .with_context(|| format!("Failed to load configuration for profile '{profile}'. Please run 'assam config' first."))?;

        // Create IdP instance (currently only Azure is supported)
        let idp = IdentityProvider::Azure(AzureProvider::new(config.azure_tenant_id.clone()));

        // Generate SAML request
        let saml_request = SamlRequest {
            issuer: config.app_id_uri.clone(),
            acs_url: AWS_SAML_ENDPOINT.to_string(),
        };
        let encoded_request = saml_request
            .generate()
            .context("Failed to create SAML request")?;

        // Build authentication URL
        let auth_url = idp.build_auth_url(&encoded_request);

        info!("Opening browser for authentication...");
        println!("Please complete authentication in the browser window.");

        // Authenticate via browser using the new abstraction
        let chrome = ChromeBrowser::new(config.chrome_user_data_dir.clone());
        let saml_response_base64 = chrome
            .capture_saml_response(auth_url, |url| url == AWS_SAML_ENDPOINT)
            .await
            .context("Failed to complete browser authentication")?;

        // Parse SAML response
        let saml_response = SamlResponse::from_base64(&saml_response_base64)
            .context("Failed to decode SAML response")?;

        // Extract available roles from SAML response
        let available_roles = AvailableRoles::from_saml_response(&saml_response)
            .context("Failed to extract roles from SAML response")?;

        // Select the appropriate role
        let selected_role = available_roles
            .assume(self.role.as_deref())
            .context("Failed to select role")?;

        info!(
            "Requesting AWS credentials for role: {}",
            selected_role.role_arn
        );

        // Get AWS credentials
        let credentials = aws::sts::assume_role_with_saml(
            profile,
            &saml_response_base64,
            &selected_role.role_arn,
            &selected_role.principal_arn,
            i32::from(config.default_session_duration_hours) * 3600,
        )
        .await
        .context("Failed to assume AWS role with SAML")?;

        // Save credentials
        aws::credentials::save_credentials(profile, &credentials)
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
