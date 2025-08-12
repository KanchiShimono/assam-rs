use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_sts::Client as StsClient;
use tracing::{debug, info};

use super::{Credentials, DEFAULT_AWS_REGION};

/// Assume role using SAML assertion
pub async fn assume_role_with_saml(
    profile: &str,
    saml_assertion: &str,
    role_arn: &str,
    principal_arn: &str,
    duration_seconds: i32,
) -> Result<Credentials> {
    info!("Calling AWS STS AssumeRoleWithSAML");
    debug!("Profile: {}", profile);
    debug!("Role ARN: {}", role_arn);
    debug!("Principal ARN: {}", principal_arn);
    debug!("Duration: {} seconds", duration_seconds);

    // Load AWS config with automatic region fallback
    // Priority: ENV vars -> Config file -> EC2 metadata -> DEFAULT_AWS_REGION
    let config = {
        let loaded = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile)
            .load()
            .await;

        match loaded.region() {
            Some(region) => {
                info!("Using region: {}", region);
                loaded
            }
            None => {
                info!(
                    "No region configured, using default {} for STS",
                    DEFAULT_AWS_REGION
                );
                aws_config::defaults(BehaviorVersion::latest())
                    .profile_name(profile)
                    .region(Region::new(DEFAULT_AWS_REGION))
                    .load()
                    .await
            }
        }
    };

    let client = StsClient::new(&config);

    let response = client
        .assume_role_with_saml()
        .role_arn(role_arn)
        .principal_arn(principal_arn)
        .saml_assertion(saml_assertion)
        .duration_seconds(duration_seconds)
        .send()
        .await
        .context("Failed to assume role with SAML")?;

    let sts_creds = response
        .credentials()
        .context("AWS STS returned no credentials")?;

    let credentials = Credentials {
        access_key_id: sts_creds.access_key_id().to_string(),
        secret_access_key: sts_creds.secret_access_key().to_string(),
        session_token: sts_creds.session_token().to_string(),
        expiration: *sts_creds.expiration(),
    };

    info!("Successfully obtained AWS credentials");
    Ok(credentials)
}
