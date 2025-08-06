use anyhow::{Context, Result, bail};
use aws_config::Region;
use aws_sdk_sts::{Client as StsClient, config::Config as StsConfig};
use aws_smithy_types::{DateTime, date_time::Format};
use ini::Ini;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{process::Command, time::Duration};
use tokio::fs;
use tracing::{debug, info};
use url::Url;

use crate::constants;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime,
}

// AWS Federation API types (internal use only)
// These types match the exact JSON format expected by AWS federation endpoint

/// Session credentials format for AWS federation getSigninToken API
#[derive(Debug, Serialize)]
struct SessionCredentials {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "sessionKey")]
    session_key: String,
    #[serde(rename = "sessionToken")]
    session_token: String,
}

/// Response from AWS federation getSigninToken API
#[derive(Debug, Deserialize)]
struct SigninTokenResponse {
    #[serde(rename = "SigninToken")]
    signin_token: String,
}

/// Assume role using SAML assertion
pub async fn assume_role_with_saml(
    role_arn: &str,
    principal_arn: &str,
    saml_assertion: &str,
    duration_seconds: i32,
) -> Result<Credentials> {
    info!("Calling AWS STS AssumeRoleWithSAML");
    debug!("Role ARN: {}", role_arn);
    debug!("Principal ARN: {}", principal_arn);
    debug!("Duration: {} seconds", duration_seconds);

    let region = Region::new("us-east-1");
    let config = StsConfig::builder().region(region).build();
    let client = StsClient::from_conf(config);

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

/// Save credentials to AWS credentials file
pub async fn save_credentials(profile: &str, creds: &Credentials) -> Result<()> {
    let path = constants::get_aws_credentials_path()
        .context("Failed to determine AWS credentials path")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    let mut ini = path
        .exists()
        .then(|| Ini::load_from_file(&path).ok())
        .flatten()
        .unwrap_or_else(Ini::new);

    let expiration = creds
        .expiration
        .fmt(Format::DateTime)
        .unwrap_or_else(|_| "unknown".to_string());

    ini.with_section(Some(profile))
        .set("aws_access_key_id", &creds.access_key_id)
        .set("aws_secret_access_key", &creds.secret_access_key)
        .set("aws_session_token", &creds.session_token)
        .set("aws_session_expiration", &expiration);

    ini.write_to_file(&path)
        .context("Failed to write credentials file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&path).await?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&path, permissions).await?;
    }

    info!("Credentials saved to profile: {}", profile);
    Ok(())
}

/// Load credentials from AWS credentials file
pub async fn load_credentials(profile: &str) -> Result<Credentials> {
    let path = constants::get_aws_credentials_path()
        .context("Failed to determine AWS credentials path")?;

    let ini = match path.exists() {
        true => Ini::load_from_file(&path).context("Failed to read AWS credentials file")?,
        false => bail!("AWS credentials file not found. Please authenticate with `assam` first"),
    };

    let section = ini
        .section(Some(profile))
        .with_context(|| format!("Profile '{profile}' not found in credentials file"))?;

    let access_key_id = section
        .get("aws_access_key_id")
        .context("aws_access_key_id not found")?
        .to_string();

    let secret_access_key = section
        .get("aws_secret_access_key")
        .context("aws_secret_access_key not found")?
        .to_string();

    let session_token = section
        .get("aws_session_token")
        .context("aws_session_token not found")?
        .to_string();

    let expiration_str = section
        .get("aws_session_expiration")
        .context("aws_session_expiration not found")?;

    // Parse expiration time - it should be in RFC 3339 format
    let expiration = DateTime::from_str(expiration_str, Format::DateTime)
        .or_else(|_| DateTime::from_str(expiration_str, Format::DateTimeWithOffset))
        .context("Failed to parse session expiration time")?;

    Ok(Credentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}

/// Open AWS Management Console in browser
pub async fn open_console(profile: &str) -> Result<()> {
    let creds = load_credentials(profile).await?;
    let url = generate_console_url(&creds, None).await?;
    open_browser(&url)?;

    info!("Opened AWS Management Console in browser");
    Ok(())
}

/// Generate AWS Management Console URL
async fn generate_console_url(creds: &Credentials, region: Option<&str>) -> Result<String> {
    // Determine AWS domain based on region
    let region = region.unwrap_or("us-east-1");
    let amazon_domain = get_console_domain(region);

    // Get signin token
    let signin_token = get_signin_token(creds, amazon_domain).await?;

    // Build console URL
    let console_url = format!("https://console.{amazon_domain}/console/home");
    let mut url = Url::parse(&format!("https://signin.{amazon_domain}/federation"))?;
    url.query_pairs_mut()
        .append_pair("Action", "login")
        .append_pair("Destination", &console_url)
        .append_pair("SigninToken", &signin_token);

    Ok(url.to_string())
}

/// Get signin token from AWS federation endpoint
async fn get_signin_token(creds: &Credentials, amazon_domain: &str) -> Result<String> {
    let session_creds = SessionCredentials {
        session_id: creds.access_key_id.clone(),
        session_key: creds.secret_access_key.clone(),
        session_token: creds.session_token.clone(),
    };

    let session_json = serde_json::to_string(&session_creds)?;

    let mut url = Url::parse(&format!("https://signin.{amazon_domain}/federation"))?;
    url.query_pairs_mut()
        .append_pair("Action", "getSigninToken")
        .append_pair("DurationSeconds", "900") // Minimum value
        .append_pair("Session", &session_json);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client
        .get(url.as_str())
        .send()
        .await
        .context("Failed to get signin token")?;

    if !response.status().is_success() {
        bail!("Failed to get signin token: {}", response.status());
    }

    let token_response: SigninTokenResponse = response
        .json()
        .await
        .context("Failed to parse signin token response")?;

    Ok(token_response.signin_token)
}

/// Get console domain based on region
fn get_console_domain(region: &str) -> &'static str {
    match region {
        r if r.starts_with("us-gov-") => "amazonaws-us-gov.com",
        r if r.starts_with("cn-") => "amazonaws.cn",
        _ => "aws.amazon.com",
    }
}

/// Open URL in browser using platform-specific command
fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(url).status();

    #[cfg(target_os = "windows")]
    let status = Command::new("cmd").args(["/c", "start", "", url]).status();

    #[cfg(target_os = "linux")]
    let status = Command::new("xdg-open").arg(url).status();

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return bail!("Unsupported operating system");

    status
        .context("Failed to execute browser command")
        .and_then(|s| {
            s.success()
                .then_some(())
                .context("Browser command returned error")
        })
}
