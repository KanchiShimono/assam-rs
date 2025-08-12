use anyhow::{Context, Result, bail};
use aws_config::BehaviorVersion;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{process::Command, time::Duration};
use tracing::info;
use url::Url;

use super::{Credentials, DEFAULT_AWS_REGION, credentials};

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

/// Open AWS Management Console in browser
pub async fn open_console(profile: &str) -> Result<()> {
    let creds = credentials::load_credentials(profile).await?;

    // Load AWS config to get the region for this profile
    let config = aws_config::defaults(BehaviorVersion::latest())
        .profile_name(profile)
        .load()
        .await;

    // Use the configured region or default to DEFAULT_AWS_REGION
    let region = config
        .region()
        .map(|r| r.as_ref())
        .or(Some(DEFAULT_AWS_REGION));
    let url = generate_console_url(&creds, region).await?;
    open_browser(&url)?;

    info!("Opened AWS Management Console in browser");
    Ok(())
}

/// Generate AWS Management Console URL
async fn generate_console_url(creds: &Credentials, region: Option<&str>) -> Result<String> {
    // Determine AWS domain based on region
    let region = region.unwrap_or(DEFAULT_AWS_REGION);
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

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;

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
