use anyhow::{Context, Result};
use aws_config::Region;
use aws_sdk_sts::{Client as StsClient, config::Config as StsConfig};
use aws_smithy_types::{DateTime, date_time::Format};
use dirs;
use ini::Ini;
use reqwest::Client as ReqwestClient;
use serde_json::json;
use std::{env, path::PathBuf, process::Command};
use tokio::fs;
use tracing::{debug, info};
use urlencoding;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime,
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

    // Use us-east-1 as default region for STS
    let region = Region::new("us-east-1");

    // Create STS config without credentials (SAML provides auth)
    let config = StsConfig::builder().region(region).build();

    // Create STS client
    let client = StsClient::from_conf(config);

    // Call AssumeRoleWithSAML
    let response = client
        .assume_role_with_saml()
        .role_arn(role_arn)
        .principal_arn(principal_arn)
        .saml_assertion(saml_assertion)
        .duration_seconds(duration_seconds)
        .send()
        .await
        .context("Failed to assume role with SAML")?;

    // Extract credentials
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
    let path = get_credentials_path()?;

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Load or create INI file
    let mut ini = if path.exists() {
        Ini::load_from_file(&path).unwrap_or_else(|_| Ini::new())
    } else {
        Ini::new()
    };

    // Format expiration time
    let expiration = creds
        .expiration
        .fmt(Format::DateTime)
        .unwrap_or_else(|_| "unknown".to_string());

    // Update profile section
    ini.with_section(Some(profile))
        .set("aws_access_key_id", &creds.access_key_id)
        .set("aws_secret_access_key", &creds.secret_access_key)
        .set("aws_session_token", &creds.session_token)
        .set("aws_session_expiration", &expiration);

    // Write to file with proper permissions
    ini.write_to_file(&path)
        .context("Failed to write credentials file")?;

    // Set file permissions to 0600 on Unix-like systems
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

/// Open AWS Management Console in browser
pub async fn open_console(profile: &str) -> Result<()> {
    info!("Opening AWS Management Console for profile: {}", profile);

    // Load credentials
    let creds = load_credentials(profile).await?;

    // Generate console URL
    let console_url = generate_console_url(&creds, None).await?;

    // Open in browser
    open_browser(&console_url)?;

    info!("AWS Management Console opened in browser");
    Ok(())
}

async fn load_credentials(profile: &str) -> Result<Credentials> {
    let path = get_credentials_path()?;

    let ini = Ini::load_from_file(&path)
        .with_context(|| format!("Failed to load credentials file: {}", path.display()))?;

    let section = ini
        .section(Some(profile))
        .with_context(|| format!("Profile '{profile}' not found in credentials"))?;

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

    // Parse expiration time
    let expiration = DateTime::from_str(expiration_str, Format::DateTime)
        .with_context(|| format!("Failed to parse expiration time: {expiration_str}"))?;

    Ok(Credentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}

async fn generate_console_url(credentials: &Credentials, region: Option<&str>) -> Result<String> {
    let region = region.unwrap_or("us-east-1");
    let signin_url = "https://signin.aws.amazon.com/federation";

    // Create session JSON
    let session = json!({
        "sessionId": credentials.access_key_id,
        "sessionKey": credentials.secret_access_key,
        "sessionToken": credentials.session_token
    });

    // Get signin token
    let client = ReqwestClient::new();
    let token_response = client
        .get(signin_url)
        .query(&[
            ("Action", "getSigninToken"),
            ("DurationSeconds", "900"),
            ("Session", &session.to_string()),
        ])
        .send()
        .await
        .context("Failed to get signin token from AWS")?;

    let token_data: serde_json::Value = token_response
        .json()
        .await
        .context("Failed to parse signin token response")?;

    let signin_token = token_data["SigninToken"]
        .as_str()
        .context("Failed to extract signin token from AWS response")?;

    // Build console URL
    let destination = format!("https://console.aws.amazon.com/console/home?region={region}");

    let console_url = format!(
        "{}?Action=login&Destination={}&SigninToken={}",
        signin_url,
        urlencoding::encode(&destination),
        signin_token
    );

    Ok(console_url)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .spawn()
            .context("Failed to open browser on macOS")?;
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(&["/c", "start", url])
            .spawn()
            .context("Failed to open browser on Windows")?;
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("Failed to open browser on Linux")?;
    }

    Ok(())
}

fn get_credentials_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("AWS_SHARED_CREDENTIALS_FILE") {
        return Ok(PathBuf::from(path));
    }

    dirs::home_dir()
        .map(|home| home.join(".aws").join("credentials"))
        .context("Failed to determine home directory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_get_credentials_path() {
        let path = get_credentials_path().unwrap();
        assert!(path.to_string_lossy().contains("credentials"));
    }

    #[test]
    #[serial]
    fn test_get_credentials_path_with_env() {
        // Save original value
        let original = env::var("AWS_SHARED_CREDENTIALS_FILE").ok();

        // Set test value
        unsafe {
            env::set_var("AWS_SHARED_CREDENTIALS_FILE", "/custom/path/credentials");
        }
        let path = get_credentials_path().unwrap();
        assert_eq!(path, PathBuf::from("/custom/path/credentials"));

        // Restore original value
        unsafe {
            match original {
                Some(val) => env::set_var("AWS_SHARED_CREDENTIALS_FILE", val),
                None => env::remove_var("AWS_SHARED_CREDENTIALS_FILE"),
            }
        }
    }
}
