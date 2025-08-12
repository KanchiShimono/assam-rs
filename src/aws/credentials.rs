use anyhow::{Context, Result};
use aws_smithy_types::date_time::Format;
use dirs;
use ini::Ini;
use std::{env, path::PathBuf};
use tokio::fs;
use tracing;

use super::Credentials;

/// Get the AWS credentials file path
/// Respects AWS_SHARED_CREDENTIALS_FILE environment variable if set
fn get_aws_credentials_path() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(path) = env::var("AWS_SHARED_CREDENTIALS_FILE") {
        return Some(PathBuf::from(path));
    }

    // Use default AWS credentials location
    dirs::home_dir().map(|home| home.join(".aws").join("credentials"))
}

/// Save credentials to AWS credentials file
pub async fn save_credentials(profile: &str, creds: &Credentials) -> Result<()> {
    let path = get_aws_credentials_path().context("Failed to determine AWS credentials path")?;

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

    tracing::info!("Credentials saved to profile: {}", profile);
    Ok(())
}

/// Load credentials from AWS credentials file
pub async fn load_credentials(profile: &str) -> Result<Credentials> {
    let path = get_aws_credentials_path().context("Failed to determine AWS credentials path")?;

    let ini = match path.exists() {
        true => Ini::load_from_file(&path).context("Failed to read AWS credentials file")?,
        false => {
            anyhow::bail!("AWS credentials file not found. Please authenticate with `assam` first")
        }
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
    let expiration = aws_smithy_types::DateTime::from_str(expiration_str, Format::DateTime)
        .or_else(|_| {
            aws_smithy_types::DateTime::from_str(expiration_str, Format::DateTimeWithOffset)
        })
        .context("Failed to parse session expiration time")?;

    Ok(Credentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_get_aws_credentials_path_with_env() {
        let original = env::var("AWS_SHARED_CREDENTIALS_FILE").ok();

        unsafe {
            env::set_var("AWS_SHARED_CREDENTIALS_FILE", "/custom/path/credentials");
        }
        let path = get_aws_credentials_path();
        assert_eq!(path, Some(PathBuf::from("/custom/path/credentials")));

        unsafe {
            match original {
                Some(val) => env::set_var("AWS_SHARED_CREDENTIALS_FILE", val),
                None => env::remove_var("AWS_SHARED_CREDENTIALS_FILE"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_get_aws_credentials_path_default() {
        let original = env::var("AWS_SHARED_CREDENTIALS_FILE").ok();

        unsafe {
            env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
        }
        let path = get_aws_credentials_path();

        if let Some(p) = path {
            let path_str = p.to_string_lossy();
            assert!(path_str.contains(".aws"));
            assert!(path_str.contains("credentials"));
        }

        unsafe {
            if let Some(val) = original {
                env::set_var("AWS_SHARED_CREDENTIALS_FILE", val);
            }
        }
    }
}
