use std::{env, path::PathBuf};

use dirs;

/// Default configuration directory name under user's config directory
pub const CONFIG_DIR_NAME: &str = "assam";

/// Chrome user data directory name
pub const CHROME_USER_DATA_DIR_NAME: &str = "chrome-user-data";

/// AWS configuration directory name
pub const AWS_CONFIG_DIR_NAME: &str = ".aws";

/// AWS configuration file name
pub const AWS_CONFIG_FILE_NAME: &str = "config";

/// Default App ID URI for AWS SAML (used as Issuer in SAML request)
pub const DEFAULT_APP_ID_URI: &str = "https://signin.aws.amazon.com/saml";

/// AWS SAML endpoint URL (where SAML response is posted)
pub const AWS_SAML_ENDPOINT: &str = "https://signin.aws.amazon.com/saml";

/// Minimum session duration in hours
pub const MIN_SESSION_DURATION_HOURS: u8 = 1;

/// Maximum session duration in hours
pub const MAX_SESSION_DURATION_HOURS: u8 = 12;

/// Default session duration in hours
pub const DEFAULT_SESSION_DURATION_HOURS: u8 = 1;

/// Default AWS region for STS operations when no region is configured
pub const DEFAULT_AWS_REGION: &str = "us-east-1";

/// Get the default Chrome user data directory path
/// Always returns: ~/.config/assam/chrome-user-data (on all platforms)
pub fn default_chrome_user_data_dir() -> PathBuf {
    // Always use home directory with .config, regardless of platform
    // This ensures consistent behavior across all OSes
    let home_dir = dirs::home_dir()
        .or_else(|| {
            // Fallback to environment variables if dirs crate fails
            env::var("HOME")
                .or_else(|_| env::var("USERPROFILE"))
                .ok()
                .map(PathBuf::from)
        })
        .expect("Could not determine home directory. Please set HOME environment variable.");

    home_dir
        .join(".config")
        .join(CONFIG_DIR_NAME)
        .join(CHROME_USER_DATA_DIR_NAME)
}

/// Get the AWS config file path
/// Respects AWS_CONFIG_FILE environment variable if set
pub fn get_aws_config_path() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(path) = env::var("AWS_CONFIG_FILE") {
        return Some(PathBuf::from(path));
    }

    // Use default AWS config location
    dirs::home_dir().map(|home| home.join(AWS_CONFIG_DIR_NAME).join(AWS_CONFIG_FILE_NAME))
}

/// Get the AWS credentials file path
/// Respects AWS_SHARED_CREDENTIALS_FILE environment variable if set
pub fn get_aws_credentials_path() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(path) = env::var("AWS_SHARED_CREDENTIALS_FILE") {
        return Some(PathBuf::from(path));
    }

    // Use default AWS credentials location
    dirs::home_dir().map(|home| home.join(AWS_CONFIG_DIR_NAME).join("credentials"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_default_chrome_user_data_dir() {
        let dir = default_chrome_user_data_dir();
        let path_str = dir.to_string_lossy();
        assert!(path_str.contains(CONFIG_DIR_NAME));
        assert!(path_str.contains(CHROME_USER_DATA_DIR_NAME));
    }

    #[test]
    #[serial]
    fn test_get_aws_config_path_with_env() {
        let original = env::var("AWS_CONFIG_FILE").ok();

        unsafe {
            env::set_var("AWS_CONFIG_FILE", "/custom/aws/config");
        }
        let path = get_aws_config_path();
        assert_eq!(path, Some(PathBuf::from("/custom/aws/config")));

        unsafe {
            match original {
                Some(val) => env::set_var("AWS_CONFIG_FILE", val),
                None => env::remove_var("AWS_CONFIG_FILE"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_get_aws_config_path_default() {
        let original = env::var("AWS_CONFIG_FILE").ok();

        unsafe {
            env::remove_var("AWS_CONFIG_FILE");
        }
        let path = get_aws_config_path();

        if let Some(p) = path {
            let path_str = p.to_string_lossy();
            assert!(path_str.contains(AWS_CONFIG_DIR_NAME));
            assert!(path_str.contains(AWS_CONFIG_FILE_NAME));
        }

        unsafe {
            if let Some(val) = original {
                env::set_var("AWS_CONFIG_FILE", val);
            }
        }
    }

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
            assert!(path_str.contains(AWS_CONFIG_DIR_NAME));
            assert!(path_str.contains("credentials"));
        }

        unsafe {
            if let Some(val) = original {
                env::set_var("AWS_SHARED_CREDENTIALS_FILE", val);
            }
        }
    }
}
