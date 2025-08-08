use crate::constants::{
    self, DEFAULT_APP_ID_URI, DEFAULT_SESSION_DURATION_HOURS, MAX_SESSION_DURATION_HOURS,
    MIN_SESSION_DURATION_HOURS,
};
use anyhow::{Context, Result};
use dialoguer::{Input, theme::ColorfulTheme};
use ini::{Ini, Properties};
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Clone)]
pub struct Config {
    pub app_id_uri: String,
    pub azure_tenant_id: String,
    pub default_session_duration_hours: u8,
    pub chrome_user_data_dir: PathBuf,
}

impl Config {
    fn from_ini_section(section: &Properties) -> Self {
        Self {
            app_id_uri: section
                .get("app_id_uri")
                .unwrap_or(DEFAULT_APP_ID_URI)
                .to_string(),
            azure_tenant_id: section.get("azure_tenant_id").unwrap_or("").to_string(),
            default_session_duration_hours: section
                .get("default_session_duration_hours")
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_SESSION_DURATION_HOURS),
            chrome_user_data_dir: section
                .get("chrome_user_data_dir")
                .map_or_else(constants::default_chrome_user_data_dir, PathBuf::from),
        }
    }

    fn save_to_ini(&self, ini: &mut Ini, profile: &str) {
        let section_name = if profile == "default" {
            profile.to_string()
        } else {
            format!("profile {profile}")
        };

        ini.with_section(Some(section_name))
            .set("app_id_uri", &self.app_id_uri)
            .set("azure_tenant_id", &self.azure_tenant_id)
            .set(
                "default_session_duration_hours",
                self.default_session_duration_hours.to_string(),
            )
            .set(
                "chrome_user_data_dir",
                self.chrome_user_data_dir.to_string_lossy(),
            );
    }
}

pub async fn load(profile: &str) -> Result<Config> {
    let path = get_config_path()?;
    let ini = Ini::load_from_file(&path)
        .context("Failed to load config file. Please run `assam config` first")?;

    let section_name = if profile == "default" {
        profile.to_string()
    } else {
        format!("profile {profile}")
    };

    let section = ini
        .section(Some(&section_name))
        .with_context(|| format!("Profile '{profile}' not found in config"))?;

    Ok(Config::from_ini_section(section))
}

pub async fn save(profile: &str, config: &Config) -> Result<()> {
    let path = get_config_path()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    let mut ini = if path.exists() {
        Ini::load_from_file(&path).unwrap_or_else(|_| Ini::new())
    } else {
        Ini::new()
    };

    config.save_to_ini(&mut ini, profile);

    ini.write_to_file(&path)
        .with_context(|| format!("Failed to write config to {}", path.display()))?;

    Ok(())
}

pub async fn configure_interactive(profile: &str) -> Result<()> {
    println!("Configuring assam for profile: {profile}");

    let existing_config = load(profile).await.ok();

    if existing_config.is_some() {
        println!("Press Enter to keep current values, or type new values.");
    }
    println!();

    let theme = ColorfulTheme::default();

    let default_config = existing_config.unwrap_or(Config {
        app_id_uri: DEFAULT_APP_ID_URI.to_string(),
        azure_tenant_id: String::new(),
        default_session_duration_hours: DEFAULT_SESSION_DURATION_HOURS,
        chrome_user_data_dir: constants::default_chrome_user_data_dir(),
    });

    let azure_tenant_id = Input::<String>::with_theme(&theme)
        .with_prompt("Azure Tenant ID")
        .default(default_config.azure_tenant_id.clone())
        .allow_empty(!default_config.azure_tenant_id.is_empty())
        .validate_with(|input: &String| {
            if input.is_empty() {
                Err("Azure Tenant ID is required")
            } else if !is_valid_uuid(input) {
                Err("Azure Tenant ID must be a valid UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
            } else {
                Ok(())
            }
        })
        .interact_text()
        .context("Failed to read Azure Tenant ID")?;

    let app_id_uri = Input::<String>::with_theme(&theme)
        .with_prompt("App ID URI")
        .default(default_config.app_id_uri)
        .interact_text()
        .context("Failed to read App ID URI")?;

    let default_session_duration_hours = Input::<u8>::with_theme(&theme)
        .with_prompt("Default Session Duration Hours (1-12)")
        .default(default_config.default_session_duration_hours)
        .validate_with(|input: &u8| {
            if *input >= MIN_SESSION_DURATION_HOURS && *input <= MAX_SESSION_DURATION_HOURS {
                Ok(())
            } else {
                Err("Please enter a value between 1 and 12")
            }
        })
        .interact_text()
        .context("Failed to read session duration")?;

    let chrome_user_data_dir = Input::<String>::with_theme(&theme)
        .with_prompt("Chrome User Data Directory")
        .default(
            default_config
                .chrome_user_data_dir
                .to_string_lossy()
                .to_string(),
        )
        .interact_text()
        .context("Failed to read Chrome user data directory")?;

    let config = Config {
        app_id_uri,
        azure_tenant_id,
        default_session_duration_hours,
        chrome_user_data_dir: PathBuf::from(chrome_user_data_dir),
    };

    save(profile, &config).await?;

    println!("\nConfiguration saved successfully.");
    Ok(())
}

fn get_config_path() -> Result<PathBuf> {
    constants::get_aws_config_path().context("Failed to determine AWS config path")
}

fn is_valid_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();

    if parts.len() != 5 {
        return false;
    }

    let expected_lengths = [8, 4, 4, 4, 12];

    parts
        .iter()
        .zip(expected_lengths.iter())
        .all(|(part, &expected_len)| {
            part.len() == expected_len && part.chars().all(|c| c.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_valid_uuid() {
        assert!(is_valid_uuid("12345678-1234-1234-1234-123456789abc"));
        assert!(is_valid_uuid("abcdef01-2345-6789-abcd-ef0123456789"));
        assert!(is_valid_uuid("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn test_invalid_uuid() {
        assert!(!is_valid_uuid(""));
        assert!(!is_valid_uuid("not-a-uuid"));
        assert!(!is_valid_uuid("12345678-1234-1234-1234"));
        assert!(!is_valid_uuid("12345678-1234-1234-1234-123456789abcd"));
        assert!(!is_valid_uuid("12345678-1234-1234-1234-123456789ab"));
        assert!(!is_valid_uuid("12345678_1234_1234_1234_123456789abc"));
        assert!(!is_valid_uuid("1234567g-1234-1234-1234-123456789abc"));
    }

    #[test]
    #[serial]
    fn test_default_chrome_user_data_dir() {
        let dir = constants::default_chrome_user_data_dir();
        assert!(dir.to_string_lossy().contains("assam"));
        assert!(dir.to_string_lossy().contains("chrome-user-data"));
    }

    #[test]
    fn test_config_from_ini_section() {
        let mut props = Properties::new();
        props.insert(
            "app_id_uri".to_string(),
            "https://example.com/saml".to_string(),
        );
        props.insert(
            "azure_tenant_id".to_string(),
            "12345678-1234-1234-1234-123456789abc".to_string(),
        );
        props.insert(
            "default_session_duration_hours".to_string(),
            "4".to_string(),
        );
        props.insert(
            "chrome_user_data_dir".to_string(),
            "/custom/path".to_string(),
        );

        let config = Config::from_ini_section(&props);

        assert_eq!(config.app_id_uri, "https://example.com/saml");
        assert_eq!(
            config.azure_tenant_id,
            "12345678-1234-1234-1234-123456789abc"
        );
        assert_eq!(config.default_session_duration_hours, 4);
        assert_eq!(config.chrome_user_data_dir, PathBuf::from("/custom/path"));
    }

    #[test]
    #[serial]
    fn test_config_from_ini_section_with_defaults() {
        let props = Properties::new();
        let config = Config::from_ini_section(&props);

        assert_eq!(config.app_id_uri, DEFAULT_APP_ID_URI);
        assert_eq!(config.azure_tenant_id, "");
        assert_eq!(
            config.default_session_duration_hours,
            DEFAULT_SESSION_DURATION_HOURS
        );
        assert!(
            config
                .chrome_user_data_dir
                .to_string_lossy()
                .contains("chrome-user-data")
        );
    }
}
