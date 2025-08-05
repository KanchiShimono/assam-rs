use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand};

use crate::commands::{AuthCommand, CompletionsCommand, ConfigureCommand, WebCommand};

#[derive(Debug, Clone, Parser)]
#[command(name = "assam", version, about = "AWS SAML authentication tool for Azure Entra ID", long_about = None, arg_required_else_help = false)]
pub struct Cli {
    #[arg(
        short = 'p',
        long,
        global = true,
        default_value = "default",
        help = "AWS profile name"
    )]
    pub profile: String,

    #[arg(short = 'v', long, global = true, action = ArgAction::Count, help = "Increase verbosity (-v info, -vv debug, -vvv trace)")]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    #[command(about = "Authenticate with AWS using SAML via Azure Entra ID")]
    Auth(AuthCommand),
    #[command(about = "Configure Azure Entra ID and AWS settings")]
    Configure(ConfigureCommand),
    #[command(about = "Open AWS Management Console in browser")]
    Web(WebCommand),
    #[command(about = "Generate shell completion scripts for assam")]
    Completions(CompletionsCommand),
}

impl Cli {
    pub async fn execute(self) -> Result<()> {
        let profile = self.profile;
        let command = self
            .command
            .unwrap_or(Commands::Auth(AuthCommand { role: None }));

        match command {
            Commands::Auth(cmd) => cmd.execute(&profile).await,
            Commands::Configure(cmd) => cmd.execute(&profile).await,
            Commands::Web(cmd) => cmd.execute(&profile).await,
            Commands::Completions(cmd) => {
                cmd.execute();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    #[test]
    fn test_default_command_is_auth() {
        let cli = Cli {
            profile: "default".to_string(),
            verbose: 0,
            command: None,
        };

        match cli
            .command
            .unwrap_or(Commands::Auth(AuthCommand { role: None }))
        {
            Commands::Auth(cmd) => assert_eq!(cmd.role, None),
            _ => panic!("Expected Auth command as default"),
        }
    }

    #[test]
    fn test_auth_command_with_role() {
        let cli = Cli {
            profile: "test".to_string(),
            verbose: 0,
            command: Some(Commands::Auth(AuthCommand {
                role: Some("AdminRole".to_string()),
            })),
        };

        match cli.command {
            Some(Commands::Auth(cmd)) => {
                assert_eq!(cmd.role, Some("AdminRole".to_string()));
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn test_auth_command_without_role() {
        let cli = Cli {
            profile: "test".to_string(),
            verbose: 0,
            command: Some(Commands::Auth(AuthCommand { role: None })),
        };

        match cli.command {
            Some(Commands::Auth(cmd)) => {
                assert_eq!(cmd.role, None);
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn test_profile_default_value() {
        let cli = Cli::try_parse_from(["assam", "auth"]).unwrap();
        assert_eq!(cli.profile, "default");
    }

    #[test]
    fn test_profile_custom_value() {
        let cli = Cli::try_parse_from(["assam", "--profile", "production", "auth"]).unwrap();
        assert_eq!(cli.profile, "production");
    }

    #[test]
    fn test_profile_short_flag() {
        let cli = Cli::try_parse_from(["assam", "-p", "dev", "auth"]).unwrap();
        assert_eq!(cli.profile, "dev");
    }

    #[test]
    fn test_auth_with_role_parsing() {
        let cli = Cli::try_parse_from(["assam", "auth", "--role", "Developer"]).unwrap();
        match cli.command {
            Some(Commands::Auth(cmd)) => {
                assert_eq!(cmd.role, Some("Developer".to_string()));
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn test_auth_with_role_short_flag() {
        let cli = Cli::try_parse_from(["assam", "auth", "-r", "Admin"]).unwrap();
        match cli.command {
            Some(Commands::Auth(cmd)) => {
                assert_eq!(cmd.role, Some("Admin".to_string()));
            }
            _ => panic!("Expected Auth command"),
        }
    }

    #[test]
    fn test_configure_command_parsing() {
        let cli = Cli::try_parse_from(["assam", "configure"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Configure(_))));
    }

    #[test]
    fn test_web_command_parsing() {
        let cli = Cli::try_parse_from(["assam", "web"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Web(_))));
    }

    #[test]
    fn test_completions_command_parsing() {
        let cli = Cli::try_parse_from(["assam", "completions", "bash"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Completions(_))));
    }

    #[test]
    fn test_no_command_defaults_to_auth() {
        let cli = Cli::try_parse_from(["assam"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_command_structure_validation() {
        let cmd = Cli::command();
        cmd.debug_assert();
    }

    #[test]
    fn test_invalid_command_fails() {
        let result = Cli::try_parse_from(["assam", "invalid"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_help_flag_works() {
        let result = Cli::try_parse_from(["assam", "--help"]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), ErrorKind::DisplayHelp);
        }
    }

    #[test]
    fn test_version_flag_works() {
        let result = Cli::try_parse_from(["assam", "--version"]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), ErrorKind::DisplayVersion);
        }
    }

    #[test]
    fn test_verbose_flag_single() {
        let cli = Cli::try_parse_from(["assam", "-v", "auth"]).unwrap();
        assert_eq!(cli.verbose, 1);
    }

    #[test]
    fn test_verbose_flag_multiple() {
        let cli = Cli::try_parse_from(["assam", "-vvv", "auth"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn test_verbose_long_flag() {
        let cli = Cli::try_parse_from(["assam", "--verbose", "--verbose", "auth"]).unwrap();
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn test_verbose_default_zero() {
        let cli = Cli::try_parse_from(["assam", "auth"]).unwrap();
        assert_eq!(cli.verbose, 0);
    }
}
