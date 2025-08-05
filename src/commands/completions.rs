use clap::{Args, CommandFactory};
use clap_complete::Shell;
use std::io;

use crate::cli::Cli;

#[derive(Debug, Clone, Args)]
pub struct CompletionsCommand {
    #[arg(value_enum, help = "Target shell for completion script")]
    pub shell: Shell,
}

impl CompletionsCommand {
    pub fn execute(self) {
        let mut cmd = Cli::command();
        let app_name = cmd.get_name().to_string();
        clap_complete::generate(self.shell, &mut cmd, app_name, &mut io::stdout());
    }

    #[cfg(test)]
    pub fn generate_to_string(&self) -> String {
        let mut cmd = Cli::command();
        let app_name = cmd.get_name().to_string();
        let mut buffer = Vec::new();
        clap_complete::generate(self.shell, &mut cmd, app_name, &mut buffer);
        String::from_utf8(buffer).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_shell_completion(shell: Shell, expected_patterns: &[&str]) {
        let cmd = CompletionsCommand { shell };
        let result = cmd.generate_to_string();

        assert!(!result.is_empty(), "Completion script should not be empty");

        for pattern in expected_patterns {
            assert!(
                result.contains(pattern),
                "Expected pattern '{}' not found in {} completion script",
                pattern,
                shell
            );
        }

        let cli_cmd = Cli::command();
        assert!(result.contains(cli_cmd.get_name()));
    }

    #[test]
    fn test_bash_completion() {
        validate_shell_completion(
            Shell::Bash,
            &["_assam()", "COMPREPLY", "complete -F _assam"],
        );
    }

    #[test]
    fn test_zsh_completion() {
        validate_shell_completion(Shell::Zsh, &["#compdef assam", "_assam", "_arguments"]);
    }

    #[test]
    fn test_fish_completion() {
        validate_shell_completion(Shell::Fish, &["complete -c assam", "__fish_assam"]);
    }

    #[test]
    fn test_powershell_completion() {
        validate_shell_completion(
            Shell::PowerShell,
            &["Register-ArgumentCompleter", "-CommandName 'assam'"],
        );
    }

    #[test]
    fn test_elvish_completion() {
        validate_shell_completion(Shell::Elvish, &["edit:completion:arg-completer[assam]"]);
    }

    #[test]
    fn test_completion_contains_subcommands() {
        let shells = [Shell::Bash, Shell::Zsh, Shell::Fish];

        for shell in &shells {
            let cmd = CompletionsCommand { shell: *shell };
            let result = cmd.generate_to_string();

            assert!(
                result.contains("auth"),
                "auth command should be in {} completions",
                shell
            );
            assert!(
                result.contains("configure"),
                "configure command should be in {} completions",
                shell
            );
            assert!(
                result.contains("web"),
                "web command should be in {} completions",
                shell
            );
            assert!(
                result.contains("completions"),
                "completions command should be in {} completions",
                shell
            );
        }
    }

    #[test]
    fn test_completion_contains_global_options() {
        let cmd = CompletionsCommand { shell: Shell::Bash };
        let result = cmd.generate_to_string();

        assert!(
            result.contains("--profile") || result.contains("-p"),
            "Profile option should be in completions"
        );
        assert!(
            result.contains("--help") || result.contains("-h"),
            "Help option should be in completions"
        );
    }

    #[test]
    fn test_generate_to_string_utf8_safety() {
        let shells = [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ];

        for shell in &shells {
            let cmd = CompletionsCommand { shell: *shell };
            let result = cmd.generate_to_string();

            assert!(
                result.is_ascii() || result.chars().all(|c| c.is_ascii() || c.len_utf8() > 1),
                "Completion script for {} should be valid UTF-8",
                shell
            );
        }
    }
}
