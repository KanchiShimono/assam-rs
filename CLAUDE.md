# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

assam-rs is a Rust CLI tool for AWS SAML authentication via Azure Entra ID. It automates AWS credential retrieval and management.

## Development Commands

```bash
# Build & Run
cargo build                    # Debug build
cargo build --release         # Release build
cargo run -- <args>          # Run with arguments
cargo run -- --help          # Show CLI help

# Testing & Quality
cargo test                    # Run all tests
cargo test <test_name>        # Run specific test
cargo test --test '*cli*'     # Run tests matching pattern
cargo fmt                    # Format code
cargo fmt --check            # Check formatting without modifying
cargo clippy                  # Lint code
cargo clippy -- -D warnings   # Strict linting

# Documentation
cargo doc --open              # Build and view docs
cargo doc --no-deps           # Build only this crate's docs

# Logging & Debug
RUST_LOG=debug cargo run      # Override verbosity with env var
cargo run -- -v              # Info level logging
cargo run -- -vv             # Debug level logging
cargo run -- -vvv            # Trace level logging

# Example Commands
cargo run -- auth            # Run auth with default profile
cargo run -- -p myprofile auth  # Auth with specific profile
cargo run -- web             # Open AWS console
cargo run -- completion bash  # Generate bash completion
```

## Architecture & Code Patterns

### Module Structure
- `src/main.rs`: Entry point with tokio runtime and logging initialization
- `src/lib.rs`: Library root that exports all public modules
- `src/cli.rs`: CLI parsing using clap v4 with derive macros
- `src/commands/`: Each subcommand in its own module (auth, config, web, completion)
- `src/aws/`: AWS operations organized by functionality
  - `mod.rs`: Module root with common types (Credentials, DEFAULT_AWS_REGION)
  - `sts.rs`: STS AssumeRoleWithSAML operations
  - `credentials.rs`: AWS credentials file management
  - `roles.rs`: IAM role parsing and selection
  - `console.rs`: AWS console federation
- `src/idp/`: Identity Provider abstraction layer (composition pattern)
  - `mod.rs`: IdentityProvider enum for multi-provider support
  - `azure.rs`: Azure Entra ID provider implementation
- `src/browser.rs`: Chrome automation via chromiumoxide with BrowserAutomation trait
- `src/saml.rs`: SAML request/response handling
- `src/config.rs`: Configuration management with AWS profile support
- Simple module design without over-abstraction for CLI scale

### Key Patterns
- **Error Handling**: Always use `anyhow::Result<T>` for simplicity
- **Async**: Tokio runtime for all async operations
- **Logging**: Uses `tracing` with structured logging
  - Verbosity controlled by `-v` flags (0=WARN, 1=INFO, 2=DEBUG, 3+=TRACE)
  - RUST_LOG env var overrides CLI verbosity
  - Additional context shown at higher verbosity (target, thread_ids, file/line)
- **Abstraction**: Trait-based design for extensibility (BrowserAutomation, future IdP providers)
- **Module Organization**: Functions accessed via module path, types imported directly
- **Testing**: Comprehensive CLI tests exist in `src/cli.rs` - follow the pattern when adding new commands

### Authentication Flow (implemented)
1. Generate SAML request (UUID + Deflate + Base64)
2. Launch Chrome via chromiumoxide with Azure Entra ID login
3. Capture SAML response from network events
4. Call AWS STS AssumeRoleWithSAML
5. Save credentials to `~/.aws/credentials` with 0600 permissions

## Critical Dependencies

- **Rust Edition**: 2024 (as specified in Cargo.toml)
- **chromiumoxide**: Browser automation for SAML flow (tokio-runtime feature only)
- **aws-sdk-sts**: AWS credential operations (v1.80.0 with behavior-version-latest)
- **tokio**: Async runtime with full features
- **clap v4**: CLI framework with derive macros
- **clap_complete**: Shell completion generation
- **anyhow**: Error handling
- **tracing/tracing-subscriber**: Structured logging
- **dialoguer**: Interactive prompts for config command
- **reqwest**: HTTP client (rustls-tls, no default features)

### Dev Dependencies
- **serial_test**: For tests that need exclusive access (use with `--test-threads=1`)

## Important Implementation Notes

### Architecture Patterns
- **IdP Abstraction**: Uses composition pattern with enum wrapper for multiple providers
  - Each provider is a separate struct with its own implementation
  - IdentityProvider enum dispatches to the appropriate provider
  - Easy to extend with new providers (Okta, Google, etc.)
- **Browser Abstraction**: Trait-based design allows for different browser implementations
  - Currently only Chrome/Chromium supported via chromiumoxide
  - BrowserAutomation trait defines the interface

### CLI Behavior
- Default command is `auth` when no subcommand specified
- Profile defaults to "default" unless specified with `-p/--profile`
- All commands receive the profile parameter for multi-profile support

### Auth Command Implementation
- SAML request must use UUID v4, Deflate compression, Base64 encoding
- Chrome browser session must be properly managed (close on error/completion)
- AWS credentials file must have 0600 permissions
- Support both interactive (default) and non-interactive modes
- Default timeout: 300 seconds for browser authentication
- Uses IdP abstraction to support multiple identity providers

### Config Command Implementation
- Use dialoguer for interactive prompts
- Store config in `~/.aws/config` (INI format, respects AWS_CONFIG_FILE env var)
- Support multiple AWS profiles (profile name as INI section)
- Configuration constants are defined in `config.rs`
- Chrome user data: `~/.config/assam/chrome-user-data` (consistent across all platforms)
- Config fields:
  - `azure_tenant_id`: Required, Azure Entra ID tenant ID
  - `app_id_uri`: Optional, defaults to `https://signin.aws.amazon.com/saml`
  - `default_session_duration_hours`: Optional, 1-12 hours, default 1
  - `chrome_user_data_dir`: Optional, defaults to `~/.config/assam/chrome-user-data`

## Testing Guidelines

Follow the existing test patterns in `src/cli.rs` and other modules:
- Test CLI parsing thoroughly
- Test command dispatch
- Test error cases and help text
- Use `#[cfg(test)]` modules with comprehensive test coverage

## CI/CD

GitHub Actions workflows (`.github/workflows/`):
- **test.yml**: Runs on PRs and pushes - rustfmt, clippy, cargo check, and tests
- **release.yml**: Triggered on version tags (vX.Y.Z) - builds binaries for multiple platforms:
  - Linux (x86_64-gnu, x86_64-musl)
  - macOS (aarch64, x86_64)
  - Windows (x86_64, aarch64)

## Debugging & Troubleshooting

Key files to check when debugging:
- Authentication issues: `src/browser.rs` (Chrome automation), `src/saml.rs` (SAML parsing)
- AWS credential issues: `src/aws/` module (STS calls in `sts.rs`, credential file operations in `credentials.rs`)
- Configuration issues: `src/config.rs`, check `~/.aws/config`
- Browser timeout issues: Check `BROWSER_TIMEOUT` in `browser.rs` (default 300s)
- Network capture issues: Review CDP network events in `browser.rs::capture_saml_response`

## Coding Rules

### Type-first implementation
Design your types before writing logic. Let the type system guide your implementation.

```rust
// ✅ Good: Define types first, then implement behavior
#[derive(Debug, Clone)]
struct Email(String);

impl Email {
    fn new(value: String) -> Result<Self> {
        if value.contains('@') && value.contains('.') {
            Ok(Self(value))
        } else {
            Err(anyhow::anyhow!("Invalid email format"))
        }
    }
}

#[derive(Debug)]
struct User {
    id: UserId,
    email: Email,
    role: UserRole,
}

#[derive(Debug, Clone, Copy)]
struct UserId(u64);

#[derive(Debug)]
enum UserRole {
    Admin,
    User,
    Guest,
}

// ❌ Bad: Stringly-typed, validation scattered throughout code
fn process_user(id: u64, email: &str, role: &str) {
    // Type safety lost, validation mixed with business logic
    if email.contains('@') {
        // Process...
    }
    // String comparisons prone to typos
    if role == "admin" {
        // ...
    }
}
```

### Use algebraic data types to make impossible states unrepresentable

```rust
// ✅ Good: Invalid states cannot be constructed
enum ConnectionState {
    Disconnected,
    Connecting { attempt: u32 },
    Connected { session_id: SessionId, since: Instant },
    Reconnecting { session_id: SessionId, attempt: u32 },
}

// The type system prevents having a session_id without being connected
// or being in multiple states simultaneously

// ❌ Bad: Multiple booleans/options allow invalid combinations
struct BadConnectionState {
    is_connected: bool,
    is_connecting: bool,
    is_reconnecting: bool,
    session_id: Option<String>,     // Can have session_id while disconnected
    connection_attempt: Option<u32>, // Can have attempt count when not connecting
}
```

### Avoid procedural processing, prioritize declarative coding style

```rust
// ✅ Good: Declarative, functional approach
fn calculate_total_price(items: &[Item]) -> Price {
    items
        .iter()
        .filter(|item| item.is_active())
        .map(|item| item.price * item.quantity)
        .fold(Price::zero(), |acc, price| acc + price)
}

fn validate_all(validators: &[Validator], input: &str) -> Result<()> {
    validators
        .iter()
        .map(|v| v.validate(input))
        .collect::<Result<Vec<_>>>()?;
    Ok(())
}

// ❌ Bad: Procedural, imperative approach
fn calculate_total_price_bad(items: &[Item]) -> Price {
    let mut total = Price::zero();
    for i in 0..items.len() {
        let item = &items[i];
        if item.is_active() {
            let price = item.price * item.quantity;
            total = total + price;
        }
    }
    total
}
```

### Avoid overly complex abstractions, prioritize simplicity

```rust
// ✅ Good: Simple, direct implementation
async fn fetch_user(id: UserId) -> Result<User> {
    let response = client
        .get(format!("/users/{}", id.0))
        .send()
        .await?;

    response.json::<User>().await
}

struct Config {
    database_url: String,
    port: u16,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")?,
            port: env::var("PORT")?.parse()?,
        })
    }
}

// ❌ Bad: Over-engineered for simple needs
trait AbstractConfigurationProvider<T> {
    type Error;
    fn provide(&self) -> Result<T, Self::Error>;
}

struct ConfigurationFactory<T, P: AbstractConfigurationProvider<T>> {
    provider: P,
    phantom: PhantomData<T>,
}

impl<T, P> ConfigurationFactory<T, P>
where
    P: AbstractConfigurationProvider<T>
{
    // Unnecessary abstraction layers for a simple config loader
}
```

### Path and Import Conventions

Follow Rust's idiomatic path conventions:

```rust
// Functions: import parent module, not the function directly
use serde_json::de;
de::from_str(json_str);  // ✅ Idiomatic

use tokio::fs;
fs::read_to_string(path).await;  // ✅ Idiomatic

// Standard library functions: use full path from std::
std::fs::read_to_string(path);  // ✅ Idiomatic for std
std::process::exit(1);  // ✅ Idiomatic for std
std::thread::sleep(duration);  // ✅ Idiomatic for std

// Logging macros from tracing: import directly at module level
use tracing::{info, warn, error, debug, trace};  // ✅ Idiomatic
info!("Starting process");  // ✅ Use without prefix
error!("Failed to connect");  // ✅ Use without prefix

// Error handling macros from anyhow: import directly at module level
use anyhow::{bail, ensure};  // ✅ Idiomatic
bail!("Invalid configuration");  // ✅ Use without prefix
ensure!(value > 0, "Value must be positive");  // ✅ Use without prefix

// Structs/Enums/Traits/Constants: bring the item itself into scope
use std::collections::HashMap;  // ✅ Idiomatic
use anyhow::Result;  // ✅ Idiomatic
use serde::{Serialize, Deserialize};  // ✅ Idiomatic
use std::f64::consts::PI;  // ✅ Idiomatic
use tokio::time::Duration;  // ✅ Idiomatic (associated constants via Duration::ZERO)

// Use nested paths to reduce separate use statements
use tokio::{fs, time::Duration};  // ✅ Good
use clap::{Parser, Subcommand, Args};  // ✅ Good

// Handle name conflicts with `as`
use std::fmt::Result;
use std::io::Result as IoResult;  // ✅ Good
use serde_json::Result as JsonResult;  // ✅ Good

// Glob operator: use sparingly
use chrono::prelude::*;  // ✅ OK for preludes
use anyhow::*;  // ⚠️ Avoid - makes it unclear what's in scope

#[cfg(test)]
mod tests {
    use super::*;  // ✅ Common in tests
}

// Re-exporting with pub use
pub use self::error::ConfigError;  // ✅ Good for public API design
```
