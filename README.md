# assam-rs

[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20Edition-orange?logo=rust)](https://doc.rust-lang.org/edition-guide/)
[![Release](https://github.com/KanchiShimono/assam-rs/actions/workflows/release.yml/badge.svg)](https://github.com/KanchiShimono/assam-rs/actions/workflows/release.yml)
[![Test](https://github.com/KanchiShimono/assam-rs/actions/workflows/test.yml/badge.svg)](https://github.com/KanchiShimono/assam-rs/actions/workflows/test.yml)
[![Homebrew](https://img.shields.io/badge/Homebrew-kanchishimono/tap-yellow)](https://github.com/KanchiShimono/homebrew-tap)

A CLI tool for AWS SAML authentication via Azure Entra ID.

Rust implementation of the archived [cybozu/assam](https://github.com/cybozu/assam) project.

## Installation

### Homebrew
```bash
brew install kanchishimono/tap/assam
```

### Manual
Download the binary from the [releases page](https://github.com/KanchiShimono/assam-rs/releases)

## Usage

### 1. Initial Setup (first time only)
```bash
assam configure
```
Configure your Azure Tenant ID and other settings interactively.

### 2. AWS Authentication
```bash
# Authenticate with default profile
assam

# Authenticate with a different profile (to preserve existing default)
assam -p myprofile
```

> ⚠️ **Important**: This will **overwrite** the specified profile in `~/.aws/credentials`.
> If no profile is specified, `default` will be overwritten.

### 3. Open AWS Console
```bash
assam web
```

## Commands

| Command | Description | Example |
|---------|------|-----|
| `auth` | AWS authentication (default) | `assam` or `assam auth` |
| `configure` | Configure profile | `assam configure -p prod` |
| `web` | Open AWS console | `assam web -p prod` |
| `completion` | Shell completion | `assam completion bash` |

### Global Options
- `-p, --profile`: Profile name (default: `default`)
- `-v, --verbose`: Verbose logging (`-vv` for debug, `-vvv` for trace)

## Multiple Profiles

```bash
# Create profiles for each environment
assam configure -p dev
assam configure -p prod

# Authenticate with specific profiles
assam -p dev
assam -p prod

# Use with AWS CLI
aws s3 ls --profile dev
```

## Troubleshooting

### Profile not found
```bash
assam configure -p <profile-name>
```

### Authentication fails
- Verify Chrome/Chromium is installed
- Complete authentication within 5 minutes
- Check that your SAML app is correctly configured in Azure Entra ID

### Debugging
```bash
assam -vv auth  # Show detailed logs
```

## Configuration File

Stored in `~/.aws/config`:
```ini
[default]
azure_tenant_id = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
app_id_uri = https://signin.aws.amazon.com/saml
default_session_duration_hours = 1
chrome_user_data_dir = ~/.config/assam/chrome-user-data
```
