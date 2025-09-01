use aws_smithy_types::DateTime;

pub(crate) mod console;
pub(crate) mod credentials;
pub(crate) mod roles;
pub(crate) mod sts;

/// Default AWS region for STS operations when no region is configured
pub(crate) const DEFAULT_AWS_REGION: &str = "us-east-1";

/// AWS temporary credentials structure
#[derive(Debug, Clone)]
pub(crate) struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime,
}

// Re-export commonly used types (functions should be accessed via module path)
pub(crate) use roles::{AvailableRoles, IamRole};
