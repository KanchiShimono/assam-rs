use aws_smithy_types::DateTime;

pub mod console;
pub mod credentials;
pub mod roles;
pub mod sts;

/// AWS temporary credentials structure
#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime,
}

// Re-export commonly used types (functions should be accessed via module path)
pub use roles::{AvailableRoles, IamRole};
