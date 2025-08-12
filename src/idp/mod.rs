pub mod azure;

use self::azure::AzureProvider;

/// Identity Provider enum using composition pattern
/// Each variant contains a provider-specific struct with its own implementation
#[derive(Debug, Clone)]
pub enum IdentityProvider {
    Azure(AzureProvider),
    // Future: Okta(okta::OktaProvider),
    // Future: Google(google::GoogleProvider),
}

impl IdentityProvider {
    /// Build SAML authentication URL with the provided SAML request
    pub fn build_auth_url(&self, saml_request: &str) -> String {
        match self {
            Self::Azure(provider) => provider.build_auth_url(saml_request),
            // Future: Self::Okta(provider) => provider.build_auth_url(saml_request),
        }
    }

    /// Check if the URL is a SAML response endpoint
    pub fn is_saml_endpoint(&self, url: &str) -> bool {
        match self {
            Self::Azure(provider) => provider.is_saml_endpoint(url),
            // Future: Self::Okta(provider) => provider.is_saml_endpoint(url),
        }
    }
}
