/// Azure Entra ID (formerly Azure AD) provider implementation
#[derive(Debug, Clone)]
pub struct AzureProvider {
    tenant_id: String,
}

impl AzureProvider {
    /// Create a new Azure provider with the specified tenant ID
    pub fn new(tenant_id: String) -> Self {
        Self { tenant_id }
    }

    /// Build SAML authentication URL with the provided SAML request
    pub fn build_auth_url(&self, saml_request: &str) -> String {
        format!(
            "https://login.microsoftonline.com/{}/saml2?SAMLRequest={}",
            self.tenant_id,
            urlencoding::encode(saml_request)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_url() {
        let provider = AzureProvider::new("test-tenant-id".to_string());
        let saml_request = "test-saml-request";
        let url = provider.build_auth_url(saml_request);

        assert!(url.contains("login.microsoftonline.com"));
        assert!(url.contains("test-tenant-id"));
        assert!(url.contains("SAMLRequest=test-saml-request"));
    }
}
