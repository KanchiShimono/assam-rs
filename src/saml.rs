use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use chrono::{SecondsFormat, Utc};
use flate2::{Compression, write::DeflateEncoder};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::io::Write;
use uuid::Uuid;

/// SAML provider configuration
#[derive(Debug, Clone)]
pub struct SamlProviderConfig {
    /// The entity that issues the SAML request (typically the application identifier)
    pub issuer: String,
    /// The URL where SAML responses should be sent (Assertion Consumer Service URL)
    pub assertion_consumer_service_url: String,
    /// The attribute name for roles in the SAML response
    pub role_attribute_name: String,
}

impl SamlProviderConfig {
    /// Create AWS SAML provider configuration with the specified issuer
    pub fn aws(issuer: String) -> Self {
        Self {
            issuer,
            assertion_consumer_service_url: crate::constants::AWS_SAML_ENDPOINT.to_string(),
            role_attribute_name: crate::constants::AWS_SAML_ROLE_ATTRIBUTE.to_string(),
        }
    }
}

/// Result of SAML role selection containing AWS ARNs
#[derive(Debug, Clone)]
pub struct SelectedRole {
    /// ARN of the IAM role to assume
    pub role_arn: String,
    /// ARN of the SAML provider principal
    pub principal_arn: String,
}

/// Generate SAML authentication request
pub fn create_request(provider_config: &SamlProviderConfig) -> Result<String> {
    let id = format!("id_{}", Uuid::new_v4());
    let instant = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

    let xml = format!(
        r#"<samlp:AuthnRequest
  AssertionConsumerServiceURL="{}"
  ID="{id}"
  IssueInstant="{instant}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  Version="2.0"
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
</samlp:AuthnRequest>"#,
        provider_config.assertion_consumer_service_url, provider_config.issuer
    );

    encode_saml_request(&xml).context("Failed to encode SAML request")
}

/// Deflate compress and Base64 encode SAML request
fn encode_saml_request(xml: &str) -> Result<String> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(xml.as_bytes())
        .context("Failed to compress SAML request")?;
    let compressed = encoder.finish().context("Failed to finish compression")?;
    Ok(general_purpose::STANDARD.encode(compressed))
}

/// Extract role information from SAML response
pub fn extract_role_from_response(
    base64_response: &str,
    role_name: Option<&str>,
    provider_config: &SamlProviderConfig,
) -> Result<SelectedRole> {
    let decoded = general_purpose::STANDARD
        .decode(base64_response)
        .context("Failed to decode SAML response from base64")?;

    let roles = parse_roles_from_saml(&decoded, &provider_config.role_attribute_name)?;

    if roles.is_empty() {
        bail!("No roles found in SAML response");
    }

    // Select role based on name or use first available
    let selected = if let Some(name) = role_name {
        roles
            .iter()
            .find(|r| r.name == name)
            .with_context(|| format!("Role '{name}' not found in SAML response"))?
    } else if roles.len() == 1 {
        &roles[0]
    } else {
        bail!(
            "Multiple roles available. Please specify one with --role flag: {}",
            roles
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        );
    };

    Ok(SelectedRole {
        role_arn: selected.role_arn.clone(),
        principal_arn: selected.principal_arn.clone(),
    })
}

#[derive(Debug, Clone)]
struct Role {
    name: String,
    role_arn: String,
    principal_arn: String,
}

impl Role {
    fn from_arn_pair(arn_pair: &str) -> Option<Self> {
        let parts: Vec<&str> = arn_pair.split(',').collect();
        if parts.len() != 2 {
            return None;
        }

        let (role_arn, principal_arn) = if parts[0].contains(":role/") {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (parts[1].to_string(), parts[0].to_string())
        };

        // Extract role name from ARN (arn:aws:iam::123456789012:role/RoleName)
        let name = role_arn
            .split('/')
            .next_back()
            .map_or_else(|| "UnknownRole".to_string(), String::from);

        Some(Role {
            name,
            role_arn,
            principal_arn,
        })
    }
}

fn parse_roles_from_saml(xml_data: &[u8], role_attribute_name: &str) -> Result<Vec<Role>> {
    let mut reader = Reader::from_reader(xml_data);
    reader.config_mut().trim_text(true);

    let mut roles = Vec::new();
    let mut in_role_attribute = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                if e.name().as_ref() == b"saml2:Attribute" || e.name().as_ref() == b"Attribute" {
                    in_role_attribute = check_role_attribute(e, role_attribute_name);
                }
            }
            Ok(Event::Text(e)) if in_role_attribute => {
                let value = String::from_utf8_lossy(e.as_ref()).to_string();
                if let Some(role) = Role::from_arn_pair(&value) {
                    roles.push(role);
                }
            }
            Ok(Event::End(ref e)) => {
                if e.name().as_ref() == b"saml2:Attribute" || e.name().as_ref() == b"Attribute" {
                    in_role_attribute = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("Error parsing SAML response: {}", e),
            _ => {}
        }
        buf.clear();
    }

    Ok(roles)
}

fn check_role_attribute(e: &BytesStart, role_attribute_name: &str) -> bool {
    e.attributes().filter_map(Result::ok).any(|attr| {
        attr.key.as_ref() == b"Name" && attr.value.as_ref() == role_attribute_name.as_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request() {
        let provider_config = SamlProviderConfig::aws("https://example.com/saml".to_string());
        let request = create_request(&provider_config).unwrap();
        assert!(!request.is_empty());

        // Verify it's valid base64
        let decoded = general_purpose::STANDARD.decode(&request);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_create_request_with_custom_provider() {
        let provider_config = SamlProviderConfig {
            issuer: "https://example.com/saml".to_string(),
            assertion_consumer_service_url: "https://custom.provider.com/saml".to_string(),
            role_attribute_name: "https://custom.provider.com/Attributes/Role".to_string(),
        };
        let request = create_request(&provider_config).unwrap();
        assert!(!request.is_empty());

        // Verify it's valid base64
        let decoded = general_purpose::STANDARD.decode(&request);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_encode_saml_request() {
        let xml = "<test>Sample XML</test>";
        let encoded = encode_saml_request(xml).unwrap();
        assert!(!encoded.is_empty());

        // Verify it's valid base64
        let decoded = general_purpose::STANDARD.decode(&encoded);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_role_from_arn_pair() {
        let arn_pair = "arn:aws:iam::123456789012:role/MyRole,arn:aws:iam::123456789012:saml-provider/MyProvider";
        let role = Role::from_arn_pair(arn_pair).unwrap();
        assert_eq!(role.name, "MyRole");
        assert_eq!(role.role_arn, "arn:aws:iam::123456789012:role/MyRole");
        assert_eq!(
            role.principal_arn,
            "arn:aws:iam::123456789012:saml-provider/MyProvider"
        );
    }

    #[test]
    fn test_role_from_arn_pair_reversed() {
        let arn_pair = "arn:aws:iam::123456789012:saml-provider/MyProvider,arn:aws:iam::123456789012:role/AdminRole";
        let role = Role::from_arn_pair(arn_pair).unwrap();
        assert_eq!(role.name, "AdminRole");
        assert_eq!(role.role_arn, "arn:aws:iam::123456789012:role/AdminRole");
        assert_eq!(
            role.principal_arn,
            "arn:aws:iam::123456789012:saml-provider/MyProvider"
        );
    }
}
