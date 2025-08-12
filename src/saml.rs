use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{SecondsFormat, Utc};
use flate2::{Compression, write::DeflateEncoder};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::io::Write;
use uuid::Uuid;

/// SAML request configuration
#[derive(Debug, Clone)]
pub struct SamlRequest {
    /// The entity that issues the SAML request (typically the application identifier)
    pub issuer: String,
    /// The URL where SAML responses should be sent (Assertion Consumer Service URL)
    pub acs_url: String,
}

impl SamlRequest {
    /// Generate SAML authentication request XML and encode it
    pub fn generate(&self) -> Result<String> {
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
            self.acs_url, self.issuer
        );

        encode_saml_request(&xml).context("Failed to encode SAML request")
    }
}

/// SAML response (provider-independent)
#[derive(Debug)]
pub struct SamlResponse {
    decoded_xml: Vec<u8>,
}

impl SamlResponse {
    /// Create from Base64-encoded response
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = STANDARD
            .decode(encoded)
            .context("Failed to decode SAML response from base64")?;
        Ok(Self {
            decoded_xml: decoded,
        })
    }

    /// Get attribute values by name (generic attribute extraction)
    pub fn get_attribute_values(&self, attribute_name: &str) -> Result<Vec<String>> {
        let mut reader = Reader::from_reader(self.decoded_xml.as_slice());
        reader.config_mut().trim_text(true);

        let mut values = Vec::new();
        let mut in_target_attribute = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                    if e.name().as_ref() == b"saml2:Attribute" || e.name().as_ref() == b"Attribute"
                    {
                        in_target_attribute = check_attribute_name(e, attribute_name);
                    }
                }
                Ok(Event::Text(e)) if in_target_attribute => {
                    let value = String::from_utf8_lossy(e.as_ref()).to_string();
                    values.push(value);
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"saml2:Attribute" || e.name().as_ref() == b"Attribute"
                    {
                        in_target_attribute = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => bail!("Error parsing SAML response: {}", e),
                _ => {}
            }
            buf.clear();
        }

        if values.is_empty() {
            bail!("No values found for attribute: {}", attribute_name);
        }

        Ok(values)
    }

    /// Get the raw decoded XML content
    pub fn as_bytes(&self) -> &[u8] {
        &self.decoded_xml
    }
}

/// Deflate compress and Base64 encode SAML request
fn encode_saml_request(xml: &str) -> Result<String> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(xml.as_bytes())
        .context("Failed to compress SAML request")?;
    let compressed = encoder.finish().context("Failed to finish compression")?;
    Ok(STANDARD.encode(compressed))
}

/// Check if the attribute element has the specified name
fn check_attribute_name(e: &BytesStart, attribute_name: &str) -> bool {
    e.attributes().filter_map(Result::ok).any(|attr| {
        attr.key.as_ref() == b"Name" && attr.value.as_ref() == attribute_name.as_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saml_request_generate() {
        let request = SamlRequest {
            issuer: "https://example.com/saml".to_string(),
            acs_url: "https://signin.aws.amazon.com/saml".to_string(),
        };
        let encoded = request.generate().unwrap();
        assert!(!encoded.is_empty());

        // Verify it's valid base64
        let decoded = STANDARD.decode(&encoded);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_encode_saml_request() {
        let xml = "<test>Sample XML</test>";
        let encoded = encode_saml_request(xml).unwrap();
        assert!(!encoded.is_empty());

        // Verify it's valid base64
        let decoded = STANDARD.decode(&encoded);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_saml_response_from_base64() {
        // Create a simple test SAML response
        let xml = r#"<saml2:Response><saml2:Assertion><saml2:AttributeStatement>
            <saml2:Attribute Name="test-attribute">
                <saml2:AttributeValue>test-value</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement></saml2:Assertion></saml2:Response>"#;

        let encoded = STANDARD.encode(xml.as_bytes());
        let response = SamlResponse::from_base64(&encoded).unwrap();

        assert!(!response.as_bytes().is_empty());

        // Test attribute extraction
        let values = response.get_attribute_values("test-attribute").unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "test-value");
    }
}
