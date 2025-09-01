use anyhow::{Context, Result, bail};

use crate::saml::SamlResponse;

/// AWS IAM Role structure
#[derive(Debug, Clone)]
pub(crate) struct IamRole {
    pub name: String,
    pub role_arn: String,
    pub principal_arn: String,
}

/// SAMLアサーションで利用可能なIAMロール（空の状態を型レベルで排除）
#[derive(Debug, Clone)]
pub(crate) enum AvailableRoles {
    /// 単一ロール（自動選択可能）
    Single(IamRole),
    /// 複数ロール（明示的な選択が必要）
    Multiple(Vec<IamRole>),
}

impl AvailableRoles {
    /// SAMLレスポンスから利用可能なロールを抽出
    pub fn from_saml_response(saml_response: &SamlResponse) -> Result<Self> {
        // AWS固有の属性名
        const AWS_ROLE_ATTRIBUTE: &str = "https://aws.amazon.com/SAML/Attributes/Role";

        let role_values = saml_response.get_attribute_values(AWS_ROLE_ATTRIBUTE)?;
        let roles: Vec<IamRole> = role_values
            .iter()
            .filter_map(|value| IamRole::parse_arn_pair(value))
            .collect();

        match roles.len() {
            0 => bail!("No roles found in SAML response"),
            1 => Ok(AvailableRoles::Single(roles.into_iter().next().unwrap())),
            _ => Ok(AvailableRoles::Multiple(roles)),
        }
    }

    /// 利用するロールを決定
    pub fn assume(self, role_name: Option<&str>) -> Result<IamRole> {
        match self {
            AvailableRoles::Single(role) => role_name
                .filter(|&name| role.name != name)
                .map(|name| {
                    bail!(
                        "Specified role '{}' does not match the only available role '{}'",
                        name,
                        role.name
                    )
                })
                .unwrap_or(Ok(role)),
            AvailableRoles::Multiple(roles) => {
                match role_name {
                    Some(name) => {
                        // First collect available role names for error message
                        let available = roles
                            .iter()
                            .map(|r| r.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");

                        roles.into_iter().find(|r| r.name == name).with_context(|| {
                            format!("Role '{name}' not found. Available roles: {available}")
                        })
                    }
                    None => {
                        let available = roles
                            .iter()
                            .map(|r| r.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        bail!(
                            "Multiple roles available. Please specify one with --role flag: {}",
                            available
                        );
                    }
                }
            }
        }
    }
}

impl IamRole {
    /// ARNペアの解析（AWS固有フォーマット）
    fn parse_arn_pair(arn_pair: &str) -> Option<Self> {
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

        Some(IamRole {
            name,
            role_arn,
            principal_arn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_from_arn_pair() {
        let arn_pair = "arn:aws:iam::123456789012:role/MyRole,arn:aws:iam::123456789012:saml-provider/MyProvider";
        let role = IamRole::parse_arn_pair(arn_pair).unwrap();
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
        let role = IamRole::parse_arn_pair(arn_pair).unwrap();
        assert_eq!(role.name, "AdminRole");
        assert_eq!(role.role_arn, "arn:aws:iam::123456789012:role/AdminRole");
        assert_eq!(
            role.principal_arn,
            "arn:aws:iam::123456789012:saml-provider/MyProvider"
        );
    }

    #[test]
    fn test_available_roles_single() {
        let role = IamRole {
            name: "TestRole".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/TestRole".to_string(),
            principal_arn: "arn:aws:iam::123456789012:saml-provider/TestProvider".to_string(),
        };
        let available = AvailableRoles::Single(role.clone());

        // Test selection without role name
        let selected = available.clone().assume(None).unwrap();
        assert_eq!(selected.role_arn, role.role_arn);
        assert_eq!(selected.principal_arn, role.principal_arn);

        // Test selection with matching role name
        let selected = available.clone().assume(Some("TestRole")).unwrap();
        assert_eq!(selected.role_arn, role.role_arn);

        // Test selection with non-matching role name
        let result = available.clone().assume(Some("WrongRole"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));

        // Test that single role is properly handled
        match &available {
            AvailableRoles::Single(role) => assert_eq!(role.name, "TestRole"),
            _ => panic!("Expected Single variant"),
        }
    }

    #[test]
    fn test_available_roles_multiple() {
        let roles = vec![
            IamRole {
                name: "Role1".to_string(),
                role_arn: "arn:aws:iam::123456789012:role/Role1".to_string(),
                principal_arn: "arn:aws:iam::123456789012:saml-provider/Provider".to_string(),
            },
            IamRole {
                name: "Role2".to_string(),
                role_arn: "arn:aws:iam::123456789012:role/Role2".to_string(),
                principal_arn: "arn:aws:iam::123456789012:saml-provider/Provider".to_string(),
            },
        ];
        let available = AvailableRoles::Multiple(roles.clone());

        // Test selection without role name (should fail)
        let result = available.clone().assume(None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Multiple roles available")
        );

        // Test selection with valid role name
        let selected = available.clone().assume(Some("Role1")).unwrap();
        assert_eq!(selected.role_arn, roles[0].role_arn);

        // Test selection with invalid role name
        let result = available.clone().assume(Some("Role3"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        // Test that multiple roles are properly handled
        match &available {
            AvailableRoles::Multiple(roles) => {
                assert_eq!(roles.len(), 2);
                assert_eq!(roles[0].name, "Role1");
                assert_eq!(roles[1].name, "Role2");
            }
            _ => panic!("Expected Multiple variant"),
        }
    }
}
