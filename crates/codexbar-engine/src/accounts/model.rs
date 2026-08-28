use crate::model::ProviderId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountIdentity {
    pub provider: ProviderId,
    pub stable_keys: Vec<ProviderIdentityKey>,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderIdentityKey {
    pub namespace: String,
    pub value: String,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCredentialBundle {
    pub api_key: Option<String>,
    pub secret_key: Option<String>,
    pub cookie_header: Option<String>,
    pub artifact_format: Option<String>,
    pub artifact: Option<Vec<u8>>,
}

impl fmt::Debug for ProviderCredentialBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCredentialBundle")
            .field("has_api_key", &self.api_key.is_some())
            .field("has_secret_key", &self.secret_key.is_some())
            .field("has_cookie_header", &self.cookie_header.is_some())
            .field("artifact_format", &self.artifact_format)
            .field("has_artifact", &self.artifact.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ManagedCredentialState {
    Available,
    Missing,
    Invalid,
    Undecryptable,
    MigrationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderEnrollmentKind {
    ManualSecret,
    BrowserLogin,
    DeviceOAuth,
    CliLogin,
    ImportCurrent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActivationTargetKind {
    CliFile,
    WindowsCredential,
    DesktopClient,
    BrowserProfile,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountCapability {
    pub enrollment: Vec<ProviderEnrollmentKind>,
    pub activation_target: ActivationTargetKind,
}

impl ProviderIdentityKey {
    pub fn new(namespace: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            value: value.into(),
        }
    }
}

impl ProviderAccountIdentity {
    pub fn new(
        provider: ProviderId,
        stable_keys: impl IntoIterator<Item = ProviderIdentityKey>,
        email: Option<String>,
        display_name: Option<String>,
    ) -> Self {
        Self {
            provider,
            stable_keys: stable_keys.into_iter().collect(),
            email,
            display_name,
        }
    }

    pub fn unverified(provider: ProviderId) -> Self {
        Self::new(provider, [], None, None)
    }

    pub fn is_activation_eligible(&self) -> bool {
        !self.stable_keys.is_empty()
    }

    pub fn matches_stable(&self, other: &Self) -> bool {
        self.provider == other.provider
            && self
                .stable_keys
                .iter()
                .any(|key| other.stable_keys.contains(key))
    }

    pub fn matches_stable_without_namespace_conflicts(&self, other: &Self) -> bool {
        self.matches_stable(other)
            && self.stable_keys.iter().all(|key| {
                !other
                    .stable_keys
                    .iter()
                    .any(|other_key| other_key.namespace == key.namespace)
                    || other.stable_keys.iter().any(|other_key| other_key == key)
            })
            && other.stable_keys.iter().all(|key| {
                !self
                    .stable_keys
                    .iter()
                    .any(|self_key| self_key.namespace == key.namespace)
                    || self.stable_keys.iter().any(|self_key| self_key == key)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivationTargetKind, ManagedCredentialState, ProviderAccountCapability,
        ProviderAccountIdentity, ProviderCredentialBundle, ProviderEnrollmentKind,
        ProviderIdentityKey,
    };
    use crate::model::ProviderId;

    #[test]
    fn stable_identity_matches_by_namespaced_key_but_never_by_email_alone() {
        let left = ProviderAccountIdentity::new(
            ProviderId::Codex,
            [ProviderIdentityKey::new("jwt-sub", "subject-a")],
            Some("same@example.com".into()),
            None,
        );
        let same_email = ProviderAccountIdentity::new(
            ProviderId::Codex,
            [ProviderIdentityKey::new("jwt-sub", "subject-b")],
            Some("same@example.com".into()),
            None,
        );
        let same_subject = ProviderAccountIdentity::new(
            ProviderId::Codex,
            [ProviderIdentityKey::new("jwt-sub", "subject-a")],
            Some("renamed@example.com".into()),
            None,
        );

        assert!(!left.matches_stable(&same_email));
        assert!(left.matches_stable(&same_subject));
    }

    #[test]
    fn empty_identity_is_monitoring_only() {
        let identity = ProviderAccountIdentity::unverified(ProviderId::Openrouter);
        assert!(!identity.is_activation_eligible());
    }

    #[test]
    fn stable_identity_does_not_match_across_providers() {
        let codex = ProviderAccountIdentity::new(
            ProviderId::Codex,
            [ProviderIdentityKey::new("subject", "account-a")],
            None,
            None,
        );
        let claude = ProviderAccountIdentity::new(
            ProviderId::Claude,
            [ProviderIdentityKey::new("subject", "account-a")],
            None,
            None,
        );

        assert!(!codex.matches_stable(&claude));
    }

    #[test]
    fn credential_bundle_debug_reports_presence_without_secrets() {
        let bundle = ProviderCredentialBundle {
            api_key: Some("api-secret".into()),
            secret_key: Some("secret-key".into()),
            cookie_header: Some("session=private".into()),
            artifact_format: Some("opaque".into()),
            artifact: Some(vec![1, 2, 3]),
        };

        let debug = format!("{bundle:?}");
        assert!(debug.contains("has_api_key: true"));
        assert!(debug.contains("has_secret_key: true"));
        assert!(debug.contains("has_cookie_header: true"));
        assert!(debug.contains("artifact_format: Some(\"opaque\")"));
        assert!(debug.contains("has_artifact: true"));
        assert!(!debug.contains("api-secret"));
        assert!(!debug.contains("secret-key"));
        assert!(!debug.contains("session=private"));
        assert!(!debug.contains("[1, 2, 3]"));
    }

    #[test]
    fn account_model_serializes_with_camel_case_fields_and_variants() {
        let identity = ProviderAccountIdentity::new(
            ProviderId::Codex,
            [ProviderIdentityKey::new("jwt-sub", "subject-a")],
            Some("person@example.com".into()),
            Some("Person".into()),
        );
        let capability = ProviderAccountCapability {
            enrollment: vec![ProviderEnrollmentKind::DeviceOAuth],
            activation_target: ActivationTargetKind::WindowsCredential,
        };

        let identity_json = serde_json::to_value(identity).unwrap();
        assert_eq!(identity_json["stableKeys"][0]["namespace"], "jwt-sub");
        assert_eq!(identity_json["displayName"], "Person");
        assert_eq!(
            serde_json::to_value(capability).unwrap()["enrollment"][0],
            "deviceOAuth"
        );
        assert_eq!(
            serde_json::to_value(ManagedCredentialState::MigrationFailed).unwrap(),
            "migrationFailed"
        );
    }
}
