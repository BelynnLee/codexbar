use super::adapters::{ActivationSupport, ProviderAccountCommandError, ProviderAdapterDeclaration};
use codexbar_engine::{
    ProviderAccountIdentity, ProviderCredentialBundle, ProviderId,
    auth::credentials::ClaudeCredentials,
};
use std::{fmt, fs, path::PathBuf};

const CLAUDE_ARTIFACT_FORMAT: &str = "claude-credentials-json";
const CLAUDE_UNSUPPORTED_REASON: &str = "Claude credential activation is unavailable because the documented Claude CLI credential schema has no stable official account identifier.";

#[derive(Clone)]
pub struct ClaudeFileAdapter {
    credential_path: PathBuf,
}

impl ClaudeFileAdapter {
    pub fn new(credential_path: PathBuf) -> Self {
        Self { credential_path }
    }

    pub fn from_default() -> Result<Self, ProviderAccountCommandError> {
        ClaudeCredentials::default_path()
            .map(Self::new)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Claude, None))
    }

    pub fn capture_bundle(&self) -> Result<ProviderCredentialBundle, ProviderAccountCommandError> {
        let bytes = fs::read(&self.credential_path).map_err(|_| {
            ProviderAccountCommandError::invalid_credential(ProviderId::Claude, None)
        })?;
        ClaudeCredentials::parse(&bytes, None).map_err(|_| {
            ProviderAccountCommandError::invalid_credential(ProviderId::Claude, None)
        })?;
        Ok(ProviderCredentialBundle {
            artifact_format: Some(CLAUDE_ARTIFACT_FORMAT.into()),
            artifact: Some(bytes),
            ..Default::default()
        })
    }

    pub fn identity(
        credentials: &[u8],
    ) -> Result<ProviderAccountIdentity, ProviderAccountCommandError> {
        ClaudeCredentials::parse(credentials, None).map_err(|_| {
            ProviderAccountCommandError::invalid_credential(ProviderId::Claude, None)
        })?;
        Err(ProviderAccountCommandError::unsupported_activation(
            ProviderId::Claude,
            None,
        ))
    }

    pub fn support(&self) -> ActivationSupport {
        ActivationSupport::unsupported_with_reason(CLAUDE_UNSUPPORTED_REASON)
    }

    pub(crate) fn declaration() -> ProviderAdapterDeclaration {
        ProviderAdapterDeclaration::monitoring_only_with_reason(
            ProviderId::Claude,
            Vec::new(),
            CLAUDE_UNSUPPORTED_REASON,
        )
    }
}

impl fmt::Debug for ClaudeFileAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeFileAdapter")
            .field("target", &"Claude CLI .credentials.json")
            .field("activation_supported", &false)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_accounts::ProviderAdapterRegistry;
    use codexbar_engine::{ActivationTargetKind, ProviderId};
    use std::fs;

    fn credential_json(extra: serde_json::Value) -> Vec<u8> {
        let mut root = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "claude-access-secret",
                "refreshToken": "claude-refresh-secret",
                "expiresAt": 4070908800000_i64,
                "scopes": ["user:profile"]
            },
            "future": {"preserved": true}
        });
        root.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::to_vec(&root).unwrap()
    }

    #[test]
    fn captures_complete_official_credential_json_as_opaque_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(".credentials.json");
        let bytes = credential_json(serde_json::json!({"newOfficialField": [1, 2, 3]}));
        fs::write(&path, &bytes).unwrap();
        let adapter = ClaudeFileAdapter::new(path);

        let bundle = adapter.capture_bundle().unwrap();

        assert_eq!(
            bundle.artifact_format.as_deref(),
            Some("claude-credentials-json")
        );
        assert_eq!(bundle.artifact.as_deref(), Some(bytes.as_slice()));
        assert!(!format!("{bundle:?}").contains("claude-access-secret"));
    }

    #[test]
    fn no_supported_credential_label_creates_a_stable_claude_identity() {
        let fixtures = [
            serde_json::json!({"email": "same@example.com"}),
            serde_json::json!({"tokenOnly": "token-label"}),
            serde_json::json!({"plan": "max", "tier": "premium"}),
            serde_json::json!({"statusLine": "Account abc@example.com"}),
            serde_json::json!({"quota": {"weekly": "75%"}}),
        ];

        for fixture in fixtures {
            assert!(
                ClaudeFileAdapter::identity(&credential_json(fixture)).is_err(),
                "fixture must remain activation-ineligible"
            );
        }
    }

    #[test]
    fn claude_activation_is_precisely_unsupported_and_no_adapter_is_registered() {
        let temporary = tempfile::tempdir().unwrap();
        let claude = ClaudeFileAdapter::new(temporary.path().join(".credentials.json"));
        let support = claude.support();
        assert_eq!(support.kind, ActivationTargetKind::Unsupported);
        assert!(
            support
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("stable official account identifier"))
        );

        let registry = ProviderAdapterRegistry::verified_file_adapters(
            super::super::codex::CodexFileAdapter::new(temporary.path().join(".codex")),
            claude,
        )
        .unwrap();
        assert!(registry.adapter(ProviderId::Claude).is_none());
        assert_eq!(registry.enrollment(ProviderId::Claude), Some([].as_slice()));
        assert_eq!(registry.activation_support(ProviderId::Claude), support);
    }
}
