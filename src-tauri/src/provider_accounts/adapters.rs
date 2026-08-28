use codexbar_engine::{
    ActivationTargetKind, ProviderAccountIdentity, ProviderCredentialBundle,
    ProviderEnrollmentKind, ProviderId, auth::credentials::is_safe_managed_account_id,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, sync::Arc};

const UNSUPPORTED_REASON: &str =
    "Official client credential activation is not supported for this provider.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationSupport {
    pub kind: ActivationTargetKind,
    pub target_description: Option<String>,
    pub blocked_reason: Option<String>,
}

impl ActivationSupport {
    fn unsupported() -> Self {
        Self::unsupported_with_reason(UNSUPPORTED_REASON)
    }

    pub(crate) fn unsupported_with_reason(reason: impl Into<String>) -> Self {
        Self {
            kind: ActivationTargetKind::Unsupported,
            target_description: None,
            blocked_reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartHint {
    pub required: bool,
    pub client_name: Option<String>,
    pub message: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialTargetSnapshot {
    pub credentials: Option<ProviderCredentialBundle>,
    pub fingerprint: Option<String>,
}

impl fmt::Debug for CredentialTargetSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialTargetSnapshot")
            .field("has_credentials", &self.credentials.is_some())
            .field("has_fingerprint", &self.fingerprint.is_some())
            .finish()
    }
}

pub trait CredentialActivationAdapter: Send + Sync + fmt::Debug {
    fn provider(&self) -> ProviderId;
    fn support(&self) -> ActivationSupport;
    fn capture(&self) -> Result<CredentialTargetSnapshot, ProviderAccountCommandError>;
    fn fingerprint(&self) -> Result<Option<String>, ProviderAccountCommandError>;
    fn target_fingerprint(
        &self,
        credentials: &ProviderCredentialBundle,
    ) -> Result<Option<String>, ProviderAccountCommandError>;
    fn current_identity(
        &self,
    ) -> Result<Option<ProviderAccountIdentity>, ProviderAccountCommandError>;
    fn validate_target(
        &self,
        identity: &ProviderAccountIdentity,
        credentials: &ProviderCredentialBundle,
    ) -> Result<(), ProviderAccountCommandError>;
    fn install(
        &self,
        credentials: &ProviderCredentialBundle,
        expected_current_fingerprint: &Option<String>,
    ) -> Result<(), ProviderAccountCommandError>;
    fn verify(&self, identity: &ProviderAccountIdentity)
    -> Result<(), ProviderAccountCommandError>;
    fn restore(
        &self,
        snapshot: &CredentialTargetSnapshot,
        expected_current_fingerprint: &Option<String>,
    ) -> Result<(), ProviderAccountCommandError>;
    fn restart_hint(&self) -> RestartHint;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAccountCommandErrorCode {
    UnsupportedActivation,
    InvalidCredential,
    IdentityMismatch,
    ExternalWrite,
    RolledBack,
    RecoveryRequired,
    RecoveryFailed,
    LoginFailure,
    OperationInProgress,
    AccountNotFound,
    AccountActive,
    AccountDisabled,
    Internal,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountCommandError {
    code: ProviderAccountCommandErrorCode,
    #[serde(rename = "providerId", skip_serializing_if = "Option::is_none")]
    provider: Option<ProviderId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    message: &'static str,
}

impl ProviderAccountCommandError {
    fn new(
        code: ProviderAccountCommandErrorCode,
        provider: ProviderId,
        account_id: Option<&str>,
    ) -> Self {
        let account_id = account_id
            .filter(|value| is_safe_managed_account_id(value))
            .map(str::to_owned);
        Self {
            code,
            provider: Some(provider),
            account_id,
            message: code.canonical_message(),
        }
    }

    pub fn unsupported_activation(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::UnsupportedActivation,
            provider,
            account_id,
        )
    }

    pub fn invalid_credential(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::InvalidCredential,
            provider,
            account_id,
        )
    }

    pub fn identity_mismatch(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::IdentityMismatch,
            provider,
            account_id,
        )
    }

    pub fn external_write(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::ExternalWrite,
            provider,
            account_id,
        )
    }

    pub fn rolled_back(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::RolledBack,
            provider,
            account_id,
        )
    }

    pub fn recovery_required(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::RecoveryRequired,
            provider,
            account_id,
        )
    }

    pub fn recovery_failed(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::RecoveryFailed,
            provider,
            account_id,
        )
    }

    pub fn login_failure(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::LoginFailure,
            provider,
            account_id,
        )
    }

    pub fn operation_in_progress(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::OperationInProgress,
            provider,
            account_id,
        )
    }

    pub fn account_not_found(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::AccountNotFound,
            provider,
            account_id,
        )
    }

    pub fn account_active(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::AccountActive,
            provider,
            account_id,
        )
    }

    pub fn account_disabled(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::AccountDisabled,
            provider,
            account_id,
        )
    }

    pub fn internal(provider: ProviderId, account_id: Option<&str>) -> Self {
        Self::new(
            ProviderAccountCommandErrorCode::Internal,
            provider,
            account_id,
        )
    }

    fn global(code: ProviderAccountCommandErrorCode) -> Self {
        Self {
            code,
            provider: None,
            account_id: None,
            message: code.canonical_message(),
        }
    }

    pub fn internal_global() -> Self {
        Self::global(ProviderAccountCommandErrorCode::Internal)
    }

    pub fn external_write_global() -> Self {
        Self::global(ProviderAccountCommandErrorCode::ExternalWrite)
    }

    pub const fn code(&self) -> ProviderAccountCommandErrorCode {
        self.code
    }

    pub const fn provider(&self) -> Option<ProviderId> {
        self.provider
    }

    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl ProviderAccountCommandErrorCode {
    const fn canonical_message(self) -> &'static str {
        match self {
            Self::UnsupportedActivation => UNSUPPORTED_REASON,
            Self::InvalidCredential => "The selected account credentials are invalid.",
            Self::IdentityMismatch => {
                "The official account identity does not match the selected account."
            }
            Self::ExternalWrite => {
                "The official client credentials changed outside CodexBar; no stale credentials were written."
            }
            Self::RolledBack => {
                "Credential activation failed and the original credentials were restored."
            }
            Self::RecoveryRequired => {
                "Credential recovery is required before another activation can start."
            }
            Self::RecoveryFailed => {
                "The original official client credentials could not be restored."
            }
            Self::LoginFailure => "The official account login did not complete successfully.",
            Self::OperationInProgress => {
                "Another account operation is already in progress for this provider."
            }
            Self::AccountNotFound => "The selected provider account was not found.",
            Self::AccountActive => "The active provider account cannot be changed this way.",
            Self::AccountDisabled => "The selected provider account is paused.",
            Self::Internal => "The provider account operation could not be completed.",
        }
    }
}

impl fmt::Display for ProviderAccountCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.provider {
            Some(provider) => write!(formatter, "{provider}: {}", self.message),
            None => formatter.write_str(self.message),
        }
    }
}

impl fmt::Debug for ProviderAccountCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAccountCommandError")
            .field("code", &self.code)
            .field("provider", &self.provider)
            .field("account_id", &self.account_id)
            .field("message", &self.message)
            .finish()
    }
}

impl std::error::Error for ProviderAccountCommandError {}

#[derive(Clone)]
pub struct ProviderAdapterDeclaration {
    provider: ProviderId,
    enrollment: Vec<ProviderEnrollmentKind>,
    adapter: Option<Arc<dyn CredentialActivationAdapter>>,
    unsupported_reason: Option<String>,
    conditional_adapter: bool,
}

impl ProviderAdapterDeclaration {
    pub fn monitoring_only(provider: ProviderId, enrollment: Vec<ProviderEnrollmentKind>) -> Self {
        Self {
            provider,
            enrollment,
            adapter: None,
            unsupported_reason: None,
            conditional_adapter: false,
        }
    }

    pub fn monitoring_only_with_reason(
        provider: ProviderId,
        enrollment: Vec<ProviderEnrollmentKind>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            enrollment,
            adapter: None,
            unsupported_reason: Some(reason.into()),
            conditional_adapter: false,
        }
    }

    pub fn with_adapter(
        provider: ProviderId,
        enrollment: Vec<ProviderEnrollmentKind>,
        adapter: Arc<dyn CredentialActivationAdapter>,
    ) -> Self {
        Self {
            provider,
            enrollment,
            adapter: Some(adapter),
            unsupported_reason: None,
            conditional_adapter: false,
        }
    }

    pub(crate) fn with_conditional_adapter(
        provider: ProviderId,
        enrollment: Vec<ProviderEnrollmentKind>,
        adapter: Arc<dyn CredentialActivationAdapter>,
    ) -> Self {
        Self {
            provider,
            enrollment,
            adapter: Some(adapter),
            unsupported_reason: None,
            conditional_adapter: true,
        }
    }
}

impl fmt::Debug for ProviderAdapterDeclaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAdapterDeclaration")
            .field("provider", &self.provider)
            .field("enrollment", &self.enrollment)
            .field("has_adapter", &self.adapter.is_some())
            .field("conditional_adapter", &self.conditional_adapter)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAdapterRegistryError {
    MissingProvider(ProviderId),
    DuplicateProvider(ProviderId),
    AdapterProviderMismatch {
        declared: ProviderId,
        actual: ProviderId,
    },
    UnsupportedAdapter(ProviderId),
    AdapterInitializationFailed {
        provider: ProviderId,
        code: ProviderAccountCommandErrorCode,
    },
}

#[derive(Clone)]
struct ProviderAdapterEntry {
    enrollment: Vec<ProviderEnrollmentKind>,
    adapter: Option<Arc<dyn CredentialActivationAdapter>>,
    unsupported_reason: Option<String>,
}

#[derive(Clone)]
pub struct ProviderAdapterRegistry {
    entries: HashMap<ProviderId, ProviderAdapterEntry>,
}

impl fmt::Debug for ProviderAdapterRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let registered_adapters = ProviderId::ALL
            .into_iter()
            .filter(|provider| {
                self.entries
                    .get(provider)
                    .is_some_and(|entry| entry.adapter.is_some())
            })
            .collect::<Vec<_>>();
        formatter
            .debug_struct("ProviderAdapterRegistry")
            .field("declared_provider_count", &self.entries.len())
            .field("registered_adapters", &registered_adapters)
            .finish()
    }
}

impl ProviderAdapterRegistry {
    pub fn empty() -> Self {
        let declarations = ProviderId::ALL
            .into_iter()
            .map(|provider| ProviderAdapterDeclaration::monitoring_only(provider, Vec::new()));
        Self::new(declarations).expect("all providers are declared exactly once")
    }

    pub fn new(
        declarations: impl IntoIterator<Item = ProviderAdapterDeclaration>,
    ) -> Result<Self, ProviderAdapterRegistryError> {
        let mut entries = HashMap::with_capacity(ProviderId::ALL.len());
        for declaration in declarations {
            if entries.contains_key(&declaration.provider) {
                return Err(ProviderAdapterRegistryError::DuplicateProvider(
                    declaration.provider,
                ));
            }
            if let Some(adapter) = declaration.adapter.as_ref() {
                let actual = adapter.provider();
                if actual != declaration.provider {
                    return Err(ProviderAdapterRegistryError::AdapterProviderMismatch {
                        declared: declaration.provider,
                        actual,
                    });
                }
                if adapter.support().kind == ActivationTargetKind::Unsupported
                    && !declaration.conditional_adapter
                {
                    return Err(ProviderAdapterRegistryError::UnsupportedAdapter(
                        declaration.provider,
                    ));
                }
            }
            entries.insert(
                declaration.provider,
                ProviderAdapterEntry {
                    enrollment: declaration.enrollment,
                    adapter: declaration.adapter,
                    unsupported_reason: declaration.unsupported_reason,
                },
            );
        }
        for provider in ProviderId::ALL {
            if !entries.contains_key(&provider) {
                return Err(ProviderAdapterRegistryError::MissingProvider(provider));
            }
        }
        Ok(Self { entries })
    }

    pub fn declared_providers(&self) -> [ProviderId; ProviderId::ALL.len()] {
        ProviderId::ALL
    }

    pub fn enrollment(&self, provider: ProviderId) -> Option<&[ProviderEnrollmentKind]> {
        self.entries
            .get(&provider)
            .map(|entry| entry.enrollment.as_slice())
    }

    pub fn activation_support(&self, provider: ProviderId) -> ActivationSupport {
        let Some(entry) = self.entries.get(&provider) else {
            return ActivationSupport::unsupported();
        };
        entry.adapter.as_ref().map_or_else(
            || {
                entry.unsupported_reason.as_ref().map_or_else(
                    ActivationSupport::unsupported,
                    ActivationSupport::unsupported_with_reason,
                )
            },
            |adapter| adapter.support(),
        )
    }

    pub fn adapter(&self, provider: ProviderId) -> Option<&dyn CredentialActivationAdapter> {
        self.entries
            .get(&provider)
            .and_then(|entry| entry.adapter.as_deref())
    }

    pub fn verified_file_adapters(
        codex: super::codex::CodexFileAdapter,
        _claude: super::claude::ClaudeFileAdapter,
    ) -> Result<Self, ProviderAdapterRegistryError> {
        codex.recover_pending_transactions().map_err(|error| {
            ProviderAdapterRegistryError::AdapterInitializationFailed {
                provider: ProviderId::Codex,
                code: error.code(),
            }
        })?;
        let declarations = ProviderId::ALL.into_iter().map(|provider| match provider {
            ProviderId::Codex => codex.clone().declaration(),
            ProviderId::Claude => super::claude::ClaudeFileAdapter::declaration(),
            _ => ProviderAdapterDeclaration::monitoring_only(provider, Vec::new()),
        });
        Self::new(declarations)
    }

    pub fn verified_default_file_adapters() -> Result<Self, ProviderAccountCommandError> {
        let codex = super::codex::CodexFileAdapter::from_default()?;
        let claude = super::claude::ClaudeFileAdapter::from_default()?;
        Self::verified_file_adapters(codex, claude).map_err(|error| match error {
            ProviderAdapterRegistryError::AdapterInitializationFailed {
                provider,
                code: ProviderAccountCommandErrorCode::OperationInProgress,
            } => ProviderAccountCommandError::operation_in_progress(provider, None),
            ProviderAdapterRegistryError::AdapterInitializationFailed {
                provider,
                code: ProviderAccountCommandErrorCode::RecoveryRequired,
            } => ProviderAccountCommandError::recovery_required(provider, None),
            ProviderAdapterRegistryError::AdapterInitializationFailed {
                provider,
                code: ProviderAccountCommandErrorCode::RecoveryFailed,
            } => ProviderAccountCommandError::recovery_failed(provider, None),
            _ => ProviderAccountCommandError::internal(ProviderId::Codex, None),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codexbar_engine::{
        ActivationTargetKind, ProviderAccountIdentity, ProviderCredentialBundle,
        ProviderEnrollmentKind, ProviderId, ProviderIdentityKey,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct FakeAdapter {
        provider: ProviderId,
        support_kind: ActivationTargetKind,
        target: Arc<Mutex<Option<ProviderCredentialBundle>>>,
        debug_label: String,
    }

    impl FakeAdapter {
        fn new(
            provider: ProviderId,
            support_kind: ActivationTargetKind,
            target: Arc<Mutex<Option<ProviderCredentialBundle>>>,
        ) -> Self {
            Self {
                provider,
                support_kind,
                target,
                debug_label: "fake-adapter".into(),
            }
        }

        fn with_debug_label(mut self, debug_label: &str) -> Self {
            self.debug_label = debug_label.into();
            self
        }
    }

    impl CredentialActivationAdapter for FakeAdapter {
        fn provider(&self) -> ProviderId {
            self.provider
        }

        fn support(&self) -> ActivationSupport {
            ActivationSupport {
                kind: self.support_kind,
                target_description: Some("Fake official CLI credential file".into()),
                blocked_reason: None,
            }
        }

        fn capture(&self) -> Result<CredentialTargetSnapshot, ProviderAccountCommandError> {
            let credentials = self.target.lock().unwrap().clone();
            Ok(CredentialTargetSnapshot {
                fingerprint: fingerprint(credentials.as_ref()),
                credentials,
            })
        }

        fn fingerprint(&self) -> Result<Option<String>, ProviderAccountCommandError> {
            Ok(fingerprint(self.target.lock().unwrap().as_ref()))
        }

        fn target_fingerprint(
            &self,
            credentials: &ProviderCredentialBundle,
        ) -> Result<Option<String>, ProviderAccountCommandError> {
            Ok(fingerprint(Some(credentials)))
        }

        fn current_identity(
            &self,
        ) -> Result<Option<ProviderAccountIdentity>, ProviderAccountCommandError> {
            Ok(self.target.lock().unwrap().as_ref().and_then(|bundle| {
                bundle.api_key.as_ref().map(|value| {
                    ProviderAccountIdentity::new(
                        self.provider,
                        [ProviderIdentityKey::new("fixture", value)],
                        None,
                        None,
                    )
                })
            }))
        }

        fn validate_target(
            &self,
            identity: &ProviderAccountIdentity,
            credentials: &ProviderCredentialBundle,
        ) -> Result<(), ProviderAccountCommandError> {
            if identity.provider != self.provider
                || !identity.is_activation_eligible()
                || credentials.api_key.is_none()
            {
                return Err(ProviderAccountCommandError::invalid_credential(
                    self.provider,
                    None,
                ));
            }
            Ok(())
        }

        fn install(
            &self,
            credentials: &ProviderCredentialBundle,
            expected_current_fingerprint: &Option<String>,
        ) -> Result<(), ProviderAccountCommandError> {
            let mut target = self.target.lock().unwrap();
            if fingerprint(target.as_ref()) != *expected_current_fingerprint {
                return Err(ProviderAccountCommandError::external_write(
                    self.provider,
                    None,
                ));
            }
            *target = Some(credentials.clone());
            Ok(())
        }

        fn verify(
            &self,
            identity: &ProviderAccountIdentity,
        ) -> Result<(), ProviderAccountCommandError> {
            let expected = identity.stable_keys.first().map(|key| key.value.as_str());
            let target = self.target.lock().unwrap();
            if target.as_ref().and_then(|bundle| bundle.api_key.as_deref()) == expected {
                Ok(())
            } else {
                Err(ProviderAccountCommandError::identity_mismatch(
                    self.provider,
                    None,
                ))
            }
        }

        fn restore(
            &self,
            snapshot: &CredentialTargetSnapshot,
            expected_current_fingerprint: &Option<String>,
        ) -> Result<(), ProviderAccountCommandError> {
            let mut target = self.target.lock().unwrap();
            if fingerprint(target.as_ref()) != *expected_current_fingerprint {
                return Err(ProviderAccountCommandError::external_write(
                    self.provider,
                    None,
                ));
            }
            *target = snapshot.credentials.clone();
            Ok(())
        }

        fn restart_hint(&self) -> RestartHint {
            RestartHint {
                required: true,
                client_name: Some("Fake CLI".into()),
                message: Some("Restart Fake CLI to use the activated account.".into()),
            }
        }
    }

    fn bundle(value: &str) -> ProviderCredentialBundle {
        ProviderCredentialBundle {
            api_key: Some(value.into()),
            ..Default::default()
        }
    }

    fn identity(provider: ProviderId, value: &str) -> ProviderAccountIdentity {
        ProviderAccountIdentity::new(
            provider,
            [ProviderIdentityKey::new("official-account-id", value)],
            None,
            None,
        )
    }

    fn fingerprint(bundle: Option<&ProviderCredentialBundle>) -> Option<String> {
        bundle.and_then(|bundle| bundle.api_key.as_ref().map(|value| format!("fp:{value}")))
    }

    fn declarations_with(
        replacement: ProviderAdapterDeclaration,
    ) -> Vec<ProviderAdapterDeclaration> {
        ProviderId::ALL
            .into_iter()
            .map(|provider| {
                if provider == replacement.provider {
                    replacement.clone()
                } else {
                    ProviderAdapterDeclaration::monitoring_only(provider, Vec::new())
                }
            })
            .collect()
    }

    #[test]
    fn fake_adapter_contract_replaces_verifies_and_restores_exact_credentials() {
        let target = Arc::new(Mutex::new(Some(bundle("old-account"))));
        let adapter = FakeAdapter::new(
            ProviderId::Codex,
            ActivationTargetKind::CliFile,
            target.clone(),
        );
        let snapshot = adapter.capture().unwrap();

        adapter
            .validate_target(
                &identity(ProviderId::Codex, "new-account"),
                &bundle("new-account"),
            )
            .unwrap();
        adapter
            .install(&bundle("new-account"), &snapshot.fingerprint)
            .unwrap();
        assert_eq!(
            adapter.fingerprint().unwrap(),
            Some("fp:new-account".into())
        );
        adapter
            .verify(&identity(ProviderId::Codex, "new-account"))
            .unwrap();
        let installed = adapter.fingerprint().unwrap();
        adapter.restore(&snapshot, &installed).unwrap();

        assert_eq!(*target.lock().unwrap(), Some(bundle("old-account")));
        assert_eq!(
            adapter.restart_hint().client_name.as_deref(),
            Some("Fake CLI")
        );
    }

    #[test]
    fn registry_returns_explicit_unsupported_capability_without_a_fake_adapter() {
        let registry = ProviderAdapterRegistry::empty();
        let support = registry.activation_support(ProviderId::Openrouter);

        assert_eq!(support.kind, ActivationTargetKind::Unsupported);
        assert!(
            support
                .blocked_reason
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(registry.adapter(ProviderId::Openrouter).is_none());
    }

    #[test]
    fn registry_declares_enrollment_and_activation_for_every_provider() {
        let registry = ProviderAdapterRegistry::empty();

        assert_eq!(registry.declared_providers(), ProviderId::ALL);
        for provider in ProviderId::ALL {
            assert!(registry.enrollment(provider).is_some());
            assert_eq!(
                registry.activation_support(provider).kind,
                ActivationTargetKind::Unsupported
            );
        }
    }

    #[test]
    fn registry_rejects_missing_and_duplicate_provider_declarations() {
        let missing = ProviderId::ALL
            .into_iter()
            .filter(|provider| *provider != ProviderId::Codex)
            .map(|provider| ProviderAdapterDeclaration::monitoring_only(provider, Vec::new()))
            .collect::<Vec<_>>();
        assert!(matches!(
            ProviderAdapterRegistry::new(missing),
            Err(ProviderAdapterRegistryError::MissingProvider(
                ProviderId::Codex
            ))
        ));

        let mut duplicate = ProviderId::ALL
            .into_iter()
            .map(|provider| ProviderAdapterDeclaration::monitoring_only(provider, Vec::new()))
            .collect::<Vec<_>>();
        duplicate.push(ProviderAdapterDeclaration::monitoring_only(
            ProviderId::Codex,
            Vec::new(),
        ));
        assert!(matches!(
            ProviderAdapterRegistry::new(duplicate),
            Err(ProviderAdapterRegistryError::DuplicateProvider(
                ProviderId::Codex
            ))
        ));
    }

    #[test]
    fn registry_rejects_mismatched_and_unsupported_adapter_registration() {
        let target = Arc::new(Mutex::new(None));
        let mismatched = ProviderAdapterDeclaration::with_adapter(
            ProviderId::Claude,
            vec![ProviderEnrollmentKind::CliLogin],
            Arc::new(FakeAdapter::new(
                ProviderId::Codex,
                ActivationTargetKind::CliFile,
                target.clone(),
            )),
        );
        assert!(matches!(
            ProviderAdapterRegistry::new(declarations_with(mismatched)),
            Err(ProviderAdapterRegistryError::AdapterProviderMismatch {
                declared: ProviderId::Claude,
                actual: ProviderId::Codex,
            })
        ));

        let unsupported = ProviderAdapterDeclaration::with_adapter(
            ProviderId::Codex,
            vec![ProviderEnrollmentKind::ImportCurrent],
            Arc::new(FakeAdapter::new(
                ProviderId::Codex,
                ActivationTargetKind::Unsupported,
                target,
            )),
        );
        assert!(matches!(
            ProviderAdapterRegistry::new(declarations_with(unsupported)),
            Err(ProviderAdapterRegistryError::UnsupportedAdapter(
                ProviderId::Codex
            ))
        ));
    }

    #[test]
    fn registered_adapter_is_keyed_by_its_provider_and_preserves_contract_behavior() {
        let target = Arc::new(Mutex::new(Some(bundle("before"))));
        let declaration = ProviderAdapterDeclaration::with_adapter(
            ProviderId::Codex,
            vec![ProviderEnrollmentKind::CliLogin],
            Arc::new(FakeAdapter::new(
                ProviderId::Codex,
                ActivationTargetKind::CliFile,
                target.clone(),
            )),
        );
        let registry = ProviderAdapterRegistry::new(declarations_with(declaration)).unwrap();
        let adapter = registry.adapter(ProviderId::Codex).unwrap();
        let snapshot = adapter.capture().unwrap();
        adapter
            .install(&bundle("after"), &snapshot.fingerprint)
            .unwrap();
        adapter
            .verify(&identity(ProviderId::Codex, "after"))
            .unwrap();
        let installed = adapter.fingerprint().unwrap();
        adapter.restore(&snapshot, &installed).unwrap();

        assert_eq!(*target.lock().unwrap(), Some(bundle("before")));
        assert_eq!(
            registry.enrollment(ProviderId::Codex),
            Some(&[ProviderEnrollmentKind::CliLogin][..])
        );
    }

    #[test]
    fn registry_debug_does_not_expand_adapter_internal_state() {
        let declaration = ProviderAdapterDeclaration::with_adapter(
            ProviderId::Codex,
            vec![ProviderEnrollmentKind::CliLogin],
            Arc::new(
                FakeAdapter::new(
                    ProviderId::Codex,
                    ActivationTargetKind::CliFile,
                    Arc::new(Mutex::new(Some(bundle("credential-secret")))),
                )
                .with_debug_label("adapter-debug-secret"),
            ),
        );
        let registry = ProviderAdapterRegistry::new(declarations_with(declaration)).unwrap();

        let debug = format!("{registry:?}");
        assert!(!debug.contains("adapter-debug-secret"));
        assert!(!debug.contains("credential-secret"));
    }

    #[test]
    fn snapshot_debug_redacts_credentials_while_serde_preserves_recovery_payload() {
        let snapshot = CredentialTargetSnapshot {
            credentials: Some(ProviderCredentialBundle {
                api_key: Some("api-super-secret".into()),
                cookie_header: Some("session=cookie-secret".into()),
                artifact: Some(b"artifact-secret".to_vec()),
                ..Default::default()
            }),
            fingerprint: Some("sha256:fingerprint".into()),
        };

        let debug = format!("{snapshot:?}");
        assert!(debug.contains("has_credentials: true"));
        assert!(debug.contains("has_fingerprint: true"));
        for secret in [
            "api-super-secret",
            "cookie-secret",
            "artifact-secret",
            "sha256:fingerprint",
        ] {
            assert!(!debug.contains(secret));
        }

        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["credentials"]["apiKey"], "api-super-secret");
        assert_eq!(json["fingerprint"], "sha256:fingerprint");
        assert_eq!(
            serde_json::from_value::<CredentialTargetSnapshot>(json).unwrap(),
            snapshot
        );
    }

    #[test]
    fn command_errors_expose_only_typed_safe_canonical_fields() {
        let constructors: [fn(ProviderId, Option<&str>) -> ProviderAccountCommandError; 9] = [
            ProviderAccountCommandError::unsupported_activation,
            ProviderAccountCommandError::invalid_credential,
            ProviderAccountCommandError::identity_mismatch,
            ProviderAccountCommandError::external_write,
            ProviderAccountCommandError::rolled_back,
            ProviderAccountCommandError::recovery_required,
            ProviderAccountCommandError::recovery_failed,
            ProviderAccountCommandError::login_failure,
            ProviderAccountCommandError::operation_in_progress,
        ];

        for constructor in constructors {
            let error = constructor(ProviderId::Codex, Some("token=do-not-leak"));
            let display = error.to_string();
            let debug = format!("{error:?}");
            let json = serde_json::to_value(&error).unwrap();
            for output in [display, debug, json.to_string()] {
                assert!(!output.contains("do-not-leak"));
                assert!(!output.contains("token="));
            }
            assert_eq!(json["providerId"], "codex");
            assert!(json["code"].is_string());
            assert!(
                json["message"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
            );
            assert!(json.get("accountId").is_none());
            assert_eq!(json.as_object().unwrap().len(), 3);
        }

        let safe = ProviderAccountCommandError::invalid_credential(
            ProviderId::Codex,
            Some("acc_safe_123"),
        );
        assert_eq!(
            safe.code(),
            ProviderAccountCommandErrorCode::InvalidCredential
        );
        assert_eq!(safe.provider(), Some(ProviderId::Codex));
        assert_eq!(safe.account_id(), Some("acc_safe_123"));
        assert_eq!(
            safe.message(),
            "The selected account credentials are invalid."
        );
        assert_eq!(
            serde_json::to_value(safe).unwrap()["accountId"],
            "acc_safe_123"
        );
    }

    #[test]
    fn global_command_errors_omit_provider_identity_and_do_not_fake_display_context() {
        let error = ProviderAccountCommandError::internal_global();
        let json = serde_json::to_value(&error).unwrap();

        assert_eq!(error.provider(), None);
        assert_eq!(error.account_id(), None);
        assert!(json.get("providerId").is_none());
        assert!(json.get("provider").is_none());
        assert_eq!(error.to_string(), error.message());
        assert!(!format!("{error:?}").contains("Some(Codex)"));
    }
}
