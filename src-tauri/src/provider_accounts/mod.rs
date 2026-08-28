pub mod adapters;
pub mod claude;
pub mod codex;
pub mod manager;

use codexbar_engine::{
    ManagedCredentialState, ProviderAccountIdentity, ProviderEnrollmentKind, ProviderId,
};
use serde::Serialize;

pub use adapters::{
    ActivationSupport, CredentialActivationAdapter, CredentialTargetSnapshot,
    ProviderAccountCommandError, ProviderAccountCommandErrorCode, ProviderAdapterDeclaration,
    ProviderAdapterRegistry, ProviderAdapterRegistryError, RestartHint,
};
pub use manager::{
    ProviderAccountManager, ProviderAccountStatus, ProviderActivationResult, ProviderImportResult,
    ProviderLoginImportRequest, ProviderRecoveryState, RecoveryAction,
};

/// Secret-free transport row for one official Provider account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountView {
    pub account_id: String,
    pub label: Option<String>,
    pub enabled: bool,
    pub identity: Option<ProviderAccountIdentity>,
    pub managed_credential_state: ManagedCredentialState,
    pub is_active: bool,
    pub can_activate: bool,
    pub activation_blocked_reason: Option<String>,
}

/// Provider-indexed account-pool state exposed to the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountPoolView {
    pub provider_id: ProviderId,
    pub enrollment: Vec<ProviderEnrollmentKind>,
    pub active_account_id: Option<String>,
    pub accounts: Vec<ProviderAccountView>,
    pub activation: ActivationSupport,
    pub external_identity: Option<ProviderAccountIdentity>,
    pub recovery_state: ProviderRecoveryState,
    pub operation_in_progress: bool,
    pub state_unavailable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountLoginStarted {
    pub session_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAccountLoginStatus {
    Waiting,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
}

/// Login events contain only routing identifiers and sanitized structured errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountLoginEvent {
    pub session_id: String,
    pub provider_id: ProviderId,
    pub status: ProviderAccountLoginStatus,
    pub account_id: Option<String>,
    pub error: Option<ProviderAccountCommandError>,
}
