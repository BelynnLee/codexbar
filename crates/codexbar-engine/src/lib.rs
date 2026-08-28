pub mod accounts;
pub mod atomic_file;
pub mod auth;
pub mod config;
pub mod config_sections;
pub mod cost;
pub mod engine;
pub mod history;
pub mod model;
pub mod pricing;
pub mod provider;
pub mod providers;
pub mod redaction;
pub mod refresh_policy;
pub mod status;
pub mod tray;
pub mod warnings;
pub mod widget_snapshot;

pub use accounts::{
    ActivationTargetKind, ManagedCredentialState, ProviderAccountCapability,
    ProviderAccountIdentity, ProviderCredentialBundle, ProviderEnrollmentKind, ProviderIdentityKey,
};
pub use atomic_file::{
    atomic_move_no_replace, atomic_replace_with_backup, atomic_write, file_has_multiple_links,
    stage_file,
};
pub use auth::github_device::{
    COPILOT_CLIENT_ID, DeviceCode, DeviceFlowError, GitHubDeviceFlow, GitHubIdentity, PollError,
    PollOutcome, parse_poll_response,
};
pub use config::{
    AppConfig, BrowserPreference, ConfigStore, CredentialField, CredentialIssue, ProviderAccount,
    ProviderConfig,
};
pub use config_sections::{
    AdaptiveRefreshConfig, HistoryConfig, LocalePreference, MenuBarConfig, MenuBarDisplayMode,
    NotificationConfig, SecurityConfig, ShortcutConfig, StatusPollingConfig, WidgetSnapshotConfig,
};
pub use cost::{
    CostBreakdown, CostDay, CostError, CostModelBreakdown, CostProvider, CostRange, CostScanner,
    TokenUsage,
};
pub use engine::Engine;
pub use history::{HistoryError, HistoryPoint, HistoryRange, HistoryStore};
pub use model::{
    AuthKind, FinancialSnapshot, ProviderAuthActionKind, ProviderCapabilityDescriptor,
    ProviderDescriptor, ProviderErrorKind, ProviderFetchAttempt, ProviderId, ProviderMaturity,
    ProviderSettingDescriptor, ProviderSettingKey, ProviderSettingKind, ProviderSnapshot,
    ProviderSourceMode, ProviderState, ProviderStatus, ProviderStrategyDescriptor,
    ProviderStrategyKind, SummaryItem, UsageWindow, provider_capabilities,
};
pub use pricing::ModelPrice;
pub use provider::{
    FetchContext, Provider, ProviderError, ProviderFetchOutcome, run_provider_fetch_pipeline,
};
pub use redaction::redact;
pub use refresh_policy::{
    RefreshDecision, RefreshReason, RefreshSignals, next_refresh, retry_delay,
};
pub use status::{
    ServiceIndicator, ServiceStatus, StatusError, fetch_service_status, parse_status_summary,
    status_polled_providers, status_source,
};
pub use tray::{IconMetric, select_tray_metric};
pub use warnings::{
    Warning, WarningKind, WarningTracker, evaluate_pace_warnings, evaluate_warnings,
};
pub use widget_snapshot::{
    WidgetProviderEntry, WidgetSnapshot, WidgetSnapshotError, WidgetSnapshotWriter,
    WidgetWindowEntry,
};
