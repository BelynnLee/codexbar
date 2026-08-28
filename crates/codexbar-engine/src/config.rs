use crate::{
    accounts::{
        CredentialMigrationReport, CredentialVaultError, ManagedCredentialState,
        ProviderAccountIdentity, ProviderCredentialBundle, ProviderCredentialVault,
        migration::{
            apply_credential_bundle, clear_credentials, credential_bundle, credential_state,
            has_credentials, resolved_identity,
        },
    },
    atomic_file::atomic_write,
    auth::dpapi::{DecodedSecret, DpapiCodec, SecretCodec, decode_secret},
    config_sections::{
        AdaptiveRefreshConfig, HistoryConfig, LocalePreference, MenuBarConfig, NotificationConfig,
        SecurityConfig, ShortcutConfig, StatusPollingConfig, WidgetSnapshotConfig,
    },
    model::{ProviderId, ProviderSourceMode},
};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::OsStr, fs, path::PathBuf, sync::Arc};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserPreference {
    #[default]
    Auto,
    Chrome,
    Edge,
}

/// One credential instance under a provider. API-key providers (`OpenRouter`, `DeepSeek`, `OpenCode` Zen)
/// may hold several; cookie/OAuth providers use a single (often implicit) account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ProviderAccount {
    /// Stable id (`acc_xxxxxxxx`). Empty on a freshly added account; assigned during `normalize`.
    pub id: String,
    pub identity: Option<ProviderAccountIdentity>,
    /// Optional user-facing name. When absent the UI derives one from the masked key.
    pub label: Option<String>,
    pub enabled: bool,
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    pub cookie_header: Option<String>,
    pub workspace_id: Option<String>,
    pub region: Option<String>,
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub deployment: Option<String>,
    pub enterprise_host: Option<String>,
    pub usage_scope: Option<String>,
    pub aws_profile: Option<String>,
    pub aws_auth_mode: Option<String>,
    pub kilo_organization_ids: Vec<String>,
    /// Self-hosted / regional endpoint base URL for providers that have no public default
    /// (`LiteLLM`, LLM Proxy, `sub2api`) or an override for those that do. Ignored by providers
    /// with a fixed endpoint.
    pub base_url: Option<String>,
    pub browser: BrowserPreference,
    #[serde(skip)]
    pub managed_credentials: Option<ProviderCredentialBundle>,
}

impl Default for ProviderAccount {
    fn default() -> Self {
        Self {
            id: String::new(),
            identity: None,
            label: None,
            enabled: true,
            api_key: None,
            secret_key: None,
            cookie_header: None,
            workspace_id: None,
            region: None,
            organization_id: None,
            project_id: None,
            deployment: None,
            enterprise_host: None,
            usage_scope: None,
            aws_profile: None,
            aws_auth_mode: None,
            kilo_organization_ids: Vec::new(),
            base_url: None,
            browser: BrowserPreference::Auto,
            managed_credentials: None,
        }
    }
}

impl ProviderAccount {
    pub fn apply_managed_credential_bundle(&mut self, credentials: &ProviderCredentialBundle) {
        self.api_key.clone_from(&credentials.api_key);
        self.secret_key.clone_from(&credentials.secret_key);
        self.cookie_header.clone_from(&credentials.cookie_header);
        self.managed_credentials = Some(ProviderCredentialBundle {
            artifact_format: credentials.artifact_format.clone(),
            artifact: credentials.artifact.clone(),
            ..ProviderCredentialBundle::default()
        });
    }

    /// Trim secrets and drop empty strings. Does not assign an id.
    fn normalize(&mut self) {
        self.id = self.id.trim().to_owned();
        self.label = normalize_owned(self.label.take());
        self.api_key = normalize_owned(self.api_key.take());
        self.secret_key = normalize_owned(self.secret_key.take());
        self.cookie_header = normalize_owned(self.cookie_header.take());
        self.workspace_id = normalize_owned(self.workspace_id.take());
        self.region = normalize_owned(self.region.take());
        self.organization_id = normalize_owned(self.organization_id.take());
        self.project_id = normalize_owned(self.project_id.take());
        self.deployment = normalize_owned(self.deployment.take());
        self.enterprise_host = normalize_owned(self.enterprise_host.take());
        self.usage_scope = normalize_owned(self.usage_scope.take());
        self.aws_profile = normalize_owned(self.aws_profile.take());
        self.aws_auth_mode = normalize_owned(self.aws_auth_mode.take());
        self.kilo_organization_ids = self
            .kilo_organization_ids
            .drain(..)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect();
        self.kilo_organization_ids.sort();
        self.kilo_organization_ids.dedup();
        self.base_url = normalize_owned(self.base_url.take());
    }

    /// True when the account carries nothing worth persisting: no credential, no label, and the
    /// default browser preference. Such accounts are dropped so a blank "add account" row vanishes.
    fn is_empty(&self) -> bool {
        self.id.is_empty()
            && self.identity.is_none()
            && self.label.is_none()
            && self.api_key.is_none()
            && self.secret_key.is_none()
            && self.cookie_header.is_none()
            && self.workspace_id.is_none()
            && self.region.is_none()
            && self.organization_id.is_none()
            && self.project_id.is_none()
            && self.deployment.is_none()
            && self.enterprise_host.is_none()
            && self.usage_scope.is_none()
            && self.aws_profile.is_none()
            && self.aws_auth_mode.is_none()
            && self.kilo_organization_ids.is_empty()
            && self.base_url.is_none()
            && self.browser == BrowserPreference::Auto
            && self.managed_credentials.is_none()
    }

    /// Label shown on the usage card: the explicit label, else a masked key suffix, else `None`
    /// (the frontend then falls back to the provider name).
    pub fn display_label(&self) -> Option<String> {
        if let Some(label) = &self.label {
            return Some(label.clone());
        }
        ProviderConfig::normalized_secret(&self.api_key).map(mask_secret)
    }
}

fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
    format!("…{tail}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ProviderConfig {
    pub enabled: bool,
    pub source_mode: ProviderSourceMode,
    pub active_account_id: Option<String>,
    pub accounts: Vec<ProviderAccount>,

    // Legacy v1 single-account fields. Read once for the v1 → v2 migration, then never written back
    // (`skip_serializing`), so old configs upgrade transparently.
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
    #[serde(skip_serializing)]
    pub cookie_header: Option<String>,
    #[serde(skip_serializing)]
    pub workspace_id: Option<String>,
    #[serde(skip_serializing)]
    pub browser: BrowserPreference,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            source_mode: ProviderSourceMode::Auto,
            active_account_id: None,
            accounts: Vec::new(),
            api_key: None,
            cookie_header: None,
            workspace_id: None,
            browser: BrowserPreference::Auto,
        }
    }
}

impl ProviderConfig {
    pub fn normalized_secret(value: &Option<String>) -> Option<&str> {
        value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Fold any legacy v1 fields into an account, trim the list, and assign stable ids.
    fn migrate_and_normalize(&mut self, provider: ProviderId) {
        self.active_account_id = normalize_owned(self.active_account_id.take());
        if provider == ProviderId::Codex
            && !matches!(
                self.source_mode,
                ProviderSourceMode::Auto | ProviderSourceMode::Oauth
            )
        {
            self.source_mode = ProviderSourceMode::Auto;
        }

        // v1 → v2: a single top-level credential becomes the first account.
        let legacy = ProviderAccount {
            id: String::new(),
            identity: None,
            label: None,
            enabled: true,
            api_key: self.api_key.take(),
            secret_key: None,
            cookie_header: self.cookie_header.take(),
            workspace_id: self.workspace_id.take(),
            region: None,
            organization_id: None,
            project_id: None,
            deployment: None,
            enterprise_host: None,
            usage_scope: None,
            aws_profile: None,
            aws_auth_mode: None,
            kilo_organization_ids: Vec::new(),
            base_url: None,
            browser: self.browser,
            managed_credentials: None,
        };
        self.browser = BrowserPreference::Auto;
        if self.accounts.is_empty() {
            self.accounts.push(legacy);
        }

        for account in &mut self.accounts {
            account.normalize();
            if provider == ProviderId::Deepgram {
                if account.project_id.is_none() {
                    account.project_id = account.workspace_id.take();
                } else {
                    account.workspace_id = None;
                }
            }
        }
        self.accounts.retain(|account| !account.is_empty());

        let mut seen: Vec<String> = Vec::new();
        for account in &mut self.accounts {
            if account.id.is_empty() || seen.contains(&account.id) {
                account.id = generate_account_id(&seen);
            }
            seen.push(account.id.clone());
        }

        if self
            .active_account_id
            .as_ref()
            .is_some_and(|active_id| !self.accounts.iter().any(|account| &account.id == active_id))
        {
            self.active_account_id = None;
        }
    }
}

fn provider_defaults(provider: ProviderId) -> ProviderConfig {
    ProviderConfig {
        enabled: provider.default_enabled(),
        ..ProviderConfig::default()
    }
}

/// Cheap dependency-free id generator: a time-seeded xorshift, re-rolled on collision within one
/// config so two accounts added in the same save never clash.
fn generate_account_id(existing: &[String]) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_nanos() as u64)
        .unwrap_or(1)
        .max(1);
    loop {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let id = format!("acc_{:08x}", seed as u32);
        if !existing.iter().any(|value| value == &id) {
            return id;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AppConfig {
    pub version: u32,
    pub refresh_interval_minutes: u64,
    pub providers: HashMap<ProviderId, ProviderConfig>,
    pub menu_bar: MenuBarConfig,
    pub history: HistoryConfig,
    pub notifications: NotificationConfig,
    pub status_polling: StatusPollingConfig,
    pub shortcuts: ShortcutConfig,
    pub locale: LocalePreference,
    pub adaptive_refresh: AdaptiveRefreshConfig,
    pub widget_snapshot: WidgetSnapshotConfig,
    pub security: SecurityConfig,
    #[serde(skip)]
    pub credential_issues: Vec<CredentialIssue>,
    #[serde(skip)]
    config_revision: Option<ConfigRevision>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: 4,
            refresh_interval_minutes: 5,
            providers: ProviderId::ALL
                .into_iter()
                .map(|provider| (provider, provider_defaults(provider)))
                .collect(),
            menu_bar: MenuBarConfig::default(),
            history: HistoryConfig::default(),
            notifications: NotificationConfig::default(),
            status_polling: StatusPollingConfig::default(),
            shortcuts: ShortcutConfig::default(),
            locale: LocalePreference::default(),
            adaptive_refresh: AdaptiveRefreshConfig::default(),
            widget_snapshot: WidgetSnapshotConfig::default(),
            security: SecurityConfig::default(),
            credential_issues: Vec::new(),
            config_revision: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialIssue {
    pub provider: ProviderId,
    pub account_id: String,
    pub field: CredentialField,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialField {
    ApiKey,
    SecretKey,
    CookieHeader,
    Vault,
}

impl AppConfig {
    pub fn provider(&self, provider: ProviderId) -> ProviderConfig {
        self.providers
            .get(&provider)
            .cloned()
            .unwrap_or_else(|| provider_defaults(provider))
    }

    pub fn normalize(&mut self) {
        self.version = 4;
        self.refresh_interval_minutes = self.refresh_interval_minutes.clamp(1, 60);
        self.menu_bar.pinned_account_id = normalize_owned(self.menu_bar.pinned_account_id.take());
        self.history.retention_days = self.history.retention_days.clamp(1, 3_650);
        self.history.codex_path = normalize_path(self.history.codex_path.take());
        self.history.claude_path = normalize_path(self.history.claude_path.take());
        normalize_thresholds(&mut self.notifications.thresholds);
        for thresholds in self.notifications.provider_thresholds.values_mut() {
            normalize_thresholds(thresholds);
        }
        self.status_polling.interval_minutes = self.status_polling.interval_minutes.clamp(1, 1_440);
        self.shortcuts.toggle_window = normalize_owned(self.shortcuts.toggle_window.take());
        self.shortcuts.refresh = normalize_owned(self.shortcuts.refresh.take());
        self.shortcuts.next_provider = normalize_owned(self.shortcuts.next_provider.take());
        self.adaptive_refresh.reset_proximity_minutes =
            self.adaptive_refresh.reset_proximity_minutes.max(1);
        self.adaptive_refresh.stale_after_seconds =
            self.adaptive_refresh.stale_after_seconds.max(1);
        self.adaptive_refresh.max_interval_minutes =
            self.adaptive_refresh.max_interval_minutes.max(1);
        self.adaptive_refresh.provider_timeout_seconds =
            self.adaptive_refresh.provider_timeout_seconds.max(1);
        self.widget_snapshot.path = normalize_path(self.widget_snapshot.path.take());
        for provider in ProviderId::ALL {
            self.providers
                .entry(provider)
                .or_insert_with(|| provider_defaults(provider));
            self.providers
                .get_mut(&provider)
                .expect("provider was inserted above")
                .migrate_and_normalize(provider);
        }
    }
}

fn normalize_owned(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalize_path(value: Option<PathBuf>) -> Option<PathBuf> {
    value.and_then(|path| {
        let Some(value) = path.to_str() else {
            return Some(path);
        };
        let value = value.trim();
        (!value.is_empty()).then(|| PathBuf::from(value))
    })
}

fn normalize_thresholds(thresholds: &mut Vec<f64>) {
    for threshold in thresholds.iter_mut() {
        *threshold = threshold.clamp(0.0, 100.0);
    }
    thresholds.sort_by(f64::total_cmp);
    thresholds.dedup_by(|left, right| left == right);
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Could not determine the Windows application data directory")]
    MissingAppData,
    #[error("Could not read CodexBar settings: {0}")]
    Read(#[source] std::io::Error),
    #[error("CodexBar settings contain invalid JSON: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("Could not serialize CodexBar settings: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("Could not write CodexBar settings: {0}")]
    Write(#[source] std::io::Error),
    #[error("Could not store credentials for {provider:?} account {account_id}")]
    CredentialVault {
        provider: ProviderId,
        account_id: String,
        #[source]
        source: CredentialVaultError,
    },
    #[error("Could not begin the provider credential Vault transaction")]
    CredentialTransaction(#[source] CredentialVaultError),
    #[error("Could not restore provider credential Vaults after a settings failure")]
    CredentialRollback,
    #[error("CodexBar settings changed during the credential transaction")]
    ConcurrentModification,
}

#[derive(Debug, Clone)]
pub struct ConfigStore {
    path: PathBuf,
    codec: Arc<dyn SecretCodec>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConfigRevision {
    exact_bytes: Option<Vec<u8>>,
}

impl std::fmt::Debug for ConfigRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigRevision")
            .field("exists", &self.exact_bytes.is_some())
            .finish()
    }
}

impl ConfigStore {
    pub fn discover() -> Result<Self, ConfigError> {
        let config_directory = std::env::var_os("CODEXBAR_CONFIG_DIR");
        if config_directory
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return discover_config_path(config_directory.as_deref(), None).map(Self::at);
        }
        let app_data = std::env::var_os("APPDATA");
        discover_config_path(None, app_data.as_deref()).map(Self::at)
    }

    pub fn at(path: PathBuf) -> Self {
        Self::at_with_codec(path, Arc::new(DpapiCodec))
    }

    pub fn at_with_codec(path: PathBuf, codec: Arc<dyn SecretCodec>) -> Self {
        Self { path, codec }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn load(&self) -> Result<AppConfig, ConfigError> {
        self.load_with_migration_report_and_revision()
            .map(|(config, _, _)| config)
    }

    pub fn load_with_revision(&self) -> Result<(AppConfig, ConfigRevision), ConfigError> {
        self.load_with_migration_report_and_revision()
            .map(|(config, _, revision)| (config, revision))
    }

    pub fn load_with_migration_report(
        &self,
    ) -> Result<(AppConfig, CredentialMigrationReport), ConfigError> {
        self.load_with_migration_report_and_revision()
            .map(|(config, report, _)| (config, report))
    }

    fn load_with_migration_report_and_revision(
        &self,
    ) -> Result<(AppConfig, CredentialMigrationReport, ConfigRevision), ConfigError> {
        let parent = self.path.parent().ok_or(ConfigError::MissingAppData)?;
        let vault = ProviderCredentialVault::new(parent, self.codec.as_ref());
        let mut transaction = vault
            .transaction()
            .map_err(ConfigError::CredentialTransaction)?;
        let Some(bytes) = read_optional_config(&self.path)? else {
            let revision = ConfigRevision { exact_bytes: None };
            let mut config = AppConfig::default();
            config.config_revision = Some(revision.clone());
            return Ok((config, CredentialMigrationReport::default(), revision));
        };
        let mut config =
            serde_json::from_slice::<AppConfig>(&bytes).map_err(ConfigError::Decode)?;
        config.normalize();
        if !config.security.persist_credentials {
            clear_all_credentials(&mut config);
            let revision = ConfigRevision {
                exact_bytes: Some(bytes),
            };
            config.config_revision = Some(revision.clone());
            return Ok((config, CredentialMigrationReport::default(), revision));
        }

        let legacy_accounts = accounts_with_credentials(&config);
        decrypt_config_secrets(&mut config, self.codec.as_ref());
        let mut report = CredentialMigrationReport::default();
        let undecryptable_accounts = config
            .credential_issues
            .iter()
            .map(|issue| (issue.provider, issue.account_id.clone()))
            .collect::<Vec<_>>();
        for (provider, account_id) in &undecryptable_accounts {
            report.record_failure(*provider, account_id, ManagedCredentialState::Undecryptable);
        }

        let mut revision_bytes = bytes.clone();
        if !legacy_accounts.is_empty() && undecryptable_accounts.is_empty() {
            if let Some(installed) = self.migrate_legacy_credentials(
                &mut transaction,
                &mut config,
                &legacy_accounts,
                &bytes,
                &mut report,
            )? {
                revision_bytes = installed;
            }
        }
        Self::hydrate_from_vaults(&transaction, &mut config, &legacy_accounts, &mut report);
        let revision = ConfigRevision {
            exact_bytes: Some(revision_bytes),
        };
        config.config_revision = Some(revision.clone());
        Ok((config, report, revision))
    }

    pub fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
        self.save_with_revision(config).map(|_| ())
    }

    pub fn save_with_revision(&self, config: &AppConfig) -> Result<ConfigRevision, ConfigError> {
        let revision = match &config.config_revision {
            Some(revision) => revision.clone(),
            None => ConfigRevision {
                exact_bytes: read_optional_config(&self.path)?,
            },
        };
        self.save_if_revision_with_installed_revision(config, &revision)
    }

    pub fn save_if_revision(
        &self,
        config: &AppConfig,
        revision: &ConfigRevision,
    ) -> Result<(), ConfigError> {
        self.save_if_revision_with_installed_revision(config, revision)
            .map(|_| ())
    }

    pub fn save_if_revision_with_installed_revision(
        &self,
        config: &AppConfig,
        revision: &ConfigRevision,
    ) -> Result<ConfigRevision, ConfigError> {
        let parent = self.path.parent().ok_or(ConfigError::MissingAppData)?;
        fs::create_dir_all(parent).map_err(ConfigError::Write)?;
        let vault = ProviderCredentialVault::new(parent, self.codec.as_ref());
        let mut transaction = vault
            .transaction()
            .map_err(ConfigError::CredentialTransaction)?;
        let expected_config = revision.exact_bytes.clone();
        if read_optional_config(&self.path)? != expected_config {
            return Err(ConfigError::ConcurrentModification);
        }
        let mut config = config.clone();
        config.normalize();
        config.credential_issues.clear();
        if !config.security.persist_credentials {
            clear_all_credentials(&mut config);
            let bytes = serde_json::to_vec_pretty(&config).map_err(ConfigError::Encode)?;
            write_config_if_unchanged(&self.path, expected_config.as_deref(), &bytes)?;
            return Ok(ConfigRevision {
                exact_bytes: Some(bytes),
            });
        }

        for provider in ProviderId::ALL {
            let Some(settings) = config.providers.get_mut(&provider) else {
                continue;
            };
            for account in &mut settings.accounts {
                let existing = match transaction.load(provider, &account.id) {
                    Ok(existing) => Some(existing),
                    Err(CredentialVaultError::Io(source))
                        if source.kind() == std::io::ErrorKind::NotFound =>
                    {
                        None
                    }
                    Err(source) => {
                        let error = credential_vault_error(provider, &account.id, source);
                        rollback_transaction(&mut transaction)?;
                        return Err(error);
                    }
                };
                let identity =
                    match resolved_identity(provider, account.identity.as_ref(), existing.as_ref())
                    {
                        Ok(identity) => identity,
                        Err(source) => {
                            let error = credential_vault_error(provider, &account.id, source);
                            rollback_transaction(&mut transaction)?;
                            return Err(error);
                        }
                    };
                let credentials = credential_bundle(account);
                if has_credentials(&credentials) {
                    if let Err(source) =
                        transaction.save(provider, &account.id, &identity, &credentials)
                    {
                        let error = credential_vault_error(provider, &account.id, source);
                        rollback_transaction(&mut transaction)?;
                        return Err(error);
                    }
                    account.identity = Some(identity);
                } else if existing.is_some() {
                    account.identity = Some(identity);
                }
                clear_credentials(account);
            }
        }

        let bytes = match serde_json::to_vec_pretty(&config) {
            Ok(bytes) => bytes,
            Err(source) => {
                rollback_transaction(&mut transaction)?;
                return Err(ConfigError::Encode(source));
            }
        };
        if let Err(error) =
            write_config_if_unchanged(&self.path, expected_config.as_deref(), &bytes)
        {
            rollback_transaction(&mut transaction)?;
            return Err(error);
        }
        Ok(ConfigRevision {
            exact_bytes: Some(bytes),
        })
    }

    fn migrate_legacy_credentials(
        &self,
        transaction: &mut crate::accounts::vault::ProviderVaultTransaction<'_, '_>,
        config: &mut AppConfig,
        legacy_accounts: &[(ProviderId, String)],
        original_config: &[u8],
        report: &mut CredentialMigrationReport,
    ) -> Result<Option<Vec<u8>>, ConfigError> {
        for (provider, account_id) in legacy_accounts {
            let account = config
                .providers
                .get_mut(provider)
                .and_then(|settings| {
                    settings
                        .accounts
                        .iter_mut()
                        .find(|account| account.id == *account_id)
                })
                .expect("legacy account was collected from normalized config");
            let existing = match transaction.load(*provider, account_id) {
                Ok(existing) => Some(existing),
                Err(CredentialVaultError::Io(source))
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    None
                }
                Err(_) => {
                    report.record_failure(
                        *provider,
                        account_id,
                        ManagedCredentialState::MigrationFailed,
                    );
                    rollback_transaction(transaction)?;
                    return Ok(None);
                }
            };
            let Ok(identity) =
                resolved_identity(*provider, account.identity.as_ref(), existing.as_ref())
            else {
                report.record_failure(
                    *provider,
                    account_id,
                    ManagedCredentialState::MigrationFailed,
                );
                rollback_transaction(transaction)?;
                return Ok(None);
            };
            let credentials = credential_bundle(account);
            if transaction
                .save(*provider, account_id, &identity, &credentials)
                .is_err()
            {
                report.record_failure(
                    *provider,
                    account_id,
                    ManagedCredentialState::MigrationFailed,
                );
                rollback_transaction(transaction)?;
                return Ok(None);
            }
            account.identity = Some(identity);
        }

        let mut persisted = config.clone();
        clear_all_credentials(&mut persisted);
        let bytes = match serde_json::to_vec_pretty(&persisted) {
            Ok(bytes) => bytes,
            Err(source) => {
                rollback_transaction(transaction)?;
                return Err(ConfigError::Encode(source));
            }
        };
        if let Err(error) = write_config_if_unchanged(&self.path, Some(original_config), &bytes) {
            rollback_transaction(transaction)?;
            return Err(error);
        }
        report.migrated.extend(legacy_accounts.iter().cloned());
        Ok(Some(bytes))
    }

    fn hydrate_from_vaults(
        transaction: &crate::accounts::vault::ProviderVaultTransaction<'_, '_>,
        config: &mut AppConfig,
        skip_accounts: &[(ProviderId, String)],
        report: &mut CredentialMigrationReport,
    ) {
        let mut vault_issues = Vec::new();
        for provider in ProviderId::ALL {
            let Some(settings) = config.providers.get_mut(&provider) else {
                continue;
            };
            for account in &mut settings.accounts {
                if skip_accounts.contains(&(provider, account.id.clone())) {
                    continue;
                }
                match transaction.load(provider, &account.id) {
                    Ok(loaded) => {
                        match resolved_identity(provider, account.identity.as_ref(), Some(&loaded))
                        {
                            Ok(identity) => {
                                account.identity = Some(identity);
                                apply_credential_bundle(account, &loaded.credentials);
                            }
                            Err(source) => {
                                let state = credential_state(&source);
                                report.record_failure(provider, &account.id, state);
                                vault_issues.push(vault_issue(provider, &account.id, state));
                            }
                        }
                    }
                    Err(source) => {
                        let state = credential_state(&source);
                        report.record_failure(provider, &account.id, state);
                        vault_issues.push(vault_issue(provider, &account.id, state));
                    }
                }
            }
        }
        config.credential_issues.extend(vault_issues);
    }
}

fn rollback_transaction(
    transaction: &mut crate::accounts::vault::ProviderVaultTransaction<'_, '_>,
) -> Result<(), ConfigError> {
    transaction
        .rollback()
        .map_err(|_| ConfigError::CredentialRollback)
}

fn read_optional_config(path: &std::path::Path) -> Result<Option<Vec<u8>>, ConfigError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ConfigError::Read(error)),
    }
}

fn write_config_if_unchanged(
    path: &std::path::Path,
    expected: Option<&[u8]>,
    bytes: &[u8],
) -> Result<(), ConfigError> {
    if read_optional_config(path)?.as_deref() != expected {
        return Err(ConfigError::ConcurrentModification);
    }
    match atomic_write(path, bytes) {
        Ok(()) => Ok(()),
        Err(source) => {
            let current = read_optional_config(path)?;
            if current.as_deref() == Some(bytes) {
                restore_config_if_installed(path, bytes, expected)?;
            } else if current.as_deref() != expected {
                return Err(ConfigError::ConcurrentModification);
            }
            Err(ConfigError::Write(source))
        }
    }
}

fn restore_config_if_installed(
    path: &std::path::Path,
    installed: &[u8],
    previous: Option<&[u8]>,
) -> Result<(), ConfigError> {
    if read_optional_config(path)?.as_deref() != Some(installed) {
        return Err(ConfigError::ConcurrentModification);
    }
    match previous {
        Some(previous) => atomic_write(path, previous).map_err(ConfigError::Write),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ConfigError::Write(error)),
        },
    }
}

fn credential_vault_error(
    provider: ProviderId,
    account_id: &str,
    source: CredentialVaultError,
) -> ConfigError {
    ConfigError::CredentialVault {
        provider,
        account_id: account_id.to_owned(),
        source,
    }
}

fn vault_issue(
    provider: ProviderId,
    account_id: &str,
    state: ManagedCredentialState,
) -> CredentialIssue {
    let message = match state {
        ManagedCredentialState::Missing => "Provider credential Vault is missing",
        ManagedCredentialState::Undecryptable => "Provider credential Vault cannot be decrypted",
        ManagedCredentialState::MigrationFailed => "Provider credential migration failed",
        ManagedCredentialState::Available | ManagedCredentialState::Invalid => {
            "Provider credential Vault is invalid"
        }
    };
    CredentialIssue {
        provider,
        account_id: account_id.to_owned(),
        field: CredentialField::Vault,
        message: message.into(),
    }
}

fn accounts_with_credentials(config: &AppConfig) -> Vec<(ProviderId, String)> {
    let mut accounts = Vec::new();
    for provider in ProviderId::ALL {
        let Some(settings) = config.providers.get(&provider) else {
            continue;
        };
        for account in &settings.accounts {
            if has_credentials(&credential_bundle(account)) {
                accounts.push((provider, account.id.clone()));
            }
        }
    }
    accounts
}

fn clear_all_credentials(config: &mut AppConfig) {
    for settings in config.providers.values_mut() {
        for account in &mut settings.accounts {
            clear_credentials(account);
        }
    }
}

fn decrypt_config_secrets(config: &mut AppConfig, codec: &dyn SecretCodec) {
    let mut issues = Vec::new();
    for (&provider, settings) in &mut config.providers {
        for account in &mut settings.accounts {
            decrypt_field(
                codec,
                provider,
                &account.id,
                CredentialField::ApiKey,
                &mut account.api_key,
                &mut issues,
            );
            decrypt_field(
                codec,
                provider,
                &account.id,
                CredentialField::SecretKey,
                &mut account.secret_key,
                &mut issues,
            );
            decrypt_field(
                codec,
                provider,
                &account.id,
                CredentialField::CookieHeader,
                &mut account.cookie_header,
                &mut issues,
            );
        }
    }
    config.credential_issues = issues;
}

fn decrypt_field(
    codec: &dyn SecretCodec,
    provider: ProviderId,
    account_id: &str,
    field: CredentialField,
    value: &mut Option<String>,
    issues: &mut Vec<CredentialIssue>,
) {
    let Some(secret) = value.take() else {
        return;
    };
    match decode_secret(codec, &secret) {
        Ok(DecodedSecret::Plaintext(decoded) | DecodedSecret::Encrypted(decoded)) => {
            *value = Some(decoded);
        }
        Err(_) => issues.push(CredentialIssue {
            provider,
            account_id: account_id.to_owned(),
            field,
            message: "Stored credential could not be decrypted".into(),
        }),
    }
}

fn discover_config_path(
    config_directory: Option<&OsStr>,
    app_data: Option<&OsStr>,
) -> Result<PathBuf, ConfigError> {
    if let Some(config_directory) = config_directory.filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(config_directory).join("config.json"));
    }
    if let Some(app_data) = app_data {
        return Ok(PathBuf::from(app_data).join("CodexBar").join("config.json"));
    }
    let project =
        ProjectDirs::from("com", "CodexBar", "CodexBar").ok_or(ConfigError::MissingAppData)?;
    Ok(project.config_dir().join("config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::dpapi::{SecretCodec, SecretError};
    use crate::config_sections::MenuBarDisplayMode;
    use std::sync::Arc;

    #[derive(Debug)]
    struct XorCodec;

    impl SecretCodec for XorCodec {
        fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(bytes.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            self.protect(bytes)
        }
    }

    #[test]
    fn default_config_uses_v4_sections() {
        let config = AppConfig::default();
        assert_eq!(config.version, 4);
        assert_eq!(config.menu_bar.display_mode, MenuBarDisplayMode::Icon);
        assert!(config.menu_bar.highest_usage);
        assert!(config.menu_bar.show_percentage);
        assert_eq!(config.history.retention_days, 90);
        assert_eq!(config.notifications.thresholds, vec![75.0, 90.0]);
        assert!(config.notifications.session_windows);
        assert!(config.notifications.weekly_windows);
        assert!(config.notifications.monthly_windows);
        assert_eq!(config.status_polling.interval_minutes, 10);
        assert_eq!(config.locale, LocalePreference::System);
        assert!(config.adaptive_refresh.enabled);
        assert_eq!(config.adaptive_refresh.reset_proximity_minutes, 10);
        assert_eq!(config.adaptive_refresh.stale_after_seconds, 60);
        assert_eq!(config.adaptive_refresh.max_interval_minutes, 30);
        assert_eq!(config.adaptive_refresh.provider_timeout_seconds, 30);
        assert!(config.widget_snapshot.enabled);
        assert!(config.security.persist_credentials);
    }

    #[test]
    fn default_config_uses_v4_and_auto_source_mode() {
        let config = AppConfig::default();

        assert_eq!(config.version, 4);
        assert_eq!(
            config.provider(ProviderId::Openrouter).source_mode,
            ProviderSourceMode::Auto
        );
    }

    #[test]
    fn retired_codex_source_modes_migrate_to_auto() {
        for retired in [ProviderSourceMode::Web, ProviderSourceMode::Cli] {
            let mut config = AppConfig::default();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .source_mode = retired;

            config.normalize();

            assert_eq!(
                config.provider(ProviderId::Codex).source_mode,
                ProviderSourceMode::Auto
            );
        }

        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .source_mode = ProviderSourceMode::Oauth;
        config.normalize();
        assert_eq!(
            config.provider(ProviderId::Codex).source_mode,
            ProviderSourceMode::Oauth
        );
    }

    #[test]
    fn v3_config_migrates_to_v4_and_normalizes_typed_account_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            r#"{
                "version": 3,
                "providers": {
                    "opencodezen": {
                        "sourceMode": "cli",
                        "accounts": [{
                            "id": " acc_zen ",
                            "secretKey": " fictional-secret ",
                            "workspaceId": " workspace ",
                            "baseUrl": " https://zen.example.test ",
                            "region": " us-west-2 ",
                            "organizationId": " org ",
                            "projectId": " project ",
                            "deployment": " deployment ",
                            "enterpriseHost": " enterprise.example.test ",
                            "usageScope": " team ",
                            "awsProfile": " qa ",
                            "awsAuthMode": " profile ",
                            "kiloOrganizationIds": [" org-b ", "", "org-a", "org-b"]
                        }]
                    }
                }
            }"#,
        )
        .unwrap();

        let config = ConfigStore::at(path).load().unwrap();
        let provider = config.provider(ProviderId::Opencodezen);
        let account = &provider.accounts[0];

        assert_eq!(config.version, 4);
        assert_eq!(provider.source_mode, ProviderSourceMode::Cli);
        assert_eq!(account.id, "acc_zen");
        assert_eq!(account.secret_key.as_deref(), Some("fictional-secret"));
        assert_eq!(account.workspace_id.as_deref(), Some("workspace"));
        assert_eq!(
            account.base_url.as_deref(),
            Some("https://zen.example.test")
        );
        assert_eq!(account.region.as_deref(), Some("us-west-2"));
        assert_eq!(account.organization_id.as_deref(), Some("org"));
        assert_eq!(account.project_id.as_deref(), Some("project"));
        assert_eq!(account.deployment.as_deref(), Some("deployment"));
        assert_eq!(
            account.enterprise_host.as_deref(),
            Some("enterprise.example.test")
        );
        assert_eq!(account.usage_scope.as_deref(), Some("team"));
        assert_eq!(account.aws_profile.as_deref(), Some("qa"));
        assert_eq!(account.aws_auth_mode.as_deref(), Some("profile"));
        assert_eq!(
            account.kilo_organization_ids,
            vec!["org-a".to_owned(), "org-b".to_owned()]
        );
    }

    #[test]
    fn deepgram_migrates_workspace_to_project_without_affecting_other_providers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            r#"{
                "version": 3,
                "providers": {
                    "deepgram": {"accounts": [{"id": "acc_d", "workspaceId": "legacy-project"}]},
                    "openrouter": {"accounts": [{"id": "acc_o", "workspaceId": "workspace"}]}
                }
            }"#,
        )
        .unwrap();

        let config = ConfigStore::at(path).load().unwrap();
        let deepgram = &config.provider(ProviderId::Deepgram).accounts[0];
        let openrouter = &config.provider(ProviderId::Openrouter).accounts[0];

        assert_eq!(deepgram.project_id.as_deref(), Some("legacy-project"));
        assert_eq!(deepgram.workspace_id, None);
        assert_eq!(openrouter.workspace_id.as_deref(), Some("workspace"));
        assert_eq!(openrouter.project_id, None);
    }

    #[test]
    fn typed_fields_keep_accounts_and_normalize_kilo_organizations() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                kilo_organization_ids: vec![
                    " org-z ".into(),
                    "org-a".into(),
                    String::new(),
                    "org-z".into(),
                ],
                ..Default::default()
            });

        config.normalize();

        let accounts = &config.provider(ProviderId::Openrouter).accounts;
        assert_eq!(accounts.len(), 1);
        assert_eq!(
            accounts[0].kilo_organization_ids,
            vec!["org-a".to_owned(), "org-z".to_owned()]
        );
    }

    #[test]
    fn secret_key_is_protected_round_trips_and_respects_disabled_persistence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_secret".into(),
                secret_key: Some("fictional-secret-key".into()),
                ..Default::default()
            });

        store.save(&config).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("fictional-secret-key"));
        assert!(!raw.contains("enc:v1:"));
        assert!(
            directory
                .path()
                .join("accounts/openrouter/acc_secret.vault")
                .exists()
        );
        assert_eq!(
            store
                .load()
                .unwrap()
                .provider(ProviderId::Openrouter)
                .accounts[0]
                .secret_key
                .as_deref(),
            Some("fictional-secret-key")
        );

        config.security.persist_credentials = false;
        store.save(&config).unwrap();
        let raw = fs::read_to_string(path).unwrap();
        assert!(!raw.contains("fictional-secret-key"));
        assert!(!raw.contains("secretKey"));
    }

    #[test]
    fn unreadable_secret_key_is_isolated_from_other_account_fields() {
        #[derive(Debug)]
        struct RejectUnprotect;

        impl SecretCodec for RejectUnprotect {
            fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Ok(bytes.to_vec())
            }

            fn unprotect(&self, _bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Err(SecretError::Platform("rejected fixture".into()))
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            r#"{"version":3,"providers":{"openrouter":{"accounts":[{"id":"acc_secret","secretKey":"enc:v1:AA==","region":"us-east-1"}]}}}"#,
        )
        .unwrap();

        let config = ConfigStore::at_with_codec(path, Arc::new(RejectUnprotect))
            .load()
            .unwrap();
        let account = &config.provider(ProviderId::Openrouter).accounts[0];

        assert_eq!(account.secret_key, None);
        assert_eq!(account.region.as_deref(), Some("us-east-1"));
        assert_eq!(config.credential_issues.len(), 1);
        assert_eq!(config.credential_issues[0].account_id, "acc_secret");
        assert_eq!(
            config.credential_issues[0].field,
            CredentialField::SecretKey
        );
    }

    #[test]
    fn a_new_config_keeps_copilot_disabled_until_login() {
        let config = AppConfig::default();
        assert!(!config.provider(ProviderId::Copilot).enabled);
    }

    #[test]
    fn v2_config_migrates_to_v4_without_losing_accounts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            concat!(
                r#"{"version":2,"refreshIntervalMinutes":7,"providers":{"openrouter":"#,
                r#"{"enabled":true,"accounts":[{"id":"acc_work","label":"Work","#,
                r#""apiKey":"legacy-key"}]}}}"#,
            ),
        )
        .unwrap();
        let config = ConfigStore::at(path).load().unwrap();
        assert_eq!(config.version, 4);
        assert_eq!(config.refresh_interval_minutes, 7);
        let account = &config.provider(ProviderId::Openrouter).accounts[0];
        assert_eq!(account.id, "acc_work");
        assert_eq!(account.label.as_deref(), Some("Work"));
        assert_eq!(account.api_key.as_deref(), Some("legacy-key"));
    }

    #[test]
    fn discover_prefers_config_directory_override() {
        let directory = tempfile::tempdir().unwrap();
        let app_data = tempfile::tempdir().unwrap();
        assert_eq!(
            discover_config_path(
                Some(directory.path().as_os_str()),
                Some(app_data.path().as_os_str()),
            )
            .unwrap(),
            directory.path().join("config.json")
        );
    }

    #[test]
    fn normalize_clamps_and_cleans_v4_sections() {
        let mut config = AppConfig::default();
        config.history.retention_days = 0;
        config.status_polling.interval_minutes = 2_000;
        config.notifications.thresholds = vec![105.0, 75.0, -5.0, 75.0];
        config
            .notifications
            .provider_thresholds
            .insert(ProviderId::Openrouter, vec![90.0, 90.0, -1.0]);
        config.shortcuts.toggle_window = Some("  Ctrl+Shift+U  ".into());
        config.shortcuts.refresh = Some("   ".into());
        config.history.codex_path = Some(PathBuf::from("  codex-history  "));
        config.history.claude_path = Some(PathBuf::from("   "));
        config.widget_snapshot.path = Some(PathBuf::from("  snapshot.json  "));
        config.menu_bar.pinned_account_id = Some("  acc_work  ".into());

        let openrouter = config.providers.get_mut(&ProviderId::Openrouter).unwrap();
        openrouter.active_account_id = Some("  acc_work  ".into());
        openrouter.accounts.push(ProviderAccount {
            id: "  acc_work  ".into(),
            label: Some("Work".into()),
            ..Default::default()
        });
        config
            .providers
            .get_mut(&ProviderId::Deepseek)
            .unwrap()
            .active_account_id = Some("missing".into());

        config.normalize();

        assert_eq!(config.history.retention_days, 1);
        assert_eq!(config.status_polling.interval_minutes, 1_440);
        assert_eq!(config.notifications.thresholds, vec![0.0, 75.0, 100.0]);
        assert_eq!(
            config.notifications.provider_thresholds[&ProviderId::Openrouter],
            vec![0.0, 90.0]
        );
        assert_eq!(
            config.shortcuts.toggle_window.as_deref(),
            Some("Ctrl+Shift+U")
        );
        assert_eq!(config.shortcuts.refresh, None);
        assert_eq!(
            config.history.codex_path.as_deref(),
            Some(std::path::Path::new("codex-history"))
        );
        assert_eq!(config.history.claude_path, None);
        assert_eq!(
            config.widget_snapshot.path.as_deref(),
            Some(std::path::Path::new("snapshot.json"))
        );
        assert_eq!(
            config.menu_bar.pinned_account_id.as_deref(),
            Some("acc_work")
        );
        assert_eq!(
            config
                .provider(ProviderId::Openrouter)
                .active_account_id
                .as_deref(),
            Some("acc_work")
        );
        assert_eq!(
            config.provider(ProviderId::Deepseek).active_account_id,
            None
        );
    }

    #[test]
    fn normalize_bounds_retention_and_status_at_their_maximums() {
        let mut config = AppConfig::default();
        config.history.retention_days = 5_000;
        config.status_polling.interval_minutes = 0;

        config.normalize();

        assert_eq!(config.history.retention_days, 3_650);
        assert_eq!(config.status_polling.interval_minutes, 1);
    }

    #[test]
    fn normalize_makes_adaptive_values_non_zero_and_preserves_positive_values() {
        let mut zeroes = AppConfig::default();
        zeroes.adaptive_refresh.reset_proximity_minutes = 0;
        zeroes.adaptive_refresh.stale_after_seconds = 0;
        zeroes.adaptive_refresh.max_interval_minutes = 0;
        zeroes.adaptive_refresh.provider_timeout_seconds = 0;
        zeroes.normalize();
        assert_eq!(zeroes.adaptive_refresh.reset_proximity_minutes, 1);
        assert_eq!(zeroes.adaptive_refresh.stale_after_seconds, 1);
        assert_eq!(zeroes.adaptive_refresh.max_interval_minutes, 1);
        assert_eq!(zeroes.adaptive_refresh.provider_timeout_seconds, 1);

        let mut positive = AppConfig::default();
        positive.adaptive_refresh.reset_proximity_minutes = 2;
        positive.adaptive_refresh.stale_after_seconds = 3;
        positive.adaptive_refresh.max_interval_minutes = 4;
        positive.adaptive_refresh.provider_timeout_seconds = 5;
        positive.normalize();
        assert_eq!(positive.adaptive_refresh.reset_proximity_minutes, 2);
        assert_eq!(positive.adaptive_refresh.stale_after_seconds, 3);
        assert_eq!(positive.adaptive_refresh.max_interval_minutes, 4);
        assert_eq!(positive.adaptive_refresh.provider_timeout_seconds, 5);
    }

    #[test]
    fn config_round_trip_assigns_ids_and_trims_secrets() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store =
            ConfigStore::at_with_codec(directory.path().join("config.json"), Arc::new(XorCodec));
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                api_key: Some(" test-key ".into()),
                label: Some("Primary".into()),
                ..Default::default()
            });
        store.save(&config).expect("save config");

        let loaded = store.load().expect("load config");
        assert_eq!(loaded.providers.len(), ProviderId::ALL.len());
        let accounts = &loaded.provider(ProviderId::Openrouter).accounts;
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].api_key.as_deref(), Some("test-key"));
        assert!(accounts[0].id.starts_with("acc_"), "id should be assigned");
    }

    #[test]
    fn save_encrypts_secrets_and_load_decrypts_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                api_key: Some("secret-value".into()),
                cookie_header: Some("fictional-cookie=value".into()),
                ..Default::default()
            });

        store.save(&config).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret-value"));
        assert!(!raw.contains("fictional-cookie=value"));
        assert!(!raw.contains("enc:v1:"));
        let loaded = store.load().unwrap();
        let account = &loaded.provider(ProviderId::Openrouter).accounts[0];
        assert_eq!(account.api_key.as_deref(), Some("secret-value"));
        assert_eq!(
            account.cookie_header.as_deref(),
            Some("fictional-cookie=value")
        );
    }

    #[test]
    fn config_metadata_omits_secrets_and_load_hydrates_each_provider_vault() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_api".into(),
                api_key: Some("openrouter-secret".into()),
                ..ProviderAccount::default()
            });
        config
            .providers
            .get_mut(&ProviderId::Cursor)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_cookie".into(),
                cookie_header: Some("WorkosCursorSessionToken=cookie-secret".into()),
                ..ProviderAccount::default()
            });

        store.save(&config).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("openrouter-secret"));
        assert!(!raw.contains("cookie-secret"));
        assert!(!raw.contains("enc:v1:"));
        let metadata: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let openrouter_account = &metadata["providers"]["openrouter"]["accounts"][0];
        let cursor_account = &metadata["providers"]["cursor"]["accounts"][0];
        assert!(openrouter_account["apiKey"].is_null());
        assert!(cursor_account["cookieHeader"].is_null());
        let openrouter_vault = directory
            .path()
            .join("accounts")
            .join("openrouter")
            .join("acc_api.vault");
        let cursor_vault = directory
            .path()
            .join("accounts")
            .join("cursor")
            .join("acc_cookie.vault");
        assert!(openrouter_vault.exists());
        assert!(cursor_vault.exists());

        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.provider(ProviderId::Openrouter).accounts[0]
                .api_key
                .as_deref(),
            Some("openrouter-secret")
        );
        assert_eq!(
            loaded.provider(ProviderId::Cursor).accounts[0]
                .cookie_header
                .as_deref(),
            Some("WorkosCursorSessionToken=cookie-secret")
        );
    }

    #[test]
    fn managed_complete_bundle_uses_config_vault_transaction_and_rolls_back_exact_bytes() {
        #[derive(Debug)]
        struct MutateConfigOnProtect {
            path: PathBuf,
            armed: std::sync::atomic::AtomicBool,
        }

        impl SecretCodec for MutateConfigOnProtect {
            fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    fs::write(&self.path, b"external-config-update").unwrap();
                }
                Ok(bytes.iter().map(|byte| byte ^ 0x5a).collect())
            }

            fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Ok(bytes.iter().map(|byte| byte ^ 0x5a).collect())
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let seed_store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut config = AppConfig::default();
        let mut account = ProviderAccount {
            id: "acc_bundle".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Openrouter,
                [crate::ProviderIdentityKey::new("fixture", "account")],
                None,
                None,
            )),
            ..ProviderAccount::default()
        };
        account.apply_managed_credential_bundle(&ProviderCredentialBundle {
            api_key: Some("old-api".into()),
            artifact_format: Some("fixture-json".into()),
            artifact: Some(b"old-artifact".to_vec()),
            ..ProviderCredentialBundle::default()
        });
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(account);
        seed_store.save(&config).unwrap();
        let vault_path = directory
            .path()
            .join("accounts/openrouter/acc_bundle.vault");
        let previous_vault = fs::read(&vault_path).unwrap();

        let codec = Arc::new(MutateConfigOnProtect {
            path: path.clone(),
            armed: std::sync::atomic::AtomicBool::new(false),
        });
        let store = ConfigStore::at_with_codec(path.clone(), codec.clone());
        let mut loaded = store.load().unwrap();
        loaded
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts[0]
            .apply_managed_credential_bundle(&ProviderCredentialBundle {
                api_key: Some("new-api".into()),
                artifact_format: Some("fixture-json".into()),
                artifact: Some(b"new-artifact".to_vec()),
                ..ProviderCredentialBundle::default()
            });
        codec.armed.store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(matches!(
            store.save(&loaded),
            Err(ConfigError::ConcurrentModification)
        ));
        assert_eq!(fs::read(vault_path).unwrap(), previous_vault);
        assert_eq!(fs::read(path).unwrap(), b"external-config-update");
    }

    #[test]
    fn stale_config_revision_rejects_save_before_creating_vaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let stale_store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let fresh_store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut initial = AppConfig::default();
        initial
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_seed".into(),
                label: Some("revision-debug-private".into()),
                ..ProviderAccount::default()
            });
        stale_store.save(&initial).unwrap();

        let (mut stale, revision) = stale_store.load_with_revision().unwrap();
        assert!(!format!("{revision:?}").contains("revision-debug-private"));

        let mut fresh = fresh_store.load().unwrap();
        fresh
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_external".into(),
                label: Some("external-writer".into()),
                ..ProviderAccount::default()
            });
        fresh_store.save(&fresh).unwrap();

        stale
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_stale".into(),
                identity: Some(ProviderAccountIdentity::new(
                    ProviderId::Codex,
                    [crate::ProviderIdentityKey::new("fixture", "stale")],
                    None,
                    None,
                )),
                api_key: Some("stale-private".into()),
                ..ProviderAccount::default()
            });

        assert!(matches!(
            stale_store.save_if_revision(&stale, &revision),
            Err(ConfigError::ConcurrentModification)
        ));
        let loaded = fresh_store.load().unwrap();
        assert!(
            loaded
                .provider(ProviderId::Claude)
                .accounts
                .iter()
                .any(|account| account.id == "acc_external")
        );
        assert!(
            loaded
                .provider(ProviderId::Codex)
                .accounts
                .iter()
                .all(|account| account.id != "acc_stale")
        );
        assert!(
            !directory
                .path()
                .join("accounts/codex/acc_stale.vault")
                .exists()
        );
    }

    #[test]
    fn installed_revision_supports_conditional_rollback_without_linking_cloned_snapshots() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = ConfigStore::at_with_codec(path, Arc::new(XorCodec));
        let mut initial = AppConfig::default();
        initial
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_original".into(),
                label: Some("installed-revision-private".into()),
                ..ProviderAccount::default()
            });
        store.save(&initial).unwrap();

        let original = store.load().unwrap();
        let mut changed = original.clone();
        changed
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts
            .clear();
        let installed = store.save_with_revision(&changed).unwrap();
        assert!(!format!("{installed:?}").contains("installed-revision-private"));
        assert!(matches!(
            store.save(&original),
            Err(ConfigError::ConcurrentModification)
        ));

        let restored = store
            .save_if_revision_with_installed_revision(&original, &installed)
            .unwrap();
        assert!(
            store
                .load()
                .unwrap()
                .provider(ProviderId::Claude)
                .accounts
                .iter()
                .any(|account| account.id == "acc_original")
        );
        assert!(matches!(
            store.save_if_revision(&changed, &installed),
            Err(ConfigError::ConcurrentModification)
        ));
        assert!(!format!("{restored:?}").contains("installed-revision-private"));
    }

    #[test]
    fn ordinary_load_carries_revision_and_rejects_stale_save_before_vault_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let stale_store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let fresh_store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut initial = AppConfig::default();
        initial
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_seed".into(),
                ..ProviderAccount::default()
            });
        stale_store.save(&initial).unwrap();

        let mut raw =
            serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap();
        raw["revisionCanary"] = serde_json::Value::String("private-revision-canary".into());
        fs::write(&path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();
        let loaded = stale_store.load().unwrap();
        assert!(!format!("{loaded:?}").contains("private-revision-canary"));
        assert!(
            !serde_json::to_string(&loaded)
                .unwrap()
                .contains("private-revision-canary")
        );
        let mut stale = loaded.clone();
        stale.normalize();

        let mut fresh = fresh_store.load().unwrap();
        fresh
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_winner".into(),
                label: Some("winner".into()),
                ..ProviderAccount::default()
            });
        fresh_store.save(&fresh).unwrap();

        stale
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_stale_ordinary".into(),
                identity: Some(ProviderAccountIdentity::new(
                    ProviderId::Codex,
                    [crate::ProviderIdentityKey::new("fixture", "stale-ordinary")],
                    None,
                    None,
                )),
                api_key: Some("stale-private".into()),
                ..ProviderAccount::default()
            });

        assert!(matches!(
            stale_store.save(&stale),
            Err(ConfigError::ConcurrentModification)
        ));
        let loaded = fresh_store.load().unwrap();
        assert!(
            loaded
                .provider(ProviderId::Claude)
                .accounts
                .iter()
                .any(|account| account.id == "acc_winner")
        );
        assert!(
            loaded
                .provider(ProviderId::Codex)
                .accounts
                .iter()
                .all(|account| account.id != "acc_stale_ordinary")
        );
        assert!(
            !directory
                .path()
                .join("accounts/codex/acc_stale_ordinary.vault")
                .exists()
        );
    }

    #[test]
    fn a_fresh_default_config_can_still_be_first_saved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = ConfigStore::at_with_codec(path, Arc::new(XorCodec));
        let mut stale_missing = store.load().unwrap();
        let mut config = AppConfig::default();
        config.refresh_interval_minutes = 17;

        store.save(&config).unwrap();

        assert_eq!(store.load().unwrap().refresh_interval_minutes, 17);
        stale_missing.refresh_interval_minutes = 29;
        assert!(matches!(
            store.save(&stale_missing),
            Err(ConfigError::ConcurrentModification)
        ));
        assert_eq!(store.load().unwrap().refresh_interval_minutes, 17);
    }

    #[test]
    fn prefixed_plaintext_secrets_are_protected_and_round_trip() {
        for (field, plaintext) in [
            (CredentialField::ApiKey, "enc:v1:not-base64"),
            (CredentialField::ApiKey, "enc:v1:AA=="),
            (CredentialField::SecretKey, "enc:v1:not-base64"),
            (CredentialField::SecretKey, "enc:v1:AA=="),
            (CredentialField::CookieHeader, "enc:v1:not-base64"),
            (CredentialField::CookieHeader, "enc:v1:AA=="),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.json");
            let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
            let mut account = ProviderAccount {
                id: "acc_prefix".into(),
                ..Default::default()
            };
            match field {
                CredentialField::ApiKey => account.api_key = Some(plaintext.into()),
                CredentialField::SecretKey => account.secret_key = Some(plaintext.into()),
                CredentialField::CookieHeader => account.cookie_header = Some(plaintext.into()),
                CredentialField::Vault => unreachable!("Vault is not a legacy config field"),
            }
            let mut config = AppConfig::default();
            config
                .providers
                .get_mut(&ProviderId::Openrouter)
                .unwrap()
                .accounts
                .push(account);

            store.save(&config).unwrap();

            let raw = fs::read_to_string(&path).unwrap();
            assert!(
                !raw.contains(plaintext),
                "{field:?} plaintext was persisted"
            );
            let loaded = store.load().unwrap();
            let loaded_account = &loaded.provider(ProviderId::Openrouter).accounts[0];
            let loaded_secret = match field {
                CredentialField::ApiKey => loaded_account.api_key.as_deref(),
                CredentialField::SecretKey => loaded_account.secret_key.as_deref(),
                CredentialField::CookieHeader => loaded_account.cookie_header.as_deref(),
                CredentialField::Vault => unreachable!("Vault is not a legacy config field"),
            };
            assert_eq!(
                loaded_secret,
                Some(plaintext),
                "{field:?} did not round-trip"
            );
        }
    }

    #[test]
    fn unreadable_ciphertext_clears_only_that_secret() {
        #[derive(Debug)]
        struct RejectUnprotect;

        impl SecretCodec for RejectUnprotect {
            fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Ok(bytes.to_vec())
            }

            fn unprotect(&self, _bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Err(SecretError::Platform("rejected fixture".into()))
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            concat!(
                r#"{"version":3,"providers":{"openrouter":{"accounts":[{"id":"acc_a","#,
                r#""apiKey":"enc:v1:AA==","cookieHeader":"legacy-cookie"}]}}}"#,
            ),
        )
        .unwrap();
        let store = ConfigStore::at_with_codec(path, Arc::new(RejectUnprotect));

        let config = store.load().unwrap();

        let account = &config.provider(ProviderId::Openrouter).accounts[0];
        assert_eq!(account.api_key, None);
        assert_eq!(account.cookie_header.as_deref(), Some("legacy-cookie"));
        assert_eq!(config.credential_issues.len(), 1);
        assert_eq!(config.credential_issues[0].account_id, "acc_a");
        assert_eq!(config.credential_issues[0].field, CredentialField::ApiKey);
    }

    #[test]
    fn credential_issues_remain_siloed_by_provider_account_and_field() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            concat!(
                r#"{"version":3,"providers":{"openrouter":{"accounts":[{"id":"acc_api","#,
                r#""apiKey":"enc:v1:not-base64","cookieHeader":"legacy-openrouter-cookie"}]},"#,
                r#""cursor":{"accounts":[{"id":"acc_cookie","apiKey":"legacy-cursor-key","#,
                r#""cookieHeader":"enc:v1:pQ=="}]}}}"#,
            ),
        )
        .unwrap();
        let store = ConfigStore::at_with_codec(path, Arc::new(XorCodec));

        let config = store.load().unwrap();

        let openrouter = &config.provider(ProviderId::Openrouter).accounts[0];
        assert_eq!(openrouter.api_key, None);
        assert_eq!(
            openrouter.cookie_header.as_deref(),
            Some("legacy-openrouter-cookie")
        );
        let cursor = &config.provider(ProviderId::Cursor).accounts[0];
        assert_eq!(cursor.api_key.as_deref(), Some("legacy-cursor-key"));
        assert_eq!(cursor.cookie_header, None);
        assert_eq!(config.credential_issues.len(), 2);
        assert!(config.credential_issues.iter().any(|issue| {
            issue.provider == ProviderId::Openrouter
                && issue.account_id == "acc_api"
                && issue.field == CredentialField::ApiKey
        }));
        assert!(config.credential_issues.iter().any(|issue| {
            issue.provider == ProviderId::Cursor
                && issue.account_id == "acc_cookie"
                && issue.field == CredentialField::CookieHeader
        }));
    }

    #[test]
    fn disabled_persistence_omits_secrets_instead_of_writing_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut config = AppConfig::default();
        config.security.persist_credentials = false;
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_a".into(),
                label: Some("Work".into()),
                api_key: Some("secret-value".into()),
                cookie_header: Some("fictional-cookie=value".into()),
                ..Default::default()
            });

        store.save(&config).unwrap();

        let raw = fs::read_to_string(path).unwrap();
        assert!(!raw.contains("secret-value"));
        assert!(!raw.contains("fictional-cookie=value"));
        assert!(!raw.contains("enc:v1:"));
        assert_eq!(
            config.provider(ProviderId::Openrouter).accounts[0]
                .api_key
                .as_deref(),
            Some("secret-value")
        );
        assert_eq!(
            config.provider(ProviderId::Openrouter).accounts[0]
                .cookie_header
                .as_deref(),
            Some("fictional-cookie=value")
        );
    }

    #[test]
    fn protect_failure_has_credential_context_and_preserves_existing_file() {
        #[derive(Debug)]
        struct RejectProtect;

        impl SecretCodec for RejectProtect {
            fn protect(&self, _bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Err(SecretError::Platform("fictional protect failure".into()))
            }

            fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Ok(bytes.to_vec())
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path, b"previous-config").unwrap();
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(RejectProtect));
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_failure".into(),
                api_key: Some("fictional-secret".into()),
                ..Default::default()
            });

        let error = store.save(&config).unwrap_err();

        match &error {
            ConfigError::CredentialVault {
                provider,
                account_id,
                source,
            } => {
                assert_eq!(*provider, ProviderId::Openrouter);
                assert_eq!(account_id, "acc_failure");
                assert!(matches!(source, CredentialVaultError::EncryptionFailed));
            }
            other => panic!("unexpected save error: {other:?}"),
        }
        let debug = format!("{error:?}");
        assert!(!debug.contains("fictional-secret"));
        assert!(!debug.contains("fictional protect failure"));
        assert_eq!(fs::read(path).unwrap(), b"previous-config");
    }

    #[test]
    fn multiple_accounts_get_distinct_ids() {
        let mut config = AppConfig::default();
        let openrouter = config.providers.get_mut(&ProviderId::Openrouter).unwrap();
        openrouter.accounts.push(ProviderAccount {
            api_key: Some("key-a".into()),
            ..Default::default()
        });
        openrouter.accounts.push(ProviderAccount {
            api_key: Some("key-b".into()),
            ..Default::default()
        });
        config.normalize();
        let accounts = &config.provider(ProviderId::Openrouter).accounts;
        assert_eq!(accounts.len(), 2);
        assert_ne!(accounts[0].id, accounts[1].id);
    }

    #[test]
    fn migrates_legacy_single_key_into_account() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            concat!(
                r#"{"version":1,"refreshIntervalMinutes":5,"providers":{"openrouter":"#,
                r#"{"enabled":true,"apiKey":"legacy-key"}}}"#,
            ),
        )
        .expect("seed legacy config");

        let store = ConfigStore::at(path);
        let loaded = store.load().expect("load config");
        assert_eq!(loaded.version, 4);
        let accounts = &loaded.provider(ProviderId::Openrouter).accounts;
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].api_key.as_deref(), Some("legacy-key"));
        assert!(accounts[0].id.starts_with("acc_"));
        store
            .save(&loaded)
            .expect("migration attaches the installed config revision");
    }

    #[test]
    fn blank_accounts_are_dropped_but_browser_choice_is_kept() {
        let mut config = AppConfig::default();
        let opencode = config.providers.get_mut(&ProviderId::Opencode).unwrap();
        opencode.accounts.push(ProviderAccount::default()); // fully blank → dropped
        opencode.accounts.push(ProviderAccount {
            browser: BrowserPreference::Edge,
            ..Default::default()
        });
        config.normalize();
        let accounts = &config.provider(ProviderId::Opencode).accounts;
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].browser, BrowserPreference::Edge);
    }

    #[test]
    fn display_label_prefers_label_then_masked_key() {
        let labelled = ProviderAccount {
            label: Some("Work".into()),
            api_key: Some("sk-secret-1234".into()),
            ..Default::default()
        };
        assert_eq!(labelled.display_label().as_deref(), Some("Work"));
        let unlabelled = ProviderAccount {
            api_key: Some("sk-secret-1234".into()),
            ..Default::default()
        };
        assert_eq!(unlabelled.display_label().as_deref(), Some("…1234"));
        assert_eq!(ProviderAccount::default().display_label(), None);
    }
}
