use super::adapters::{
    ActivationSupport, CredentialActivationAdapter, CredentialTargetSnapshot,
    ProviderAccountCommandError, ProviderAdapterRegistry, RestartHint,
};
use codexbar_engine::{
    AppConfig, ConfigStore, HistoryStore, ProviderAccount, ProviderAccountIdentity, ProviderConfig,
    ProviderCredentialBundle, ProviderEnrollmentKind, ProviderId,
    accounts::ProviderCredentialVault,
    atomic_write,
    auth::{credentials::is_safe_managed_account_id, dpapi::SecretCodec},
    config::ConfigRevision,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;

const RECOVERY_VERSION: u8 = 1;
const MAX_LOGIN_SESSIONS: usize = 32;
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryAction {
    RestoreOriginal,
    KeepCurrent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderRecoveryState {
    None,
    Required,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderActivationResult {
    pub provider_id: ProviderId,
    pub previous_account_id: Option<String>,
    pub active_account_id: String,
    pub restart_hint: RestartHint,
    pub quota_refresh_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountStatus {
    pub provider_id: ProviderId,
    pub enrollment: Vec<ProviderEnrollmentKind>,
    pub activation: ActivationSupport,
    pub active_account_id: Option<String>,
    pub external_identity: Option<ProviderAccountIdentity>,
    pub recovery: ProviderRecoveryState,
    pub operation_in_progress: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderImportResult {
    pub provider_id: ProviderId,
    pub account_id: String,
    pub updated_existing: bool,
}

pub struct ProviderLoginImportRequest {
    pub session_id: String,
    pub provider: ProviderId,
    pub requested_account_id: Option<String>,
    pub label: Option<String>,
    pub identity: ProviderAccountIdentity,
    pub credentials: ProviderCredentialBundle,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RecoveryRecord {
    provider: ProviderId,
    snapshot: CredentialTargetSnapshot,
    original_fingerprint: Option<String>,
    expected_target_fingerprint: Option<String>,
    previous_account_id: Option<String>,
    target_account_id: String,
}

impl fmt::Debug for RecoveryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryRecord")
            .field("provider", &self.provider)
            .field("has_snapshot", &self.snapshot.credentials.is_some())
            .field(
                "has_original_fingerprint",
                &self.original_fingerprint.is_some(),
            )
            .field(
                "has_expected_target_fingerprint",
                &self.expected_target_fingerprint.is_some(),
            )
            .field("previous_account_id", &self.previous_account_id)
            .field("target_account_id", &self.target_account_id)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryEnvelope {
    version: u8,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfficialIdentitySnapshot {
    identity: Option<ProviderAccountIdentity>,
    matched_account_id: Option<String>,
}

pub struct ProviderAccountManager {
    config_dir: PathBuf,
    codec: Arc<dyn SecretCodec>,
    adapters: ProviderAdapterRegistry,
    locks: HashMap<ProviderId, Arc<Mutex<()>>>,
    config_commit: Mutex<()>,
    login_sessions: Mutex<HashMap<String, (ProviderId, Arc<AtomicBool>)>>,
    next_account_sequence: AtomicU64,
}

impl fmt::Debug for ProviderAccountManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderAccountManager")
            .field("config_dir", &self.config_dir)
            .field("adapters", &self.adapters)
            .field("provider_lock_count", &self.locks.len())
            .finish_non_exhaustive()
    }
}

impl ProviderAccountManager {
    pub fn new(
        config_dir: PathBuf,
        codec: Arc<dyn SecretCodec>,
        adapters: ProviderAdapterRegistry,
    ) -> Self {
        let locks = ProviderId::ALL
            .into_iter()
            .map(|provider| (provider, Arc::new(Mutex::new(()))))
            .collect();
        Self {
            config_dir,
            codec,
            adapters,
            locks,
            config_commit: Mutex::new(()),
            login_sessions: Mutex::new(HashMap::new()),
            next_account_sequence: AtomicU64::new(1),
        }
    }

    fn lock(&self, provider: ProviderId) -> Arc<Mutex<()>> {
        Arc::clone(self.locks.get(&provider).expect("all providers have locks"))
    }

    fn adapter(
        &self,
        provider: ProviderId,
        account_id: Option<&str>,
    ) -> Result<&dyn CredentialActivationAdapter, ProviderAccountCommandError> {
        self.adapters.adapter(provider).ok_or_else(|| {
            ProviderAccountCommandError::unsupported_activation(provider, account_id)
        })
    }

    pub async fn activate(
        &self,
        provider: ProviderId,
        account_id: &str,
        expected_current_identity: Option<ProviderAccountIdentity>,
        config_store: &ConfigStore,
    ) -> Result<ProviderActivationResult, ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        self.ensure_no_login(provider, Some(account_id)).await?;
        if self.recovery_path(provider).exists() {
            return Err(ProviderAccountCommandError::recovery_required(
                provider,
                Some(account_id),
            ));
        }
        let adapter = self.adapter(provider, Some(account_id))?;
        let (config, _) = Self::load_config(config_store, provider, Some(account_id))?;
        let settings = config.providers.get(&provider).ok_or_else(|| {
            ProviderAccountCommandError::account_not_found(provider, Some(account_id))
        })?;
        let account = settings
            .accounts
            .iter()
            .find(|item| item.id == account_id)
            .ok_or_else(|| {
                ProviderAccountCommandError::account_not_found(provider, Some(account_id))
            })?;
        if !account.enabled {
            return Err(ProviderAccountCommandError::account_disabled(
                provider,
                Some(account_id),
            ));
        }
        let expected_identity = account
            .identity
            .as_ref()
            .filter(|id| id.provider == provider && id.is_activation_eligible())
            .ok_or_else(|| {
                ProviderAccountCommandError::invalid_credential(provider, Some(account_id))
            })?
            .clone();
        let vault = ProviderCredentialVault::new(&self.config_dir, self.codec.as_ref());
        let loaded = vault.load(provider, account_id).map_err(|_| {
            ProviderAccountCommandError::invalid_credential(provider, Some(account_id))
        })?;
        if !loaded.identity.matches_stable(&expected_identity)
            || loaded.credentials == ProviderCredentialBundle::default()
        {
            return Err(ProviderAccountCommandError::invalid_credential(
                provider,
                Some(account_id),
            ));
        }
        adapter.validate_target(&expected_identity, &loaded.credentials)?;
        let expected_installed_fingerprint = adapter.target_fingerprint(&loaded.credentials)?;
        let snapshot = adapter.capture()?;
        let first = adapter.fingerprint()?;
        if snapshot.fingerprint != first {
            return Err(ProviderAccountCommandError::external_write(
                provider,
                Some(account_id),
            ));
        }
        let actual_current_identity = adapter
            .current_identity()
            .map_err(|_| ProviderAccountCommandError::internal(provider, Some(account_id)))?;
        let expected_identity_matches = match (
            expected_current_identity.as_ref(),
            actual_current_identity.as_ref(),
        ) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                expected.provider == provider
                    && expected.is_activation_eligible()
                    && actual.provider == provider
                    && actual.is_activation_eligible()
                    && actual.matches_stable(expected)
            }
            _ => false,
        };
        if !expected_identity_matches {
            return Err(ProviderAccountCommandError::external_write(
                provider,
                Some(account_id),
            ));
        }
        let previous = settings.active_account_id.clone();
        let record = RecoveryRecord {
            provider,
            snapshot,
            original_fingerprint: first.clone(),
            expected_target_fingerprint: expected_installed_fingerprint.clone(),
            previous_account_id: previous.clone(),
            target_account_id: account_id.to_owned(),
        };
        let recovery_bytes = self.save_recovery(&record)?;
        let second = match adapter.fingerprint() {
            Ok(fingerprint) => fingerprint,
            Err(_) => {
                return Err(
                    if self.clear_recovery_if(provider, &recovery_bytes).is_ok() {
                        ProviderAccountCommandError::internal(provider, Some(account_id))
                    } else {
                        ProviderAccountCommandError::recovery_required(provider, Some(account_id))
                    },
                );
            }
        };
        if second != first {
            self.clear_recovery_if(provider, &recovery_bytes)?;
            return Err(ProviderAccountCommandError::external_write(
                provider,
                Some(account_id),
            ));
        }
        if adapter.install(&loaded.credentials, &second).is_err() {
            let current = adapter.fingerprint().map_err(|_| {
                ProviderAccountCommandError::recovery_required(provider, Some(account_id))
            })?;
            if current != record.original_fingerprint
                && current != record.expected_target_fingerprint
            {
                return Err(ProviderAccountCommandError::external_write(
                    provider,
                    Some(account_id),
                ));
            }
            return self.rollback_failed_activation(
                adapter,
                &record,
                &recovery_bytes,
                Some(&current),
            );
        }
        let installed_fingerprint = adapter.fingerprint().map_err(|_| {
            ProviderAccountCommandError::recovery_required(provider, Some(account_id))
        })?;
        if installed_fingerprint != expected_installed_fingerprint {
            return Err(ProviderAccountCommandError::external_write(
                provider,
                Some(account_id),
            ));
        }
        let current_identity = adapter.current_identity();
        if current_identity
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .is_none_or(|identity| !identity.matches_stable(&expected_identity))
        {
            return self.rollback_failed_activation(
                adapter,
                &record,
                &recovery_bytes,
                Some(&expected_installed_fingerprint),
            );
        }
        if adapter.verify(&expected_identity).is_err() {
            return self.rollback_failed_activation(
                adapter,
                &record,
                &recovery_bytes,
                Some(&expected_installed_fingerprint),
            );
        }
        match adapter.fingerprint() {
            Ok(fingerprint) if fingerprint == expected_installed_fingerprint => {}
            Ok(_) => {
                return Err(ProviderAccountCommandError::external_write(
                    provider,
                    Some(account_id),
                ));
            }
            Err(_) => {
                return Err(ProviderAccountCommandError::recovery_required(
                    provider,
                    Some(account_id),
                ));
            }
        }
        let config_guard = self.config_commit.lock().await;
        let (mut config, config_revision) =
            Self::load_config(config_store, provider, Some(account_id))?;
        if Self::validated_account_identity(&config, provider, account_id)
            .is_none_or(|identity| !identity.matches_stable(&expected_identity))
        {
            drop(config_guard);
            return self.rollback_failed_activation(
                adapter,
                &record,
                &recovery_bytes,
                Some(&expected_installed_fingerprint),
            );
        }
        match adapter.fingerprint() {
            Ok(fingerprint) if fingerprint == expected_installed_fingerprint => {}
            Ok(_) => {
                drop(config_guard);
                return Err(ProviderAccountCommandError::external_write(
                    provider,
                    Some(account_id),
                ));
            }
            Err(_) => {
                drop(config_guard);
                return Err(ProviderAccountCommandError::recovery_required(
                    provider,
                    Some(account_id),
                ));
            }
        }
        config
            .providers
            .get_mut(&provider)
            .expect("loaded provider")
            .active_account_id = Some(account_id.to_owned());
        if config_store
            .save_if_revision(&config, &config_revision)
            .is_err()
        {
            drop(config_guard);
            return self.rollback_failed_activation(
                adapter,
                &record,
                &recovery_bytes,
                Some(&expected_installed_fingerprint),
            );
        }
        drop(config_guard);
        match adapter.fingerprint() {
            Ok(fingerprint) if fingerprint == expected_installed_fingerprint => {}
            Ok(_) => {
                return Err(ProviderAccountCommandError::external_write(
                    provider,
                    Some(account_id),
                ));
            }
            Err(_) => {
                return Err(ProviderAccountCommandError::recovery_required(
                    provider,
                    Some(account_id),
                ));
            }
        }
        self.clear_recovery_if(provider, &recovery_bytes)?;
        Ok(ProviderActivationResult {
            provider_id: provider,
            previous_account_id: previous,
            active_account_id: account_id.to_owned(),
            restart_hint: adapter.restart_hint(),
            quota_refresh_required: true,
        })
    }

    fn rollback_failed_activation<T>(
        &self,
        adapter: &dyn CredentialActivationAdapter,
        record: &RecoveryRecord,
        recovery_bytes: &[u8],
        installed_fingerprint: Option<&Option<String>>,
    ) -> Result<T, ProviderAccountCommandError> {
        let current = adapter.fingerprint().map_err(|_| {
            ProviderAccountCommandError::recovery_required(
                record.provider,
                Some(&record.target_account_id),
            )
        })?;
        if let Some(installed) = installed_fingerprint {
            if &current != installed {
                return Err(ProviderAccountCommandError::external_write(
                    record.provider,
                    Some(&record.target_account_id),
                ));
            }
        } else if current != record.original_fingerprint {
            return Err(ProviderAccountCommandError::recovery_required(
                record.provider,
                Some(&record.target_account_id),
            ));
        }
        if adapter.restore(&record.snapshot, &current).is_err()
            || adapter.fingerprint().ok() != Some(record.original_fingerprint.clone())
        {
            return Err(ProviderAccountCommandError::recovery_required(
                record.provider,
                Some(&record.target_account_id),
            ));
        }
        self.clear_recovery_if(record.provider, recovery_bytes)?;
        Err(ProviderAccountCommandError::rolled_back(
            record.provider,
            Some(&record.target_account_id),
        ))
    }

    pub async fn recover(
        &self,
        provider: ProviderId,
        action: RecoveryAction,
        config_store: &ConfigStore,
    ) -> Result<(), ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        self.ensure_no_login(provider, None).await?;
        let (record, bytes) = self.load_recovery(provider)?;
        let adapter = self.adapter(provider, Some(&record.target_account_id))?;
        match action {
            RecoveryAction::RestoreOriginal => {
                let current_fingerprint = adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })?;
                let safe_to_restore = current_fingerprint == record.original_fingerprint
                    || current_fingerprint == record.expected_target_fingerprint;
                if !safe_to_restore {
                    return Err(ProviderAccountCommandError::external_write(
                        provider,
                        Some(&record.target_account_id),
                    ));
                }
                adapter
                    .restore(&record.snapshot, &current_fingerprint)
                    .map_err(|_| {
                        ProviderAccountCommandError::recovery_failed(
                            provider,
                            Some(&record.target_account_id),
                        )
                    })?;
                if adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_failed(
                        provider,
                        Some(&record.target_account_id),
                    )
                })? != record.original_fingerprint
                {
                    return Err(ProviderAccountCommandError::recovery_failed(
                        provider,
                        Some(&record.target_account_id),
                    ));
                }
                let _config_guard = self.config_commit.lock().await;
                if adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })? != record.original_fingerprint
                {
                    return Err(ProviderAccountCommandError::external_write(
                        provider,
                        Some(&record.target_account_id),
                    ));
                }
                let (mut config, config_revision) =
                    Self::load_config(config_store, provider, Some(&record.target_account_id))?;
                config
                    .providers
                    .get_mut(&provider)
                    .expect("provider exists")
                    .active_account_id = record.previous_account_id;
                config_store
                    .save_if_revision(&config, &config_revision)
                    .map_err(|_| {
                        ProviderAccountCommandError::recovery_failed(
                            provider,
                            Some(&record.target_account_id),
                        )
                    })?;
                if adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })? != record.original_fingerprint
                {
                    return Err(ProviderAccountCommandError::external_write(
                        provider,
                        Some(&record.target_account_id),
                    ));
                }
            }
            RecoveryAction::KeepCurrent => {
                let expected_fingerprint = adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })?;
                let current = adapter.current_identity().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })?;
                if adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })? != expected_fingerprint
                {
                    return Err(ProviderAccountCommandError::external_write(
                        provider,
                        Some(&record.target_account_id),
                    ));
                }
                let _config_guard = self.config_commit.lock().await;
                if adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })? != expected_fingerprint
                {
                    return Err(ProviderAccountCommandError::external_write(
                        provider,
                        Some(&record.target_account_id),
                    ));
                }
                let (mut config, config_revision) =
                    Self::load_config(config_store, provider, Some(&record.target_account_id))?;
                let active = current.as_ref().and_then(|identity| {
                    config
                        .provider(provider)
                        .accounts
                        .iter()
                        .find(|account| {
                            account
                                .identity
                                .as_ref()
                                .is_some_and(|known| known.matches_stable(identity))
                        })
                        .map(|account| account.id.clone())
                });
                config
                    .providers
                    .get_mut(&provider)
                    .expect("provider exists")
                    .active_account_id = active;
                config_store
                    .save_if_revision(&config, &config_revision)
                    .map_err(|_| {
                        ProviderAccountCommandError::recovery_failed(
                            provider,
                            Some(&record.target_account_id),
                        )
                    })?;
                if adapter.fingerprint().map_err(|_| {
                    ProviderAccountCommandError::recovery_required(
                        provider,
                        Some(&record.target_account_id),
                    )
                })? != expected_fingerprint
                {
                    return Err(ProviderAccountCommandError::external_write(
                        provider,
                        Some(&record.target_account_id),
                    ));
                }
            }
        }
        self.clear_recovery_if(provider, &bytes)
    }

    pub async fn reconcile(
        &self,
        provider: ProviderId,
        config_store: &ConfigStore,
    ) -> Result<Option<ProviderAccountIdentity>, ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        self.ensure_no_login(provider, None).await?;
        if self.recovery_path(provider).exists() {
            return Err(ProviderAccountCommandError::recovery_required(
                provider, None,
            ));
        }
        let adapter = self.adapter(provider, None)?;
        let expected_fingerprint = adapter.fingerprint()?;
        let current = adapter.current_identity()?;
        if adapter.fingerprint()? != expected_fingerprint {
            return Err(ProviderAccountCommandError::external_write(provider, None));
        }
        let _config_guard = self.config_commit.lock().await;
        if adapter.fingerprint()? != expected_fingerprint {
            return Err(ProviderAccountCommandError::external_write(provider, None));
        }
        let (mut config, config_revision) = Self::load_config(config_store, provider, None)?;
        let matched = current.as_ref().and_then(|identity| {
            config
                .provider(provider)
                .accounts
                .iter()
                .find(|account| {
                    account
                        .identity
                        .as_ref()
                        .is_some_and(|known| known.matches_stable(identity))
                })
                .map(|account| account.id.clone())
        });
        config
            .providers
            .get_mut(&provider)
            .expect("provider exists")
            .active_account_id = matched.clone();
        config_store
            .save_if_revision(&config, &config_revision)
            .map_err(|_| ProviderAccountCommandError::internal(provider, None))?;
        if adapter.fingerprint()? != expected_fingerprint {
            return Err(ProviderAccountCommandError::external_write(provider, None));
        }
        Ok(if matched.is_none() { current } else { None })
    }

    pub async fn import_bundle(
        &self,
        provider: ProviderId,
        requested_account_id: Option<&str>,
        label: Option<String>,
        identity: ProviderAccountIdentity,
        credentials: ProviderCredentialBundle,
        config_store: &ConfigStore,
    ) -> Result<ProviderImportResult, ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        self.ensure_no_login(provider, requested_account_id).await?;
        self.import_bundle_locked(
            provider,
            requested_account_id,
            label,
            identity,
            credentials,
            config_store,
        )
        .await
    }

    pub async fn complete_login_import(
        &self,
        request: ProviderLoginImportRequest,
        config_store: &ConfigStore,
    ) -> Result<Option<ProviderImportResult>, ProviderAccountCommandError> {
        let ProviderLoginImportRequest {
            session_id,
            provider,
            requested_account_id,
            label,
            identity,
            credentials,
        } = request;
        if !is_safe_session_id(&session_id) {
            return Err(ProviderAccountCommandError::operation_in_progress(
                provider,
                requested_account_id.as_deref(),
            ));
        }
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        let cancelled = {
            let mut sessions = self.login_sessions.lock().await;
            if sessions.get(&session_id).map(|(owner, _)| *owner) != Some(provider)
                || sessions
                    .iter()
                    .any(|(id, (owner, _))| id != &session_id && *owner == provider)
            {
                return Err(ProviderAccountCommandError::operation_in_progress(
                    provider,
                    requested_account_id.as_deref(),
                ));
            }
            sessions
                .remove(&session_id)
                .expect("validated login session")
                .1
                .load(Ordering::Acquire)
        };
        if cancelled {
            return Ok(None);
        }
        self.import_bundle_locked(
            provider,
            requested_account_id.as_deref(),
            label,
            identity,
            credentials,
            config_store,
        )
        .await
        .map(Some)
    }

    async fn import_bundle_locked(
        &self,
        provider: ProviderId,
        requested_account_id: Option<&str>,
        label: Option<String>,
        identity: ProviderAccountIdentity,
        credentials: ProviderCredentialBundle,
        config_store: &ConfigStore,
    ) -> Result<ProviderImportResult, ProviderAccountCommandError> {
        let _config_guard = self.config_commit.lock().await;
        if identity.provider != provider
            || !identity.is_activation_eligible()
            || credentials == ProviderCredentialBundle::default()
        {
            return Err(ProviderAccountCommandError::invalid_credential(
                provider,
                requested_account_id,
            ));
        }
        let (mut config, config_revision) =
            Self::load_config(config_store, provider, requested_account_id)?;
        let settings = config
            .providers
            .get_mut(&provider)
            .expect("provider exists");
        let existing = if let Some(requested) = requested_account_id {
            let account = settings
                .accounts
                .iter()
                .find(|account| account.id == requested)
                .ok_or_else(|| {
                    ProviderAccountCommandError::account_not_found(provider, Some(requested))
                })?;
            if !account
                .identity
                .as_ref()
                .is_some_and(|known| known.matches_stable(&identity))
            {
                return Err(ProviderAccountCommandError::identity_mismatch(
                    provider,
                    Some(requested),
                ));
            }
            Some(requested.to_owned())
        } else {
            settings
                .accounts
                .iter()
                .find(|account| {
                    account
                        .identity
                        .as_ref()
                        .is_some_and(|known| known.matches_stable(&identity))
                })
                .map(|account| account.id.clone())
        };
        let updated_existing = existing.is_some();
        let account_id = match existing {
            Some(account_id) => account_id,
            None => self.next_account_id(provider, settings)?,
        };
        if let Some(account) = settings
            .accounts
            .iter_mut()
            .find(|account| account.id == account_id)
        {
            account.identity = Some(identity.clone());
            account.apply_managed_credential_bundle(&credentials);
            if label.is_some() {
                account.label = label;
            }
        } else {
            let mut account = ProviderAccount {
                id: account_id.clone(),
                identity: Some(identity),
                label,
                ..ProviderAccount::default()
            };
            account.apply_managed_credential_bundle(&credentials);
            settings.accounts.push(account);
        }
        if config_store
            .save_if_revision(&config, &config_revision)
            .is_err()
        {
            return Err(ProviderAccountCommandError::internal(
                provider,
                Some(&account_id),
            ));
        }
        Ok(ProviderImportResult {
            provider_id: provider,
            account_id,
            updated_existing,
        })
    }

    pub async fn set_enabled(
        &self,
        provider: ProviderId,
        account_id: &str,
        enabled: bool,
        config_store: &ConfigStore,
    ) -> Result<(), ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        self.ensure_no_login(provider, Some(account_id)).await?;
        let _config_guard = self.config_commit.lock().await;
        let (mut config, config_revision) =
            Self::load_config(config_store, provider, Some(account_id))?;
        let settings = config
            .providers
            .get_mut(&provider)
            .expect("provider exists");
        if !enabled && settings.active_account_id.as_deref() == Some(account_id) {
            return Err(ProviderAccountCommandError::account_active(
                provider,
                Some(account_id),
            ));
        }
        if !enabled {
            self.reject_official_active(provider, account_id, settings)?;
        }
        let account = settings
            .accounts
            .iter_mut()
            .find(|account| account.id == account_id)
            .ok_or_else(|| {
                ProviderAccountCommandError::account_not_found(provider, Some(account_id))
            })?;
        account.enabled = enabled;
        config_store
            .save_if_revision(&config, &config_revision)
            .map_err(|_| ProviderAccountCommandError::internal(provider, Some(account_id)))
    }

    pub async fn delete(
        &self,
        provider: ProviderId,
        account_id: &str,
        config_store: &ConfigStore,
        history: &HistoryStore,
    ) -> Result<(), ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        self.ensure_no_login(provider, Some(account_id)).await?;
        let _config_guard = self.config_commit.lock().await;
        let (mut config, config_revision) =
            Self::load_config(config_store, provider, Some(account_id))?;
        let settings = config
            .providers
            .get_mut(&provider)
            .expect("provider exists");
        if settings.active_account_id.as_deref() == Some(account_id) {
            return Err(ProviderAccountCommandError::account_active(
                provider,
                Some(account_id),
            ));
        }
        self.reject_official_active(provider, account_id, settings)?;
        let index = settings
            .accounts
            .iter()
            .position(|account| account.id == account_id)
            .ok_or_else(|| {
                ProviderAccountCommandError::account_not_found(provider, Some(account_id))
            })?;
        let vault = ProviderCredentialVault::new(&self.config_dir, self.codec.as_ref());
        let history_stage = history
            .stage_delete_account(provider, account_id)
            .map_err(|_| ProviderAccountCommandError::internal(provider, Some(account_id)))?;
        let vault_stage = match vault.stage_delete(provider, account_id) {
            Ok(stage) => stage,
            Err(_) => {
                return Err(if history_stage.rollback().is_ok() {
                    ProviderAccountCommandError::internal(provider, Some(account_id))
                } else {
                    ProviderAccountCommandError::recovery_failed(provider, Some(account_id))
                });
            }
        };
        settings.accounts.remove(index);
        if config_store
            .save_if_revision(&config, &config_revision)
            .is_err()
        {
            let vault_ok = vault_stage.rollback().is_ok();
            let history_ok = history_stage.rollback().is_ok();
            return Err(if vault_ok && history_ok {
                ProviderAccountCommandError::internal(provider, Some(account_id))
            } else {
                ProviderAccountCommandError::recovery_failed(provider, Some(account_id))
            });
        }
        let vault_committed = vault_stage.commit().is_ok();
        let history_committed = history_stage.commit().is_ok();
        if vault_committed && history_committed {
            Ok(())
        } else {
            Err(ProviderAccountCommandError::recovery_failed(
                provider,
                Some(account_id),
            ))
        }
    }

    pub async fn status(
        &self,
        provider: ProviderId,
        config_store: &ConfigStore,
    ) -> ProviderAccountStatus {
        let config = config_store.load().unwrap_or_else(|_| AppConfig::default());
        self.status_with_config(provider, &config).await
    }

    pub async fn status_with_config(
        &self,
        provider: ProviderId,
        config: &AppConfig,
    ) -> ProviderAccountStatus {
        let lock = self.lock(provider);
        let operation_guard = lock.try_lock();
        let operation_in_progress = if operation_guard.is_err() {
            true
        } else {
            self.login_sessions
                .lock()
                .await
                .values()
                .any(|(session_provider, _)| *session_provider == provider)
        };
        let recovery = match self.load_recovery(provider) {
            Ok(_) => ProviderRecoveryState::Required,
            Err(_) if !self.recovery_path(provider).exists() => ProviderRecoveryState::None,
            Err(_) => ProviderRecoveryState::Corrupt,
        };
        let activation = self.adapters.activation_support(provider);
        let (active_account_id, external_identity) =
            if activation.kind == codexbar_engine::ActivationTargetKind::Unsupported {
                (None, None)
            } else if operation_in_progress {
                (config.provider(provider).active_account_id.clone(), None)
            } else {
                match self
                    .adapters
                    .adapter(provider)
                    .expect("supported activation has an adapter")
                    .current_identity()
                {
                    Ok(Some(identity)) => {
                        let matched = Self::matching_account_id(config, provider, &identity);
                        if matched.is_some() {
                            (matched, None)
                        } else {
                            (None, Some(identity))
                        }
                    }
                    Ok(None) | Err(_) => (None, None),
                }
            };
        ProviderAccountStatus {
            provider_id: provider,
            enrollment: self
                .adapters
                .enrollment(provider)
                .unwrap_or_default()
                .to_vec(),
            activation,
            active_account_id,
            external_identity,
            recovery,
            operation_in_progress,
        }
    }

    pub async fn save_settings_if_authorized(
        &self,
        providers: &[ProviderId],
        proposed: &AppConfig,
        expected_revision: &ConfigRevision,
        config_store: &ConfigStore,
    ) -> Result<(), ProviderAccountCommandError> {
        let providers = ProviderId::ALL
            .into_iter()
            .filter(|provider| providers.contains(provider))
            .collect::<Vec<_>>();
        let lock_arcs = providers
            .iter()
            .map(|provider| self.lock(*provider))
            .collect::<Vec<_>>();
        let mut provider_guards = Vec::with_capacity(lock_arcs.len());
        for lock in lock_arcs {
            provider_guards.push(lock.lock_owned().await);
        }
        for provider in &providers {
            self.ensure_no_login(*provider, None).await?;
            if self.recovery_path(*provider).exists() {
                return Err(ProviderAccountCommandError::recovery_required(
                    *provider, None,
                ));
            }
        }
        let _config_guard = self.config_commit.lock().await;
        let (current, revision) = config_store
            .load_with_revision()
            .map_err(|_| ProviderAccountCommandError::internal_global())?;
        if &revision != expected_revision {
            return Err(ProviderAccountCommandError::internal_global());
        }
        let before = self.official_identity_snapshots(&providers, &current)?;
        let mut proposed = proposed.clone();
        for provider in &providers {
            proposed
                .providers
                .get_mut(provider)
                .expect("normalized provider config")
                .active_account_id = None;
        }
        for (provider, snapshot) in &before {
            proposed
                .providers
                .get_mut(provider)
                .expect("normalized provider config")
                .active_account_id = snapshot.matched_account_id.clone();
        }
        for (provider, snapshot) in &before {
            let Some(active_account_id) = snapshot.matched_account_id.as_deref() else {
                continue;
            };
            let settings = proposed.provider(*provider);
            let preserves_active = settings.enabled
                && settings
                    .accounts
                    .iter()
                    .any(|account| account.id == active_account_id && account.enabled);
            if !preserves_active {
                return Err(ProviderAccountCommandError::account_active(
                    *provider,
                    Some(active_account_id),
                ));
            }
        }
        let installed_revision = config_store
            .save_if_revision_with_installed_revision(&proposed, expected_revision)
            .map_err(|_| ProviderAccountCommandError::internal_global())?;
        let after = match self.official_identity_snapshots(&providers, &current) {
            Ok(after) => after,
            Err(error) => {
                let _ = config_store.save_if_revision(&current, &installed_revision);
                return Err(error);
            }
        };
        if after == before {
            return Ok(());
        }
        let changed_provider = ProviderId::ALL.into_iter().find(|provider| {
            let before_snapshot = before
                .iter()
                .find_map(|(candidate, snapshot)| (*candidate == *provider).then_some(snapshot));
            let after_snapshot = after
                .iter()
                .find_map(|(candidate, snapshot)| (*candidate == *provider).then_some(snapshot));
            before_snapshot != after_snapshot
        });
        if config_store
            .save_if_revision(&current, &installed_revision)
            .is_err()
        {
            return Err(ProviderAccountCommandError::external_write_global());
        }
        changed_provider.map_or_else(
            || Err(ProviderAccountCommandError::external_write_global()),
            |provider| Err(ProviderAccountCommandError::external_write(provider, None)),
        )
    }

    pub async fn begin_login_session(
        &self,
        provider: ProviderId,
    ) -> Result<(String, Arc<AtomicBool>), ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        self.begin_login_session_locked(provider).await
    }

    pub async fn begin_login_session_for_account(
        &self,
        provider: ProviderId,
        requested_account_id: Option<&str>,
        config_store: &ConfigStore,
    ) -> Result<(String, Arc<AtomicBool>, Option<String>), ProviderAccountCommandError> {
        let lock = self.lock(provider);
        let _guard = lock.lock().await;
        let requested_account_id = match requested_account_id {
            None => None,
            Some(account_id) => {
                if !is_safe_managed_account_id(account_id) {
                    return Err(ProviderAccountCommandError::account_not_found(
                        provider, None,
                    ));
                }
                let (config, _) = Self::load_config(config_store, provider, None)?;
                if !config
                    .provider(provider)
                    .accounts
                    .iter()
                    .any(|account| account.id == account_id)
                {
                    return Err(ProviderAccountCommandError::account_not_found(
                        provider, None,
                    ));
                }
                Some(account_id.to_owned())
            }
        };
        let (session_id, cancellation) = self.begin_login_session_locked(provider).await?;
        Ok((session_id, cancellation, requested_account_id))
    }

    async fn begin_login_session_locked(
        &self,
        provider: ProviderId,
    ) -> Result<(String, Arc<AtomicBool>), ProviderAccountCommandError> {
        let mut sessions = self.login_sessions.lock().await;
        if sessions
            .values()
            .any(|(session_provider, _)| *session_provider == provider)
        {
            return Err(ProviderAccountCommandError::operation_in_progress(
                provider, None,
            ));
        }
        if sessions.len() >= MAX_LOGIN_SESSIONS {
            return Err(ProviderAccountCommandError::operation_in_progress(
                provider, None,
            ));
        }
        let id = format!(
            "login_{:016x}",
            NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        sessions.insert(id.clone(), (provider, Arc::clone(&cancelled)));
        Ok((id, cancelled))
    }

    pub async fn cancel_login_session(&self, session_id: &str) -> bool {
        if !is_safe_session_id(session_id) {
            return false;
        }
        self.login_sessions
            .lock()
            .await
            .get(session_id)
            .is_some_and(|(_, flag)| {
                flag.store(true, Ordering::Release);
                true
            })
    }

    pub async fn finish_login_session(
        &self,
        provider: ProviderId,
        session_id: &str,
    ) -> Option<bool> {
        if !is_safe_session_id(session_id) {
            return None;
        }
        let mut sessions = self.login_sessions.lock().await;
        if sessions.get(session_id).map(|(owner, _)| *owner) != Some(provider) {
            return None;
        }
        let (_, cancellation) = sessions.remove(session_id)?;
        Some(cancellation.load(Ordering::Acquire))
    }

    fn load_config(
        store: &ConfigStore,
        provider: ProviderId,
        account: Option<&str>,
    ) -> Result<(AppConfig, ConfigRevision), ProviderAccountCommandError> {
        store
            .load_with_revision()
            .map_err(|_| ProviderAccountCommandError::internal(provider, account))
    }

    async fn ensure_no_login(
        &self,
        provider: ProviderId,
        account_id: Option<&str>,
    ) -> Result<(), ProviderAccountCommandError> {
        if self
            .login_sessions
            .lock()
            .await
            .values()
            .any(|(session_provider, _)| *session_provider == provider)
        {
            Err(ProviderAccountCommandError::operation_in_progress(
                provider, account_id,
            ))
        } else {
            Ok(())
        }
    }

    fn validated_account_identity<'config>(
        config: &'config AppConfig,
        provider: ProviderId,
        account_id: &str,
    ) -> Option<&'config ProviderAccountIdentity> {
        config
            .providers
            .get(&provider)?
            .accounts
            .iter()
            .find(|account| account.id == account_id && account.enabled)
            .and_then(|account| account.identity.as_ref())
            .filter(|identity| identity.provider == provider && identity.is_activation_eligible())
    }

    fn matching_account_id(
        config: &AppConfig,
        provider: ProviderId,
        identity: &ProviderAccountIdentity,
    ) -> Option<String> {
        config
            .provider(provider)
            .accounts
            .iter()
            .find(|account| {
                account.identity.as_ref().is_some_and(|known| {
                    known.provider == provider && known.matches_stable(identity)
                })
            })
            .map(|account| account.id.clone())
    }

    fn official_identity_snapshots(
        &self,
        providers: &[ProviderId],
        config: &AppConfig,
    ) -> Result<Vec<(ProviderId, OfficialIdentitySnapshot)>, ProviderAccountCommandError> {
        providers
            .iter()
            .filter(|provider| {
                self.adapters.activation_support(**provider).kind
                    != codexbar_engine::ActivationTargetKind::Unsupported
            })
            .filter_map(|provider| {
                self.adapters.adapter(*provider).map(|adapter| {
                    let identity = adapter
                        .current_identity()
                        .map_err(|_| ProviderAccountCommandError::internal(*provider, None))?;
                    let matched_account_id = identity.as_ref().and_then(|identity| {
                        Self::matching_account_id(config, *provider, identity)
                    });
                    Ok((
                        *provider,
                        OfficialIdentitySnapshot {
                            identity,
                            matched_account_id,
                        },
                    ))
                })
            })
            .collect()
    }

    fn next_account_id(
        &self,
        provider: ProviderId,
        settings: &ProviderConfig,
    ) -> Result<String, ProviderAccountCommandError> {
        let mut reserved = settings
            .accounts
            .iter()
            .map(|account| account.id.clone())
            .collect::<HashSet<_>>();
        let provider_dir = self.config_dir.join("accounts").join(provider.as_str());
        match fs::read_dir(&provider_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry =
                        entry.map_err(|_| ProviderAccountCommandError::internal(provider, None))?;
                    let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    if let Some(account_id) = name.strip_suffix(".vault")
                        && is_safe_managed_account_id(account_id)
                    {
                        reserved.insert(account_id.to_owned());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(ProviderAccountCommandError::internal(provider, None));
            }
        }
        let vault = ProviderCredentialVault::new(&self.config_dir, self.codec.as_ref());
        for _ in 0..=reserved.len() {
            let candidate = format!(
                "acc_{:016x}",
                self.next_account_sequence.fetch_add(1, Ordering::Relaxed)
            );
            if reserved.contains(&candidate) {
                continue;
            }
            let path = vault
                .path(provider, &candidate)
                .map_err(|_| ProviderAccountCommandError::internal(provider, None))?;
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    reserved.insert(candidate);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(candidate);
                }
                Err(_) => {
                    return Err(ProviderAccountCommandError::internal(provider, None));
                }
            }
        }
        Err(ProviderAccountCommandError::internal(provider, None))
    }

    fn reject_official_active(
        &self,
        provider: ProviderId,
        account_id: &str,
        settings: &ProviderConfig,
    ) -> Result<(), ProviderAccountCommandError> {
        let Some(adapter) = self.adapters.adapter(provider) else {
            return Ok(());
        };
        let current = adapter
            .current_identity()
            .map_err(|_| ProviderAccountCommandError::internal(provider, Some(account_id)))?;
        let target = settings
            .accounts
            .iter()
            .find(|account| account.id == account_id)
            .and_then(|account| account.identity.as_ref());
        if current
            .as_ref()
            .zip(target)
            .is_some_and(|(current, target)| current.matches_stable(target))
        {
            Err(ProviderAccountCommandError::account_active(
                provider,
                Some(account_id),
            ))
        } else {
            Ok(())
        }
    }

    fn recovery_path(&self, provider: ProviderId) -> PathBuf {
        self.config_dir
            .join("accounts")
            .join(provider.as_str())
            .join(".recovery.vault")
    }

    fn save_recovery(
        &self,
        record: &RecoveryRecord,
    ) -> Result<Vec<u8>, ProviderAccountCommandError> {
        let plaintext = serde_json::to_vec(record).map_err(|_| {
            ProviderAccountCommandError::internal(record.provider, Some(&record.target_account_id))
        })?;
        let protected = self.codec.protect(&plaintext).map_err(|_| {
            ProviderAccountCommandError::internal(record.provider, Some(&record.target_account_id))
        })?;
        let bytes = serde_json::to_vec(&RecoveryEnvelope {
            version: RECOVERY_VERSION,
            ciphertext: protected,
        })
        .map_err(|_| {
            ProviderAccountCommandError::internal(record.provider, Some(&record.target_account_id))
        })?;
        let path = self.recovery_path(record.provider);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| {
                ProviderAccountCommandError::internal(
                    record.provider,
                    Some(&record.target_account_id),
                )
            })?;
        }
        if path.exists() {
            return Err(ProviderAccountCommandError::recovery_required(
                record.provider,
                Some(&record.target_account_id),
            ));
        }
        atomic_write(&path, &bytes).map_err(|_| {
            ProviderAccountCommandError::internal(record.provider, Some(&record.target_account_id))
        })?;
        let (loaded, installed) = self.load_recovery(record.provider)?;
        if loaded != *record || installed != bytes {
            return Err(ProviderAccountCommandError::recovery_required(
                record.provider,
                Some(&record.target_account_id),
            ));
        }
        Ok(bytes)
    }

    fn load_recovery(
        &self,
        provider: ProviderId,
    ) -> Result<(RecoveryRecord, Vec<u8>), ProviderAccountCommandError> {
        let bytes = fs::read(self.recovery_path(provider))
            .map_err(|_| ProviderAccountCommandError::recovery_required(provider, None))?;
        let envelope: RecoveryEnvelope = serde_json::from_slice(&bytes)
            .map_err(|_| ProviderAccountCommandError::recovery_required(provider, None))?;
        if envelope.version != RECOVERY_VERSION {
            return Err(ProviderAccountCommandError::recovery_required(
                provider, None,
            ));
        }
        let plaintext = self
            .codec
            .unprotect(&envelope.ciphertext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(provider, None))?;
        let record: RecoveryRecord = serde_json::from_slice(&plaintext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(provider, None))?;
        if record.provider != provider
            || !is_safe_managed_account_id(&record.target_account_id)
            || record
                .previous_account_id
                .as_deref()
                .is_some_and(|account_id| !is_safe_managed_account_id(account_id))
            || record.snapshot.fingerprint != record.original_fingerprint
        {
            return Err(ProviderAccountCommandError::recovery_required(
                provider, None,
            ));
        }
        Ok((record, bytes))
    }

    fn clear_recovery_if(
        &self,
        provider: ProviderId,
        expected: &[u8],
    ) -> Result<(), ProviderAccountCommandError> {
        let path = self.recovery_path(provider);
        if read_optional(&path).ok().flatten().as_deref() != Some(expected) {
            return Err(ProviderAccountCommandError::recovery_required(
                provider, None,
            ));
        }
        fs::remove_file(path)
            .map_err(|_| ProviderAccountCommandError::recovery_required(provider, None))
    }
}

fn read_optional(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn is_safe_session_id(value: &str) -> bool {
    value
        .strip_prefix("login_")
        .is_some_and(|tail| tail.len() == 16 && tail.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::super::adapters::{ProviderAccountCommandErrorCode, ProviderAdapterDeclaration};
    use super::*;
    use codexbar_engine::{
        ActivationTargetKind, ProviderEnrollmentKind, ProviderIdentityKey,
        auth::dpapi::{SecretCodec, SecretError},
    };
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct XorCodec;

    impl SecretCodec for XorCodec {
        fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(bytes.iter().map(|byte| byte ^ 0xa5).collect())
        }

        fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            self.protect(bytes)
        }
    }

    #[derive(Debug)]
    struct DeleteMutationCodec {
        config_path: PathBuf,
        external_vault_path: Option<PathBuf>,
        armed: AtomicBool,
    }

    impl SecretCodec for DeleteMutationCodec {
        fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                fs::write(&self.config_path, b"external-config-update").unwrap();
                if let Some(path) = &self.external_vault_path {
                    fs::write(path, b"external-new-vault").unwrap();
                }
            }
            Ok(bytes.iter().map(|byte| byte ^ 0xa5).collect())
        }

        fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(bytes.iter().map(|byte| byte ^ 0xa5).collect())
        }
    }

    #[derive(Debug)]
    struct DeleteCommitMutationCodec {
        external_vault_path: PathBuf,
        external_history_path: PathBuf,
        armed: AtomicBool,
    }

    impl SecretCodec for DeleteCommitMutationCodec {
        fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                fs::write(&self.external_vault_path, b"external-commit-vault").unwrap();
                fs::write(&self.external_history_path, b"external-commit-history").unwrap();
            }
            Ok(bytes.iter().map(|byte| byte ^ 0xa5).collect())
        }

        fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(bytes.iter().map(|byte| byte ^ 0xa5).collect())
        }
    }

    type IdentityHook = Box<dyn FnOnce() + Send>;

    struct FakeAdapter {
        provider: ProviderId,
        target: StdMutex<Option<ProviderCredentialBundle>>,
        race_after_install: AtomicBool,
        mutate_on_fingerprint_call: AtomicUsize,
        fingerprint_calls: AtomicUsize,
        fail_install: AtomicBool,
        fail_install_after_write: AtomicBool,
        external_during_install: AtomicBool,
        fail_restore: AtomicBool,
        fail_fingerprint_on_call: AtomicUsize,
        fail_identity: AtomicBool,
        current_identity_calls: AtomicUsize,
        support_override: StdMutex<Option<ActivationSupport>>,
        identity_override: StdMutex<Option<ProviderAccountIdentity>>,
        identity_results: StdMutex<
            VecDeque<Result<Option<ProviderAccountIdentity>, ProviderAccountCommandError>>,
        >,
        before_identity: StdMutex<Option<IdentityHook>>,
        before_identity_on_call: StdMutex<Option<(usize, IdentityHook)>>,
    }

    impl fmt::Debug for FakeAdapter {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FakeAdapter")
                .field("provider", &self.provider)
                .field("has_target", &self.target.lock().unwrap().is_some())
                .finish_non_exhaustive()
        }
    }

    impl FakeAdapter {
        fn new(provider: ProviderId, key: &str) -> Self {
            Self {
                provider,
                target: StdMutex::new(Some(bundle(key))),
                race_after_install: AtomicBool::new(false),
                mutate_on_fingerprint_call: AtomicUsize::new(0),
                fingerprint_calls: AtomicUsize::new(0),
                fail_install: AtomicBool::new(false),
                fail_install_after_write: AtomicBool::new(false),
                external_during_install: AtomicBool::new(false),
                fail_restore: AtomicBool::new(false),
                fail_fingerprint_on_call: AtomicUsize::new(0),
                fail_identity: AtomicBool::new(false),
                current_identity_calls: AtomicUsize::new(0),
                support_override: StdMutex::new(None),
                identity_override: StdMutex::new(None),
                identity_results: StdMutex::new(VecDeque::new()),
                before_identity: StdMutex::new(None),
                before_identity_on_call: StdMutex::new(None),
            }
        }
    }

    impl CredentialActivationAdapter for FakeAdapter {
        fn provider(&self) -> ProviderId {
            self.provider
        }
        fn support(&self) -> ActivationSupport {
            if let Some(support) = self.support_override.lock().unwrap().clone() {
                return support;
            }
            ActivationSupport {
                kind: ActivationTargetKind::CliFile,
                target_description: Some("Fixture CLI file".into()),
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
            let call = self.fingerprint_calls.fetch_add(1, Ordering::AcqRel) + 1;
            if self.fail_fingerprint_on_call.load(Ordering::Acquire) == call {
                return Err(ProviderAccountCommandError::internal(self.provider, None));
            }
            if self.mutate_on_fingerprint_call.load(Ordering::Acquire) == call {
                *self.target.lock().unwrap() = Some(bundle("external"));
            }
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
            if let Some(hook) = self.before_identity.lock().unwrap().take() {
                hook();
            }
            let call = self.current_identity_calls.fetch_add(1, Ordering::AcqRel) + 1;
            let scheduled_hook = {
                let mut hook = self.before_identity_on_call.lock().unwrap();
                if hook.as_ref().is_some_and(|(expected, _)| *expected == call) {
                    hook.take().map(|(_, hook)| hook)
                } else {
                    None
                }
            };
            if let Some(hook) = scheduled_hook {
                hook();
            }
            if let Some(result) = self.identity_results.lock().unwrap().pop_front() {
                return result;
            }
            if self.fail_identity.load(Ordering::Acquire) {
                return Err(ProviderAccountCommandError::internal(self.provider, None));
            }
            if let Some(identity) = self.identity_override.lock().unwrap().clone() {
                return Ok(Some(identity));
            }
            Ok(self
                .target
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|credentials| {
                    credentials
                        .api_key
                        .as_ref()
                        .map(|key| identity(self.provider, key, None))
                }))
        }
        fn validate_target(
            &self,
            identity: &ProviderAccountIdentity,
            credentials: &ProviderCredentialBundle,
        ) -> Result<(), ProviderAccountCommandError> {
            if identity.provider == self.provider
                && identity.is_activation_eligible()
                && credentials.api_key.is_some()
            {
                Ok(())
            } else {
                Err(ProviderAccountCommandError::invalid_credential(
                    self.provider,
                    None,
                ))
            }
        }
        fn install(
            &self,
            credentials: &ProviderCredentialBundle,
            expected_current_fingerprint: &Option<String>,
        ) -> Result<(), ProviderAccountCommandError> {
            if self.fail_install.load(Ordering::Acquire) {
                return Err(ProviderAccountCommandError::invalid_credential(
                    self.provider,
                    None,
                ));
            }
            let mut target = self.target.lock().unwrap();
            if self.external_during_install.load(Ordering::Acquire) {
                *target = Some(bundle("external"));
            }
            if fingerprint(target.as_ref()) != *expected_current_fingerprint {
                return Err(ProviderAccountCommandError::external_write(
                    self.provider,
                    None,
                ));
            }
            *target = Some(credentials.clone());
            drop(target);
            if self.fail_install_after_write.load(Ordering::Acquire) {
                return Err(ProviderAccountCommandError::internal(self.provider, None));
            }
            if self.race_after_install.load(Ordering::Acquire) {
                *self.target.lock().unwrap() = Some(bundle("external"));
            }
            Ok(())
        }
        fn verify(
            &self,
            expected: &ProviderAccountIdentity,
        ) -> Result<(), ProviderAccountCommandError> {
            if self
                .current_identity()?
                .as_ref()
                .is_some_and(|actual| actual.matches_stable(expected))
            {
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
            if self.fail_restore.load(Ordering::Acquire) {
                return Err(ProviderAccountCommandError::recovery_failed(
                    self.provider,
                    None,
                ));
            }
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
                client_name: Some("Fixture CLI".into()),
                message: None,
            }
        }
    }

    struct MutateTargetOnProtect {
        adapter: Arc<FakeAdapter>,
        armed: AtomicBool,
    }

    impl fmt::Debug for MutateTargetOnProtect {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("MutateTargetOnProtect")
                .field("armed", &self.armed.load(Ordering::Acquire))
                .finish_non_exhaustive()
        }
    }

    impl SecretCodec for MutateTargetOnProtect {
        fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            if self.armed.swap(false, Ordering::AcqRel) {
                *self.adapter.target.lock().unwrap() = Some(bundle("external"));
            }
            Ok(bytes.iter().map(|byte| byte ^ 0xa5).collect())
        }

        fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(bytes.iter().map(|byte| byte ^ 0xa5).collect())
        }
    }

    struct Fixture {
        temp: tempfile::TempDir,
        manager: ProviderAccountManager,
        store: ConfigStore,
        adapter: Arc<FakeAdapter>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let codec: Arc<dyn SecretCodec> = Arc::new(XorCodec);
            let store =
                ConfigStore::at_with_codec(temp.path().join("config.json"), Arc::clone(&codec));
            let adapter = Arc::new(FakeAdapter::new(ProviderId::Codex, "original"));
            let declarations = ProviderId::ALL.into_iter().map(|provider| {
                if provider == ProviderId::Codex {
                    ProviderAdapterDeclaration::with_adapter(
                        provider,
                        vec![
                            ProviderEnrollmentKind::CliLogin,
                            ProviderEnrollmentKind::ImportCurrent,
                        ],
                        adapter.clone(),
                    )
                } else {
                    ProviderAdapterDeclaration::monitoring_only(provider, Vec::new())
                }
            });
            let manager = ProviderAccountManager::new(
                temp.path().to_path_buf(),
                codec,
                ProviderAdapterRegistry::new(declarations).unwrap(),
            );
            let mut config = AppConfig::default();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: "acc_target".into(),
                    identity: Some(identity(
                        ProviderId::Codex,
                        "target",
                        Some("same@example.com"),
                    )),
                    api_key: Some("target".into()),
                    ..ProviderAccount::default()
                });
            store.save(&config).unwrap();
            Self {
                temp,
                manager,
                store,
                adapter,
            }
        }
    }

    fn identity(provider: ProviderId, key: &str, email: Option<&str>) -> ProviderAccountIdentity {
        ProviderAccountIdentity::new(
            provider,
            [ProviderIdentityKey::new("fixture-sub", key)],
            email.map(str::to_owned),
            None,
        )
    }

    fn bundle(key: &str) -> ProviderCredentialBundle {
        ProviderCredentialBundle {
            api_key: Some(key.into()),
            ..ProviderCredentialBundle::default()
        }
    }

    fn fingerprint(credentials: Option<&ProviderCredentialBundle>) -> Option<String> {
        credentials.map(|value| format!("{:x}", Sha256::digest(serde_json::to_vec(value).unwrap())))
    }

    fn registry_with(adapter: Arc<FakeAdapter>) -> ProviderAdapterRegistry {
        ProviderAdapterRegistry::new(ProviderId::ALL.into_iter().map(|provider| {
            if provider == ProviderId::Codex {
                ProviderAdapterDeclaration::with_adapter(
                    provider,
                    vec![ProviderEnrollmentKind::ImportCurrent],
                    adapter.clone(),
                )
            } else {
                ProviderAdapterDeclaration::monitoring_only(provider, Vec::new())
            }
        }))
        .unwrap()
    }

    type DeleteRollbackFixture = (
        tempfile::TempDir,
        ProviderAccountManager,
        ConfigStore,
        HistoryStore,
        Arc<DeleteMutationCodec>,
        PathBuf,
        PathBuf,
        Vec<u8>,
        Vec<u8>,
    );

    fn delete_rollback_fixture(external_vault_conflict: bool) -> DeleteRollbackFixture {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.json");
        let target_vault_path = temp.path().join("accounts/codex/acc_target.vault");
        let codec = Arc::new(DeleteMutationCodec {
            config_path: config_path.clone(),
            external_vault_path: external_vault_conflict.then(|| target_vault_path.clone()),
            armed: AtomicBool::new(false),
        });
        let store = ConfigStore::at_with_codec(config_path.clone(), codec.clone());
        let adapter = Arc::new(FakeAdapter::new(ProviderId::Codex, "original"));
        let manager = ProviderAccountManager::new(
            temp.path().to_path_buf(),
            codec.clone(),
            registry_with(adapter),
        );
        let mut config = AppConfig::default();
        let settings = config.providers.get_mut(&ProviderId::Codex).unwrap();
        for (id, key) in [("acc_target", "target"), ("acc_sibling", "sibling")] {
            settings.accounts.push(ProviderAccount {
                id: id.into(),
                identity: Some(identity(ProviderId::Codex, key, None)),
                api_key: Some(key.into()),
                ..ProviderAccount::default()
            });
        }
        store.save(&config).unwrap();
        let original_vault = fs::read(&target_vault_path).unwrap();
        let history_root = temp.path().join("history");
        fs::create_dir_all(&history_root).unwrap();
        let history_path = history_root.join("codex.jsonl");
        let original_history = br#"{"timestamp":"2026-07-15T10:00:00Z","provider":"codex","accountId":"acc_target","windowId":"weekly","usedPercent":10.0,"resetsAt":null,"balance":null,"spend":null,"currency":null}
{"timestamp":"2026-07-15T10:00:00Z","provider":"codex","accountId":"acc_sibling","windowId":"weekly","usedPercent":20.0,"resetsAt":null,"balance":null,"spend":null,"currency":null}
"#.to_vec();
        fs::write(&history_path, &original_history).unwrap();
        let history = HistoryStore::at(history_root);
        (
            temp,
            manager,
            store,
            history,
            codec,
            config_path,
            target_vault_path,
            original_vault,
            original_history,
        )
    }

    #[test]
    fn manager_contract_is_provider_neutral() {
        let _: Option<ProviderAccountManager> = None;
        let _ = RecoveryAction::RestoreOriginal;
        let _ = ProviderRecoveryState::None;
    }

    #[test]
    fn status_with_config_projects_the_supplied_snapshot_without_reloading_the_store() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let mut config = AppConfig::default();
            let settings = config.providers.get_mut(&ProviderId::Codex).unwrap();
            settings.active_account_id = Some("acc_supplied".into());
            settings.accounts.push(ProviderAccount {
                id: "acc_supplied".into(),
                identity: Some(identity(ProviderId::Codex, "original", None)),
                ..ProviderAccount::default()
            });

            let status = fixture
                .manager
                .status_with_config(ProviderId::Codex, &config)
                .await;

            assert_eq!(status.active_account_id.as_deref(), Some("acc_supplied"));
            assert_eq!(status.external_identity, None);
        });
    }

    #[test]
    fn status_prefers_the_known_official_identity_over_stale_config_active() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let mut config = fixture.store.load().unwrap();
            let settings = config.providers.get_mut(&ProviderId::Codex).unwrap();
            settings.active_account_id = Some("acc_target".into());
            settings.accounts.push(ProviderAccount {
                id: "acc_current".into(),
                identity: Some(identity(ProviderId::Codex, "original", None)),
                ..ProviderAccount::default()
            });

            let status = fixture
                .manager
                .status_with_config(ProviderId::Codex, &config)
                .await;

            assert_eq!(status.active_account_id.as_deref(), Some("acc_current"));
            assert_eq!(status.external_identity, None);
        });
    }

    #[test]
    fn status_clears_active_for_unknown_official_identity() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let mut config = fixture.store.load().unwrap();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .active_account_id = Some("acc_target".into());
            let external = identity(ProviderId::Codex, "external", None);
            *fixture.adapter.identity_override.lock().unwrap() = Some(external.clone());

            let status = fixture
                .manager
                .status_with_config(ProviderId::Codex, &config)
                .await;

            assert_eq!(status.active_account_id, None);
            assert_eq!(status.external_identity, Some(external));
        });
    }

    #[test]
    fn status_clears_active_when_official_target_has_no_identity() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let mut config = fixture.store.load().unwrap();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .active_account_id = Some("acc_target".into());
            *fixture.adapter.target.lock().unwrap() = None;

            let status = fixture
                .manager
                .status_with_config(ProviderId::Codex, &config)
                .await;

            assert_eq!(status.active_account_id, None);
            assert_eq!(status.external_identity, None);
        });
    }

    #[test]
    fn status_fails_closed_when_official_identity_read_fails() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let mut config = fixture.store.load().unwrap();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .active_account_id = Some("acc_target".into());
            fixture.adapter.fail_identity.store(true, Ordering::Release);

            let status = fixture
                .manager
                .status_with_config(ProviderId::Codex, &config)
                .await;

            assert_eq!(status.active_account_id, None);
            assert_eq!(status.external_identity, None);
        });
    }

    #[test]
    fn unsupported_status_never_projects_a_config_active_account() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let mut config = fixture.store.load().unwrap();
            config
                .providers
                .get_mut(&ProviderId::Claude)
                .unwrap()
                .active_account_id = Some("acc_stale".into());

            let status = fixture
                .manager
                .status_with_config(ProviderId::Claude, &config)
                .await;

            assert_eq!(status.active_account_id, None);
            assert_eq!(status.external_identity, None);
            assert!(status.enrollment.is_empty());
        });
    }

    #[test]
    fn settings_commit_protects_actual_official_active_when_raw_active_is_stale() {
        tauri::async_runtime::block_on(async {
            for mutation in ["pause", "remove", "disable-provider"] {
                let fixture = Fixture::new();
                *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
                let (current, revision) = fixture.store.load_with_revision().unwrap();
                assert_eq!(current.provider(ProviderId::Codex).active_account_id, None);
                let mut proposed = current.clone();
                let settings = proposed.providers.get_mut(&ProviderId::Codex).unwrap();
                match mutation {
                    "pause" => settings.accounts[0].enabled = false,
                    "remove" => settings.accounts.clear(),
                    "disable-provider" => settings.enabled = false,
                    _ => unreachable!(),
                }

                let error = fixture
                    .manager
                    .save_settings_if_authorized(
                        &[ProviderId::Codex],
                        &proposed,
                        &revision,
                        &fixture.store,
                    )
                    .await
                    .unwrap_err();

                assert_eq!(error.code(), ProviderAccountCommandErrorCode::AccountActive);
                let unchanged = fixture.store.load().unwrap();
                let settings = unchanged.provider(ProviderId::Codex);
                assert!(settings.enabled);
                assert!(settings.accounts[0].enabled);
            }
        });
    }

    #[test]
    fn settings_commit_rejects_official_identity_change_between_checks() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            fixture.adapter.identity_results.lock().unwrap().extend([
                Ok(Some(identity(ProviderId::Codex, "target", None))),
                Ok(Some(identity(ProviderId::Codex, "external", None))),
            ]);
            let (current, revision) = fixture.store.load_with_revision().unwrap();
            let mut proposed = current.clone();
            proposed
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .label = Some("Renamed".into());

            let error = fixture
                .manager
                .save_settings_if_authorized(
                    &[ProviderId::Claude, ProviderId::Codex],
                    &proposed,
                    &revision,
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(error.provider(), Some(ProviderId::Codex));
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts[0]
                    .label,
                None
            );
        });
    }

    #[test]
    fn multi_provider_settings_commit_preserves_exact_codex_post_read_failure() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            fixture.adapter.identity_results.lock().unwrap().extend([
                Ok(Some(identity(ProviderId::Codex, "target", None))),
                Err(ProviderAccountCommandError::internal(
                    ProviderId::Codex,
                    None,
                )),
            ]);
            let (current, revision) = fixture.store.load_with_revision().unwrap();
            let mut proposed = current.clone();
            proposed
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .label = Some("Renamed".into());

            let error = fixture
                .manager
                .save_settings_if_authorized(
                    &[ProviderId::Claude, ProviderId::Codex],
                    &proposed,
                    &revision,
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::Internal);
            assert_eq!(error.provider(), Some(ProviderId::Codex));
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts[0]
                    .label,
                None
            );
        });
    }

    #[test]
    fn settings_commit_uses_the_callers_config_revision_cas() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            let (current, revision) = fixture.store.load_with_revision().unwrap();
            let mut proposed = current.clone();
            proposed
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .label = Some("Stale".into());
            let mut external = current;
            external
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .label = Some("External".into());
            fixture
                .store
                .save_if_revision(&external, &revision)
                .unwrap();

            let error = fixture
                .manager
                .save_settings_if_authorized(
                    &[ProviderId::Claude, ProviderId::Codex],
                    &proposed,
                    &revision,
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.provider(), None);
            let serialized = serde_json::to_value(&error).unwrap();
            assert!(serialized.get("providerId").is_none());
            assert!(serialized.get("provider").is_none());
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::Internal);
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts[0]
                    .label
                    .as_deref(),
                Some("External")
            );
        });
    }

    #[test]
    fn settings_commit_rechecks_recovery_after_provider_locks_are_held() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            let recovery_path = fixture.manager.recovery_path(ProviderId::Codex);
            fs::create_dir_all(recovery_path.parent().unwrap()).unwrap();
            fs::write(&recovery_path, b"pending-recovery").unwrap();
            let (current, revision) = fixture.store.load_with_revision().unwrap();

            let error = fixture
                .manager
                .save_settings_if_authorized(
                    &[ProviderId::Codex],
                    &current,
                    &revision,
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired
            );
        });
    }

    #[test]
    fn settings_rollback_cas_failure_reports_external_write_and_preserves_external_config() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            fixture.adapter.identity_results.lock().unwrap().extend([
                Ok(Some(identity(ProviderId::Codex, "target", None))),
                Ok(Some(identity(ProviderId::Codex, "external", None))),
            ]);
            let (current, revision) = fixture.store.load_with_revision().unwrap();
            let mut proposed = current.clone();
            proposed
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .label = Some("Proposed".into());
            let config_path = fixture.store.path().to_path_buf();
            *fixture.adapter.before_identity_on_call.lock().unwrap() = Some((
                2,
                Box::new(move || {
                    let mut external =
                        serde_json::from_slice::<AppConfig>(&fs::read(&config_path).unwrap())
                            .unwrap();
                    external
                        .providers
                        .get_mut(&ProviderId::Codex)
                        .unwrap()
                        .accounts[0]
                        .label = Some("External".into());
                    fs::write(&config_path, serde_json::to_vec_pretty(&external).unwrap()).unwrap();
                }),
            ));

            let error = fixture
                .manager
                .save_settings_if_authorized(
                    &[ProviderId::Codex],
                    &proposed,
                    &revision,
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(error.provider(), None);
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts[0]
                    .label
                    .as_deref(),
                Some("External")
            );
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn settings_skip_official_identity_reads_when_activation_is_currently_unsupported() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.support_override.lock().unwrap() = Some(ActivationSupport {
                kind: ActivationTargetKind::Unsupported,
                target_description: None,
                blocked_reason: Some("Fixture mode does not expose a verified target.".into()),
            });
            fixture.adapter.fail_identity.store(true, Ordering::Release);
            let (current, revision) = fixture.store.load_with_revision().unwrap();
            let mut proposed = current.clone();
            proposed
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .label = Some("Renamed".into());

            fixture
                .manager
                .save_settings_if_authorized(
                    &[ProviderId::Codex],
                    &proposed,
                    &revision,
                    &fixture.store,
                )
                .await
                .unwrap();

            assert_eq!(
                fixture
                    .adapter
                    .current_identity_calls
                    .load(Ordering::Acquire),
                0
            );
        });
    }

    #[test]
    fn settings_commit_persists_the_verified_official_active_account() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            let (current, revision) = fixture.store.load_with_revision().unwrap();
            assert_eq!(current.provider(ProviderId::Codex).active_account_id, None);
            let mut proposed = current;
            proposed
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .label = Some("Renamed".into());

            fixture
                .manager
                .save_settings_if_authorized(
                    &[ProviderId::Codex],
                    &proposed,
                    &revision,
                    &fixture.store,
                )
                .await
                .unwrap();

            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .active_account_id
                    .as_deref(),
                Some("acc_target")
            );
        });
    }

    #[test]
    fn session_ids_are_safe_and_adversarial_values_are_rejected() {
        assert!(is_safe_session_id("login_0000000000000001"));
        assert!(!is_safe_session_id("../secret"));
        assert!(!is_safe_session_id("login_token-value"));
    }

    #[test]
    fn login_cancellation_is_bounded_and_isolated_by_opaque_session_id() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let (codex_id, codex_cancelled) = fixture
                .manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let duplicate = fixture
                .manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap_err();
            assert_eq!(
                duplicate.code(),
                ProviderAccountCommandErrorCode::OperationInProgress
            );
            let before = fixture
                .adapter
                .current_identity_calls
                .load(Ordering::Acquire);
            let status = fixture
                .manager
                .status(ProviderId::Codex, &fixture.store)
                .await;
            assert!(status.operation_in_progress);
            assert_eq!(status.external_identity, None);
            assert_eq!(
                fixture
                    .adapter
                    .current_identity_calls
                    .load(Ordering::Acquire),
                before
            );
            let activation = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                activation.code(),
                ProviderAccountCommandErrorCode::OperationInProgress
            );
            let (claude_id, claude_cancelled) = fixture
                .manager
                .begin_login_session(ProviderId::Claude)
                .await
                .unwrap();
            assert!(fixture.manager.cancel_login_session(&codex_id).await);
            assert!(codex_cancelled.load(Ordering::Acquire));
            assert!(!claude_cancelled.load(Ordering::Acquire));
            assert!(!fixture.manager.cancel_login_session("../unsafe").await);
            let activation = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                activation.code(),
                ProviderAccountCommandErrorCode::OperationInProgress
            );
            let import = fixture
                .manager
                .import_bundle(
                    ProviderId::Codex,
                    None,
                    None,
                    identity(ProviderId::Codex, "cancelled-import", None),
                    bundle("cancelled-import"),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                import.code(),
                ProviderAccountCommandErrorCode::OperationInProgress
            );
            let history = HistoryStore::at(fixture.temp.path().join("history"));
            let delete = fixture
                .manager
                .delete(ProviderId::Codex, "acc_target", &fixture.store, &history)
                .await
                .unwrap_err();
            assert_eq!(
                delete.code(),
                ProviderAccountCommandErrorCode::OperationInProgress
            );
            assert!(
                fixture
                    .manager
                    .status(ProviderId::Codex, &fixture.store)
                    .await
                    .operation_in_progress
            );
            assert!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Codex, &codex_id)
                    .await
                    .is_some()
            );
            assert!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Claude, &claude_id)
                    .await
                    .is_some()
            );
            fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap();
            assert!(
                !fixture
                    .manager
                    .status(ProviderId::Claude, &fixture.store)
                    .await
                    .operation_in_progress
            );
        });
    }

    #[test]
    fn terminal_session_cleanup_is_owner_aware_and_returns_cancellation_state() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let (session_id, _) = fixture
                .manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            assert!(fixture.manager.cancel_login_session(&session_id).await);

            assert_eq!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Claude, &session_id)
                    .await,
                None
            );
            assert_eq!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Codex, &session_id)
                    .await,
                Some(true)
            );
            assert_eq!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Codex, &session_id)
                    .await,
                None
            );
        });
    }

    #[test]
    fn login_completion_requires_the_exact_provider_session_and_preserves_other_sessions() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let (codex_id, _) = fixture
                .manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let (claude_id, _) = fixture
                .manager
                .begin_login_session(ProviderId::Claude)
                .await
                .unwrap();

            let mismatch = fixture
                .manager
                .complete_login_import(
                    ProviderLoginImportRequest {
                        session_id: claude_id.clone(),
                        provider: ProviderId::Codex,
                        requested_account_id: None,
                        label: None,
                        identity: identity(ProviderId::Codex, "target", None),
                        credentials: bundle("target"),
                    },
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                mismatch.code(),
                ProviderAccountCommandErrorCode::OperationInProgress
            );

            let imported = fixture
                .manager
                .complete_login_import(
                    ProviderLoginImportRequest {
                        session_id: codex_id.clone(),
                        provider: ProviderId::Codex,
                        requested_account_id: None,
                        label: None,
                        identity: identity(ProviderId::Codex, "target", None),
                        credentials: bundle("target"),
                    },
                    &fixture.store,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(imported.account_id, "acc_target");
            assert!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Codex, &codex_id)
                    .await
                    .is_none()
            );
            assert!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Claude, &claude_id)
                    .await
                    .is_some()
            );
        });
    }

    #[test]
    fn cancelled_session_cannot_complete_an_import_and_does_not_claim_another_provider() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let original_account_ids = fixture
                .store
                .load()
                .unwrap()
                .provider(ProviderId::Codex)
                .accounts
                .iter()
                .map(|account| account.id.clone())
                .collect::<Vec<_>>();
            let (codex_id, _) = fixture
                .manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let (claude_id, _) = fixture
                .manager
                .begin_login_session(ProviderId::Claude)
                .await
                .unwrap();
            assert!(fixture.manager.cancel_login_session(&codex_id).await);

            let _ = fixture
                .manager
                .complete_login_import(
                    ProviderLoginImportRequest {
                        session_id: codex_id.clone(),
                        provider: ProviderId::Codex,
                        requested_account_id: None,
                        label: Some("Must not import".into()),
                        identity: identity(ProviderId::Codex, "cancelled", None),
                        credentials: bundle("cancelled"),
                    },
                    &fixture.store,
                )
                .await;

            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts
                    .iter()
                    .map(|account| account.id.clone())
                    .collect::<Vec<_>>(),
                original_account_ids
            );
            assert!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Codex, &codex_id)
                    .await
                    .is_none()
            );
            assert!(fixture.manager.cancel_login_session(&claude_id).await);
            assert!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Claude, &claude_id)
                    .await
                    .is_some()
            );
        });
    }

    #[test]
    fn account_login_reservation_validates_existence_under_the_provider_lock() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let (session_id, _, account_id) = fixture
                .manager
                .begin_login_session_for_account(
                    ProviderId::Codex,
                    Some("acc_target"),
                    &fixture.store,
                )
                .await
                .unwrap();
            assert_eq!(account_id.as_deref(), Some("acc_target"));

            let history = HistoryStore::at(fixture.temp.path().join("history"));
            let delete = fixture
                .manager
                .delete(ProviderId::Codex, "acc_target", &fixture.store, &history)
                .await
                .unwrap_err();
            assert_eq!(
                delete.code(),
                ProviderAccountCommandErrorCode::OperationInProgress
            );
            assert!(
                fixture
                    .manager
                    .finish_login_session(ProviderId::Codex, &session_id)
                    .await
                    .is_some()
            );
            fixture
                .manager
                .delete(ProviderId::Codex, "acc_target", &fixture.store, &history)
                .await
                .unwrap();

            let missing = fixture
                .manager
                .begin_login_session_for_account(
                    ProviderId::Codex,
                    Some("acc_target"),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                missing.code(),
                ProviderAccountCommandErrorCode::AccountNotFound
            );
            assert_eq!(missing.account_id(), None);
        });
    }

    #[test]
    fn expected_current_identity_mismatch_rejects_before_any_activation_write() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("actual-b"));
            let target_before = fixture.adapter.target.lock().unwrap().clone();
            let config_before = fs::read(fixture.store.path()).unwrap();

            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "expected-a", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(*fixture.adapter.target.lock().unwrap(), target_before);
            assert_eq!(fs::read(fixture.store.path()).unwrap(), config_before);
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn expected_missing_identity_rejects_an_actual_official_identity_without_writes() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let target_before = fixture.adapter.target.lock().unwrap().clone();
            let config_before = fs::read(fixture.store.path()).unwrap();

            let error = fixture
                .manager
                .activate(ProviderId::Codex, "acc_target", None, &fixture.store)
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(*fixture.adapter.target.lock().unwrap(), target_before);
            assert_eq!(fs::read(fixture.store.path()).unwrap(), config_before);
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn expected_identity_read_failure_is_internal_and_never_starts_recovery() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture.adapter.fail_identity.store(true, Ordering::Release);
            let target_before = fixture.adapter.target.lock().unwrap().clone();
            let config_before = fs::read(fixture.store.path()).unwrap();

            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::Internal);
            assert_eq!(*fixture.adapter.target.lock().unwrap(), target_before);
            assert_eq!(fs::read(fixture.store.path()).unwrap(), config_before);
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn matched_expected_identity_is_still_fenced_by_the_second_fingerprint() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .adapter
                .mutate_on_fingerprint_call
                .store(2, Ordering::Release);
            let config_before = fs::read(fixture.store.path()).unwrap();

            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(
                fixture.adapter.current_identity().unwrap().unwrap(),
                identity(ProviderId::Codex, "external", None)
            );
            assert_eq!(fs::read(fixture.store.path()).unwrap(), config_before);
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn activation_installs_official_credentials_and_persists_active_account() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let result = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap();
            assert_eq!(result.active_account_id, "acc_target");
            assert!(result.restart_hint.required);
            assert!(result.quota_refresh_required);
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .active_account_id
                    .as_deref(),
                Some("acc_target")
            );
            assert_eq!(
                fixture.adapter.current_identity().unwrap().unwrap(),
                identity(ProviderId::Codex, "target", None)
            );
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn external_write_after_install_wins_and_recovery_remains() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .adapter
                .race_after_install
                .store(true, Ordering::Release);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(
                fixture.adapter.current_identity().unwrap().unwrap(),
                identity(ProviderId::Codex, "external", None)
            );
            assert!(fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn second_fingerprint_race_aborts_without_overwriting_external_credentials() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .adapter
                .mutate_on_fingerprint_call
                .store(2, Ordering::Release);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(
                fixture.adapter.current_identity().unwrap().unwrap(),
                identity(ProviderId::Codex, "external", None)
            );
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn second_fingerprint_read_failure_clears_recovery_without_touching_target() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .adapter
                .fail_fingerprint_on_call
                .store(2, Ordering::Release);

            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::Internal);
            assert_eq!(
                fixture
                    .adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("original")
            );
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn install_failure_is_verified_rolled_back_and_clears_recovery() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture.adapter.fail_install.store(true, Ordering::Release);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::RolledBack);
            assert_eq!(
                fixture.adapter.current_identity().unwrap().unwrap(),
                identity(ProviderId::Codex, "original", None)
            );
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn conditional_install_preserves_external_login_after_second_fingerprint() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .adapter
                .external_during_install
                .store(true, Ordering::Release);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(
                fixture
                    .adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("external")
            );
            assert!(fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn install_that_writes_target_then_errors_is_conditionally_rolled_back() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .adapter
                .fail_install_after_write
                .store(true, Ordering::Release);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::RolledBack);
            assert_eq!(
                fixture
                    .adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("original")
            );
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn restore_failure_retains_recovery_and_blocks_only_provider() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture.adapter.fail_install.store(true, Ordering::Release);
            fixture.adapter.fail_restore.store(true, Ordering::Release);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired
            );
            assert!(fixture.manager.recovery_path(ProviderId::Codex).exists());
            assert_eq!(
                fixture
                    .manager
                    .status(ProviderId::Claude, &fixture.store)
                    .await
                    .recovery,
                ProviderRecoveryState::None
            );
        });
    }

    #[test]
    fn recovery_record_encrypts_the_complete_snapshot() {
        let fixture = Fixture::new();
        let record = RecoveryRecord {
            provider: ProviderId::Codex,
            snapshot: CredentialTargetSnapshot {
                credentials: Some(bundle("adversarial-secret")),
                fingerprint: Some("opaque".into()),
            },
            original_fingerprint: Some("opaque".into()),
            expected_target_fingerprint: Some("target-opaque".into()),
            previous_account_id: None,
            target_account_id: "acc_target".into(),
        };
        let bytes = fixture.manager.save_recovery(&record).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("adversarial-secret"));
        assert_eq!(
            fixture.manager.load_recovery(ProviderId::Codex).unwrap().0,
            record
        );
        let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            envelope
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["ciphertext", "version"]
        );
    }

    #[test]
    fn provider_locks_are_independent_and_same_provider_is_busy() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let codex = fixture.manager.lock(ProviderId::Codex);
            let _codex_guard = codex.lock().await;
            assert!(fixture.manager.lock(ProviderId::Claude).try_lock().is_ok());
            assert!(fixture.manager.lock(ProviderId::Codex).try_lock().is_err());
        });
    }

    #[test]
    fn email_only_never_deduplicates_imports() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let result = fixture
                .manager
                .import_bundle(
                    ProviderId::Codex,
                    None,
                    None,
                    identity(ProviderId::Codex, "different", Some("same@example.com")),
                    bundle("different"),
                    &fixture.store,
                )
                .await
                .unwrap();
            assert!(!result.updated_existing);
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts
                    .len(),
                2
            );
        });
    }

    #[test]
    fn reauthentication_rejects_a_different_stable_identity() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let error = fixture
                .manager
                .import_bundle(
                    ProviderId::Codex,
                    Some("acc_target"),
                    None,
                    identity(ProviderId::Codex, "different", Some("same@example.com")),
                    bundle("different"),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::IdentityMismatch
            );
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts
                    .len(),
                1
            );
        });
    }

    #[test]
    fn restart_counter_skips_metadata_collision_when_the_vault_is_missing() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let collision_id = "acc_0000000000000001";
            let mut config = fixture.store.load().unwrap();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: collision_id.into(),
                    identity: Some(identity(ProviderId::Codex, "collision", None)),
                    label: Some("keep-collision".into()),
                    api_key: Some("collision".into()),
                    ..ProviderAccount::default()
                });
            fixture.store.save(&config).unwrap();
            let collision_vault = fixture
                .manager
                .config_dir
                .join("accounts/codex")
                .join(format!("{collision_id}.vault"));
            fs::remove_file(&collision_vault).unwrap();
            fixture
                .manager
                .next_account_sequence
                .store(1, Ordering::Release);

            let result = fixture
                .manager
                .import_bundle(
                    ProviderId::Codex,
                    None,
                    None,
                    identity(ProviderId::Codex, "new-after-restart", None),
                    bundle("new-after-restart"),
                    &fixture.store,
                )
                .await
                .unwrap();

            assert_eq!(result.account_id, "acc_0000000000000002");
            let config = fixture.store.load().unwrap();
            let collision = config
                .provider(ProviderId::Codex)
                .accounts
                .into_iter()
                .find(|account| account.id == collision_id)
                .unwrap();
            assert_eq!(collision.label.as_deref(), Some("keep-collision"));
            assert!(collision.identity.as_ref().is_some_and(|known| {
                known.matches_stable(&identity(ProviderId::Codex, "collision", None))
            }));
            assert!(!collision_vault.exists());
        });
    }

    #[test]
    fn restart_counter_skips_an_orphan_vault_without_replacing_it() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let orphan_id = "acc_0000000000000001";
            let vault = ProviderCredentialVault::new(
                &fixture.manager.config_dir,
                fixture.manager.codec.as_ref(),
            );
            let orphan_path = vault
                .save(
                    ProviderId::Codex,
                    orphan_id,
                    &identity(ProviderId::Codex, "orphan", None),
                    &bundle("orphan"),
                )
                .unwrap();
            let orphan_bytes = fs::read(&orphan_path).unwrap();
            fixture
                .manager
                .next_account_sequence
                .store(1, Ordering::Release);

            let result = fixture
                .manager
                .import_bundle(
                    ProviderId::Codex,
                    None,
                    None,
                    identity(ProviderId::Codex, "new-after-orphan", None),
                    bundle("new-after-orphan"),
                    &fixture.store,
                )
                .await
                .unwrap();

            assert_eq!(result.account_id, "acc_0000000000000002");
            assert_eq!(fs::read(&orphan_path).unwrap(), orphan_bytes);
            assert!(
                vault
                    .load(ProviderId::Codex, orphan_id)
                    .unwrap()
                    .identity
                    .matches_stable(&identity(ProviderId::Codex, "orphan", None))
            );
        });
    }

    #[test]
    fn restart_counter_skips_metadata_collision_when_persistence_is_disabled() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let collision_id = "acc_0000000000000001";
            let mut config = fixture.store.load().unwrap();
            config.security.persist_credentials = false;
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: collision_id.into(),
                    identity: Some(identity(ProviderId::Codex, "disabled-collision", None)),
                    label: Some("keep-disabled".into()),
                    ..ProviderAccount::default()
                });
            fixture.store.save(&config).unwrap();
            fixture
                .manager
                .next_account_sequence
                .store(1, Ordering::Release);

            let result = fixture
                .manager
                .import_bundle(
                    ProviderId::Codex,
                    None,
                    None,
                    identity(ProviderId::Codex, "disabled-new", None),
                    bundle("disabled-new"),
                    &fixture.store,
                )
                .await
                .unwrap();

            assert_eq!(result.account_id, "acc_0000000000000002");
            let config = fixture.store.load().unwrap();
            assert!(
                config
                    .provider(ProviderId::Codex)
                    .accounts
                    .iter()
                    .any(|account| {
                        account.id == collision_id
                            && account.label.as_deref() == Some("keep-disabled")
                    })
            );
            assert!(
                !fixture
                    .manager
                    .config_dir
                    .join("accounts/codex/acc_0000000000000002.vault")
                    .exists()
            );
        });
    }

    #[test]
    fn active_account_cannot_be_paused_or_deleted() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap();
            let pause = fixture
                .manager
                .set_enabled(ProviderId::Codex, "acc_target", false, &fixture.store)
                .await
                .unwrap_err();
            assert_eq!(pause.code(), ProviderAccountCommandErrorCode::AccountActive);
            let history = HistoryStore::at(fixture.temp.path().join("history"));
            let delete = fixture
                .manager
                .delete(ProviderId::Codex, "acc_target", &fixture.store, &history)
                .await
                .unwrap_err();
            assert_eq!(
                delete.code(),
                ProviderAccountCommandErrorCode::AccountActive
            );
        });
    }

    #[test]
    fn official_current_identity_blocks_pause_and_delete_when_metadata_is_stale() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            assert!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .active_account_id
                    .is_none()
            );
            let pause = fixture
                .manager
                .set_enabled(ProviderId::Codex, "acc_target", false, &fixture.store)
                .await
                .unwrap_err();
            assert_eq!(pause.code(), ProviderAccountCommandErrorCode::AccountActive);
            let history = HistoryStore::at(fixture.temp.path().join("history"));
            let delete = fixture
                .manager
                .delete(ProviderId::Codex, "acc_target", &fixture.store, &history)
                .await
                .unwrap_err();
            assert_eq!(
                delete.code(),
                ProviderAccountCommandErrorCode::AccountActive
            );
        });
    }

    #[test]
    fn concurrent_provider_imports_merge_latest_config_without_lost_updates() {
        let fixture = Fixture::new();
        let manager = Arc::new(fixture.manager);
        let store = Arc::new(fixture.store);
        let handles = [
            (ProviderId::Codex, "codex-new"),
            (ProviderId::Claude, "claude-new"),
        ]
        .map(|(provider, key)| {
            let manager = Arc::clone(&manager);
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                tauri::async_runtime::block_on(async move {
                    manager
                        .import_bundle(
                            provider,
                            None,
                            None,
                            identity(provider, key, None),
                            bundle(key),
                            &store,
                        )
                        .await
                })
            })
        });
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        let config = store.load().unwrap();
        assert!(
            config
                .provider(ProviderId::Codex)
                .accounts
                .iter()
                .any(|account| account.identity.as_ref().is_some_and(
                    |id| id.matches_stable(&identity(ProviderId::Codex, "codex-new", None))
                ))
        );
        assert!(
            config
                .provider(ProviderId::Claude)
                .accounts
                .iter()
                .any(|account| account.identity.as_ref().is_some_and(
                    |id| id.matches_stable(&identity(ProviderId::Claude, "claude-new", None))
                ))
        );
    }

    #[test]
    fn separate_managers_reject_a_stale_config_save_without_losing_the_winner() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let manager_b = Arc::new(ProviderAccountManager::new(
                fixture.temp.path().to_path_buf(),
                Arc::new(XorCodec),
                registry_with(Arc::new(FakeAdapter::new(
                    ProviderId::Codex,
                    "other-manager",
                ))),
            ));
            let store_b = Arc::new(fixture.store.clone());
            *fixture.adapter.before_identity.lock().unwrap() = Some(Box::new(move || {
                let manager_b = Arc::clone(&manager_b);
                let store_b = Arc::clone(&store_b);
                std::thread::spawn(move || {
                    tauri::async_runtime::block_on(async move {
                        manager_b
                            .import_bundle(
                                ProviderId::Claude,
                                None,
                                Some("winner".into()),
                                identity(ProviderId::Claude, "winner", None),
                                bundle("winner"),
                                &store_b,
                            )
                            .await
                    })
                })
                .join()
                .unwrap()
                .unwrap();
            }));

            let error = fixture
                .manager
                .set_enabled(ProviderId::Codex, "acc_target", false, &fixture.store)
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::Internal);
            let config = fixture.store.load().unwrap();
            assert!(
                config
                    .provider(ProviderId::Codex)
                    .accounts
                    .iter()
                    .find(|account| account.id == "acc_target")
                    .unwrap()
                    .enabled
            );
            assert!(
                config
                    .provider(ProviderId::Claude)
                    .accounts
                    .iter()
                    .any(|account| {
                        account.identity.as_ref().is_some_and(|known| {
                            known.matches_stable(&identity(ProviderId::Claude, "winner", None))
                        })
                    })
            );
        });
    }

    #[test]
    fn activation_reloads_and_revalidates_config_after_waiting_to_persist() {
        tauri::async_runtime::block_on(async {
            let Fixture {
                temp: _temp,
                manager,
                store,
                adapter,
            } = Fixture::new();
            let manager = Arc::new(manager);
            let store = Arc::new(store);
            let config_guard = manager.config_commit.lock().await;
            let activation = {
                let manager = Arc::clone(&manager);
                let store = Arc::clone(&store);
                tauri::async_runtime::spawn(async move {
                    manager
                        .activate(
                            ProviderId::Codex,
                            "acc_target",
                            Some(identity(ProviderId::Codex, "original", None)),
                            &store,
                        )
                        .await
                })
            };
            while adapter
                .target
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|credentials| credentials.api_key.as_deref())
                != Some("target")
            {
                tokio::task::yield_now().await;
            }
            let mut external = store.load().unwrap();
            external
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts[0]
                .enabled = false;
            store.save(&external).unwrap();
            drop(config_guard);

            let error = activation.await.unwrap().unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::RolledBack);
            assert_eq!(
                adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("original")
            );
            assert!(!store.load().unwrap().provider(ProviderId::Codex).accounts[0].enabled);
        });
    }

    #[test]
    fn inactive_delete_removes_only_exact_metadata_and_vault() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let vault_path = fixture
                .manager
                .config_dir
                .join("accounts/codex/acc_target.vault");
            assert!(vault_path.exists());
            let history = HistoryStore::at(fixture.temp.path().join("history"));
            fixture
                .manager
                .delete(ProviderId::Codex, "acc_target", &fixture.store, &history)
                .await
                .unwrap();
            assert!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts
                    .is_empty()
            );
            assert!(!vault_path.exists());
        });
    }

    #[test]
    fn delete_config_conflict_restores_exact_vault_history_and_preserves_external_config() {
        tauri::async_runtime::block_on(async {
            let (
                temp,
                manager,
                store,
                history,
                codec,
                config_path,
                vault_path,
                original_vault,
                original_history,
            ) = delete_rollback_fixture(false);
            codec.armed.store(true, Ordering::SeqCst);

            let error = manager
                .delete(ProviderId::Codex, "acc_target", &store, &history)
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::Internal);
            assert_eq!(fs::read(config_path).unwrap(), b"external-config-update");
            assert_eq!(fs::read(vault_path).unwrap(), original_vault);
            assert_eq!(
                fs::read(temp.path().join("history/codex.jsonl")).unwrap(),
                original_history
            );
        });
    }

    #[test]
    fn delete_rollback_preserves_external_vault_and_reports_recovery_failed() {
        tauri::async_runtime::block_on(async {
            let (
                temp,
                manager,
                store,
                history,
                codec,
                _config_path,
                vault_path,
                _original_vault,
                original_history,
            ) = delete_rollback_fixture(true);
            codec.armed.store(true, Ordering::SeqCst);

            let error = manager
                .delete(ProviderId::Codex, "acc_target", &store, &history)
                .await
                .unwrap_err();

            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryFailed
            );
            assert_eq!(fs::read(vault_path).unwrap(), b"external-new-vault");
            assert_eq!(
                fs::read(temp.path().join("history/codex.jsonl")).unwrap(),
                original_history
            );
        });
    }

    #[test]
    fn delete_commit_conflicts_preserve_external_files_and_report_recovery_failed() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let config_path = temp.path().join("config.json");
            let vault_path = temp.path().join("accounts/codex/acc_target.vault");
            let history_root = temp.path().join("history");
            let history_path = history_root.join("codex.jsonl");
            let codec = Arc::new(DeleteCommitMutationCodec {
                external_vault_path: vault_path.clone(),
                external_history_path: history_path.clone(),
                armed: AtomicBool::new(false),
            });
            let store = ConfigStore::at_with_codec(config_path, codec.clone());
            let adapter = Arc::new(FakeAdapter::new(ProviderId::Codex, "original"));
            let manager = ProviderAccountManager::new(
                temp.path().to_path_buf(),
                codec.clone(),
                registry_with(adapter),
            );
            let mut config = AppConfig::default();
            for (id, key) in [("acc_target", "target"), ("acc_sibling", "sibling")] {
                config
                    .providers
                    .get_mut(&ProviderId::Codex)
                    .unwrap()
                    .accounts
                    .push(ProviderAccount {
                        id: id.into(),
                        identity: Some(identity(ProviderId::Codex, key, None)),
                        api_key: Some(key.into()),
                        ..ProviderAccount::default()
                    });
            }
            store.save(&config).unwrap();
            fs::create_dir_all(&history_root).unwrap();
            fs::write(
                &history_path,
                br#"{"timestamp":"2026-07-15T10:00:00Z","provider":"codex","accountId":"acc_target","windowId":"weekly","usedPercent":10.0,"resetsAt":null,"balance":null,"spend":null,"currency":null}
"#,
            )
            .unwrap();
            let history = HistoryStore::at(history_root);
            codec.armed.store(true, Ordering::SeqCst);

            let error = manager
                .delete(ProviderId::Codex, "acc_target", &store, &history)
                .await
                .unwrap_err();

            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryFailed
            );
            assert_eq!(fs::read(vault_path).unwrap(), b"external-commit-vault");
            assert_eq!(fs::read(history_path).unwrap(), b"external-commit-history");
        });
    }

    #[test]
    fn corrupt_wrong_provider_and_unsafe_recovery_records_are_rejected() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let codex_path = fixture.manager.recovery_path(ProviderId::Codex);
            fs::create_dir_all(codex_path.parent().unwrap()).unwrap();
            fs::write(&codex_path, b"adversarial-secret-not-an-envelope").unwrap();
            assert_eq!(
                fixture
                    .manager
                    .status(ProviderId::Codex, &fixture.store)
                    .await
                    .recovery,
                ProviderRecoveryState::Corrupt
            );
            fs::remove_file(&codex_path).unwrap();
            let record = RecoveryRecord {
                provider: ProviderId::Codex,
                snapshot: CredentialTargetSnapshot {
                    credentials: Some(bundle("original")),
                    fingerprint: fingerprint(Some(&bundle("original"))),
                },
                original_fingerprint: fingerprint(Some(&bundle("original"))),
                expected_target_fingerprint: fingerprint(Some(&bundle("target"))),
                previous_account_id: None,
                target_account_id: "acc_target".into(),
            };
            let bytes = fixture.manager.save_recovery(&record).unwrap();
            let claude_path = fixture.manager.recovery_path(ProviderId::Claude);
            fs::create_dir_all(claude_path.parent().unwrap()).unwrap();
            fs::write(&claude_path, bytes).unwrap();
            assert!(fixture.manager.load_recovery(ProviderId::Claude).is_err());

            let invalid_records = [
                RecoveryRecord {
                    provider: ProviderId::Codex,
                    snapshot: CredentialTargetSnapshot {
                        credentials: Some(bundle("original")),
                        fingerprint: fingerprint(Some(&bundle("original"))),
                    },
                    original_fingerprint: fingerprint(Some(&bundle("original"))),
                    expected_target_fingerprint: fingerprint(Some(&bundle("target"))),
                    previous_account_id: Some("../unsafe".into()),
                    target_account_id: "acc_target".into(),
                },
                RecoveryRecord {
                    provider: ProviderId::Codex,
                    snapshot: CredentialTargetSnapshot {
                        credentials: Some(bundle("original")),
                        fingerprint: fingerprint(Some(&bundle("different"))),
                    },
                    original_fingerprint: fingerprint(Some(&bundle("original"))),
                    expected_target_fingerprint: fingerprint(Some(&bundle("target"))),
                    previous_account_id: None,
                    target_account_id: "acc_target".into(),
                },
            ];
            for invalid in invalid_records {
                let plaintext = serde_json::to_vec(&invalid).unwrap();
                let ciphertext = fixture.manager.codec.protect(&plaintext).unwrap();
                let bytes = serde_json::to_vec(&RecoveryEnvelope {
                    version: RECOVERY_VERSION,
                    ciphertext,
                })
                .unwrap();
                fs::write(&codex_path, bytes).unwrap();
                assert_eq!(
                    fixture
                        .manager
                        .load_recovery(ProviderId::Codex)
                        .unwrap_err()
                        .code(),
                    ProviderAccountCommandErrorCode::RecoveryRequired
                );
            }
        });
    }

    #[test]
    fn keep_current_unknown_identity_marks_external_without_importing() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let record = RecoveryRecord {
                provider: ProviderId::Codex,
                snapshot: CredentialTargetSnapshot {
                    credentials: Some(bundle("original")),
                    fingerprint: fingerprint(Some(&bundle("original"))),
                },
                original_fingerprint: fingerprint(Some(&bundle("original"))),
                expected_target_fingerprint: fingerprint(Some(&bundle("target"))),
                previous_account_id: None,
                target_account_id: "acc_target".into(),
            };
            fixture.manager.save_recovery(&record).unwrap();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("unknown"));
            fixture
                .manager
                .recover(
                    ProviderId::Codex,
                    RecoveryAction::KeepCurrent,
                    &fixture.store,
                )
                .await
                .unwrap();
            let config = fixture.store.load().unwrap();
            assert!(
                config
                    .provider(ProviderId::Codex)
                    .active_account_id
                    .is_none()
            );
            assert_eq!(config.provider(ProviderId::Codex).accounts.len(), 1);
            assert_eq!(
                fixture
                    .manager
                    .status(ProviderId::Codex, &fixture.store)
                    .await
                    .external_identity,
                Some(identity(ProviderId::Codex, "unknown", None))
            );
        });
    }

    #[test]
    fn reconcile_matches_only_stable_provider_identity() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("target"));
            assert_eq!(
                fixture
                    .manager
                    .reconcile(ProviderId::Codex, &fixture.store)
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .active_account_id
                    .as_deref(),
                Some("acc_target")
            );
            *fixture.adapter.target.lock().unwrap() = Some(bundle("unknown"));
            assert_eq!(
                fixture
                    .manager
                    .reconcile(ProviderId::Codex, &fixture.store)
                    .await
                    .unwrap(),
                Some(identity(ProviderId::Codex, "unknown", None))
            );
            assert!(
                fixture
                    .store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .active_account_id
                    .is_none()
            );
        });
    }

    #[test]
    fn restore_original_rejects_same_identity_with_a_new_external_fingerprint() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let record = RecoveryRecord {
                provider: ProviderId::Codex,
                snapshot: CredentialTargetSnapshot {
                    credentials: Some(bundle("original")),
                    fingerprint: fingerprint(Some(&bundle("original"))),
                },
                original_fingerprint: fingerprint(Some(&bundle("original"))),
                expected_target_fingerprint: fingerprint(Some(&bundle("target"))),
                previous_account_id: None,
                target_account_id: "acc_target".into(),
            };
            fixture.manager.save_recovery(&record).unwrap();
            *fixture.adapter.target.lock().unwrap() = Some(bundle("refreshed-token"));
            *fixture.adapter.identity_override.lock().unwrap() =
                Some(identity(ProviderId::Codex, "target", None));

            let error = fixture
                .manager
                .recover(
                    ProviderId::Codex,
                    RecoveryAction::RestoreOriginal,
                    &fixture.store,
                )
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(
                fixture
                    .adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("refreshed-token")
            );
            assert!(fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn restore_original_rechecks_fingerprint_after_config_persistence() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let adapter = Arc::new(FakeAdapter::new(ProviderId::Codex, "target"));
            let codec = Arc::new(MutateTargetOnProtect {
                adapter: Arc::clone(&adapter),
                armed: AtomicBool::new(false),
            });
            let store = ConfigStore::at_with_codec(temp.path().join("config.json"), codec.clone());
            let manager = ProviderAccountManager::new(
                temp.path().to_path_buf(),
                codec.clone(),
                registry_with(Arc::clone(&adapter)),
            );
            let mut config = AppConfig::default();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: "acc_target".into(),
                    identity: Some(identity(ProviderId::Codex, "target", None)),
                    api_key: Some("target".into()),
                    ..ProviderAccount::default()
                });
            store.save(&config).unwrap();
            manager
                .save_recovery(&RecoveryRecord {
                    provider: ProviderId::Codex,
                    snapshot: CredentialTargetSnapshot {
                        credentials: Some(bundle("original")),
                        fingerprint: fingerprint(Some(&bundle("original"))),
                    },
                    original_fingerprint: fingerprint(Some(&bundle("original"))),
                    expected_target_fingerprint: fingerprint(Some(&bundle("target"))),
                    previous_account_id: None,
                    target_account_id: "acc_target".into(),
                })
                .unwrap();
            codec.armed.store(true, Ordering::Release);

            let error = manager
                .recover(ProviderId::Codex, RecoveryAction::RestoreOriginal, &store)
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(
                adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("external")
            );
            assert!(manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn keep_current_rechecks_fingerprint_after_config_persistence() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let adapter = Arc::new(FakeAdapter::new(ProviderId::Codex, "target"));
            let codec = Arc::new(MutateTargetOnProtect {
                adapter: Arc::clone(&adapter),
                armed: AtomicBool::new(false),
            });
            let store = ConfigStore::at_with_codec(temp.path().join("config.json"), codec.clone());
            let manager = ProviderAccountManager::new(
                temp.path().to_path_buf(),
                codec.clone(),
                registry_with(Arc::clone(&adapter)),
            );
            let mut config = AppConfig::default();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: "acc_target".into(),
                    identity: Some(identity(ProviderId::Codex, "target", None)),
                    api_key: Some("target".into()),
                    ..ProviderAccount::default()
                });
            store.save(&config).unwrap();
            manager
                .save_recovery(&RecoveryRecord {
                    provider: ProviderId::Codex,
                    snapshot: CredentialTargetSnapshot {
                        credentials: Some(bundle("original")),
                        fingerprint: fingerprint(Some(&bundle("original"))),
                    },
                    original_fingerprint: fingerprint(Some(&bundle("original"))),
                    expected_target_fingerprint: fingerprint(Some(&bundle("target"))),
                    previous_account_id: None,
                    target_account_id: "acc_target".into(),
                })
                .unwrap();
            codec.armed.store(true, Ordering::Release);

            let error = manager
                .recover(ProviderId::Codex, RecoveryAction::KeepCurrent, &store)
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert!(manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn reconcile_rechecks_fingerprint_after_config_persistence() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let adapter = Arc::new(FakeAdapter::new(ProviderId::Codex, "target"));
            let codec = Arc::new(MutateTargetOnProtect {
                adapter: Arc::clone(&adapter),
                armed: AtomicBool::new(false),
            });
            let store = ConfigStore::at_with_codec(temp.path().join("config.json"), codec.clone());
            let manager = ProviderAccountManager::new(
                temp.path().to_path_buf(),
                codec.clone(),
                registry_with(Arc::clone(&adapter)),
            );
            let mut config = AppConfig::default();
            config
                .providers
                .get_mut(&ProviderId::Codex)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: "acc_target".into(),
                    identity: Some(identity(ProviderId::Codex, "target", None)),
                    api_key: Some("target".into()),
                    ..ProviderAccount::default()
                });
            store.save(&config).unwrap();
            codec.armed.store(true, Ordering::Release);

            let error = manager
                .reconcile(ProviderId::Codex, &store)
                .await
                .unwrap_err();

            assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
            assert_eq!(
                adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("external")
            );
        });
    }

    #[test]
    fn post_install_fingerprint_read_failure_requires_recovery() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture
                .adapter
                .fail_fingerprint_on_call
                .store(3, Ordering::Release);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired
            );
            assert!(fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn post_install_identity_read_failure_rolls_back_owned_target() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            fixture.adapter.identity_results.lock().unwrap().extend([
                Ok(Some(identity(ProviderId::Codex, "original", None))),
                Err(ProviderAccountCommandError::internal(
                    ProviderId::Codex,
                    None,
                )),
            ]);
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "original", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::RolledBack);
            assert_eq!(
                fixture
                    .adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("original")
            );
            assert!(!fixture.manager.recovery_path(ProviderId::Codex).exists());
        });
    }

    #[test]
    fn post_install_identity_mismatch_rolls_back_owned_target() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            *fixture.adapter.identity_override.lock().unwrap() =
                Some(identity(ProviderId::Codex, "wrong", None));
            let error = fixture
                .manager
                .activate(
                    ProviderId::Codex,
                    "acc_target",
                    Some(identity(ProviderId::Codex, "wrong", None)),
                    &fixture.store,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ProviderAccountCommandErrorCode::RolledBack);
            assert_eq!(
                fixture
                    .adapter
                    .target
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .api_key
                    .as_deref(),
                Some("original")
            );
        });
    }

    #[test]
    fn status_does_not_read_identity_while_provider_operation_is_in_progress() {
        tauri::async_runtime::block_on(async {
            let fixture = Fixture::new();
            let lock = fixture.manager.lock(ProviderId::Codex);
            let _guard = lock.lock().await;
            let before = fixture
                .adapter
                .current_identity_calls
                .load(Ordering::Acquire);
            let status = fixture
                .manager
                .status(ProviderId::Codex, &fixture.store)
                .await;
            assert!(status.operation_in_progress);
            assert_eq!(status.external_identity, None);
            assert_eq!(
                fixture
                    .adapter
                    .current_identity_calls
                    .load(Ordering::Acquire),
                before
            );
        });
    }
}
