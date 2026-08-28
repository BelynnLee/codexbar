// This compatibility module remains temporarily for legacy on-disk migration. Most of its former
// runtime command surface is intentionally unreachable while existing installations transition to
// the generic provider-account manager.
#![allow(dead_code)]

use codexbar_engine::{
    AppConfig, ConfigStore, HistoryStore, ProviderAccount, ProviderId, atomic_write,
    auth::{
        credentials::CodexCredentials,
        dpapi::{DecodedSecret, DpapiCodec, SecretCodec, decode_secret, encode_secret},
        profile_vault::{
            CodexCredentialStoreMode, CodexProfileIdentity, CodexProfileVault, ProfileVaultError,
            managed_codex_legacy_path, parse_codex_credential_store_mode,
        },
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{Mutex, oneshot};

const RECOVERY_FILE: &str = "default-auth-recovery.vault";
static NEXT_LOGIN_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ManagedCredentialState {
    Available,
    Missing,
    Invalid,
    Undecryptable,
    MigrationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CodexRecoveryState {
    None,
    Required,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexProfileStatusView {
    pub credential_store_mode: CodexCredentialStoreMode,
    pub active_profile_id: Option<String>,
    pub external_identity: Option<CodexProfileIdentity>,
    pub switching_available: bool,
    pub switching_blocked_reason: Option<String>,
    pub recovery_state: CodexRecoveryState,
    pub switching: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CodexProfileErrorCode {
    StorageUnsupported,
    ProfileNotFound,
    ProfileActive,
    ProfileDisabled,
    InvalidCredential,
    IdentityMismatch,
    ExternalWrite,
    RolledBack,
    RecoveryRequired,
    RecoveryFailed,
    LoginFailed,
    OperationInProgress,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexProfileCommandError {
    pub code: CodexProfileErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
}

impl std::fmt::Display for CodexProfileCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CodexProfileCommandError {}

impl CodexProfileCommandError {
    fn new(code: CodexProfileErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            profile_id: None,
        }
    }

    fn for_profile(mut self, profile_id: impl Into<String>) -> Self {
        self.profile_id = Some(profile_id.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileActivation {
    pub previous_profile_id: Option<String>,
    pub active_profile_id: String,
    pub restart_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryAction {
    RestoreOriginal,
    KeepCurrent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryRecord {
    original_auth: Option<Vec<u8>>,
    original_fingerprint: String,
    previous_profile_id: Option<String>,
}

#[derive(Debug)]
pub struct CodexProfileManager {
    codec: Arc<dyn SecretCodec>,
    codex_home_override: Option<PathBuf>,
    switch_lock: Mutex<()>,
    login_cancellations: Mutex<HashMap<String, oneshot::Sender<()>>>,
}

impl Default for CodexProfileManager {
    fn default() -> Self {
        Self::new(Arc::new(DpapiCodec), None)
    }
}

impl CodexProfileManager {
    pub fn new(codec: Arc<dyn SecretCodec>, codex_home_override: Option<PathBuf>) -> Self {
        Self {
            codec,
            codex_home_override,
            switch_lock: Mutex::new(()),
            login_cancellations: Mutex::new(HashMap::new()),
        }
    }

    fn config_dir(config_store: &ConfigStore) -> Result<&Path, CodexProfileCommandError> {
        config_store.path().parent().ok_or_else(|| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::Internal,
                "Could not resolve the CodexBar config directory.",
            )
        })
    }

    fn codex_home(&self) -> Result<PathBuf, CodexProfileCommandError> {
        if let Some(path) = &self.codex_home_override {
            return Ok(path.clone());
        }
        CodexCredentials::default_path()
            .map_err(|_| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::Internal,
                    "Could not resolve CODEX_HOME.",
                )
            })?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::Internal,
                    "Could not resolve CODEX_HOME.",
                )
            })
    }

    fn default_auth_path(&self) -> Result<PathBuf, CodexProfileCommandError> {
        Ok(self.codex_home()?.join("auth.json"))
    }

    pub fn credential_store_mode(&self) -> CodexCredentialStoreMode {
        let Ok(home) = self.codex_home() else {
            return CodexCredentialStoreMode::Invalid;
        };
        match fs::read_to_string(home.join("config.toml")) {
            Ok(contents) => parse_codex_credential_store_mode(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                CodexCredentialStoreMode::Unset
            }
            Err(_) => CodexCredentialStoreMode::Invalid,
        }
    }

    fn require_file_store(&self) -> Result<(), CodexProfileCommandError> {
        let mode = self.credential_store_mode();
        if mode.is_switchable() {
            return Ok(());
        }
        Err(CodexProfileCommandError::new(
            CodexProfileErrorCode::StorageUnsupported,
            format!(
                "Codex Profile switching requires cli_auth_credentials_store = \"file\"; current mode is {mode:?}."
            ),
        ))
    }

    fn vault<'a>(
        &'a self,
        config_store: &'a ConfigStore,
    ) -> Result<CodexProfileVault<'a>, CodexProfileCommandError> {
        Ok(CodexProfileVault::new(
            Self::config_dir(config_store)?,
            self.codec.as_ref(),
        ))
    }

    fn recovery_path(config_store: &ConfigStore) -> Result<PathBuf, CodexProfileCommandError> {
        Ok(Self::config_dir(config_store)?
            .join("accounts")
            .join("codex")
            .join(RECOVERY_FILE))
    }

    pub fn migrate_legacy_profiles(
        &self,
        config_store: &ConfigStore,
    ) -> HashMap<String, ManagedCredentialState> {
        let Ok(_guard) = self.switch_lock.try_lock() else {
            return HashMap::new();
        };
        let Ok(config) = config_store.load() else {
            return HashMap::new();
        };
        let Ok(vault) = self.vault(config_store) else {
            return HashMap::new();
        };
        config
            .provider(ProviderId::Codex)
            .accounts
            .iter()
            .filter_map(|account| match vault.migrate_legacy(&account.id) {
                Ok(_) => None,
                Err(_) => Some((account.id.clone(), ManagedCredentialState::MigrationFailed)),
            })
            .collect()
    }

    pub fn credential_state(
        &self,
        config_store: &ConfigStore,
        profile_id: &str,
    ) -> ManagedCredentialState {
        let Ok(vault) = self.vault(config_store) else {
            return ManagedCredentialState::Invalid;
        };
        let legacy_exists = managed_codex_legacy_path(
            Self::config_dir(config_store).unwrap_or_else(|_| Path::new("")),
            profile_id,
        )
        .is_ok_and(|path| path.exists());
        match vault.load(profile_id) {
            Ok(_) => ManagedCredentialState::Available,
            Err(ProfileVaultError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                if legacy_exists {
                    ManagedCredentialState::MigrationFailed
                } else {
                    ManagedCredentialState::Missing
                }
            }
            Err(_) if legacy_exists => ManagedCredentialState::MigrationFailed,
            Err(ProfileVaultError::Secret(_)) => ManagedCredentialState::Undecryptable,
            Err(_) => ManagedCredentialState::Invalid,
        }
    }

    pub fn profile_identity(
        &self,
        config_store: &ConfigStore,
        profile_id: &str,
    ) -> Option<CodexProfileIdentity> {
        self.vault(config_store)
            .ok()?
            .load(profile_id)
            .ok()
            .map(|profile| profile.identity)
    }

    pub fn synchronize_default_auth(
        &self,
        config_store: &ConfigStore,
    ) -> Result<Option<CodexProfileIdentity>, CodexProfileCommandError> {
        let _guard = self.try_operation_lock()?;
        if Self::recovery_path(config_store)?.exists() {
            return Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::RecoveryRequired,
                "A previous Codex credential switch must be recovered first.",
            ));
        }
        self.synchronize_default_auth_unlocked(config_store)
    }

    fn synchronize_default_auth_unlocked(
        &self,
        config_store: &ConfigStore,
    ) -> Result<Option<CodexProfileIdentity>, CodexProfileCommandError> {
        let default_path = self.default_auth_path()?;
        let default = match fs::read(default_path) {
            Ok(bytes) => Some(CodexProfileIdentity::from_auth_json(&bytes).map_err(|_| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::InvalidCredential,
                    "The default Codex auth.json is invalid.",
                )
            })?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => {
                return Err(CodexProfileCommandError::new(
                    CodexProfileErrorCode::InvalidCredential,
                    "The default Codex auth.json could not be read.",
                ));
            }
        };
        let mut config = config_store.load().map_err(internal_config_error)?;
        let settings = config.providers.entry(ProviderId::Codex).or_default();
        let matched = default.as_ref().and_then(|identity| {
            let vault = self.vault(config_store).ok()?;
            settings.accounts.iter().find_map(|account| {
                vault
                    .load(&account.id)
                    .ok()
                    .filter(|loaded| loaded.identity.matches(identity))
                    .map(|_| account.id.clone())
            })
        });
        if settings.active_account_id != matched {
            settings.active_account_id = matched.clone();
            config_store.save(&config).map_err(internal_config_error)?;
        }
        Ok(default.filter(|_| matched.is_none()))
    }

    pub fn status(
        &self,
        config_store: &ConfigStore,
    ) -> Result<CodexProfileStatusView, CodexProfileCommandError> {
        let config = config_store.load().map_err(internal_config_error)?;
        let mode = self.credential_store_mode();
        let recovery_state = if Self::recovery_path(config_store)?.exists() {
            CodexRecoveryState::Required
        } else {
            CodexRecoveryState::None
        };
        let external_identity = self.external_identity(config_store, &config)?;
        let switching_blocked_reason = if recovery_state == CodexRecoveryState::Required {
            Some(
                "A previous switch must be recovered before another Profile can be activated."
                    .into(),
            )
        } else if !mode.is_switchable() {
            Some("Set cli_auth_credentials_store = \"file\" in Codex config.toml to enable switching.".into())
        } else {
            None
        };
        Ok(CodexProfileStatusView {
            credential_store_mode: mode,
            active_profile_id: config.provider(ProviderId::Codex).active_account_id.clone(),
            external_identity,
            switching_available: switching_blocked_reason.is_none(),
            switching_blocked_reason,
            recovery_state,
            switching: self.switch_lock.try_lock().is_err(),
        })
    }

    fn external_identity(
        &self,
        config_store: &ConfigStore,
        config: &AppConfig,
    ) -> Result<Option<CodexProfileIdentity>, CodexProfileCommandError> {
        let bytes = match fs::read(self.default_auth_path()?) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Ok(None),
        };
        let identity = match CodexProfileIdentity::from_auth_json(&bytes) {
            Ok(identity) => identity,
            Err(_) => return Ok(None),
        };
        let vault = self.vault(config_store)?;
        let known = config
            .provider(ProviderId::Codex)
            .accounts
            .iter()
            .any(|account| {
                vault
                    .load(&account.id)
                    .is_ok_and(|profile| profile.identity.matches(&identity))
            });
        Ok((!known).then_some(identity))
    }

    pub fn import_current(
        &self,
        config_store: &ConfigStore,
        label: Option<String>,
    ) -> Result<String, CodexProfileCommandError> {
        self.require_file_store()?;
        let auth_json = fs::read(self.default_auth_path()?).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::InvalidCredential,
                "Could not read the current Codex auth.json. Run codex login first.",
            )
        })?;
        self.import_auth_data(config_store, None, label, &auth_json)
    }

    pub fn import_auth_data(
        &self,
        config_store: &ConfigStore,
        requested_profile_id: Option<&str>,
        label: Option<String>,
        auth_json: &[u8],
    ) -> Result<String, CodexProfileCommandError> {
        let _guard = self.try_operation_lock()?;
        let identity = CodexProfileIdentity::from_auth_json(auth_json).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::InvalidCredential,
                "Codex login did not produce a valid OAuth identity.",
            )
        })?;
        let vault = self.vault(config_store)?;
        let mut config = config_store.load().map_err(internal_config_error)?;
        let settings = config.providers.entry(ProviderId::Codex).or_default();
        let label = clean_label(label);
        let mut created = false;

        let profile_id = if let Some(requested) = requested_profile_id {
            let account = settings
                .accounts
                .iter_mut()
                .find(|account| account.id == requested)
                .ok_or_else(|| {
                    CodexProfileCommandError::new(
                        CodexProfileErrorCode::ProfileNotFound,
                        "The Codex Profile no longer exists.",
                    )
                    .for_profile(requested)
                })?;
            let existing = vault.load(requested).map_err(|_| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::InvalidCredential,
                    "The existing Codex Profile credential is unavailable.",
                )
                .for_profile(requested)
            })?;
            if !existing.identity.matches(&identity) {
                return Err(CodexProfileCommandError::new(
                    CodexProfileErrorCode::IdentityMismatch,
                    "The login belongs to another account. Add it as a new Profile instead.",
                )
                .for_profile(requested));
            }
            if let Some(label) = label.clone() {
                account.label = Some(label);
            }
            account.enabled = true;
            requested.to_owned()
        } else if let Some(existing) = settings.accounts.iter_mut().find(|account| {
            vault
                .load(&account.id)
                .is_ok_and(|loaded| loaded.identity.matches(&identity))
        }) {
            if let Some(label) = label.clone() {
                existing.label = Some(label);
            }
            existing.enabled = true;
            existing.id.clone()
        } else {
            created = true;
            let mut account = ProviderAccount::default();
            account.id = next_profile_id(&settings.accounts);
            account.label = label
                .clone()
                .or_else(|| identity.email.clone())
                .or_else(|| Some("Codex Profile".into()));
            let profile_id = account.id.clone();
            settings.accounts.push(account);
            settings.enabled = true;
            profile_id
        };

        vault.save(&profile_id, auth_json).map_err(vault_error)?;
        let settings = config.providers.entry(ProviderId::Codex).or_default();
        settings.enabled = true;
        if fs::read(self.default_auth_path()?)
            .ok()
            .and_then(|bytes| CodexProfileIdentity::from_auth_json(&bytes).ok())
            .is_some_and(|current| current.matches(&identity))
        {
            settings.active_account_id = Some(profile_id.clone());
        }
        if let Err(error) = config_store.save(&config) {
            if created {
                let _ = vault.delete(&profile_id);
            }
            return Err(internal_config_error(error));
        }
        Ok(profile_id)
    }

    pub async fn activate(
        &self,
        config_store: &ConfigStore,
        profile_id: &str,
    ) -> Result<ProfileActivation, CodexProfileCommandError> {
        self.activate_with_hooks(config_store, profile_id, || {}, || {})
            .await
    }

    async fn activate_with_hooks(
        &self,
        config_store: &ConfigStore,
        profile_id: &str,
        before_fingerprint_recheck: impl FnOnce(),
        after_replace: impl FnOnce(),
    ) -> Result<ProfileActivation, CodexProfileCommandError> {
        let _guard = self.switch_lock.lock().await;
        self.require_file_store()?;
        let recovery_path = Self::recovery_path(config_store)?;
        if recovery_path.exists() {
            return Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::RecoveryRequired,
                "Recover the previous Codex credential transaction before switching again.",
            ));
        }
        let mut config = config_store.load().map_err(internal_config_error)?;
        let settings = config.providers.entry(ProviderId::Codex).or_default();
        let target = settings
            .accounts
            .iter()
            .find(|account| account.id == profile_id)
            .ok_or_else(|| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::ProfileNotFound,
                    "The selected Codex Profile no longer exists.",
                )
                .for_profile(profile_id)
            })?;
        if !target.enabled {
            return Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::ProfileDisabled,
                "Resume monitoring for this Profile before activating it.",
            )
            .for_profile(profile_id));
        }
        let previous_profile_id = settings.active_account_id.clone();
        let target = self
            .vault(config_store)?
            .load(profile_id)
            .map_err(vault_error)?;
        let default_path = self.default_auth_path()?;
        let original_auth = read_optional(&default_path)?;
        let original_fingerprint = fingerprint_optional(original_auth.as_deref());
        self.write_recovery(
            &recovery_path,
            &RecoveryRecord {
                original_auth: original_auth.clone(),
                original_fingerprint: original_fingerprint.clone(),
                previous_profile_id: previous_profile_id.clone(),
            },
        )?;

        before_fingerprint_recheck();
        let current_auth = read_optional(&default_path)?;
        if fingerprint_optional(current_auth.as_deref()) != original_fingerprint {
            remove_if_exists(&recovery_path).map_err(|_| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::RecoveryFailed,
                    "Codex auth.json changed externally and was preserved, but the recovery record could not be cleared. Choose Keep current state.",
                )
            })?;
            return Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::ExternalWrite,
                "Codex auth.json changed during the switch; the newer external login was preserved.",
            ));
        }

        if let Some(parent) = default_path.parent() {
            fs::create_dir_all(parent).map_err(internal_io_error)?;
        }
        if atomic_write(&default_path, &target.auth_json).is_err() {
            return Self::rollback_switch(
                &default_path,
                &recovery_path,
                original_auth.as_deref(),
                "The target credential could not be verified.",
            );
        }
        after_replace();
        let installed = match read_optional(&default_path) {
            Ok(installed) => installed,
            Err(_) => {
                return Self::rollback_switch(
                    &default_path,
                    &recovery_path,
                    original_auth.as_deref(),
                    "The target credential could not be read back.",
                );
            }
        };
        if fingerprint_optional(installed.as_deref())
            != fingerprint_optional(Some(target.auth_json.as_slice()))
        {
            remove_if_exists(&recovery_path).map_err(|_| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::RecoveryFailed,
                    "Codex auth.json changed externally after the switch and was preserved, but the recovery record could not be cleared. Choose Keep current state.",
                )
            })?;
            return Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::ExternalWrite,
                "Codex auth.json changed immediately after the switch; the newer external result was preserved.",
            ));
        }
        let applied = installed
            .as_deref()
            .and_then(|bytes| CodexProfileIdentity::from_auth_json(bytes).ok())
            .is_some_and(|identity| identity.matches(&target.identity));
        if !applied {
            return Self::rollback_switch(
                &default_path,
                &recovery_path,
                original_auth.as_deref(),
                "The target credential could not be verified.",
            );
        }

        settings.active_account_id = Some(profile_id.to_owned());
        if let Err(error) = config_store.save(&config) {
            return Self::rollback_switch(
                &default_path,
                &recovery_path,
                original_auth.as_deref(),
                &format!("The Profile setting could not be saved: {error}"),
            );
        }
        remove_if_exists(&recovery_path).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::RecoveryFailed,
                "The account switched, but its recovery record could not be cleared. Choose Keep current state.",
            )
        })?;
        Ok(ProfileActivation {
            previous_profile_id,
            active_profile_id: profile_id.to_owned(),
            restart_required: true,
        })
    }

    fn rollback_switch(
        default_path: &Path,
        recovery_path: &Path,
        original_auth: Option<&[u8]>,
        reason: &str,
    ) -> Result<ProfileActivation, CodexProfileCommandError> {
        let restored = restore_optional(default_path, original_auth).is_ok()
            && read_optional(default_path).is_ok_and(|bytes| {
                fingerprint_optional(bytes.as_deref()) == fingerprint_optional(original_auth)
            });
        if restored {
            if remove_if_exists(recovery_path).is_err() {
                return Err(CodexProfileCommandError::new(
                    CodexProfileErrorCode::RecoveryFailed,
                    format!(
                        "{reason} The original credential was restored, but the recovery record could not be cleared."
                    ),
                ));
            }
            Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::RolledBack,
                format!("{reason} The original Codex credential was restored."),
            ))
        } else {
            Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::RecoveryFailed,
                format!("{reason} Automatic recovery failed; choose a recovery action."),
            ))
        }
    }

    pub async fn recover(
        &self,
        config_store: &ConfigStore,
        action: RecoveryAction,
    ) -> Result<(), CodexProfileCommandError> {
        let _guard = self.switch_lock.lock().await;
        let recovery_path = Self::recovery_path(config_store)?;
        let record = self.read_recovery(&recovery_path)?;
        let default_path = self.default_auth_path()?;
        match action {
            RecoveryAction::RestoreOriginal => {
                restore_optional(&default_path, record.original_auth.as_deref()).map_err(|_| {
                    CodexProfileCommandError::new(
                        CodexProfileErrorCode::RecoveryFailed,
                        "The original Codex credential could not be restored.",
                    )
                })?;
                let restored = read_optional(&default_path)?;
                if fingerprint_optional(restored.as_deref()) != record.original_fingerprint {
                    return Err(CodexProfileCommandError::new(
                        CodexProfileErrorCode::RecoveryFailed,
                        "The restored Codex credential failed verification.",
                    ));
                }
            }
            RecoveryAction::KeepCurrent => {
                let current = fs::read(&default_path).map_err(|_| {
                    CodexProfileCommandError::new(
                        CodexProfileErrorCode::RecoveryFailed,
                        "There is no valid current Codex credential to keep.",
                    )
                })?;
                CodexProfileIdentity::from_auth_json(&current).map_err(|_| {
                    CodexProfileCommandError::new(
                        CodexProfileErrorCode::RecoveryFailed,
                        "The current Codex credential is invalid.",
                    )
                })?;
            }
        }
        self.synchronize_default_auth_unlocked(config_store)?;
        remove_if_exists(&recovery_path)?;
        Ok(())
    }

    pub fn delete_profile(
        &self,
        config_store: &ConfigStore,
        profile_id: &str,
    ) -> Result<(), CodexProfileCommandError> {
        self.delete_profile_with_hook(config_store, profile_id, || {})
    }

    fn delete_profile_with_hook(
        &self,
        config_store: &ConfigStore,
        profile_id: &str,
        after_config_delete: impl FnOnce(),
    ) -> Result<(), CodexProfileCommandError> {
        let _guard = self.try_operation_lock()?;
        let mut config = config_store.load().map_err(internal_config_error)?;
        let original_config = config.clone();
        let settings = config.provider(ProviderId::Codex);
        if settings.active_account_id.as_deref() == Some(profile_id) {
            return Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::ProfileActive,
                "The active Codex Profile cannot be deleted.",
            )
            .for_profile(profile_id));
        }
        let index = settings
            .accounts
            .iter()
            .position(|account| account.id == profile_id)
            .ok_or_else(|| {
                CodexProfileCommandError::new(
                    CodexProfileErrorCode::ProfileNotFound,
                    "The Codex Profile no longer exists.",
                )
                .for_profile(profile_id)
            })?;
        let vault = self.vault(config_store)?;
        let vault_path = vault.path(profile_id).map_err(vault_error)?;
        let staged_path = vault_path.with_extension("vault.deleting");
        let legacy_path = managed_codex_legacy_path(Self::config_dir(config_store)?, profile_id)
            .map_err(vault_error)?;
        let staged_legacy_path = legacy_path.with_extension("json.deleting");
        if vault_path.exists() {
            fs::rename(&vault_path, &staged_path).map_err(internal_io_error)?;
        }
        if legacy_path.exists() {
            if let Err(error) = fs::rename(&legacy_path, &staged_legacy_path) {
                let _ = fs::rename(&staged_path, &vault_path);
                return Err(internal_io_error(error));
            }
        }
        config
            .providers
            .entry(ProviderId::Codex)
            .or_default()
            .accounts
            .remove(index);
        let installed_delete_revision = match config_store.save_with_revision(&config) {
            Ok(revision) => revision,
            Err(error) => {
                let _ = fs::rename(&staged_path, &vault_path);
                let _ = fs::rename(&staged_legacy_path, &legacy_path);
                return Err(internal_config_error(error));
            }
        };
        after_config_delete();
        let history = HistoryStore::at(Self::config_dir(config_store)?.join("history"));
        if let Err(error) = history.delete_account(ProviderId::Codex, profile_id) {
            if config_store
                .save_if_revision_with_installed_revision(
                    &original_config,
                    &installed_delete_revision,
                )
                .is_err()
            {
                return Err(CodexProfileCommandError::new(
                    CodexProfileErrorCode::RecoveryFailed,
                    "Profile history deletion failed and the previous settings could not be restored. Credential recovery artifacts were preserved.",
                )
                .for_profile(profile_id));
            }
            let vault_restored = if vault_path.exists() {
                remove_if_exists(&staged_path).is_ok()
            } else {
                fs::rename(&staged_path, &vault_path).is_ok()
            };
            let legacy_restored = if staged_legacy_path.exists() {
                !legacy_path.exists() && fs::rename(&staged_legacy_path, &legacy_path).is_ok()
            } else {
                true
            };
            if !vault_restored || !legacy_restored {
                return Err(CodexProfileCommandError::new(
                    CodexProfileErrorCode::RecoveryFailed,
                    "Profile metadata was restored, but credential recovery could not be completed. Recovery artifacts were preserved.",
                )
                .for_profile(profile_id));
            }
            return Err(CodexProfileCommandError::new(
                CodexProfileErrorCode::RolledBack,
                format!(
                    "Could not delete the Profile history; Profile metadata and credentials were restored: {error}"
                ),
            )
            .for_profile(profile_id));
        }
        remove_if_exists(&staged_path)?;
        remove_if_exists(&staged_legacy_path)?;
        Ok(())
    }

    fn write_recovery(
        &self,
        path: &Path,
        record: &RecoveryRecord,
    ) -> Result<(), CodexProfileCommandError> {
        let plaintext = serde_json::to_string(record).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::Internal,
                "Could not prepare the encrypted recovery record.",
            )
        })?;
        let envelope = encode_secret(self.codec.as_ref(), &plaintext).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::Internal,
                "Could not encrypt the recovery record.",
            )
        })?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(internal_io_error)?;
        }
        atomic_write(path, envelope.as_bytes()).map_err(internal_io_error)
    }

    fn read_recovery(&self, path: &Path) -> Result<RecoveryRecord, CodexProfileCommandError> {
        let envelope = fs::read_to_string(path).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::RecoveryRequired,
                "No Codex recovery record is available.",
            )
        })?;
        let plaintext = match decode_secret(self.codec.as_ref(), &envelope).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::RecoveryFailed,
                "The Codex recovery record could not be decrypted.",
            )
        })? {
            DecodedSecret::Encrypted(value) => value,
            DecodedSecret::Plaintext(_) => {
                return Err(CodexProfileCommandError::new(
                    CodexProfileErrorCode::RecoveryFailed,
                    "An unencrypted Codex recovery record was rejected.",
                ));
            }
        };
        serde_json::from_str(&plaintext).map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::RecoveryFailed,
                "The Codex recovery record is invalid.",
            )
        })
    }

    pub async fn reserve_login_session(&self) -> (String, oneshot::Receiver<()>) {
        let session_id = format!(
            "codex-login-{}-{}",
            std::process::id(),
            NEXT_LOGIN_SESSION.fetch_add(1, Ordering::Relaxed)
        );
        let (sender, receiver) = oneshot::channel();
        self.login_cancellations
            .lock()
            .await
            .insert(session_id.clone(), sender);
        (session_id, receiver)
    }

    pub async fn finish_login_session(&self, session_id: &str) {
        self.login_cancellations.lock().await.remove(session_id);
    }

    pub async fn cancel_login_session(&self, session_id: &str) -> bool {
        self.login_cancellations
            .lock()
            .await
            .remove(session_id)
            .is_some_and(|sender| sender.send(()).is_ok())
    }

    pub fn operation_in_progress(&self) -> bool {
        self.switch_lock.try_lock().is_err()
    }

    fn try_operation_lock(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, CodexProfileCommandError> {
        self.switch_lock.try_lock().map_err(|_| {
            CodexProfileCommandError::new(
                CodexProfileErrorCode::OperationInProgress,
                "Another Codex Profile operation is already in progress.",
            )
        })
    }
}

fn clean_label(label: Option<String>) -> Option<String> {
    label
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn next_profile_id(accounts: &[ProviderAccount]) -> String {
    loop {
        let id = format!(
            "acc_{:08x}",
            NEXT_LOGIN_SESSION.fetch_add(1, Ordering::Relaxed) ^ u64::from(std::process::id())
        );
        if !accounts.iter().any(|account| account.id == id) {
            return id;
        }
    }
}

fn fingerprint_optional(bytes: Option<&[u8]>) -> String {
    match bytes {
        Some(bytes) => format!("present:{:x}", Sha256::digest(bytes)),
        None => "missing".into(),
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, CodexProfileCommandError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(internal_io_error(error)),
    }
}

fn restore_optional(path: &Path, bytes: Option<&[u8]>) -> std::io::Result<()> {
    if let Some(bytes) = bytes {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(path, bytes)
    } else {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn remove_if_exists(path: &Path) -> Result<(), CodexProfileCommandError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(internal_io_error(error)),
    }
}

fn vault_error(error: ProfileVaultError) -> CodexProfileCommandError {
    CodexProfileCommandError::new(
        match error {
            ProfileVaultError::Secret(_) => CodexProfileErrorCode::RecoveryFailed,
            ProfileVaultError::IdentityMismatch => CodexProfileErrorCode::IdentityMismatch,
            ProfileVaultError::MissingIdentity | ProfileVaultError::InvalidData => {
                CodexProfileErrorCode::InvalidCredential
            }
            ProfileVaultError::UnsafeProfileId | ProfileVaultError::Io(_) => {
                CodexProfileErrorCode::Internal
            }
        },
        error.to_string(),
    )
}

fn internal_config_error(error: impl std::fmt::Display) -> CodexProfileCommandError {
    CodexProfileCommandError::new(
        CodexProfileErrorCode::Internal,
        format!("Could not update Codex Profile settings: {error}"),
    )
}

fn internal_io_error(error: std::io::Error) -> CodexProfileCommandError {
    CodexProfileCommandError::new(
        CodexProfileErrorCode::Internal,
        format!("Codex Profile storage failed: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use codexbar_engine::auth::dpapi::SecretError;

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

    fn fixture() -> (tempfile::TempDir, ConfigStore, CodexProfileManager) {
        let directory = tempfile::tempdir().unwrap();
        let config_store = ConfigStore::at_with_codec(
            directory.path().join("app/config.json"),
            Arc::new(XorCodec),
        );
        let codex_home = directory.path().join("codex");
        fs::create_dir_all(&codex_home).unwrap();
        fs::write(
            codex_home.join("config.toml"),
            "cli_auth_credentials_store = \"file\"",
        )
        .unwrap();
        let manager = CodexProfileManager::new(Arc::new(XorCodec), Some(codex_home));
        (directory, config_store, manager)
    }

    fn auth(account_id: &str, subject: &str, email: &str) -> Vec<u8> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{subject}","email":"{email}"}}"#));
        format!(
            r#"{{"tokens":{{"access_token":"secret-{account_id}","refresh_token":"refresh-{account_id}","account_id":"{account_id}","id_token":"header.{claims}.signature"}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn switching_replaces_default_atomically_and_updates_active_profile() {
        run_async(async {
            let (_directory, store, manager) = fixture();
            fs::write(
                manager.default_auth_path().unwrap(),
                auth("acct-a", "sub-a", "a@example.com"),
            )
            .unwrap();
            let first = manager.import_current(&store, Some("A".into())).unwrap();
            let second_auth = auth("acct-b", "sub-b", "b@example.com");
            let second = manager
                .import_auth_data(&store, None, Some("B".into()), &second_auth)
                .unwrap();

            let result = manager.activate(&store, &second).await.unwrap();

            assert_eq!(result.previous_profile_id.as_deref(), Some(first.as_str()));
            assert_eq!(result.active_profile_id, second);
            assert!(result.restart_required);
            assert_eq!(
                fs::read(manager.default_auth_path().unwrap()).unwrap(),
                second_auth
            );
            assert!(!CodexProfileManager::recovery_path(&store).unwrap().exists());
        });
    }

    #[test]
    fn external_login_race_aborts_without_overwriting_new_auth() {
        run_async(async {
            let (_directory, store, manager) = fixture();
            fs::write(
                manager.default_auth_path().unwrap(),
                auth("acct-a", "sub-a", "a@example.com"),
            )
            .unwrap();
            manager.import_current(&store, Some("A".into())).unwrap();
            let second = manager
                .import_auth_data(
                    &store,
                    None,
                    Some("B".into()),
                    &auth("acct-b", "sub-b", "b@example.com"),
                )
                .unwrap();
            let external = auth("acct-c", "sub-c", "c@example.com");
            let path = manager.default_auth_path().unwrap();

            let error = manager
                .activate_with_hooks(
                    &store,
                    &second,
                    || fs::write(&path, &external).unwrap(),
                    || {},
                )
                .await
                .unwrap_err();

            assert_eq!(error.code, CodexProfileErrorCode::ExternalWrite);
            assert_eq!(fs::read(path).unwrap(), external);
            assert!(!CodexProfileManager::recovery_path(&store).unwrap().exists());
        });
    }

    #[test]
    fn external_login_after_replace_is_preserved_instead_of_rolled_back() {
        run_async(async {
            let (_directory, store, manager) = fixture();
            let original = auth("acct-a", "sub-a", "a@example.com");
            fs::write(manager.default_auth_path().unwrap(), &original).unwrap();
            manager.import_current(&store, Some("A".into())).unwrap();
            let second = manager
                .import_auth_data(
                    &store,
                    None,
                    Some("B".into()),
                    &auth("acct-b", "sub-b", "b@example.com"),
                )
                .unwrap();
            let external = auth("acct-c", "sub-c", "c@example.com");
            let path = manager.default_auth_path().unwrap();

            let error = manager
                .activate_with_hooks(
                    &store,
                    &second,
                    || {},
                    || fs::write(&path, &external).unwrap(),
                )
                .await
                .unwrap_err();

            assert_eq!(error.code, CodexProfileErrorCode::ExternalWrite);
            assert_eq!(fs::read(path).unwrap(), external);
            assert!(!CodexProfileManager::recovery_path(&store).unwrap().exists());
        });
    }

    #[test]
    fn recovery_record_is_encrypted_and_can_restore_original_auth() {
        let (_directory, store, manager) = fixture();
        let original = auth("acct-a", "sub-a", "a@example.com");
        let record = RecoveryRecord {
            original_auth: Some(original.clone()),
            original_fingerprint: fingerprint_optional(Some(&original)),
            previous_profile_id: Some("acc_a".into()),
        };
        let path = CodexProfileManager::recovery_path(&store).unwrap();
        manager.write_recovery(&path, &record).unwrap();
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("secret-acct-a"));
        assert_eq!(
            manager.read_recovery(&path).unwrap().original_auth,
            Some(original)
        );
    }

    #[test]
    fn reauthentication_rejects_another_identity() {
        let (_directory, store, manager) = fixture();
        fs::write(
            manager.default_auth_path().unwrap(),
            auth("acct-a", "sub-a", "a@example.com"),
        )
        .unwrap();
        let profile = manager.import_current(&store, None).unwrap();

        let error = manager
            .import_auth_data(
                &store,
                Some(&profile),
                None,
                &auth("acct-b", "sub-b", "b@example.com"),
            )
            .unwrap_err();

        assert_eq!(error.code, CodexProfileErrorCode::IdentityMismatch);
    }

    #[test]
    fn active_profile_cannot_be_deleted() {
        let (_directory, store, manager) = fixture();
        fs::write(
            manager.default_auth_path().unwrap(),
            auth("acct-a", "sub-a", "a@example.com"),
        )
        .unwrap();
        let profile = manager.import_current(&store, None).unwrap();
        let error = manager.delete_profile(&store, &profile).unwrap_err();
        assert_eq!(error.code, CodexProfileErrorCode::ProfileActive);
    }

    #[test]
    fn matching_email_alone_never_merges_profiles() {
        let (_directory, store, manager) = fixture();
        let first = manager
            .import_auth_data(
                &store,
                None,
                None,
                &auth("acct-a", "sub-a", "same@example.com"),
            )
            .unwrap();
        let second = manager
            .import_auth_data(
                &store,
                None,
                None,
                &auth("acct-b", "sub-b", "same@example.com"),
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            store
                .load()
                .unwrap()
                .provider(ProviderId::Codex)
                .accounts
                .len(),
            2
        );
    }

    #[test]
    fn unknown_external_login_clears_active_without_overwriting_it() {
        let (_directory, store, manager) = fixture();
        let known = auth("acct-a", "sub-a", "a@example.com");
        fs::write(manager.default_auth_path().unwrap(), &known).unwrap();
        manager.import_current(&store, None).unwrap();
        let external = auth("acct-external", "sub-external", "outside@example.com");
        fs::write(manager.default_auth_path().unwrap(), &external).unwrap();

        let identity = manager.synchronize_default_auth(&store).unwrap().unwrap();

        assert_eq!(identity.email.as_deref(), Some("outside@example.com"));
        assert_eq!(
            store
                .load()
                .unwrap()
                .provider(ProviderId::Codex)
                .active_account_id,
            None
        );
        assert_eq!(
            fs::read(manager.default_auth_path().unwrap()).unwrap(),
            external
        );
    }

    #[test]
    fn encrypted_recovery_can_restore_the_previous_profile_after_a_crash() {
        let (_directory, store, manager) = fixture();
        let original = auth("acct-a", "sub-a", "a@example.com");
        fs::write(manager.default_auth_path().unwrap(), &original).unwrap();
        let first = manager.import_current(&store, None).unwrap();
        let current = auth("acct-b", "sub-b", "b@example.com");
        manager
            .import_auth_data(&store, None, None, &current)
            .unwrap();
        let recovery_path = CodexProfileManager::recovery_path(&store).unwrap();
        manager
            .write_recovery(
                &recovery_path,
                &RecoveryRecord {
                    original_auth: Some(original.clone()),
                    original_fingerprint: fingerprint_optional(Some(&original)),
                    previous_profile_id: Some(first.clone()),
                },
            )
            .unwrap();
        fs::write(manager.default_auth_path().unwrap(), current).unwrap();

        run_async(async {
            manager
                .recover(&store, RecoveryAction::RestoreOriginal)
                .await
                .unwrap();
        });

        assert_eq!(
            fs::read(manager.default_auth_path().unwrap()).unwrap(),
            original
        );
        assert_eq!(
            store
                .load()
                .unwrap()
                .provider(ProviderId::Codex)
                .active_account_id
                .as_deref(),
            Some(first.as_str())
        );
        assert!(!recovery_path.exists());
    }

    #[test]
    fn deleting_an_inactive_profile_removes_vault_config_and_history() {
        let (_directory, store, manager) = fixture();
        let original = auth("acct-a", "sub-a", "a@example.com");
        fs::write(manager.default_auth_path().unwrap(), &original).unwrap();
        manager.import_current(&store, None).unwrap();
        let second = manager
            .import_auth_data(
                &store,
                None,
                None,
                &auth("acct-b", "sub-b", "b@example.com"),
            )
            .unwrap();
        let legacy =
            managed_codex_legacy_path(CodexProfileManager::config_dir(&store).unwrap(), &second)
                .unwrap();
        fs::write(&legacy, b"legacy-credential").unwrap();
        let history = HistoryStore::at(
            CodexProfileManager::config_dir(&store)
                .unwrap()
                .join("history"),
        );
        let now = chrono::Utc::now();
        let mut snapshot = codexbar_engine::ProviderSnapshot::new(ProviderId::Codex, "test");
        snapshot
            .windows
            .push(codexbar_engine::UsageWindow::new("weekly", "Weekly", 12.0));
        snapshot.fetched_at = now;
        let descriptor = codexbar_engine::ProviderDescriptor {
            id: ProviderId::Codex,
            display_name: "Codex",
            auth_kind: codexbar_engine::AuthKind::CliOAuth,
            color: "#000",
            dashboard_url: "https://example.invalid",
            credential_hint: "test",
            supports_multiple_accounts: true,
            capabilities: codexbar_engine::provider_capabilities(ProviderId::Codex),
        };
        let state = codexbar_engine::ProviderState::ready(descriptor, snapshot)
            .with_account(second.clone(), None);
        history.append_states(&[state], now, 90).unwrap();

        manager.delete_profile(&store, &second).unwrap();

        assert!(
            !manager
                .vault(&store)
                .unwrap()
                .path(&second)
                .unwrap()
                .exists()
        );
        assert!(
            !store
                .load()
                .unwrap()
                .provider(ProviderId::Codex)
                .accounts
                .iter()
                .any(|account| account.id == second)
        );
        assert!(!legacy.exists());
        assert!(
            history
                .query(
                    ProviderId::Codex,
                    Some(&second),
                    codexbar_engine::HistoryRange::Days7,
                    now,
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn history_delete_failure_rolls_back_profile_metadata_and_credentials_together() {
        let (_directory, store, manager) = fixture();
        let original = auth("acct-a", "sub-a", "a@example.com");
        fs::write(manager.default_auth_path().unwrap(), &original).unwrap();
        manager.import_current(&store, None).unwrap();
        let second_auth = auth("acct-b", "sub-b", "b@example.com");
        let second = manager
            .import_auth_data(&store, None, None, &second_auth)
            .unwrap();
        let vault = manager.vault(&store).unwrap();
        let vault_path = vault.path(&second).unwrap();
        let staged_vault_path = vault_path.with_extension("vault.deleting");
        let legacy =
            managed_codex_legacy_path(CodexProfileManager::config_dir(&store).unwrap(), &second)
                .unwrap();
        let staged_legacy = legacy.with_extension("json.deleting");
        fs::write(&legacy, b"legacy-credential").unwrap();
        let history_path = CodexProfileManager::config_dir(&store)
            .unwrap()
            .join("history/codex.jsonl");
        fs::create_dir_all(&history_path).unwrap();

        let error = manager.delete_profile(&store, &second).unwrap_err();

        assert_eq!(error.code, CodexProfileErrorCode::RolledBack);
        assert!(
            store
                .load()
                .unwrap()
                .provider(ProviderId::Codex)
                .accounts
                .iter()
                .any(|account| account.id == second)
        );
        assert_eq!(vault.load(&second).unwrap().auth_json, second_auth);
        assert!(vault_path.exists());
        assert!(!staged_vault_path.exists());
        assert_eq!(fs::read(legacy).unwrap(), b"legacy-credential");
        assert!(!staged_legacy.exists());
    }

    #[test]
    fn external_config_write_blocks_history_failure_rollback_and_preserves_recovery_artifacts() {
        let (_directory, store, manager) = fixture();
        let original = auth("acct-a", "sub-a", "a@example.com");
        fs::write(manager.default_auth_path().unwrap(), &original).unwrap();
        manager.import_current(&store, None).unwrap();
        let second = manager
            .import_auth_data(
                &store,
                None,
                None,
                &auth("acct-b", "sub-b", "b@example.com"),
            )
            .unwrap();
        let vault_path = manager.vault(&store).unwrap().path(&second).unwrap();
        let original_vault = fs::read(&vault_path).unwrap();
        let staged_vault_path = vault_path.with_extension("vault.deleting");
        let legacy =
            managed_codex_legacy_path(CodexProfileManager::config_dir(&store).unwrap(), &second)
                .unwrap();
        let staged_legacy = legacy.with_extension("json.deleting");
        fs::write(&legacy, b"legacy-credential").unwrap();
        let history_path = CodexProfileManager::config_dir(&store)
            .unwrap()
            .join("history/codex.jsonl");
        fs::create_dir_all(&history_path).unwrap();

        let error = manager
            .delete_profile_with_hook(&store, &second, || {
                let mut external = store.load().unwrap();
                external.refresh_interval_minutes = 23;
                store.save(&external).unwrap();
            })
            .unwrap_err();

        assert_eq!(error.code, CodexProfileErrorCode::RecoveryFailed);
        let external = store.load().unwrap();
        assert_eq!(external.refresh_interval_minutes, 23);
        assert!(
            external
                .provider(ProviderId::Codex)
                .accounts
                .iter()
                .all(|account| account.id != second)
        );
        assert!(!vault_path.exists());
        assert_eq!(fs::read(staged_vault_path).unwrap(), original_vault);
        assert!(!legacy.exists());
        assert_eq!(fs::read(staged_legacy).unwrap(), b"legacy-credential");
    }

    #[test]
    fn login_session_can_be_cancelled_without_starting_a_real_cli() {
        let (_directory, _store, manager) = fixture();
        run_async(async {
            let (session_id, cancellation) = manager.reserve_login_session().await;
            assert!(manager.cancel_login_session(&session_id).await);
            assert_eq!(cancellation.await, Ok(()));
            assert!(!manager.cancel_login_session(&session_id).await);
        });
    }

    fn run_async(future: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future);
    }
}
