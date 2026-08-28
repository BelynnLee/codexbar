use crate::{
    accounts::{ProviderAccountIdentity, ProviderCredentialBundle},
    atomic_file::atomic_write,
    auth::{credentials::is_safe_managed_account_id, dpapi::SecretCodec},
    model::ProviderId,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use thiserror::Error;

const VAULT_VERSION: u8 = 1;
static VAULT_WRITE_TRANSACTION: Mutex<()> = Mutex::new(());

#[derive(Clone, PartialEq, Eq)]
pub struct LoadedProviderCredential {
    pub provider: ProviderId,
    pub account_id: String,
    pub identity: ProviderAccountIdentity,
    pub credentials: ProviderCredentialBundle,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for LoadedProviderCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedProviderCredential")
            .field("provider", &self.provider)
            .field("account_id", &self.account_id)
            .field("identity", &self.identity)
            .field("credentials", &self.credentials)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMigration {
    NotFound,
    AlreadyMigrated,
    Migrated,
}

#[derive(Debug, Error)]
pub enum CredentialVaultError {
    #[error("Provider credential account id was rejected")]
    UnsafeAccountId,
    #[error("Provider credential vault could not be read or written")]
    Io(#[source] std::io::Error),
    #[error("Provider credential vault data is invalid")]
    InvalidData,
    #[error("Provider credential vault encryption failed")]
    EncryptionFailed,
    #[error("Provider credential vault decryption failed")]
    DecryptionFailed,
    #[error("Provider credential vault contains another provider")]
    ProviderMismatch,
    #[error("Provider credential vault contains another account")]
    AccountMismatch,
    #[error("Provider credential stable identity does not match")]
    IdentityMismatch,
    #[error("Activatable credentials require a stable identity")]
    MissingStableIdentity,
    #[error("Legacy provider credentials could not be parsed")]
    MigrationParseFailed,
    #[error("Legacy credential source conflicts with the target vault")]
    SourceTargetConflict,
    #[error("Provider credential vault rollback failed")]
    RollbackFailed,
    #[error("Provider credential vault transaction failed")]
    TransactionFailed,
    #[error("Provider credential vault changed during the transaction")]
    ExternalModification,
}

impl From<std::io::Error> for CredentialVaultError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultEnvelope {
    version: u8,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderVaultPayload {
    provider: ProviderId,
    account_id: String,
    identity: ProviderAccountIdentity,
    credentials: ProviderCredentialBundle,
    updated_at: DateTime<Utc>,
}

pub struct ProviderCredentialVault<'a> {
    config_dir: &'a Path,
    codec: &'a dyn SecretCodec,
}

pub struct StagedVaultDelete {
    path: PathBuf,
    previous: Option<Vec<u8>>,
}

impl fmt::Debug for StagedVaultDelete {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedVaultDelete")
            .field("path", &self.path)
            .field("has_previous", &self.previous.is_some())
            .finish()
    }
}

impl StagedVaultDelete {
    pub fn rollback(self) -> Result<(), CredentialVaultError> {
        let _transaction = begin_write_transaction()?;
        if read_optional(&self.path)?.is_some() {
            return Err(CredentialVaultError::ExternalModification);
        }
        if let Some(previous) = self.previous {
            atomic_write(&self.path, &previous)?;
        }
        Ok(())
    }

    pub fn commit(self) -> Result<(), CredentialVaultError> {
        let _transaction = begin_write_transaction()?;
        if read_optional(&self.path)?.is_some() {
            Err(CredentialVaultError::ExternalModification)
        } else {
            Ok(())
        }
    }
}

struct StagedVault {
    path: PathBuf,
    previous: Option<Vec<u8>>,
    installed: Option<Vec<u8>>,
}

pub(crate) struct ProviderVaultTransaction<'vault, 'codec> {
    vault: &'vault ProviderCredentialVault<'codec>,
    _guard: MutexGuard<'static, ()>,
    staged: Vec<StagedVault>,
}

impl<'a> ProviderCredentialVault<'a> {
    pub const fn new(config_dir: &'a Path, codec: &'a dyn SecretCodec) -> Self {
        Self { config_dir, codec }
    }

    pub fn path(
        &self,
        provider: ProviderId,
        account_id: &str,
    ) -> Result<PathBuf, CredentialVaultError> {
        if !is_safe_managed_account_id(account_id) {
            return Err(CredentialVaultError::UnsafeAccountId);
        }
        Ok(self
            .config_dir
            .join("accounts")
            .join(provider.to_string())
            .join(format!("{account_id}.vault")))
    }

    pub fn save(
        &self,
        provider: ProviderId,
        account_id: &str,
        identity: &ProviderAccountIdentity,
        credentials: &ProviderCredentialBundle,
    ) -> Result<PathBuf, CredentialVaultError> {
        let path = self.path(provider, account_id)?;
        let mut transaction = self.transaction()?;
        transaction.save(provider, account_id, identity, credentials)?;
        Ok(path)
    }

    pub(crate) fn transaction(
        &self,
    ) -> Result<ProviderVaultTransaction<'_, 'a>, CredentialVaultError> {
        Ok(ProviderVaultTransaction {
            vault: self,
            _guard: begin_write_transaction()?,
            staged: Vec::new(),
        })
    }

    fn save_locked(
        &self,
        provider: ProviderId,
        account_id: &str,
        identity: &ProviderAccountIdentity,
        credentials: &ProviderCredentialBundle,
    ) -> Result<PathBuf, CredentialVaultError> {
        let path = self.path(provider, account_id)?;
        let expected = read_optional(&path)?;
        self.save_locked_expected(
            provider,
            account_id,
            identity,
            credentials,
            expected.as_deref(),
        )?;
        Ok(path)
    }

    fn save_locked_expected(
        &self,
        provider: ProviderId,
        account_id: &str,
        identity: &ProviderAccountIdentity,
        credentials: &ProviderCredentialBundle,
        expected: Option<&[u8]>,
    ) -> Result<Vec<u8>, CredentialVaultError> {
        let path = self.path(provider, account_id)?;
        if identity.provider != provider {
            return Err(CredentialVaultError::ProviderMismatch);
        }
        let payload = ProviderVaultPayload {
            provider,
            account_id: account_id.to_owned(),
            identity: identity.clone(),
            credentials: credentials.clone(),
            updated_at: Utc::now(),
        };
        let plaintext =
            serde_json::to_vec(&payload).map_err(|_| CredentialVaultError::InvalidData)?;
        let ciphertext = self
            .codec
            .protect(&plaintext)
            .map_err(|_| CredentialVaultError::EncryptionFailed)?;
        let envelope = VaultEnvelope {
            version: VAULT_VERSION,
            ciphertext: STANDARD.encode(ciphertext),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| CredentialVaultError::InvalidData)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if read_optional(&path)?.as_deref() != expected {
            return Err(CredentialVaultError::ExternalModification);
        }
        atomic_write(&path, &bytes)?;

        let verification = self.load(provider, account_id).and_then(|loaded| {
            if loaded.provider == provider
                && loaded.account_id == account_id
                && loaded.identity == *identity
                && loaded.credentials == *credentials
                && loaded.updated_at == payload.updated_at
            {
                Ok(())
            } else {
                Err(CredentialVaultError::IdentityMismatch)
            }
        });
        if let Err(error) = verification {
            if restore_if_installed(&path, &bytes, expected).is_err() {
                return Err(CredentialVaultError::RollbackFailed);
            }
            return Err(error);
        }
        Ok(bytes)
    }

    pub fn load(
        &self,
        provider: ProviderId,
        account_id: &str,
    ) -> Result<LoadedProviderCredential, CredentialVaultError> {
        let path = self.path(provider, account_id)?;
        let bytes = fs::read(path)?;
        let envelope: VaultEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| CredentialVaultError::InvalidData)?;
        if envelope.version != VAULT_VERSION {
            return Err(CredentialVaultError::InvalidData);
        }
        let ciphertext = STANDARD
            .decode(envelope.ciphertext)
            .map_err(|_| CredentialVaultError::InvalidData)?;
        let plaintext = self
            .codec
            .unprotect(&ciphertext)
            .map_err(|_| CredentialVaultError::DecryptionFailed)?;
        let payload: ProviderVaultPayload =
            serde_json::from_slice(&plaintext).map_err(|_| CredentialVaultError::InvalidData)?;
        if payload.provider != provider || payload.identity.provider != provider {
            return Err(CredentialVaultError::ProviderMismatch);
        }
        if payload.account_id != account_id {
            return Err(CredentialVaultError::AccountMismatch);
        }
        Ok(LoadedProviderCredential {
            provider: payload.provider,
            account_id: payload.account_id,
            identity: payload.identity,
            credentials: payload.credentials,
            updated_at: payload.updated_at,
        })
    }

    pub fn delete(
        &self,
        provider: ProviderId,
        account_id: &str,
    ) -> Result<(), CredentialVaultError> {
        self.stage_delete(provider, account_id)?.commit()
    }

    pub fn stage_delete(
        &self,
        provider: ProviderId,
        account_id: &str,
    ) -> Result<StagedVaultDelete, CredentialVaultError> {
        let _transaction = begin_write_transaction()?;
        let path = self.path(provider, account_id)?;
        let previous = read_optional(&path)?;
        if previous.is_some() {
            fs::remove_file(&path)?;
        }
        if read_optional(&path)?.is_some() {
            return Err(CredentialVaultError::ExternalModification);
        }
        Ok(StagedVaultDelete { path, previous })
    }

    pub fn migrate_file<IdentityParser, CredentialParser>(
        &self,
        provider: ProviderId,
        account_id: &str,
        source_path: &Path,
        identity_parser: IdentityParser,
        credential_parser: CredentialParser,
    ) -> Result<CredentialMigration, CredentialVaultError>
    where
        IdentityParser: FnOnce(&[u8]) -> Result<ProviderAccountIdentity, CredentialVaultError>,
        CredentialParser: FnOnce(&[u8]) -> Result<ProviderCredentialBundle, CredentialVaultError>,
    {
        let _transaction = begin_write_transaction()?;
        self.migrate_file_locked(
            provider,
            account_id,
            source_path,
            identity_parser,
            credential_parser,
        )
    }

    fn migrate_file_locked<IdentityParser, CredentialParser>(
        &self,
        provider: ProviderId,
        account_id: &str,
        source_path: &Path,
        identity_parser: IdentityParser,
        credential_parser: CredentialParser,
    ) -> Result<CredentialMigration, CredentialVaultError>
    where
        IdentityParser: FnOnce(&[u8]) -> Result<ProviderAccountIdentity, CredentialVaultError>,
        CredentialParser: FnOnce(&[u8]) -> Result<ProviderCredentialBundle, CredentialVaultError>,
    {
        let target_path = self.path(provider, account_id)?;
        if paths_refer_to_same_file(source_path, &target_path) {
            return Err(CredentialVaultError::SourceTargetConflict);
        }
        let source = match fs::read(source_path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(if target_path.exists() {
                    CredentialMigration::AlreadyMigrated
                } else {
                    CredentialMigration::NotFound
                });
            }
            Err(error) => return Err(error.into()),
        };
        let identity =
            identity_parser(&source).map_err(|_| CredentialVaultError::MigrationParseFailed)?;
        let credentials =
            credential_parser(&source).map_err(|_| CredentialVaultError::MigrationParseFailed)?;
        if identity.provider != provider {
            return Err(CredentialVaultError::ProviderMismatch);
        }
        if credentials_are_activatable(&credentials) && !identity.is_activation_eligible() {
            return Err(CredentialVaultError::MissingStableIdentity);
        }
        if target_path.exists() {
            let existing = self.load(provider, account_id)?;
            if !identity.matches_stable(&existing.identity) {
                return Err(CredentialVaultError::IdentityMismatch);
            }
        }

        self.save_locked(provider, account_id, &identity, &credentials)?;
        let loaded = self.load(provider, account_id)?;
        if loaded.provider != provider
            || loaded.account_id != account_id
            || loaded.identity != identity
            || loaded.credentials != credentials
            || !loaded.identity.matches_stable(&identity)
        {
            return Err(CredentialVaultError::IdentityMismatch);
        }
        fs::remove_file(source_path)?;
        Ok(CredentialMigration::Migrated)
    }
}

impl ProviderVaultTransaction<'_, '_> {
    pub(crate) fn load(
        &self,
        provider: ProviderId,
        account_id: &str,
    ) -> Result<LoadedProviderCredential, CredentialVaultError> {
        self.vault.load(provider, account_id)
    }

    pub(crate) fn save(
        &mut self,
        provider: ProviderId,
        account_id: &str,
        identity: &ProviderAccountIdentity,
        credentials: &ProviderCredentialBundle,
    ) -> Result<Vec<u8>, CredentialVaultError> {
        let path = self.vault.path(provider, account_id)?;
        let staged_index = self.staged.iter().position(|staged| staged.path == path);
        let staged_index = if let Some(staged_index) = staged_index {
            staged_index
        } else {
            let previous = read_optional(&path)?;
            self.staged.push(StagedVault {
                path: path.clone(),
                previous,
                installed: None,
            });
            self.staged.len() - 1
        };
        let expected = self.staged[staged_index]
            .installed
            .as_ref()
            .or(self.staged[staged_index].previous.as_ref())
            .cloned();
        let installed = self.vault.save_locked_expected(
            provider,
            account_id,
            identity,
            credentials,
            expected.as_deref(),
        )?;
        self.staged[staged_index].installed = Some(installed.clone());
        Ok(installed)
    }

    pub(crate) fn rollback(&mut self) -> Result<(), CredentialVaultError> {
        let mut failed = false;
        for staged in std::mem::take(&mut self.staged).into_iter().rev() {
            let Some(installed) = staged.installed else {
                continue;
            };
            let current = match fs::read(&staged.path) {
                Ok(current) => Some(current),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => {
                    failed = true;
                    continue;
                }
            };
            if current.as_deref() != Some(installed.as_slice()) {
                failed = true;
                continue;
            }
            match staged.previous {
                Some(previous) => {
                    if atomic_write(&staged.path, &previous).is_err() {
                        failed = true;
                    }
                }
                None => match fs::remove_file(&staged.path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => failed = true,
                },
            }
        }
        if failed {
            Err(CredentialVaultError::RollbackFailed)
        } else {
            Ok(())
        }
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, CredentialVaultError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn restore_if_installed(
    path: &Path,
    installed: &[u8],
    previous: Option<&[u8]>,
) -> Result<(), CredentialVaultError> {
    if read_optional(path)?.as_deref() != Some(installed) {
        return Err(CredentialVaultError::RollbackFailed);
    }
    match previous {
        Some(previous) => {
            atomic_write(path, previous).map_err(|_| CredentialVaultError::RollbackFailed)
        }
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CredentialVaultError::RollbackFailed),
        },
    }
}

fn begin_write_transaction() -> Result<MutexGuard<'static, ()>, CredentialVaultError> {
    VAULT_WRITE_TRANSACTION
        .lock()
        .map_err(|_| CredentialVaultError::TransactionFailed)
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    left == right
        || fs::canonicalize(left)
            .ok()
            .zip(fs::canonicalize(right).ok())
            .is_some_and(|(left, right)| left == right)
}

fn credentials_are_activatable(credentials: &ProviderCredentialBundle) -> bool {
    credentials.api_key.is_some()
        || credentials.secret_key.is_some()
        || credentials.cookie_header.is_some()
        || credentials.artifact.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounts::{ProviderAccountIdentity, ProviderCredentialBundle, ProviderIdentityKey},
        auth::dpapi::{SecretCodec, SecretError},
        model::ProviderId,
    };
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use std::{
        fs,
        path::Path,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    #[derive(Debug)]
    struct XorCodec;

    impl SecretCodec for XorCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            self.protect(ciphertext)
        }
    }

    #[derive(Debug)]
    struct RejectProtect;

    impl SecretCodec for RejectProtect {
        fn protect(&self, _plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::Platform("deliberate protect failure".into()))
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(ciphertext.to_vec())
        }
    }

    #[derive(Debug)]
    struct RejectUnprotect;

    impl SecretCodec for RejectUnprotect {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.to_vec())
        }

        fn unprotect(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Err(SecretError::Platform("deliberate unprotect failure".into()))
        }
    }

    #[derive(Debug)]
    struct TimestampTamperingCodec;

    impl SecretCodec for TimestampTamperingCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.to_vec())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            let mut payload: serde_json::Value = serde_json::from_slice(ciphertext).unwrap();
            payload["updatedAt"] = serde_json::Value::String("2000-01-01T00:00:00Z".into());
            Ok(serde_json::to_vec(&payload).unwrap())
        }
    }

    #[derive(Debug, Default)]
    struct FailNextUnprotect {
        fail_next: AtomicBool,
    }

    impl FailNextUnprotect {
        fn arm(&self) {
            self.fail_next.store(true, Ordering::SeqCst);
        }
    }

    impl SecretCodec for FailNextUnprotect {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(SecretError::Platform(
                    "deliberate verification failure".into(),
                ));
            }
            self.protect(ciphertext)
        }
    }

    struct CoordinatedCodec {
        block_on_unprotect: usize,
        fail_blocked_unprotect: bool,
        unprotect_count: AtomicUsize,
        blocked: Mutex<bool>,
        blocked_changed: Condvar,
        released: Mutex<bool>,
        released_changed: Condvar,
    }

    impl fmt::Debug for CoordinatedCodec {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("CoordinatedCodec")
        }
    }

    impl CoordinatedCodec {
        fn new(block_on_unprotect: usize, fail_blocked_unprotect: bool) -> Self {
            Self {
                block_on_unprotect,
                fail_blocked_unprotect,
                unprotect_count: AtomicUsize::new(0),
                blocked: Mutex::new(false),
                blocked_changed: Condvar::new(),
                released: Mutex::new(false),
                released_changed: Condvar::new(),
            }
        }

        fn wait_until_blocked(&self) {
            let blocked = self.blocked.lock().unwrap();
            let (blocked, timeout) = self
                .blocked_changed
                .wait_timeout_while(blocked, Duration::from_secs(5), |blocked| !*blocked)
                .unwrap();
            assert!(!timeout.timed_out());
            assert!(*blocked);
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.released_changed.notify_all();
        }
    }

    impl SecretCodec for CoordinatedCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            let call = self.unprotect_count.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.block_on_unprotect {
                *self.blocked.lock().unwrap() = true;
                self.blocked_changed.notify_all();
                let released = self.released.lock().unwrap();
                let (released, timeout) = self
                    .released_changed
                    .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                    .unwrap();
                if timeout.timed_out() || !*released {
                    return Err(SecretError::Platform("coordination timed out".into()));
                }
                if self.fail_blocked_unprotect {
                    return Err(SecretError::Platform(
                        "coordinated verification failure".into(),
                    ));
                }
            }
            self.protect(ciphertext)
        }
    }

    struct BlockingProtectCodec {
        blocked: Mutex<bool>,
        blocked_changed: Condvar,
        released: Mutex<bool>,
        released_changed: Condvar,
    }

    impl fmt::Debug for BlockingProtectCodec {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("BlockingProtectCodec")
        }
    }

    impl BlockingProtectCodec {
        fn new() -> Self {
            Self {
                blocked: Mutex::new(false),
                blocked_changed: Condvar::new(),
                released: Mutex::new(false),
                released_changed: Condvar::new(),
            }
        }

        fn wait_until_blocked(&self) {
            let blocked = self.blocked.lock().unwrap();
            let (blocked, timeout) = self
                .blocked_changed
                .wait_timeout_while(blocked, Duration::from_secs(5), |blocked| !*blocked)
                .unwrap();
            assert!(!timeout.timed_out());
            assert!(*blocked);
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.released_changed.notify_all();
        }
    }

    impl SecretCodec for BlockingProtectCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            *self.blocked.lock().unwrap() = true;
            self.blocked_changed.notify_all();
            let released = self.released.lock().unwrap();
            let (released, timeout) = self
                .released_changed
                .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                .unwrap();
            if timeout.timed_out() || !*released {
                return Err(SecretError::Platform("coordination timed out".into()));
            }
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(ciphertext.iter().map(|byte| byte ^ 0x5a).collect())
        }
    }

    fn identity(provider: ProviderId, stable_id: &str) -> ProviderAccountIdentity {
        ProviderAccountIdentity::new(
            provider,
            [ProviderIdentityKey::new("subject", stable_id)],
            Some("person@example.com".into()),
            Some("Person".into()),
        )
    }

    fn artifact_bundle(secret: &str) -> ProviderCredentialBundle {
        ProviderCredentialBundle {
            artifact_format: Some("test-auth-json".into()),
            artifact: Some(format!(r#"{{"token":"{secret}"}}"#).into_bytes()),
            ..Default::default()
        }
    }

    fn write_payload(path: &Path, codec: &dyn SecretCodec, payload: &ProviderVaultPayload) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let plaintext = serde_json::to_vec(payload).unwrap();
        let envelope = VaultEnvelope {
            version: VAULT_VERSION,
            ciphertext: STANDARD.encode(codec.protect(&plaintext).unwrap()),
        };
        fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    }

    #[test]
    fn provider_vault_silos_equal_account_ids_and_hides_plaintext() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let codex_identity = identity(ProviderId::Codex, "subject-a");
        let bundle = ProviderCredentialBundle {
            artifact_format: Some("codex-auth-json".into()),
            artifact: Some(br#"{"token":"secret-token"}"#.to_vec()),
            ..Default::default()
        };

        vault
            .save(ProviderId::Codex, "acc_same", &codex_identity, &bundle)
            .unwrap();
        vault
            .save(
                ProviderId::Claude,
                "acc_same",
                &identity(ProviderId::Claude, "user-a"),
                &bundle,
            )
            .unwrap();

        let codex_path = vault.path(ProviderId::Codex, "acc_same").unwrap();
        let claude_path = vault.path(ProviderId::Claude, "acc_same").unwrap();
        assert_ne!(codex_path, claude_path);
        let codex_bytes = fs::read(codex_path).unwrap();
        let on_disk = String::from_utf8_lossy(&codex_bytes);
        assert!(!on_disk.contains("secret-token"));
        let outer: serde_json::Value = serde_json::from_slice(&codex_bytes).unwrap();
        let mut keys = outer
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, ["ciphertext", "version"]);

        let loaded = vault.load(ProviderId::Codex, "acc_same").unwrap();
        assert_eq!(loaded.provider, ProviderId::Codex);
        assert_eq!(loaded.account_id, "acc_same");
        assert_eq!(loaded.identity, codex_identity);
        assert_eq!(loaded.credentials, bundle);
    }

    #[test]
    fn vault_paths_reject_unsafe_accounts_and_keep_all_providers_siloed() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        for account_id in [
            "",
            "same",
            "../escape",
            "acc_a/../../escape",
            "C:\\escape",
            "acc_a.vault",
        ] {
            assert!(matches!(
                vault.path(ProviderId::Codex, account_id),
                Err(CredentialVaultError::UnsafeAccountId)
            ));
        }

        for provider in ProviderId::ALL {
            let path = vault.path(provider, "acc_safe").unwrap();
            let provider_root = temp.path().join("accounts").join(provider.to_string());
            assert_eq!(path.parent(), Some(provider_root.as_path()));
            assert_eq!(path.file_name().unwrap(), "acc_safe.vault");
        }
    }

    #[test]
    fn load_rejects_wrong_envelope_version_base64_and_ciphertext() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let path = vault.path(ProviderId::Codex, "acc_bad").unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        fs::write(&path, br#"{"version":2,"ciphertext":"AA=="}"#).unwrap();
        assert!(matches!(
            vault.load(ProviderId::Codex, "acc_bad"),
            Err(CredentialVaultError::InvalidData)
        ));

        fs::write(&path, br#"{"version":1,"ciphertext":"%%%"}"#).unwrap();
        assert!(matches!(
            vault.load(ProviderId::Codex, "acc_bad"),
            Err(CredentialVaultError::InvalidData)
        ));

        fs::write(&path, br#"{"version":1,"ciphertext":"AA=="}"#).unwrap();
        let rejecting = ProviderCredentialVault::new(temp.path(), &RejectUnprotect);
        assert!(matches!(
            rejecting.load(ProviderId::Codex, "acc_bad"),
            Err(CredentialVaultError::DecryptionFailed)
        ));
    }

    #[test]
    fn load_rejects_provider_and_account_mismatch_inside_payload() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let path = vault.path(ProviderId::Codex, "acc_expected").unwrap();
        let base = ProviderVaultPayload {
            provider: ProviderId::Claude,
            account_id: "acc_expected".into(),
            identity: identity(ProviderId::Claude, "subject-a"),
            credentials: artifact_bundle("provider-mismatch-secret"),
            updated_at: Utc::now(),
        };
        write_payload(&path, &XorCodec, &base);
        assert!(matches!(
            vault.load(ProviderId::Codex, "acc_expected"),
            Err(CredentialVaultError::ProviderMismatch)
        ));

        write_payload(
            &path,
            &XorCodec,
            &ProviderVaultPayload {
                provider: ProviderId::Codex,
                account_id: "acc_other".into(),
                identity: identity(ProviderId::Codex, "subject-a"),
                ..base
            },
        );
        assert!(matches!(
            vault.load(ProviderId::Codex, "acc_expected"),
            Err(CredentialVaultError::AccountMismatch)
        ));
    }

    #[test]
    fn save_verification_failure_restores_exact_previous_vault() {
        let temp = tempfile::tempdir().unwrap();
        let codec = FailNextUnprotect::default();
        let vault = ProviderCredentialVault::new(temp.path(), &codec);
        vault
            .save(
                ProviderId::Codex,
                "acc_work",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("first-secret"),
            )
            .unwrap();
        let path = vault.path(ProviderId::Codex, "acc_work").unwrap();
        let previous = fs::read(&path).unwrap();

        codec.arm();
        assert!(matches!(
            vault.save(
                ProviderId::Codex,
                "acc_work",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("replacement-secret"),
            ),
            Err(CredentialVaultError::DecryptionFailed)
        ));
        assert_eq!(fs::read(path).unwrap(), previous);
    }

    #[test]
    fn save_verification_rejects_a_changed_update_timestamp() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &TimestampTamperingCodec);

        let result = vault.save(
            ProviderId::Codex,
            "acc_time",
            &identity(ProviderId::Codex, "subject-a"),
            &artifact_bundle("timestamp-secret"),
        );

        assert!(result.is_err());
        assert!(!vault.path(ProviderId::Codex, "acc_time").unwrap().exists());
    }

    #[test]
    fn transaction_save_rejects_external_mutation_between_staging_and_replace() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().to_path_buf();
        let path = ProviderCredentialVault::new(&config_dir, &XorCodec)
            .save(
                ProviderId::Codex,
                "acc_external",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("initial-private"),
            )
            .unwrap();
        let codec = Arc::new(BlockingProtectCodec::new());
        let writer_dir = config_dir.clone();
        let writer_codec = Arc::clone(&codec);
        let writer = thread::spawn(move || {
            ProviderCredentialVault::new(&writer_dir, writer_codec.as_ref()).save(
                ProviderId::Codex,
                "acc_external",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("replacement-private"),
            )
        });
        codec.wait_until_blocked();
        fs::write(&path, b"external-private-bytes").unwrap();
        codec.release();

        let error = writer.join().unwrap().unwrap_err();

        assert!(matches!(error, CredentialVaultError::ExternalModification));
        assert_eq!(fs::read(path).unwrap(), b"external-private-bytes");
        let debug = format!("{error:?}");
        for forbidden in [
            "initial-private",
            "replacement-private",
            "external-private-bytes",
        ] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[test]
    fn transaction_save_records_the_exact_installed_envelope_without_a_followup_read() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let mut transaction = vault.transaction().unwrap();

        let installed = transaction
            .save(
                ProviderId::Codex,
                "acc_recorded",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("recorded-private"),
            )
            .unwrap();

        assert_eq!(transaction.staged[0].installed.as_ref(), Some(&installed));
        assert_eq!(
            fs::read(vault.path(ProviderId::Codex, "acc_recorded").unwrap()).unwrap(),
            installed
        );
    }

    #[test]
    fn repeated_transaction_save_uses_the_last_install_as_the_expected_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let path = vault
            .save(
                ProviderId::Codex,
                "acc_repeated",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("original-private"),
            )
            .unwrap();
        let original = fs::read(&path).unwrap();
        let mut transaction = vault.transaction().unwrap();
        let first = transaction
            .save(
                ProviderId::Codex,
                "acc_repeated",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("first-private"),
            )
            .unwrap();
        let second = transaction
            .save(
                ProviderId::Codex,
                "acc_repeated",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("second-private"),
            )
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(fs::read(&path).unwrap(), second);
        transaction.rollback().unwrap();
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn rollback_continues_after_an_external_conflict_and_restores_other_vaults() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        for id in ["acc_a", "acc_b"] {
            vault
                .save(
                    ProviderId::Codex,
                    id,
                    &identity(ProviderId::Codex, "subject-a"),
                    &artifact_bundle(&format!("old-{id}")),
                )
                .unwrap();
        }
        let path_a = vault.path(ProviderId::Codex, "acc_a").unwrap();
        let path_b = vault.path(ProviderId::Codex, "acc_b").unwrap();
        let previous_a = fs::read(&path_a).unwrap();
        let mut transaction = vault.transaction().unwrap();
        transaction
            .save(
                ProviderId::Codex,
                "acc_a",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("new-a-private"),
            )
            .unwrap();
        transaction
            .save(
                ProviderId::Codex,
                "acc_b",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("new-b-private"),
            )
            .unwrap();
        fs::write(&path_b, b"external-b-private").unwrap();

        assert!(matches!(
            transaction.rollback(),
            Err(CredentialVaultError::RollbackFailed)
        ));
        assert_eq!(fs::read(path_a).unwrap(), previous_a);
        assert_eq!(fs::read(path_b).unwrap(), b"external-b-private");
    }

    #[test]
    fn failed_save_rollback_cannot_overwrite_a_concurrent_successful_save() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().to_path_buf();
        let codec = Arc::new(CoordinatedCodec::new(2, true));
        let vault = ProviderCredentialVault::new(&config_dir, codec.as_ref());
        let expected_identity = identity(ProviderId::Codex, "subject-a");
        vault
            .save(
                ProviderId::Codex,
                "acc_race",
                &expected_identity,
                &artifact_bundle("initial-secret"),
            )
            .unwrap();

        let failing_dir = config_dir.clone();
        let failing_codec = Arc::clone(&codec);
        let failing_identity = expected_identity.clone();
        let failing = thread::spawn(move || {
            ProviderCredentialVault::new(&failing_dir, failing_codec.as_ref()).save(
                ProviderId::Codex,
                "acc_race",
                &failing_identity,
                &artifact_bundle("failing-secret"),
            )
        });
        codec.wait_until_blocked();

        let successful_dir = config_dir.clone();
        let successful_codec = Arc::clone(&codec);
        let successful_identity = expected_identity.clone();
        let expected_bundle = artifact_bundle("successful-secret");
        let successful_bundle = expected_bundle.clone();
        let (successful_tx, successful_rx) = mpsc::channel();
        let successful = thread::spawn(move || {
            let result = ProviderCredentialVault::new(&successful_dir, successful_codec.as_ref())
                .save(
                    ProviderId::Codex,
                    "acc_race",
                    &successful_identity,
                    &successful_bundle,
                );
            successful_tx.send(result).unwrap();
        });

        let completed_while_failure_was_blocked =
            successful_rx.recv_timeout(Duration::from_secs(1)).ok();
        codec.release();
        assert!(failing.join().unwrap().is_err());
        let successful_result = match completed_while_failure_was_blocked {
            Some(result) => result,
            None => successful_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        };
        successful_result.unwrap();
        successful.join().unwrap();

        let loaded = vault.load(ProviderId::Codex, "acc_race").unwrap();
        assert_eq!(loaded.credentials, expected_bundle);
    }

    #[test]
    fn staged_delete_rollback_preserves_a_new_external_vault() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let path = vault
            .save(
                ProviderId::Codex,
                "acc_delete",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("original-secret"),
            )
            .unwrap();
        let staged = vault.stage_delete(ProviderId::Codex, "acc_delete").unwrap();
        assert!(!path.exists());
        fs::write(&path, b"external-new-vault").unwrap();

        assert!(matches!(
            staged.rollback(),
            Err(CredentialVaultError::ExternalModification)
        ));
        assert_eq!(fs::read(path).unwrap(), b"external-new-vault");
    }

    #[test]
    fn staged_delete_commit_rejects_a_recreated_external_vault() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let path = vault
            .save(
                ProviderId::Codex,
                "acc_delete_commit",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("original-secret"),
            )
            .unwrap();
        let staged = vault
            .stage_delete(ProviderId::Codex, "acc_delete_commit")
            .unwrap();
        fs::write(&path, b"external-recreated-vault").unwrap();

        assert!(matches!(
            staged.commit(),
            Err(CredentialVaultError::ExternalModification)
        ));
        assert_eq!(fs::read(path).unwrap(), b"external-recreated-vault");
    }

    #[test]
    fn staged_delete_debug_never_contains_ciphertext() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        vault
            .save(
                ProviderId::Codex,
                "acc_debug_delete",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("debug-delete-secret"),
            )
            .unwrap();
        let staged = vault
            .stage_delete(ProviderId::Codex, "acc_debug_delete")
            .unwrap();
        let debug = format!("{staged:?}");
        assert!(debug.contains("has_previous: true"));
        assert!(!debug.contains("debug-delete-secret"));
        assert!(!debug.contains("ciphertext"));
    }

    #[test]
    fn migration_verification_and_source_delete_exclude_concurrent_writers() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().to_path_buf();
        let source = temp.path().join("legacy-auth.json");
        fs::write(&source, b"legacy-credential-bytes").unwrap();
        let codec = Arc::new(CoordinatedCodec::new(2, false));
        let expected_identity = identity(ProviderId::Codex, "subject-a");
        let migrated_bundle = artifact_bundle("migrated-secret");

        let migration_dir = config_dir.clone();
        let migration_source = source.clone();
        let migration_codec = Arc::clone(&codec);
        let migration_identity = expected_identity.clone();
        let migration_bundle = migrated_bundle.clone();
        let migration = thread::spawn(move || {
            ProviderCredentialVault::new(&migration_dir, migration_codec.as_ref()).migrate_file(
                ProviderId::Codex,
                "acc_migration_race",
                &migration_source,
                |_| Ok(migration_identity),
                |_| Ok(migration_bundle),
            )
        });
        codec.wait_until_blocked();

        let writer_dir = config_dir.clone();
        let writer_codec = Arc::clone(&codec);
        let writer_identity = expected_identity.clone();
        let writer_bundle = artifact_bundle("concurrent-secret");
        let expected_final_bundle = writer_bundle.clone();
        let (writer_tx, writer_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            let result = ProviderCredentialVault::new(&writer_dir, writer_codec.as_ref()).save(
                ProviderId::Codex,
                "acc_migration_race",
                &writer_identity,
                &writer_bundle,
            );
            writer_tx.send(result).unwrap();
        });

        let writer_completed_during_migration =
            writer_rx.recv_timeout(Duration::from_millis(500)).ok();
        let writer_completed_early = writer_completed_during_migration.is_some();
        codec.release();
        assert_eq!(
            migration.join().unwrap().unwrap(),
            CredentialMigration::Migrated
        );
        let writer_result = match writer_completed_during_migration {
            Some(result) => result,
            None => writer_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        };
        writer_result.unwrap();
        writer.join().unwrap();

        assert!(!writer_completed_early);
        assert!(!source.exists());
        let loaded = ProviderCredentialVault::new(&config_dir, codec.as_ref())
            .load(ProviderId::Codex, "acc_migration_race")
            .unwrap();
        assert_eq!(loaded.credentials, expected_final_bundle);
    }

    #[test]
    fn delete_is_idempotent_for_a_missing_vault() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        vault.delete(ProviderId::Codex, "acc_missing").unwrap();
        vault.delete(ProviderId::Codex, "acc_missing").unwrap();
    }

    #[test]
    fn migration_deletes_source_only_after_verified_generic_read_back() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let source = temp.path().join("legacy-auth.json");
        fs::write(&source, b"legacy-credential-bytes").unwrap();
        let expected_identity = identity(ProviderId::Codex, "subject-a");
        let expected_bundle = artifact_bundle("migrated-secret");

        let result = vault
            .migrate_file(
                ProviderId::Codex,
                "acc_work",
                &source,
                |_| Ok(expected_identity.clone()),
                |_| Ok(expected_bundle.clone()),
            )
            .unwrap();

        assert_eq!(result, CredentialMigration::Migrated);
        assert!(!source.exists());
        let loaded = vault.load(ProviderId::Codex, "acc_work").unwrap();
        assert_eq!(loaded.identity, expected_identity);
        assert_eq!(loaded.credentials, expected_bundle);
    }

    #[test]
    fn migration_parse_and_encryption_failures_preserve_legacy_source() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("legacy-auth.json");
        fs::write(&source, b"legacy-credential-bytes").unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        assert!(matches!(
            vault.migrate_file(
                ProviderId::Codex,
                "acc_work",
                &source,
                |_| Err(CredentialVaultError::InvalidData),
                |_| Ok(artifact_bundle("unused-secret")),
            ),
            Err(CredentialVaultError::MigrationParseFailed)
        ));
        assert!(source.exists());
        assert!(!vault.path(ProviderId::Codex, "acc_work").unwrap().exists());

        let rejecting = ProviderCredentialVault::new(temp.path(), &RejectProtect);
        assert!(matches!(
            rejecting.migrate_file(
                ProviderId::Codex,
                "acc_work",
                &source,
                |_| Ok(identity(ProviderId::Codex, "subject-a")),
                |_| Ok(artifact_bundle("encryption-secret")),
            ),
            Err(CredentialVaultError::EncryptionFailed)
        ));
        assert!(source.exists());
        assert!(
            !rejecting
                .path(ProviderId::Codex, "acc_work")
                .unwrap()
                .exists()
        );
    }

    #[test]
    fn migration_identity_conflict_preserves_source_and_exact_existing_target() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        vault
            .save(
                ProviderId::Codex,
                "acc_work",
                &identity(ProviderId::Codex, "subject-original"),
                &artifact_bundle("original-secret"),
            )
            .unwrap();
        let target = vault.path(ProviderId::Codex, "acc_work").unwrap();
        let target_before = fs::read(&target).unwrap();
        let source = temp.path().join("legacy-auth.json");
        fs::write(&source, b"legacy-credential-bytes").unwrap();

        assert!(matches!(
            vault.migrate_file(
                ProviderId::Codex,
                "acc_work",
                &source,
                |_| Ok(identity(ProviderId::Codex, "subject-conflict")),
                |_| Ok(artifact_bundle("conflicting-secret")),
            ),
            Err(CredentialVaultError::IdentityMismatch)
        ));
        assert!(source.exists());
        assert_eq!(fs::read(target).unwrap(), target_before);
    }

    #[test]
    fn migration_rejects_activatable_artifact_without_stable_identity() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let source = temp.path().join("legacy-auth.json");
        fs::write(&source, b"legacy-credential-bytes").unwrap();

        assert!(matches!(
            vault.migrate_file(
                ProviderId::Codex,
                "acc_work",
                &source,
                |_| Ok(ProviderAccountIdentity::unverified(ProviderId::Codex)),
                |_| Ok(artifact_bundle("activation-secret")),
            ),
            Err(CredentialVaultError::MissingStableIdentity)
        ));
        assert!(source.exists());
        assert!(!vault.path(ProviderId::Codex, "acc_work").unwrap().exists());
    }

    #[test]
    fn migration_missing_source_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let source = temp.path().join("missing.json");
        let parser_was_called = AtomicBool::new(false);

        let result = vault
            .migrate_file(
                ProviderId::Codex,
                "acc_work",
                &source,
                |_| {
                    parser_was_called.store(true, Ordering::SeqCst);
                    Ok(identity(ProviderId::Codex, "unused"))
                },
                |_| Ok(artifact_bundle("unused-secret")),
            )
            .unwrap();
        assert_eq!(result, CredentialMigration::NotFound);
        assert!(!parser_was_called.load(Ordering::SeqCst));

        vault
            .save(
                ProviderId::Codex,
                "acc_work",
                &identity(ProviderId::Codex, "subject-a"),
                &artifact_bundle("saved-secret"),
            )
            .unwrap();
        let result = vault
            .migrate_file(
                ProviderId::Codex,
                "acc_work",
                &source,
                |_| Ok(identity(ProviderId::Codex, "unused")),
                |_| Ok(artifact_bundle("unused-secret")),
            )
            .unwrap();
        assert_eq!(result, CredentialMigration::AlreadyMigrated);
    }

    #[test]
    fn migration_refuses_to_treat_the_target_vault_as_its_source() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let expected_identity = identity(ProviderId::Codex, "subject-a");
        let expected_bundle = artifact_bundle("target-secret");
        let target = vault
            .save(
                ProviderId::Codex,
                "acc_work",
                &expected_identity,
                &expected_bundle,
            )
            .unwrap();
        let target_before = fs::read(&target).unwrap();

        let result = vault.migrate_file(
            ProviderId::Codex,
            "acc_work",
            &target,
            |_| Ok(expected_identity.clone()),
            |_| Ok(expected_bundle.clone()),
        );

        assert!(result.is_err());
        assert!(target.exists());
        assert_eq!(fs::read(target).unwrap(), target_before);
    }

    #[test]
    fn loaded_debug_and_errors_do_not_reveal_credentials_or_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temp.path(), &XorCodec);
        let bundle = ProviderCredentialBundle {
            api_key: Some("api-private-value".into()),
            secret_key: Some("secret-private-value".into()),
            cookie_header: Some("cookie-private-value".into()),
            artifact_format: Some("test-auth-json".into()),
            artifact: Some(b"artifact-private-value".to_vec()),
        };
        vault
            .save(
                ProviderId::Codex,
                "acc_debug",
                &identity(ProviderId::Codex, "subject-a"),
                &bundle,
            )
            .unwrap();
        let debug = format!("{:?}", vault.load(ProviderId::Codex, "acc_debug").unwrap());
        for secret in [
            "api-private-value",
            "secret-private-value",
            "cookie-private-value",
            "artifact-private-value",
        ] {
            assert!(!debug.contains(secret));
        }

        let rejecting = ProviderCredentialVault::new(temp.path(), &RejectProtect);
        let error_debug = format!(
            "{:?}",
            rejecting
                .save(
                    ProviderId::Codex,
                    "acc_error",
                    &identity(ProviderId::Codex, "subject-a"),
                    &artifact_bundle("error-path-private-value"),
                )
                .unwrap_err()
        );
        for secret in ["error-path-private-value", "deliberate protect failure"] {
            assert!(!error_debug.contains(secret));
        }
    }
}
