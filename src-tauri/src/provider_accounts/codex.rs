use super::adapters::{
    ActivationSupport, CredentialActivationAdapter, CredentialTargetSnapshot,
    ProviderAccountCommandError, ProviderAccountCommandErrorCode, ProviderAdapterDeclaration,
    RestartHint,
};
use codexbar_engine::{
    ActivationTargetKind, ProviderAccountIdentity, ProviderCredentialBundle,
    ProviderEnrollmentKind, ProviderId, atomic_move_no_replace, atomic_replace_with_backup,
    auth::{
        credentials::{
            CodexCredentialStoreMode, CodexCredentials, parse_codex_credential_store_mode,
        },
        dpapi::{DpapiCodec, SecretCodec},
    },
    file_has_multiple_links,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CODEX_ARTIFACT_FORMAT: &str = "codex-auth-json";
const CODEX_FILE_STORE_REASON: &str =
    "Codex switching requires an explicit root cli_auth_credentials_store = \"file\" setting.";
const CODEX_LOGIN_TIMEOUT: Duration = Duration::from_secs(600);
const CODEX_TRANSACTION_VERSION: u8 = 1;
const CODEX_TRANSACTION_DIRECTORY: &str = ".codexbar-transactions";
static NEXT_CODEX_TRANSACTION_ID: AtomicU64 = AtomicU64::new(0);

struct CodexTargetState {
    auth: Option<Vec<u8>>,
    config: Option<Vec<u8>>,
    mode: CodexCredentialStoreMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CodexTransactionPhase {
    Prepared,
    Staged,
    SwapReady,
    ExternalCaptured,
    RecoverySwap,
    RestoreMissingTarget,
    DeleteMoveReady,
    RestoreRemovedExternal,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexTransactionCheckpoint {
    AfterStage,
    BeforeSwap,
    AfterReplaceBeforeValidation,
    MismatchBeforeRestore,
    AfterRecoverySwapBeforeValidation,
    AfterMissingTargetRestoreBeforeValidation,
    AfterDeleteTombstoneMove,
    AfterRemovedExternalRestoreBeforeValidation,
    BeforeCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexPublisherArtifactKind {
    Journal,
    GenerationHead,
    CurrentHead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexPublisherCheckpoint {
    TemporaryVerified {
        kind: CodexPublisherArtifactKind,
        sequence: u32,
    },
    JournalPublished {
        sequence: u32,
    },
    GenerationHeadPublished {
        sequence: u32,
    },
    CurrentReplaceBeforePreviousCleanup {
        sequence: u32,
    },
    ArtifactReconciled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexReadRecoveryCheckpoint {
    AfterUnlockedOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CodexTransactionPaths {
    transaction_directory: String,
    journal_prefix: String,
    stage: String,
    backup: String,
    recovery: String,
    removed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CodexTransactionRecord {
    version: u8,
    transaction_id: String,
    sequence: u32,
    previous_record_hash: Option<String>,
    canonical_target: String,
    expected_auth: Option<Vec<u8>>,
    expected_auth_hash: String,
    expected_config_hash: String,
    expected_mode: String,
    intended_auth: Option<Vec<u8>>,
    intended_file: Vec<u8>,
    intended_hash: String,
    displaced_auth: Option<Vec<u8>>,
    restore_guard_auth: Vec<u8>,
    phase: CodexTransactionPhase,
    paths: CodexTransactionPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SealedCodexTransaction {
    version: u8,
    transaction_id: String,
    sequence: u32,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CodexTransactionHead {
    version: u8,
    transaction_id: String,
    sequence: u32,
    record_hash: String,
}

struct CodexTransactionGuard {
    _lock_file: File,
}

trait CodexFileOps: Send + Sync {
    fn replace_with_backup(
        &self,
        destination: &Path,
        replacement: &Path,
        backup: &Path,
    ) -> std::io::Result<()>;

    fn move_no_replace(&self, source: &Path, destination: &Path) -> std::io::Result<()>;
}

trait CodexPublisherOps: Send + Sync {
    fn replace_current(
        &self,
        destination: &Path,
        replacement: &Path,
        backup: &Path,
    ) -> std::io::Result<()>;
}

#[derive(Debug)]
struct SystemCodexFileOps;

impl CodexFileOps for SystemCodexFileOps {
    fn replace_with_backup(
        &self,
        destination: &Path,
        replacement: &Path,
        backup: &Path,
    ) -> std::io::Result<()> {
        atomic_replace_with_backup(destination, replacement, backup)
    }

    fn move_no_replace(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
        atomic_move_no_replace(source, destination)
    }
}

#[derive(Debug)]
struct SystemCodexPublisherOps;

impl CodexPublisherOps for SystemCodexPublisherOps {
    fn replace_current(
        &self,
        destination: &Path,
        replacement: &Path,
        backup: &Path,
    ) -> std::io::Result<()> {
        atomic_replace_with_backup(destination, replacement, backup)
    }
}

#[derive(Clone)]
pub struct CodexFileAdapter {
    codex_home: PathBuf,
    codec: Arc<dyn SecretCodec>,
    file_ops: Arc<dyn CodexFileOps>,
    publisher_ops: Arc<dyn CodexPublisherOps>,
    publisher_hook: Arc<dyn Fn(CodexPublisherCheckpoint) -> bool + Send + Sync>,
    read_recovery_hook: Arc<dyn Fn(CodexReadRecoveryCheckpoint) + Send + Sync>,
    transaction_hook: Arc<dyn Fn(CodexTransactionCheckpoint) -> bool + Send + Sync>,
}

impl CodexFileAdapter {
    pub fn new(codex_home: PathBuf) -> Self {
        Self::with_codec(codex_home, Arc::new(DpapiCodec))
    }

    pub(crate) fn with_codec(codex_home: PathBuf, codec: Arc<dyn SecretCodec>) -> Self {
        Self {
            codex_home,
            codec,
            file_ops: Arc::new(SystemCodexFileOps),
            publisher_ops: Arc::new(SystemCodexPublisherOps),
            publisher_hook: Arc::new(|_| false),
            read_recovery_hook: Arc::new(|_| {}),
            transaction_hook: Arc::new(|_| false),
        }
    }

    #[cfg(test)]
    fn with_file_ops(mut self, file_ops: Arc<dyn CodexFileOps>) -> Self {
        self.file_ops = file_ops;
        self
    }

    #[cfg(test)]
    fn with_publisher_ops(mut self, publisher_ops: Arc<dyn CodexPublisherOps>) -> Self {
        self.publisher_ops = publisher_ops;
        self
    }

    #[cfg(test)]
    fn with_publisher_hook(
        mut self,
        hook: Arc<dyn Fn(CodexPublisherCheckpoint) -> bool + Send + Sync>,
    ) -> Self {
        self.publisher_hook = hook;
        self
    }

    #[cfg(test)]
    fn with_read_recovery_hook(
        mut self,
        hook: Arc<dyn Fn(CodexReadRecoveryCheckpoint) + Send + Sync>,
    ) -> Self {
        self.read_recovery_hook = hook;
        self
    }

    #[cfg(test)]
    fn with_before_commit_hook(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.transaction_hook = Arc::new(move |checkpoint| {
            if checkpoint == CodexTransactionCheckpoint::BeforeSwap {
                hook();
            }
            false
        });
        self
    }

    #[cfg(test)]
    fn with_transaction_hook(
        mut self,
        hook: Arc<dyn Fn(CodexTransactionCheckpoint) -> bool + Send + Sync>,
    ) -> Self {
        self.transaction_hook = hook;
        self
    }

    pub fn from_default() -> Result<Self, ProviderAccountCommandError> {
        let auth_path = CodexCredentials::default_path()
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        let adapter = auth_path
            .parent()
            .map(Path::to_path_buf)
            .map(Self::new)
            .ok_or_else(|| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        adapter.recover_pending_transactions()?;
        Ok(adapter)
    }

    pub fn identity(
        auth_json: &[u8],
    ) -> Result<ProviderAccountIdentity, ProviderAccountCommandError> {
        CodexCredentials::parse(auth_json, PathBuf::from("auth.json"))
            .and_then(|credentials| credentials.provider_identity())
            .map_err(|_| ProviderAccountCommandError::invalid_credential(ProviderId::Codex, None))
    }

    pub fn credential_bundle(
        auth_json: &[u8],
    ) -> Result<ProviderCredentialBundle, ProviderAccountCommandError> {
        Self::identity(auth_json)?;
        Ok(Self::raw_bundle(auth_json))
    }

    fn raw_bundle(auth_json: &[u8]) -> ProviderCredentialBundle {
        ProviderCredentialBundle {
            artifact_format: Some(CODEX_ARTIFACT_FORMAT.into()),
            artifact: Some(auth_json.to_vec()),
            ..Default::default()
        }
    }

    fn config_path(&self) -> PathBuf {
        self.codex_home.join("config.toml")
    }

    fn auth_path(&self) -> PathBuf {
        self.codex_home.join("auth.json")
    }

    fn artifact(
        credentials: &ProviderCredentialBundle,
    ) -> Result<&[u8], ProviderAccountCommandError> {
        if credentials.artifact_format.as_deref() != Some(CODEX_ARTIFACT_FORMAT) {
            return Err(ProviderAccountCommandError::invalid_credential(
                ProviderId::Codex,
                None,
            ));
        }
        credentials
            .artifact
            .as_deref()
            .ok_or_else(|| ProviderAccountCommandError::invalid_credential(ProviderId::Codex, None))
    }

    fn with_recovered_operation<T>(
        &self,
        mut operation: impl FnMut() -> Result<T, ProviderAccountCommandError>,
    ) -> Result<T, ProviderAccountCommandError> {
        let transaction_directory =
            if let Some(directory) = self.existing_transaction_directory()? {
                directory
            } else {
                let unlocked_result = operation();
                (self.read_recovery_hook)(CodexReadRecoveryCheckpoint::AfterUnlockedOperation);
                let Some(directory) = self.existing_transaction_directory()? else {
                    return unlocked_result;
                };
                directory
            };
        let _guard = Self::acquire_transaction_guard_in(&transaction_directory)?;
        for record in self.scan_transactions()? {
            self.recover_record(&record)?;
        }
        operation()
    }

    fn read_optional_file(path: PathBuf) -> Result<Option<Vec<u8>>, ProviderAccountCommandError> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ProviderAccountCommandError::internal(
                ProviderId::Codex,
                None,
            )),
        }
    }

    fn read_target(&self) -> Result<Option<Vec<u8>>, ProviderAccountCommandError> {
        Self::read_optional_file(self.auth_path())
    }

    fn read_target_state(&self) -> Result<CodexTargetState, ProviderAccountCommandError> {
        let auth = self.read_target()?;
        let config = Self::read_optional_file(self.config_path())?;
        let mode = match config.as_deref() {
            None => CodexCredentialStoreMode::Unset,
            Some(bytes) => std::str::from_utf8(bytes).map_or(
                CodexCredentialStoreMode::Invalid,
                parse_codex_credential_store_mode,
            ),
        };
        Ok(CodexTargetState { auth, config, mode })
    }

    fn canonical_home(&self) -> Result<PathBuf, ProviderAccountCommandError> {
        fs::create_dir_all(&self.codex_home)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        fs::canonicalize(&self.codex_home)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))
    }

    fn transaction_directory(&self) -> Result<PathBuf, ProviderAccountCommandError> {
        let canonical_home = self.canonical_home()?;
        let directory = canonical_home.join(CODEX_TRANSACTION_DIRECTORY);
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(ProviderAccountCommandError::internal(
                    ProviderId::Codex,
                    None,
                ));
            }
        }
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if !metadata.is_dir() || metadata_is_reparse_or_link(&metadata) {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let canonical_directory = fs::canonicalize(&directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if canonical_directory.parent() != Some(canonical_home.as_path()) {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        Ok(canonical_directory)
    }

    fn existing_transaction_directory(
        &self,
    ) -> Result<Option<PathBuf>, ProviderAccountCommandError> {
        let canonical_home = match fs::canonicalize(&self.codex_home) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(ProviderAccountCommandError::internal(
                    ProviderId::Codex,
                    None,
                ));
            }
        };
        let directory = canonical_home.join(CODEX_TRANSACTION_DIRECTORY);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
        };
        if !metadata.is_dir() || metadata_is_reparse_or_link(&metadata) {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let canonical_directory = fs::canonicalize(&directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if canonical_directory.parent() != Some(canonical_home.as_path()) {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        Ok(Some(canonical_directory))
    }

    fn acquire_transaction_guard(
        &self,
    ) -> Result<CodexTransactionGuard, ProviderAccountCommandError> {
        let transaction_directory = self.transaction_directory()?;
        Self::acquire_transaction_guard_in(&transaction_directory)
    }

    fn acquire_transaction_guard_in(
        transaction_directory: &Path,
    ) -> Result<CodexTransactionGuard, ProviderAccountCommandError> {
        let lock_path = transaction_directory.join(".lock");
        if let Ok(metadata) = fs::symlink_metadata(&lock_path)
            && metadata_is_reparse_or_link(&metadata)
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let lock_file = open_exclusive_lock(&lock_path).map_err(|error| {
            if is_lock_contention(&error) {
                ProviderAccountCommandError::operation_in_progress(ProviderId::Codex, None)
            } else {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            }
        })?;
        let metadata = lock_file
            .metadata()
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if metadata_is_reparse_or_link(&metadata)
            || !metadata.is_file()
            || file_has_multiple_links(&lock_file).unwrap_or(true)
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        Ok(CodexTransactionGuard {
            _lock_file: lock_file,
        })
    }

    fn next_transaction_id() -> String {
        let counter = NEXT_CODEX_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{}-{timestamp:x}-{counter:x}", std::process::id())
    }

    fn transaction_paths(
        &self,
        transaction_id: &str,
    ) -> Result<CodexTransactionPaths, ProviderAccountCommandError> {
        if transaction_id.is_empty()
            || !transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let directory = self.transaction_directory()?;
        let prefix = directory.join(format!("codexbar-txn-{transaction_id}"));
        Ok(CodexTransactionPaths {
            transaction_directory: path_text(&directory),
            journal_prefix: path_text(&prefix),
            stage: path_text(&prefix.with_extension("stage")),
            backup: path_text(&prefix.with_extension("backup")),
            recovery: path_text(&prefix.with_extension("recovery")),
            removed: path_text(&prefix.with_extension("removed")),
        })
    }

    fn begin_transaction(
        &self,
        current: &CodexTargetState,
        intended_auth: Option<&[u8]>,
        intended_file: Vec<u8>,
    ) -> Result<CodexTransactionRecord, ProviderAccountCommandError> {
        let transaction_id = Self::next_transaction_id();
        let paths = self.transaction_paths(&transaction_id)?;
        let canonical_target = self.canonical_home()?.join("auth.json");
        let record = CodexTransactionRecord {
            version: CODEX_TRANSACTION_VERSION,
            transaction_id,
            sequence: 0,
            previous_record_hash: None,
            canonical_target: path_text(&canonical_target),
            expected_auth: current.auth.clone(),
            expected_auth_hash: optional_fingerprint_text(current.auth.as_deref()),
            expected_config_hash: optional_fingerprint_text(current.config.as_deref()),
            expected_mode: format!("{:?}", current.mode),
            intended_auth: intended_auth.map(ToOwned::to_owned),
            intended_hash: fingerprint(Some(&intended_file))
                .expect("an intended transaction file always has bytes"),
            restore_guard_auth: intended_file.clone(),
            intended_file,
            displaced_auth: None,
            phase: CodexTransactionPhase::Prepared,
            paths,
        };
        self.persist_transaction_record(&record)?;
        Ok(record)
    }

    fn persist_transaction_record(
        &self,
        record: &CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        self.validate_transaction_record(record)?;
        let plaintext = serde_json::to_vec(record)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        let ciphertext = self
            .codec
            .protect(&plaintext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        let envelope = SealedCodexTransaction {
            version: CODEX_TRANSACTION_VERSION,
            transaction_id: record.transaction_id.clone(),
            sequence: record.sequence,
            ciphertext,
        };
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        let journal_path = Self::journal_path(record)?;
        secure_publish_new(
            self,
            &journal_path,
            &bytes,
            CodexPublisherArtifactKind::Journal,
            record.sequence,
        )?;
        self.publisher_checkpoint(CodexPublisherCheckpoint::JournalPublished {
            sequence: record.sequence,
        })?;
        let verified = self.read_transaction_record(&journal_path)?;
        if verified != *record {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let head = CodexTransactionHead {
            version: CODEX_TRANSACTION_VERSION,
            transaction_id: record.transaction_id.clone(),
            sequence: record.sequence,
            record_hash: transaction_record_hash(record)?,
        };
        let head_plaintext = serde_json::to_vec(&head)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        let head_ciphertext = self
            .codec
            .protect(&head_plaintext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        let head_envelope = SealedCodexTransaction {
            version: CODEX_TRANSACTION_VERSION,
            transaction_id: record.transaction_id.clone(),
            sequence: record.sequence,
            ciphertext: head_ciphertext,
        };
        let head_bytes = serde_json::to_vec(&head_envelope)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        let head_path = Self::head_path(record)?;
        secure_publish_new(
            self,
            &head_path,
            &head_bytes,
            CodexPublisherArtifactKind::GenerationHead,
            record.sequence,
        )?;
        self.publisher_checkpoint(CodexPublisherCheckpoint::GenerationHeadPublished {
            sequence: record.sequence,
        })?;
        if self.read_transaction_head(&head_path)? != head {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let current_head_path = Self::current_head_path(record)?;
        secure_publish_current(self, &current_head_path, &head_bytes, record.sequence)?;
        if self.read_transaction_head(&current_head_path)? != head {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        Ok(())
    }

    fn advance_transaction(
        &self,
        record: &mut CodexTransactionRecord,
        phase: CodexTransactionPhase,
    ) -> Result<(), ProviderAccountCommandError> {
        let persisted = self.read_transaction_record(&Self::journal_path(record)?)?;
        if persisted.transaction_id != record.transaction_id
            || persisted.sequence != record.sequence
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        record.previous_record_hash = Some(transaction_record_hash(&persisted)?);
        record.sequence = record.sequence.checked_add(1).ok_or_else(|| {
            ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
        })?;
        record.phase = phase;
        self.persist_transaction_record(record)
    }

    fn journal_path(
        record: &CodexTransactionRecord,
    ) -> Result<PathBuf, ProviderAccountCommandError> {
        let prefix = PathBuf::from(&record.paths.journal_prefix);
        Ok(PathBuf::from(format!(
            "{}-{}.journal",
            prefix.to_string_lossy(),
            record.sequence
        )))
    }

    fn head_path(record: &CodexTransactionRecord) -> Result<PathBuf, ProviderAccountCommandError> {
        let prefix = PathBuf::from(&record.paths.journal_prefix);
        Ok(PathBuf::from(format!(
            "{}-{}.head",
            prefix.to_string_lossy(),
            record.sequence
        )))
    }

    fn current_head_path(
        record: &CodexTransactionRecord,
    ) -> Result<PathBuf, ProviderAccountCommandError> {
        let prefix = PathBuf::from(&record.paths.journal_prefix);
        Ok(PathBuf::from(format!(
            "{}.head-current",
            prefix.to_string_lossy()
        )))
    }

    fn read_transaction_record(
        &self,
        journal_path: &Path,
    ) -> Result<CodexTransactionRecord, ProviderAccountCommandError> {
        let metadata = fs::symlink_metadata(journal_path)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if metadata_is_reparse_or_link(&metadata) || !metadata.is_file() {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let bytes = Self::read_optional_sidecar(journal_path)?.ok_or_else(|| {
            ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
        })?;
        let envelope: SealedCodexTransaction = serde_json::from_slice(&bytes)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if envelope.version != CODEX_TRANSACTION_VERSION {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let plaintext = self
            .codec
            .unprotect(&envelope.ciphertext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        let record: CodexTransactionRecord = serde_json::from_slice(&plaintext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if record.transaction_id != envelope.transaction_id || record.sequence != envelope.sequence
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        self.validate_transaction_record(&record)?;
        Ok(record)
    }

    fn read_transaction_head(
        &self,
        head_path: &Path,
    ) -> Result<CodexTransactionHead, ProviderAccountCommandError> {
        let metadata = fs::symlink_metadata(head_path)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if metadata_is_reparse_or_link(&metadata) || !metadata.is_file() {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let bytes = Self::read_optional_sidecar(head_path)?.ok_or_else(|| {
            ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
        })?;
        let envelope: SealedCodexTransaction = serde_json::from_slice(&bytes)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if envelope.version != CODEX_TRANSACTION_VERSION {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let plaintext = self
            .codec
            .unprotect(&envelope.ciphertext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        let head: CodexTransactionHead = serde_json::from_slice(&plaintext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if head.version != CODEX_TRANSACTION_VERSION
            || head.transaction_id != envelope.transaction_id
            || head.sequence != envelope.sequence
            || !is_sha256_fingerprint(&head.record_hash)
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        Ok(head)
    }

    fn validate_transaction_record(
        &self,
        record: &CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        if record.version != CODEX_TRANSACTION_VERSION
            || (record.sequence == 0) != record.previous_record_hash.is_none()
            || record
                .previous_record_hash
                .as_deref()
                .is_some_and(|hash| !is_sha256_fingerprint(hash))
            || record.expected_auth_hash
                != optional_fingerprint_text(record.expected_auth.as_deref())
            || record.intended_hash
                != fingerprint(Some(&record.intended_file))
                    .expect("an intended transaction file always has bytes")
            || record
                .intended_auth
                .as_deref()
                .is_some_and(|auth| auth != record.intended_file)
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let expected_paths = self.transaction_paths(&record.transaction_id)?;
        let expected_target = self.canonical_home()?.join("auth.json");
        if record.paths != expected_paths || record.canonical_target != path_text(&expected_target)
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        Ok(())
    }

    fn expected_transaction_head(
        record: &CodexTransactionRecord,
    ) -> Result<CodexTransactionHead, ProviderAccountCommandError> {
        Ok(CodexTransactionHead {
            version: CODEX_TRANSACTION_VERSION,
            transaction_id: record.transaction_id.clone(),
            sequence: record.sequence,
            record_hash: transaction_record_hash(record)?,
        })
    }

    fn seal_transaction_head(
        &self,
        head: &CodexTransactionHead,
    ) -> Result<Vec<u8>, ProviderAccountCommandError> {
        let plaintext = serde_json::to_vec(head)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        let ciphertext = self
            .codec
            .protect(&plaintext)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        serde_json::to_vec(&SealedCodexTransaction {
            version: CODEX_TRANSACTION_VERSION,
            transaction_id: head.transaction_id.clone(),
            sequence: head.sequence,
            ciphertext,
        })
        .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))
    }

    fn reconcile_publication_artifacts(
        &self,
        directory: &Path,
    ) -> Result<(), ProviderAccountCommandError> {
        let mut transaction_ids = std::collections::BTreeSet::new();
        for entry in fs::read_dir(directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?
        {
            let entry = entry.map_err(|_| {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some((transaction_id, _)) =
                parse_journal_name(&name).or_else(|| parse_head_name(&name))
            {
                transaction_ids.insert(transaction_id);
            } else if let Some(transaction_id) = parse_current_head_name(&name) {
                transaction_ids.insert(transaction_id);
            } else if let Some((transaction_id, _, _)) = parse_publication_artifact_name(&name) {
                transaction_ids.insert(transaction_id);
            }
        }
        if transaction_ids.len() > 1 {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        for transaction_id in transaction_ids {
            self.reconcile_transaction_publication(directory, &transaction_id)?;
        }
        Ok(())
    }

    fn reconcile_transaction_publication(
        &self,
        directory: &Path,
        transaction_id: &str,
    ) -> Result<(), ProviderAccountCommandError> {
        let paths = self.transaction_paths(transaction_id)?;
        let prefix = PathBuf::from(&paths.journal_prefix);
        let mut journal_temporaries = BTreeMap::new();
        let mut head_temporaries = BTreeMap::new();
        let mut current_temporaries = BTreeMap::new();
        let mut current_previous = BTreeMap::new();
        for entry in fs::read_dir(directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?
        {
            let entry = entry.map_err(|_| {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some((artifact_transaction, sequence, kind)) =
                parse_publication_artifact_name(&name)
            else {
                continue;
            };
            if artifact_transaction != transaction_id {
                continue;
            }
            let target = match kind {
                CodexPublicationArtifact::JournalPublishing => &mut journal_temporaries,
                CodexPublicationArtifact::GenerationHeadPublishing => &mut head_temporaries,
                CodexPublicationArtifact::CurrentPublishing => &mut current_temporaries,
                CodexPublicationArtifact::CurrentPrevious => &mut current_previous,
            };
            if target.insert(sequence, entry.path()).is_some() {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
        }

        for (sequence, temporary) in &journal_temporaries {
            let record = self.read_transaction_record(temporary)?;
            if record.transaction_id != transaction_id || record.sequence != *sequence {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            if *sequence > 0 {
                let previous_path = PathBuf::from(format!(
                    "{}-{}.journal",
                    prefix.to_string_lossy(),
                    sequence - 1
                ));
                let previous = self.read_transaction_record(&previous_path)?;
                if record.previous_record_hash.as_deref()
                    != Some(transaction_record_hash(&previous)?.as_str())
                {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
            }
            let final_path =
                PathBuf::from(format!("{}-{sequence}.journal", prefix.to_string_lossy()));
            if final_path.exists() {
                if self.read_transaction_record(&final_path)? != record {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                Self::cleanup_sidecar(temporary)?;
            } else {
                atomic_move_no_replace(temporary, &final_path).map_err(|_| {
                    ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
                })?;
            }
            self.publisher_checkpoint(CodexPublisherCheckpoint::ArtifactReconciled)?;
        }

        let mut journals = BTreeMap::new();
        for entry in fs::read_dir(directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?
        {
            let entry = entry.map_err(|_| {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some((journal_transaction, sequence)) = parse_journal_name(&name)
                && journal_transaction == transaction_id
            {
                journals.insert(sequence, entry.path());
            }
        }
        let Some((&first_sequence, _)) = journals.first_key_value() else {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        };
        let mut records = BTreeMap::new();
        let mut previous_hash = None;
        for (offset, (sequence, path)) in journals.iter().enumerate() {
            if *sequence != first_sequence + offset as u32 {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            let record = self.read_transaction_record(path)?;
            if let Some(previous_hash) = previous_hash.as_deref()
                && record.previous_record_hash.as_deref() != Some(previous_hash)
            {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            previous_hash = Some(transaction_record_hash(&record)?);
            records.insert(*sequence, record);
        }
        let latest = records
            .last_key_value()
            .map(|(_, record)| record)
            .expect("journal map is not empty");
        if first_sequence != 0 && latest.phase != CodexTransactionPhase::Cleanup {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }

        for (sequence, temporary) in &head_temporaries {
            let Some(record) = records.get(sequence) else {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            };
            let expected = Self::expected_transaction_head(record)?;
            if self.read_transaction_head(temporary)? != expected {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            let final_path = PathBuf::from(format!("{}-{sequence}.head", prefix.to_string_lossy()));
            if final_path.exists() {
                if self.read_transaction_head(&final_path)? != expected {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                Self::cleanup_sidecar(temporary)?;
            } else {
                atomic_move_no_replace(temporary, &final_path).map_err(|_| {
                    ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
                })?;
            }
            self.publisher_checkpoint(CodexPublisherCheckpoint::ArtifactReconciled)?;
        }

        for (sequence, record) in &records {
            let head_path = PathBuf::from(format!("{}-{sequence}.head", prefix.to_string_lossy()));
            let expected = Self::expected_transaction_head(record)?;
            if head_path.exists() {
                if self.read_transaction_head(&head_path)? != expected {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
            } else {
                let bytes = self.seal_transaction_head(&expected)?;
                secure_publish_new(
                    self,
                    &head_path,
                    &bytes,
                    CodexPublisherArtifactKind::GenerationHead,
                    *sequence,
                )?;
                self.publisher_checkpoint(CodexPublisherCheckpoint::ArtifactReconciled)?;
            }
        }

        let latest_head = Self::expected_transaction_head(latest)?;
        if current_temporaries
            .keys()
            .chain(current_previous.keys())
            .any(|sequence| *sequence != latest.sequence)
            || current_temporaries.len() > 1
            || current_previous.len() > 1
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let current_path = PathBuf::from(format!("{}.head-current", prefix.to_string_lossy()));
        let current = if current_path.exists() {
            Some(self.read_transaction_head(&current_path)?)
        } else {
            None
        };
        let temporary = current_temporaries.get(&latest.sequence);
        let previous = current_previous.get(&latest.sequence);
        if let Some(temporary) = temporary
            && self.read_transaction_head(temporary)? != latest_head
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let validate_old_head =
            |path: &Path| -> Result<CodexTransactionHead, ProviderAccountCommandError> {
                let head = self.read_transaction_head(path)?;
                if head.transaction_id != transaction_id || head.sequence >= latest.sequence {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                let generation = PathBuf::from(format!(
                    "{}-{}.head",
                    prefix.to_string_lossy(),
                    head.sequence
                ));
                if self.read_transaction_head(&generation)? != head {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                Ok(head)
            };

        if current.as_ref() == Some(&latest_head) {
            if let Some(temporary) = temporary {
                Self::cleanup_sidecar(temporary)?;
                self.publisher_checkpoint(CodexPublisherCheckpoint::ArtifactReconciled)?;
            }
            if let Some(previous) = previous {
                validate_old_head(previous)?;
                Self::cleanup_sidecar(previous)?;
                self.publisher_checkpoint(CodexPublisherCheckpoint::ArtifactReconciled)?;
            }
            return Ok(());
        }

        if let Some(current) = current.as_ref() {
            validate_old_head(&current_path)?;
            if current.sequence >= latest.sequence || previous.is_some() {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
        }
        if let Some(previous) = previous {
            validate_old_head(previous)?;
        }
        let Some(temporary) = temporary else {
            let bytes = self.seal_transaction_head(&latest_head)?;
            secure_publish_current(self, &current_path, &bytes, latest.sequence)?;
            self.publisher_checkpoint(CodexPublisherCheckpoint::ArtifactReconciled)?;
            return Ok(());
        };

        if let Some(current_head) = current.as_ref() {
            let previous_path = publication_previous_path(&current_path, latest.sequence)?;
            self.publisher_ops
                .replace_current(&current_path, temporary, &previous_path)
                .map_err(|_| {
                    ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
                })?;
            if self.read_transaction_head(&previous_path)? != *current_head {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
        } else {
            atomic_move_no_replace(temporary, &current_path).map_err(|_| {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            })?;
        }
        if self.read_transaction_head(&current_path)? != latest_head {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        self.publisher_checkpoint(CodexPublisherCheckpoint::ArtifactReconciled)?;
        if let Some(previous) = previous {
            Self::cleanup_sidecar(previous)?;
        } else {
            let generated_previous = publication_previous_path(&current_path, latest.sequence)?;
            if generated_previous.exists() {
                validate_old_head(&generated_previous)?;
                Self::cleanup_sidecar(&generated_previous)?;
            }
        }
        Ok(())
    }

    fn scan_transactions(
        &self,
    ) -> Result<Vec<CodexTransactionRecord>, ProviderAccountCommandError> {
        let directory = self.transaction_directory()?;
        self.reconcile_publication_artifacts(&directory)?;
        let mut grouped =
            BTreeMap::<String, (BTreeMap<u32, PathBuf>, BTreeMap<u32, PathBuf>)>::new();
        let mut current_heads = BTreeMap::<String, PathBuf>::new();
        let mut raw_sidecars = Vec::new();
        for entry in fs::read_dir(&directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?
        {
            let entry = entry.map_err(|_| {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == ".lock" {
                continue;
            }
            if let Some((transaction_id, sequence)) = parse_journal_name(&name) {
                grouped
                    .entry(transaction_id)
                    .or_default()
                    .0
                    .insert(sequence, entry.path());
            } else if let Some((transaction_id, sequence)) = parse_head_name(&name) {
                grouped
                    .entry(transaction_id)
                    .or_default()
                    .1
                    .insert(sequence, entry.path());
            } else if let Some(transaction_id) = parse_current_head_name(&name) {
                grouped.entry(transaction_id.clone()).or_default();
                if current_heads.insert(transaction_id, entry.path()).is_some() {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
            } else if name.starts_with("codexbar-txn-") {
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| {
                    ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
                })?;
                if metadata_is_reparse_or_link(&metadata) {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                raw_sidecars.push(entry.path());
            }
        }
        let mut records = Vec::new();
        for (transaction_id, (journals, heads)) in grouped {
            let Some((&first_sequence, _)) = journals.first_key_value() else {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            };
            let mut decoded = BTreeMap::new();
            let mut previous_hash = None;
            for (offset, (sequence, journal)) in journals.iter().enumerate() {
                if *sequence != first_sequence + offset as u32 {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                let record = self.read_transaction_record(journal)?;
                if record.transaction_id != transaction_id || record.sequence != *sequence {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                if let Some(previous_hash) = previous_hash.as_deref()
                    && record.previous_record_hash.as_deref() != Some(previous_hash)
                {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                let record_hash = transaction_record_hash(&record)?;
                if let Some(head_path) = heads.get(sequence) {
                    let head = self.read_transaction_head(head_path)?;
                    if head.transaction_id != transaction_id
                        || head.sequence != *sequence
                        || head.record_hash != record_hash
                    {
                        return Err(ProviderAccountCommandError::recovery_required(
                            ProviderId::Codex,
                            None,
                        ));
                    }
                }
                previous_hash = Some(record_hash);
                decoded.insert(*sequence, record);
            }
            let latest = decoded
                .last_key_value()
                .map(|(_, record)| record)
                .expect("journal group is not empty");
            let cleanup = latest.phase == CodexTransactionPhase::Cleanup;
            if first_sequence != 0 && !cleanup {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            let latest_journal_sequence = latest.sequence;
            if let Some((&latest_head_sequence, _)) = heads.last_key_value()
                && latest_head_sequence > latest_journal_sequence
            {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            if !cleanup
                && (heads.len() != journals.len()
                    || heads.last_key_value().map(|(sequence, _)| *sequence)
                        != Some(latest_journal_sequence))
            {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            if let Some(current_head_path) = current_heads.remove(&transaction_id) {
                let current_head = self.read_transaction_head(&current_head_path)?;
                if current_head.transaction_id != transaction_id
                    || current_head.sequence != latest_journal_sequence
                    || current_head.record_hash != transaction_record_hash(latest)?
                {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
            } else if !cleanup {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            for (sequence, head_path) in &heads {
                let head = self.read_transaction_head(head_path)?;
                if head.transaction_id != transaction_id || head.sequence != *sequence {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                if let Some(record) = decoded.get(sequence) {
                    if head.record_hash != transaction_record_hash(record)? {
                        return Err(ProviderAccountCommandError::recovery_required(
                            ProviderId::Codex,
                            None,
                        ));
                    }
                } else if !cleanup || *sequence >= first_sequence {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
            }
            records.push(latest.clone());
        }
        if !current_heads.is_empty() {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        if records.len() > 1 {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        if !raw_sidecars.is_empty() {
            let Some(record) = records.first() else {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            };
            let allowed = [
                PathBuf::from(&record.paths.stage),
                PathBuf::from(&record.paths.backup),
                PathBuf::from(&record.paths.recovery),
                PathBuf::from(&record.paths.removed),
            ];
            for sidecar in raw_sidecars {
                if !allowed.contains(&sidecar) {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                Self::read_required_sidecar(&sidecar)?;
            }
        }
        Ok(records)
    }

    fn cleanup_transaction(
        record: &CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        let is_known_credential = |bytes: &[u8]| {
            bytes == record.intended_file
                || bytes == record.restore_guard_auth
                || record.expected_auth.as_deref() == Some(bytes)
                || record.displaced_auth.as_deref() == Some(bytes)
        };
        for path in [
            &record.paths.stage,
            &record.paths.backup,
            &record.paths.recovery,
            &record.paths.removed,
        ] {
            let path = Path::new(path);
            if let Some(bytes) = Self::read_optional_sidecar(path)? {
                if !is_known_credential(&bytes) {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                Self::cleanup_sidecar(path)?;
            }
        }
        let directory = PathBuf::from(&record.paths.transaction_directory);
        let journal_prefix = Path::new(&record.paths.journal_prefix)
            .file_name()
            .ok_or_else(|| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?
            .to_string_lossy()
            .into_owned();
        let mut journals = BTreeMap::new();
        let mut heads = BTreeMap::new();
        for entry in fs::read_dir(directory)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?
        {
            let entry = entry.map_err(|_| {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&journal_prefix)
                && name.ends_with(".journal")
                && let Some((transaction_id, sequence)) = parse_journal_name(&name)
                && transaction_id == record.transaction_id
            {
                journals.insert(sequence, entry.path());
            } else if name.starts_with(&journal_prefix)
                && name.ends_with(".head")
                && let Some((transaction_id, sequence)) = parse_head_name(&name)
                && transaction_id == record.transaction_id
            {
                heads.insert(sequence, entry.path());
            }
        }
        let current_head = PathBuf::from(format!("{}.head-current", record.paths.journal_prefix));
        Self::cleanup_sidecar(&current_head)?;
        for sequence in journals
            .keys()
            .chain(heads.keys())
            .copied()
            .filter(|sequence| *sequence != record.sequence)
            .collect::<std::collections::BTreeSet<_>>()
        {
            if let Some(head) = heads.get(&sequence) {
                Self::cleanup_sidecar(head)?;
            }
            if let Some(journal) = journals.get(&sequence) {
                Self::cleanup_sidecar(journal)?;
            }
        }
        if let Some(head) = heads.get(&record.sequence) {
            Self::cleanup_sidecar(head)?;
        }
        if let Some(journal) = journals.get(&record.sequence) {
            Self::cleanup_sidecar(journal)?;
        }
        Ok(())
    }

    fn finish_transaction(
        &self,
        record: &mut CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        if record.phase != CodexTransactionPhase::Cleanup {
            self.advance_transaction(record, CodexTransactionPhase::Cleanup)?;
            self.checkpoint(CodexTransactionCheckpoint::BeforeCleanup)?;
        }
        Self::cleanup_transaction(record)
    }

    fn recover_record(
        &self,
        record: &CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        let mut record = record.clone();
        if record.phase == CodexTransactionPhase::Cleanup {
            return Self::cleanup_transaction(&record);
        }

        let state = self.read_target_state()?;
        if matches!(
            record.phase,
            CodexTransactionPhase::Prepared | CodexTransactionPhase::Staged
        ) {
            let stage = Self::read_optional_sidecar(Path::new(&record.paths.stage))?;
            let backup = Self::read_optional_sidecar(Path::new(&record.paths.backup))?;
            let recovery = Self::read_optional_sidecar(Path::new(&record.paths.recovery))?;
            let removed = Self::read_optional_sidecar(Path::new(&record.paths.removed))?;
            let target_is_expected = state.auth == record.expected_auth
                && record.expected_config_hash
                    == optional_fingerprint_text(state.config.as_deref())
                && record.expected_mode == format!("{:?}", state.mode);
            let exact = match record.phase {
                CodexTransactionPhase::Prepared => {
                    target_is_expected
                        && stage.is_none()
                        && backup.is_none()
                        && recovery.is_none()
                        && removed.is_none()
                }
                CodexTransactionPhase::Staged => {
                    target_is_expected
                        && stage.as_deref() == Some(record.intended_file.as_slice())
                        && backup.is_none()
                        && recovery.is_none()
                        && removed.is_none()
                }
                _ => unreachable!("phase was matched above"),
            };
            if !exact {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            return self.finish_transaction(&mut record);
        }

        if record.phase == CodexTransactionPhase::RestoreMissingTarget {
            self.restore_missing_target(&record)?;
            return self.finish_transaction(&mut record);
        }

        if record.phase == CodexTransactionPhase::ExternalCaptured
            || record.phase == CodexTransactionPhase::RecoverySwap
        {
            self.restore_captured_external(&mut record)?;
            return self.finish_transaction(&mut record);
        }

        if record.phase == CodexTransactionPhase::RestoreRemovedExternal {
            self.restore_removed_external(&record)?;
            return self.finish_transaction(&mut record);
        }

        if record.phase == CodexTransactionPhase::DeleteMoveReady {
            self.complete_delete_move(&mut record)?;
            return self.finish_transaction(&mut record);
        }

        let backup = Self::read_optional_sidecar(Path::new(&record.paths.backup))?;
        if state.auth.is_none()
            && Self::read_optional_sidecar(Path::new(&record.paths.stage))?.as_deref()
                == Some(record.intended_file.as_slice())
            && let Some(displaced) = backup.as_deref()
        {
            record.displaced_auth = Some(displaced.to_vec());
            record.restore_guard_auth = record.intended_file.clone();
            self.advance_transaction(&mut record, CodexTransactionPhase::RestoreMissingTarget)?;
            self.restore_missing_target(&record)?;
            return self.finish_transaction(&mut record);
        }
        if state.auth.is_none() {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        if let (Some(expected), Some(displaced)) =
            (record.expected_auth.as_deref(), backup.as_deref())
            && displaced != expected
        {
            record.displaced_auth = Some(displaced.to_vec());
            record.restore_guard_auth = record.intended_file.clone();
            self.advance_transaction(&mut record, CodexTransactionPhase::ExternalCaptured)?;
            if state.auth.as_deref() == Some(record.intended_file.as_slice()) {
                self.restore_captured_external(&mut record)?;
            }
            return self.finish_transaction(&mut record);
        }

        if state.auth.as_deref() != Some(record.intended_file.as_slice()) {
            return self.finish_transaction(&mut record);
        }
        if record.expected_auth.is_some() && backup.is_none() {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        if record.expected_config_hash != optional_fingerprint_text(state.config.as_deref())
            || record.expected_mode != format!("{:?}", state.mode)
        {
            self.rollback_to_expected(&mut record)?;
            return self.finish_transaction(&mut record);
        }
        if record.intended_auth.is_none() {
            self.advance_transaction(&mut record, CodexTransactionPhase::DeleteMoveReady)?;
            self.complete_delete_move(&mut record)?;
        }
        self.finish_transaction(&mut record)
    }

    pub fn recover_pending_transactions(&self) -> Result<(), ProviderAccountCommandError> {
        self.with_recovered_operation(|| Ok(()))
    }

    fn checkpoint(
        &self,
        checkpoint: CodexTransactionCheckpoint,
    ) -> Result<(), ProviderAccountCommandError> {
        if (self.transaction_hook)(checkpoint) {
            Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ))
        } else {
            Ok(())
        }
    }

    fn publisher_checkpoint(
        &self,
        checkpoint: CodexPublisherCheckpoint,
    ) -> Result<(), ProviderAccountCommandError> {
        if (self.publisher_hook)(checkpoint) {
            Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ))
        } else {
            Ok(())
        }
    }

    fn replace_if_fingerprint(
        &self,
        replacement: Option<&[u8]>,
        expected_current_fingerprint: Option<&String>,
        require_file_store: bool,
    ) -> Result<(), ProviderAccountCommandError> {
        self.recover_pending_transactions()?;
        if self
            .checked_mutation_state(
                replacement,
                expected_current_fingerprint,
                require_file_store,
            )?
            .is_none()
        {
            return Ok(());
        }
        let _guard = self.acquire_transaction_guard()?;
        for pending in self.scan_transactions()? {
            self.recover_record(&pending)?;
        }
        let Some(current) = self.checked_mutation_state(
            replacement,
            expected_current_fingerprint,
            require_file_store,
        )?
        else {
            return Ok(());
        };
        fs::create_dir_all(&self.codex_home)
            .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
        let tombstone = replacement.is_none().then(Self::deletion_tombstone);
        let installed = replacement.unwrap_or_else(|| {
            tombstone
                .as_deref()
                .expect("deletion tombstone is present for a missing replacement")
        });
        let mut transaction = self.begin_transaction(&current, replacement, installed.to_vec())?;
        let staged = PathBuf::from(&transaction.paths.stage);
        secure_create_new(&staged, installed)?;
        self.advance_transaction(&mut transaction, CodexTransactionPhase::Staged)?;
        self.checkpoint(CodexTransactionCheckpoint::AfterStage)?;
        self.advance_transaction(&mut transaction, CodexTransactionPhase::SwapReady)?;
        self.checkpoint(CodexTransactionCheckpoint::BeforeSwap)?;
        let commit = self.commit_staged_auth(&mut transaction);
        if let Err(error) = commit {
            if !matches!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryFailed
                    | ProviderAccountCommandErrorCode::RecoveryRequired
            ) {
                self.finish_transaction(&mut transaction)?;
            }
            return Err(error);
        }

        let after = self.read_target_state()?;
        if after.auth.as_deref() != replacement {
            self.finish_transaction(&mut transaction)?;
            return Err(ProviderAccountCommandError::external_write(
                ProviderId::Codex,
                None,
            ));
        }
        if after.config != current.config || after.mode != current.mode {
            self.rollback_to_expected(&mut transaction)?;
            self.finish_transaction(&mut transaction)?;
            return Err(ProviderAccountCommandError::external_write(
                ProviderId::Codex,
                None,
            ));
        }
        self.finish_transaction(&mut transaction)?;
        Ok(())
    }

    fn checked_mutation_state(
        &self,
        replacement: Option<&[u8]>,
        expected_current_fingerprint: Option<&String>,
        require_file_store: bool,
    ) -> Result<Option<CodexTargetState>, ProviderAccountCommandError> {
        let current = self.read_target_state()?;
        if target_state_fingerprint(&current).as_ref() != expected_current_fingerprint {
            return Err(ProviderAccountCommandError::external_write(
                ProviderId::Codex,
                None,
            ));
        }
        if require_file_store && !current.mode.is_switchable() {
            return Err(ProviderAccountCommandError::unsupported_activation(
                ProviderId::Codex,
                None,
            ));
        }
        if current.auth.as_deref() == replacement {
            return Ok(None);
        }
        Ok(Some(current))
    }

    fn restore_missing_target(
        &self,
        transaction: &CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        let displaced = transaction.displaced_auth.as_deref().ok_or_else(|| {
            ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
        })?;
        let target = PathBuf::from(&transaction.canonical_target);
        let backup = PathBuf::from(&transaction.paths.backup);
        match self.read_target()? {
            Some(current) if current == displaced => return Ok(()),
            Some(_) => return Ok(()),
            None => {}
        }
        match Self::read_optional_sidecar(&backup)? {
            Some(bytes) if bytes == displaced => {}
            Some(_) => {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            None => secure_create_new(&backup, displaced)?,
        }
        if self.file_ops.move_no_replace(&backup, &target).is_err() {
            return match self.read_target()? {
                Some(_) => Ok(()),
                None => Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                )),
            };
        }
        self.checkpoint(CodexTransactionCheckpoint::AfterMissingTargetRestoreBeforeValidation)?;
        if self.read_target()?.is_some() {
            Ok(())
        } else {
            Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ))
        }
    }

    fn restore_captured_external(
        &self,
        transaction: &mut CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        let target = PathBuf::from(&transaction.canonical_target);
        let backup = PathBuf::from(&transaction.paths.backup);
        let recovery = PathBuf::from(&transaction.paths.recovery);
        for _ in 0..128 {
            let captured = transaction.displaced_auth.clone().ok_or_else(|| {
                ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
            })?;
            let guard = transaction.restore_guard_auth.clone();
            let current = self.read_target()?;

            if current.is_none() {
                let backup_bytes = Self::read_optional_sidecar(&backup)?;
                let recovery_bytes = Self::read_optional_sidecar(&recovery)?;
                if backup_bytes.as_deref() != Some(captured.as_slice())
                    || recovery_bytes.as_deref() != Some(guard.as_slice())
                {
                    return Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ));
                }
                if self.file_ops.move_no_replace(&backup, &target).is_err() {
                    return match self.read_target()? {
                        Some(_) => Ok(()),
                        None => Err(ProviderAccountCommandError::recovery_required(
                            ProviderId::Codex,
                            None,
                        )),
                    };
                }
                return Ok(());
            }
            if current.as_deref() == Some(captured.as_slice()) {
                if let Some(recovered) = Self::read_optional_sidecar(&recovery)? {
                    if recovered == guard {
                        return Ok(());
                    }
                    transaction.displaced_auth = Some(recovered);
                    transaction.restore_guard_auth = captured;
                    self.advance_transaction(transaction, CodexTransactionPhase::ExternalCaptured)?;
                    continue;
                }
                return Ok(());
            }
            if current.as_deref() != Some(guard.as_slice()) {
                return Ok(());
            }

            match Self::read_optional_sidecar(&backup)? {
                Some(bytes) if bytes == captured => {}
                Some(_) => {
                    Self::cleanup_sidecar(&backup)?;
                    secure_create_new(&backup, &captured)?;
                }
                None => secure_create_new(&backup, &captured)?,
            }
            Self::cleanup_sidecar(&recovery)?;
            self.advance_transaction(transaction, CodexTransactionPhase::RecoverySwap)?;
            self.file_ops
                .replace_with_backup(&target, &backup, &recovery)
                .map_err(|_| {
                    ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
                })?;
            self.checkpoint(CodexTransactionCheckpoint::AfterRecoverySwapBeforeValidation)?;
            let recovered = Self::read_required_sidecar(&recovery)?;
            if recovered == guard {
                return Ok(());
            }
            transaction.displaced_auth = Some(recovered);
            transaction.restore_guard_auth = captured;
            self.advance_transaction(transaction, CodexTransactionPhase::ExternalCaptured)?;
        }
        Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ))
    }

    fn rollback_to_expected(
        &self,
        transaction: &mut CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        if self.read_target()?.as_deref() != Some(transaction.intended_file.as_slice()) {
            return Err(ProviderAccountCommandError::external_write(
                ProviderId::Codex,
                None,
            ));
        }
        if let Some(expected) = transaction.expected_auth.clone() {
            transaction.displaced_auth = Some(expected);
            transaction.restore_guard_auth = transaction.intended_file.clone();
            self.advance_transaction(transaction, CodexTransactionPhase::ExternalCaptured)?;
            self.restore_captured_external(transaction)?;
        } else {
            self.advance_transaction(transaction, CodexTransactionPhase::DeleteMoveReady)?;
            self.complete_delete_move(transaction)?;
        }
        Ok(())
    }

    fn commit_staged_auth(
        &self,
        transaction: &mut CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        let target = PathBuf::from(&transaction.canonical_target);
        let staged = PathBuf::from(&transaction.paths.stage);
        let backup = PathBuf::from(&transaction.paths.backup);
        let Some(expected) = transaction.expected_auth.as_deref() else {
            if self.file_ops.move_no_replace(&staged, &target).is_err() {
                return if self.read_target()?.is_some() {
                    Err(ProviderAccountCommandError::external_write(
                        ProviderId::Codex,
                        None,
                    ))
                } else {
                    Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ))
                };
            }
            self.checkpoint(CodexTransactionCheckpoint::AfterReplaceBeforeValidation)?;
            return Ok(());
        };

        if self
            .file_ops
            .replace_with_backup(&target, &staged, &backup)
            .is_err()
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        self.checkpoint(CodexTransactionCheckpoint::AfterReplaceBeforeValidation)?;
        let displaced = Self::read_required_sidecar(&backup)?;
        if displaced != expected {
            transaction.displaced_auth = Some(displaced);
            self.advance_transaction(transaction, CodexTransactionPhase::ExternalCaptured)?;
            self.checkpoint(CodexTransactionCheckpoint::MismatchBeforeRestore)?;
            self.restore_captured_external(transaction)?;
            return Err(ProviderAccountCommandError::external_write(
                ProviderId::Codex,
                None,
            ));
        }

        if transaction.intended_auth.is_none() {
            self.advance_transaction(transaction, CodexTransactionPhase::DeleteMoveReady)?;
            self.complete_delete_move(transaction)?;
        }
        Ok(())
    }

    fn complete_delete_move(
        &self,
        transaction: &mut CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        let target = PathBuf::from(&transaction.canonical_target);
        let removed_path = PathBuf::from(&transaction.paths.removed);
        let current = self.read_target()?;
        let removed = Self::read_optional_sidecar(&removed_path)?;

        if current.as_deref() == Some(transaction.intended_file.as_slice()) {
            if removed.is_some() {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            if self
                .file_ops
                .move_no_replace(&target, &removed_path)
                .is_err()
            {
                return if self.read_target()?.as_deref()
                    == Some(transaction.intended_file.as_slice())
                {
                    Err(ProviderAccountCommandError::recovery_required(
                        ProviderId::Codex,
                        None,
                    ))
                } else {
                    self.complete_delete_move(transaction)
                };
            }
            self.checkpoint(CodexTransactionCheckpoint::AfterDeleteTombstoneMove)?;
            return self.complete_delete_move(transaction);
        }

        match (current.as_deref(), removed.as_deref()) {
            (None, Some(bytes)) if bytes == transaction.intended_file => Ok(()),
            (None, Some(bytes)) => {
                transaction.displaced_auth = Some(bytes.to_vec());
                transaction.restore_guard_auth = transaction.intended_file.clone();
                self.advance_transaction(
                    transaction,
                    CodexTransactionPhase::RestoreRemovedExternal,
                )?;
                self.restore_removed_external(transaction)
            }
            (None, None) => Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            )),
            (Some(_), None) => Ok(()),
            (Some(_), Some(bytes)) if bytes == transaction.intended_file => Ok(()),
            (Some(_), Some(bytes)) => {
                transaction.displaced_auth = Some(bytes.to_vec());
                transaction.restore_guard_auth = transaction.intended_file.clone();
                self.advance_transaction(
                    transaction,
                    CodexTransactionPhase::RestoreRemovedExternal,
                )?;
                self.restore_removed_external(transaction)
            }
        }
    }

    fn restore_removed_external(
        &self,
        transaction: &CodexTransactionRecord,
    ) -> Result<(), ProviderAccountCommandError> {
        let displaced = transaction.displaced_auth.as_deref().ok_or_else(|| {
            ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
        })?;
        let target = PathBuf::from(&transaction.canonical_target);
        let removed = PathBuf::from(&transaction.paths.removed);
        match self.read_target()? {
            Some(current) if current == displaced => return Ok(()),
            Some(_) => return Ok(()),
            None => {}
        }
        match Self::read_optional_sidecar(&removed)? {
            Some(bytes) if bytes == displaced => {}
            Some(_) => {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
            None => secure_create_new(&removed, displaced)?,
        }
        if self.file_ops.move_no_replace(&removed, &target).is_err() {
            return match self.read_target()? {
                Some(_) => Ok(()),
                None => Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                )),
            };
        }
        self.checkpoint(CodexTransactionCheckpoint::AfterRemovedExternalRestoreBeforeValidation)?;
        if self.read_target()?.is_some() {
            Ok(())
        } else {
            Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ))
        }
    }

    fn deletion_tombstone() -> Vec<u8> {
        let id = NEXT_CODEX_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        format!(
            "{{\"codexbar_transaction_tombstone\":\"{}-{id}\"}}",
            std::process::id()
        )
        .into_bytes()
    }

    fn read_required_sidecar(path: &Path) -> Result<Vec<u8>, ProviderAccountCommandError> {
        Self::read_optional_sidecar(path)?
            .ok_or_else(|| ProviderAccountCommandError::recovery_failed(ProviderId::Codex, None))
    }

    fn read_optional_sidecar(path: &Path) -> Result<Option<Vec<u8>>, ProviderAccountCommandError> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(ProviderAccountCommandError::recovery_required(
                    ProviderId::Codex,
                    None,
                ));
            }
        };
        let metadata = file
            .metadata()
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        if metadata_is_reparse_or_link(&metadata)
            || !metadata.is_file()
            || file_has_multiple_links(&file).unwrap_or(true)
        {
            return Err(ProviderAccountCommandError::recovery_required(
                ProviderId::Codex,
                None,
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
        Ok(Some(bytes))
    }

    fn cleanup_sidecar(path: &Path) -> Result<(), ProviderAccountCommandError> {
        if Self::read_optional_sidecar(path)?.is_none() {
            return Ok(());
        }
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ProviderAccountCommandError::recovery_failed(
                ProviderId::Codex,
                None,
            )),
        }
    }

    pub(crate) fn declaration(self) -> ProviderAdapterDeclaration {
        ProviderAdapterDeclaration::with_conditional_adapter(
            ProviderId::Codex,
            vec![
                ProviderEnrollmentKind::CliLogin,
                ProviderEnrollmentKind::ImportCurrent,
            ],
            std::sync::Arc::new(self),
        )
    }
}

impl fmt::Debug for CodexFileAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexFileAdapter")
            .field("target", &"Codex CLI auth.json")
            .finish()
    }
}

impl CredentialActivationAdapter for CodexFileAdapter {
    fn provider(&self) -> ProviderId {
        ProviderId::Codex
    }

    fn support(&self) -> ActivationSupport {
        match self.with_recovered_operation(|| self.read_target_state()) {
            Ok(state) if state.mode.is_switchable() => ActivationSupport {
                kind: ActivationTargetKind::CliFile,
                target_description: Some("Codex CLI auth.json".into()),
                blocked_reason: None,
            },
            Ok(_) => ActivationSupport::unsupported_with_reason(CODEX_FILE_STORE_REASON),
            Err(error) => ActivationSupport::unsupported_with_reason(error.to_string()),
        }
    }

    fn capture(&self) -> Result<CredentialTargetSnapshot, ProviderAccountCommandError> {
        self.with_recovered_operation(|| {
            let state = self.read_target_state()?;
            Ok(CredentialTargetSnapshot {
                fingerprint: target_state_fingerprint(&state),
                credentials: state.auth.as_deref().map(Self::raw_bundle),
            })
        })
    }

    fn fingerprint(&self) -> Result<Option<String>, ProviderAccountCommandError> {
        self.with_recovered_operation(|| {
            self.read_target_state()
                .map(|state| target_state_fingerprint(&state))
        })
    }

    fn target_fingerprint(
        &self,
        credentials: &ProviderCredentialBundle,
    ) -> Result<Option<String>, ProviderAccountCommandError> {
        self.with_recovered_operation(|| {
            let current = self.read_target_state()?;
            Ok(target_fingerprint(
                Some(Self::artifact(credentials)?),
                current.config.as_deref(),
                current.mode,
            ))
        })
    }

    fn current_identity(
        &self,
    ) -> Result<Option<ProviderAccountIdentity>, ProviderAccountCommandError> {
        self.with_recovered_operation(|| {
            self.read_target()?
                .as_deref()
                .map(Self::identity)
                .transpose()
        })
    }

    fn validate_target(
        &self,
        identity: &ProviderAccountIdentity,
        credentials: &ProviderCredentialBundle,
    ) -> Result<(), ProviderAccountCommandError> {
        self.with_recovered_operation(|| {
            if identity.provider != ProviderId::Codex || !identity.is_activation_eligible() {
                return Err(ProviderAccountCommandError::invalid_credential(
                    ProviderId::Codex,
                    None,
                ));
            }
            let parsed = Self::identity(Self::artifact(credentials)?)?;
            if !parsed.matches_stable_without_namespace_conflicts(identity) {
                return Err(ProviderAccountCommandError::identity_mismatch(
                    ProviderId::Codex,
                    None,
                ));
            }
            Ok(())
        })
    }

    fn install(
        &self,
        credentials: &ProviderCredentialBundle,
        expected_current_fingerprint: &Option<String>,
    ) -> Result<(), ProviderAccountCommandError> {
        self.recover_pending_transactions()?;
        let artifact = Self::artifact(credentials)?;
        Self::identity(artifact)?;
        self.replace_if_fingerprint(Some(artifact), expected_current_fingerprint.as_ref(), true)
    }

    fn verify(
        &self,
        identity: &ProviderAccountIdentity,
    ) -> Result<(), ProviderAccountCommandError> {
        let current = self.current_identity()?.ok_or_else(|| {
            ProviderAccountCommandError::identity_mismatch(ProviderId::Codex, None)
        })?;
        if current.matches_stable_without_namespace_conflicts(identity) {
            Ok(())
        } else {
            Err(ProviderAccountCommandError::identity_mismatch(
                ProviderId::Codex,
                None,
            ))
        }
    }

    fn restore(
        &self,
        snapshot: &CredentialTargetSnapshot,
        expected_current_fingerprint: &Option<String>,
    ) -> Result<(), ProviderAccountCommandError> {
        self.recover_pending_transactions()?;
        let replacement = snapshot
            .credentials
            .as_ref()
            .map(Self::artifact)
            .transpose()?;
        self.replace_if_fingerprint(replacement, expected_current_fingerprint.as_ref(), false)
    }

    fn restart_hint(&self) -> RestartHint {
        RestartHint {
            required: true,
            client_name: Some("Codex".into()),
            message: Some("Restart Codex to use the activated account.".into()),
        }
    }
}

fn fingerprint(bytes: Option<&[u8]>) -> Option<String> {
    bytes.map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn target_state_fingerprint(state: &CodexTargetState) -> Option<String> {
    target_fingerprint(state.auth.as_deref(), state.config.as_deref(), state.mode)
}

fn target_fingerprint(
    auth: Option<&[u8]>,
    config: Option<&[u8]>,
    mode: CodexCredentialStoreMode,
) -> Option<String> {
    Some(format!(
        "codex-target-v2:auth={};config={};mode={mode:?}",
        fingerprint(auth).as_deref().unwrap_or("missing"),
        fingerprint(config).as_deref().unwrap_or("missing"),
    ))
}

fn optional_fingerprint_text(bytes: Option<&[u8]>) -> String {
    fingerprint(bytes).unwrap_or_else(|| "missing".into())
}

fn transaction_record_hash(
    record: &CodexTransactionRecord,
) -> Result<String, ProviderAccountCommandError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|_| ProviderAccountCommandError::internal(ProviderId::Codex, None))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn parse_journal_name(name: &str) -> Option<(String, u32)> {
    let body = name
        .strip_prefix("codexbar-txn-")?
        .strip_suffix(".journal")?;
    let (transaction_id, sequence) = body.rsplit_once('-')?;
    let sequence = sequence.parse().ok()?;
    if transaction_id.is_empty()
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some((transaction_id.to_owned(), sequence))
}

fn parse_head_name(name: &str) -> Option<(String, u32)> {
    let body = name.strip_prefix("codexbar-txn-")?.strip_suffix(".head")?;
    let (transaction_id, sequence) = body.rsplit_once('-')?;
    let sequence = sequence.parse().ok()?;
    if transaction_id.is_empty()
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some((transaction_id.to_owned(), sequence))
}

fn parse_current_head_name(name: &str) -> Option<String> {
    let transaction_id = name
        .strip_prefix("codexbar-txn-")?
        .strip_suffix(".head-current")?;
    if transaction_id.is_empty()
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some(transaction_id.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexPublicationArtifact {
    JournalPublishing,
    GenerationHeadPublishing,
    CurrentPublishing,
    CurrentPrevious,
}

fn parse_publication_artifact_name(name: &str) -> Option<(String, u32, CodexPublicationArtifact)> {
    let (body, kind) = [
        (
            ".journal-publishing",
            CodexPublicationArtifact::JournalPublishing,
        ),
        (
            ".head-publishing",
            CodexPublicationArtifact::GenerationHeadPublishing,
        ),
        (
            ".current-publishing",
            CodexPublicationArtifact::CurrentPublishing,
        ),
        (
            ".current-previous",
            CodexPublicationArtifact::CurrentPrevious,
        ),
    ]
    .into_iter()
    .find_map(|(suffix, kind)| name.strip_suffix(suffix).map(|body| (body, kind)))?;
    let body = body.strip_prefix("codexbar-txn-")?;
    let (transaction_id, sequence) = body.rsplit_once('-')?;
    let sequence = sequence.parse().ok()?;
    if transaction_id.is_empty()
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some((transaction_id.to_owned(), sequence, kind))
}

fn secure_publish_new(
    adapter: &CodexFileAdapter,
    path: &Path,
    bytes: &[u8],
    kind: CodexPublisherArtifactKind,
    sequence: u32,
) -> Result<(), ProviderAccountCommandError> {
    let temporary = publication_temporary_path(path, kind, sequence)?;
    secure_create_new(&temporary, bytes)?;
    if CodexFileAdapter::read_optional_sidecar(&temporary)?.as_deref() != Some(bytes) {
        return Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ));
    }
    adapter.publisher_checkpoint(CodexPublisherCheckpoint::TemporaryVerified { kind, sequence })?;
    atomic_move_no_replace(&temporary, path)
        .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
    if CodexFileAdapter::read_optional_sidecar(path)?.as_deref() != Some(bytes) {
        return Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ));
    }
    Ok(())
}

fn secure_publish_current(
    adapter: &CodexFileAdapter,
    path: &Path,
    bytes: &[u8],
    sequence: u32,
) -> Result<(), ProviderAccountCommandError> {
    let Some(previous) = CodexFileAdapter::read_optional_sidecar(path)? else {
        return secure_publish_new(
            adapter,
            path,
            bytes,
            CodexPublisherArtifactKind::CurrentHead,
            sequence,
        );
    };
    let temporary =
        publication_temporary_path(path, CodexPublisherArtifactKind::CurrentHead, sequence)?;
    let backup = publication_previous_path(path, sequence)?;
    if CodexFileAdapter::read_optional_sidecar(&backup)?.is_some() {
        return Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ));
    }
    secure_create_new(&temporary, bytes)?;
    if CodexFileAdapter::read_optional_sidecar(&temporary)?.as_deref() != Some(bytes) {
        return Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ));
    }
    adapter.publisher_checkpoint(CodexPublisherCheckpoint::TemporaryVerified {
        kind: CodexPublisherArtifactKind::CurrentHead,
        sequence,
    })?;
    adapter
        .publisher_ops
        .replace_current(path, &temporary, &backup)
        .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
    if CodexFileAdapter::read_optional_sidecar(path)?.as_deref() != Some(bytes)
        || CodexFileAdapter::read_optional_sidecar(&backup)?.as_deref() != Some(previous.as_slice())
    {
        return Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ));
    }
    adapter.publisher_checkpoint(
        CodexPublisherCheckpoint::CurrentReplaceBeforePreviousCleanup { sequence },
    )?;
    CodexFileAdapter::cleanup_sidecar(&backup)
}

fn publication_temporary_path(
    final_path: &Path,
    kind: CodexPublisherArtifactKind,
    sequence: u32,
) -> Result<PathBuf, ProviderAccountCommandError> {
    match kind {
        CodexPublisherArtifactKind::Journal => Ok(final_path.with_extension("journal-publishing")),
        CodexPublisherArtifactKind::GenerationHead => {
            Ok(final_path.with_extension("head-publishing"))
        }
        CodexPublisherArtifactKind::CurrentHead => {
            let file_name = final_path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".head-current"))
                .ok_or_else(|| {
                    ProviderAccountCommandError::recovery_required(ProviderId::Codex, None)
                })?;
            Ok(final_path.with_file_name(format!("{file_name}-{sequence}.current-publishing")))
        }
    }
}

fn publication_previous_path(
    current_path: &Path,
    sequence: u32,
) -> Result<PathBuf, ProviderAccountCommandError> {
    let file_name = current_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".head-current"))
        .ok_or_else(|| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
    Ok(current_path.with_file_name(format!("{file_name}-{sequence}.current-previous")))
}

fn secure_create_new(path: &Path, bytes: &[u8]) -> Result<(), ProviderAccountCommandError> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
    let metadata = file
        .metadata()
        .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))?;
    if metadata_is_reparse_or_link(&metadata)
        || !metadata.is_file()
        || file_has_multiple_links(&file).unwrap_or(true)
    {
        return Err(ProviderAccountCommandError::recovery_required(
            ProviderId::Codex,
            None,
        ));
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProviderAccountCommandError::recovery_required(ProviderId::Codex, None))
}

#[cfg(windows)]
fn open_exclusive_lock(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_exclusive_lock(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

fn is_lock_contention(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
    ) || cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33))
}

#[cfg(windows)]
fn metadata_is_reparse_or_link(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_or_link(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

pub struct CodexLoginInvocation {
    command: Command,
    timeout: Duration,
    hide_windows_console: bool,
}

impl CodexLoginInvocation {
    pub fn new(codex_home: &Path) -> Self {
        let mut command = Command::new("codex");
        command
            .arg("login")
            .arg("-c")
            .arg("cli_auth_credentials_store=\"file\"")
            .env("CODEX_HOME", codex_home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            command.creation_flags(0x0800_0000);
        }
        Self {
            command,
            timeout: CODEX_LOGIN_TIMEOUT,
            hide_windows_console: true,
        }
    }

    pub const fn command(&self) -> &Command {
        &self.command
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub const fn hides_windows_console(&self) -> bool {
        self.hide_windows_console
    }
}

impl fmt::Debug for CodexLoginInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexLoginInvocation")
            .field("program", &"codex")
            .field("timeout", &self.timeout)
            .field("hide_windows_console", &self.hide_windows_console)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexLoginRunResult {
    Succeeded,
    Cancelled,
    TimedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum CodexEnrollmentError {
    #[error("Codex login could not be started")]
    StartFailed,
    #[error("Codex login could not be monitored")]
    MonitorFailed,
    #[error("Codex login child process could not be terminated and reaped")]
    CleanupFailed,
    #[error("Codex login did not complete successfully")]
    LoginFailed,
    #[error("Codex login did not produce a valid auth.json")]
    InvalidCredential,
}

pub trait CodexLoginRunner: Send + Sync + fmt::Debug {
    fn run(
        &self,
        invocation: &mut CodexLoginInvocation,
        cancellation: &AtomicBool,
    ) -> Result<CodexLoginRunResult, CodexEnrollmentError>;
}

#[derive(Debug, Default)]
pub struct ProcessCodexLoginRunner;

trait CodexChildControl {
    fn try_wait(&mut self) -> Result<Option<bool>, ()>;
    fn terminate(&mut self) -> Result<(), ()>;
    fn reap(&mut self) -> Result<(), ()>;
}

impl CodexChildControl for std::process::Child {
    fn try_wait(&mut self) -> Result<Option<bool>, ()> {
        std::process::Child::try_wait(self)
            .map(|status| status.map(|status| status.success()))
            .map_err(|_| ())
    }

    fn terminate(&mut self) -> Result<(), ()> {
        self.kill().map_err(|_| ())
    }

    fn reap(&mut self) -> Result<(), ()> {
        self.wait().map(|_| ()).map_err(|_| ())
    }
}

fn terminate_and_reap(child: &mut dyn CodexChildControl) -> Result<(), CodexEnrollmentError> {
    let terminated = child.terminate();
    let reaped = child.reap();
    if terminated.is_err() || reaped.is_err() {
        Err(CodexEnrollmentError::CleanupFailed)
    } else {
        Ok(())
    }
}

fn monitor_codex_child(
    child: &mut dyn CodexChildControl,
    cancellation: &AtomicBool,
    mut timed_out: impl FnMut() -> bool,
    mut wait_before_retry: impl FnMut(),
) -> Result<CodexLoginRunResult, CodexEnrollmentError> {
    loop {
        if cancellation.load(Ordering::SeqCst) {
            terminate_and_reap(child)?;
            return Ok(CodexLoginRunResult::Cancelled);
        }
        match child.try_wait() {
            Ok(Some(true)) => return Ok(CodexLoginRunResult::Succeeded),
            Ok(Some(false)) => return Err(CodexEnrollmentError::LoginFailed),
            Ok(None) => {}
            Err(()) => {
                terminate_and_reap(child)?;
                return Err(CodexEnrollmentError::MonitorFailed);
            }
        }
        if timed_out() {
            terminate_and_reap(child)?;
            return Ok(CodexLoginRunResult::TimedOut);
        }
        wait_before_retry();
    }
}

impl CodexLoginRunner for ProcessCodexLoginRunner {
    fn run(
        &self,
        invocation: &mut CodexLoginInvocation,
        cancellation: &AtomicBool,
    ) -> Result<CodexLoginRunResult, CodexEnrollmentError> {
        let mut child = invocation
            .command
            .spawn()
            .map_err(|_| CodexEnrollmentError::StartFailed)?;
        let deadline = Instant::now() + invocation.timeout;
        monitor_codex_child(
            &mut child,
            cancellation,
            || Instant::now() >= deadline,
            || thread::sleep(Duration::from_millis(250)),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexEnrollmentOutcome {
    Captured {
        identity: ProviderAccountIdentity,
        credentials: ProviderCredentialBundle,
    },
    Cancelled,
    TimedOut,
}

pub fn run_codex_enrollment(
    runner: &dyn CodexLoginRunner,
    cancellation: &AtomicBool,
) -> Result<CodexEnrollmentOutcome, CodexEnrollmentError> {
    let temporary_home = tempfile::tempdir().map_err(|_| CodexEnrollmentError::StartFailed)?;
    let mut invocation = CodexLoginInvocation::new(temporary_home.path());
    match runner.run(&mut invocation, cancellation)? {
        CodexLoginRunResult::Cancelled => Ok(CodexEnrollmentOutcome::Cancelled),
        CodexLoginRunResult::TimedOut => Ok(CodexEnrollmentOutcome::TimedOut),
        CodexLoginRunResult::Succeeded => {
            let auth_json = fs::read(temporary_home.path().join("auth.json"))
                .map_err(|_| CodexEnrollmentError::InvalidCredential)?;
            let identity = CodexFileAdapter::identity(&auth_json)
                .map_err(|_| CodexEnrollmentError::InvalidCredential)?;
            let credentials = CodexFileAdapter::credential_bundle(&auth_json)
                .map_err(|_| CodexEnrollmentError::InvalidCredential)?;
            Ok(CodexEnrollmentOutcome::Captured {
                identity,
                credentials,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_accounts::{
        CredentialActivationAdapter, ProviderAccountCommandErrorCode, ProviderAdapterRegistry,
        ProviderAdapterRegistryError,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use codexbar_engine::{
        ActivationTargetKind, ProviderCredentialBundle,
        auth::{
            credentials::{CodexCredentialStoreMode, parse_codex_credential_store_mode},
            dpapi::{SecretCodec, SecretError},
        },
    };
    use std::{
        ffi::OsStr,
        fs,
        path::{Path, PathBuf},
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    fn auth_json(account_id: Option<&str>, subject: Option<&str>, email: Option<&str>) -> Vec<u8> {
        let claims = serde_json::json!({
            "sub": subject,
            "email": email,
        });
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let mut tokens = serde_json::json!({
            "access_token": "access-secret",
            "refresh_token": "refresh-secret",
            "id_token": format!("header.{claims}.signature"),
        });
        if let Some(account_id) = account_id {
            tokens["account_id"] = serde_json::Value::String(account_id.into());
        }
        serde_json::to_vec(&serde_json::json!({
            "tokens": tokens,
            "future": {"preserved": true},
        }))
        .unwrap()
    }

    fn adapter_fixture(config: &str, auth: &[u8]) -> (tempfile::TempDir, CodexFileAdapter) {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("config.toml"), config).unwrap();
        fs::write(temporary.path().join("auth.json"), auth).unwrap();
        let adapter = CodexFileAdapter::new(temporary.path().to_path_buf());
        (temporary, adapter)
    }

    fn transaction_residue(directory: &Path) -> Vec<PathBuf> {
        fs::read_dir(directory)
            .unwrap()
            .flatten()
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.contains(".tmp-") || name.contains(".codexbar-transaction-")
            })
            .map(|entry| entry.path())
            .collect()
    }

    fn directory_tree(directory: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(root: &Path, current: &Path, entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            if !current.exists() {
                return;
            }
            for entry in fs::read_dir(current).unwrap().flatten() {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                if path.is_dir() {
                    entries.insert(relative, None);
                    visit(root, &path, entries);
                } else {
                    entries.insert(relative, Some(fs::read(path).unwrap()));
                }
            }
        }

        let mut entries = BTreeMap::new();
        visit(directory, directory, &mut entries);
        entries
    }

    fn tree_contains_file_bytes(directory: &Path, expected: &[u8]) -> bool {
        directory_tree(directory)
            .values()
            .any(|bytes| bytes.as_deref() == Some(expected))
    }

    #[derive(Debug)]
    struct ReplaceErrorFileOps {
        error: i32,
    }

    impl CodexFileOps for ReplaceErrorFileOps {
        fn replace_with_backup(
            &self,
            destination: &Path,
            replacement: &Path,
            backup: &Path,
        ) -> std::io::Result<()> {
            if self.error == 1177 {
                atomic_move_no_replace(destination, backup)?;
            }
            let _ = replacement;
            Err(std::io::Error::from_raw_os_error(self.error))
        }

        fn move_no_replace(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
            atomic_move_no_replace(source, destination)
        }
    }

    #[derive(Debug)]
    struct DeleteMoveErrorFileOps;

    impl CodexFileOps for DeleteMoveErrorFileOps {
        fn replace_with_backup(
            &self,
            destination: &Path,
            replacement: &Path,
            backup: &Path,
        ) -> std::io::Result<()> {
            atomic_replace_with_backup(destination, replacement, backup)
        }

        fn move_no_replace(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
            if source.file_name() == Some(OsStr::new("auth.json"))
                && destination.extension() == Some(OsStr::new("removed"))
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "simulated delete move failure",
                ))
            } else {
                atomic_move_no_replace(source, destination)
            }
        }
    }

    #[derive(Debug)]
    struct MissingTargetReplaceErrorFileOps;

    impl CodexFileOps for MissingTargetReplaceErrorFileOps {
        fn replace_with_backup(
            &self,
            destination: &Path,
            _replacement: &Path,
            _backup: &Path,
        ) -> std::io::Result<()> {
            fs::remove_file(destination)?;
            Err(std::io::Error::from_raw_os_error(5))
        }

        fn move_no_replace(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
            atomic_move_no_replace(source, destination)
        }
    }

    #[derive(Debug)]
    struct PublisherReplace1177Ops;

    impl CodexPublisherOps for PublisherReplace1177Ops {
        fn replace_current(
            &self,
            destination: &Path,
            _replacement: &Path,
            backup: &Path,
        ) -> std::io::Result<()> {
            atomic_move_no_replace(destination, backup)?;
            Err(std::io::Error::from_raw_os_error(1177))
        }
    }

    #[derive(Debug)]
    struct AuthenticatedTestCodec;

    impl SecretCodec for AuthenticatedTestCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            let mut protected = Sha256::digest(plaintext).to_vec();
            protected.extend(plaintext.iter().map(|byte| byte ^ 0x5a));
            Ok(protected)
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            if ciphertext.len() < 32 {
                return Err(SecretError::Platform(
                    "test transaction envelope failed authentication".into(),
                ));
            }
            let plaintext = ciphertext[32..]
                .iter()
                .map(|byte| byte ^ 0x5a)
                .collect::<Vec<_>>();
            if ciphertext[..32] != Sha256::digest(&plaintext)[..] {
                return Err(SecretError::Platform(
                    "test transaction envelope failed authentication".into(),
                ));
            }
            Ok(plaintext)
        }
    }

    fn test_codec() -> Arc<dyn SecretCodec> {
        Arc::new(AuthenticatedTestCodec)
    }

    #[test]
    fn credential_store_mode_requires_one_explicit_root_file_value() {
        let fixtures = [
            (
                "cli_auth_credentials_store = \"file\"",
                CodexCredentialStoreMode::File,
            ),
            (
                "cli_auth_credentials_store = \"keyring\"",
                CodexCredentialStoreMode::Keyring,
            ),
            (
                "cli_auth_credentials_store = \"auto\"",
                CodexCredentialStoreMode::Auto,
            ),
            ("model = \"gpt-5.2-codex\"", CodexCredentialStoreMode::Unset),
            (
                "[profile]\ncli_auth_credentials_store = \"file\"",
                CodexCredentialStoreMode::Unset,
            ),
            (
                "cli_auth_credentials_store = \"file\"\ncli_auth_credentials_store = \"file\"",
                CodexCredentialStoreMode::Invalid,
            ),
            (
                "cli_auth_credentials_store = \"file\"\n[profile",
                CodexCredentialStoreMode::Invalid,
            ),
            (
                "cli_auth_credentials_store = 1",
                CodexCredentialStoreMode::Invalid,
            ),
        ];

        for (contents, expected) in fixtures {
            assert_eq!(
                parse_codex_credential_store_mode(contents),
                expected,
                "fixture: {contents}"
            );
        }
        assert!(CodexCredentialStoreMode::File.is_switchable());
        for mode in [
            CodexCredentialStoreMode::Keyring,
            CodexCredentialStoreMode::Auto,
            CodexCredentialStoreMode::Unset,
            CodexCredentialStoreMode::Invalid,
        ] {
            assert!(!mode.is_switchable());
        }
    }

    #[test]
    fn identity_uses_only_official_account_id_or_jwt_subject() {
        let both = CodexFileAdapter::identity(&auth_json(
            Some("acct-1"),
            Some("subject-1"),
            Some("a@b.c"),
        ))
        .unwrap();
        assert!(
            both.stable_keys
                .iter()
                .any(|key| key.namespace == "codex-account-id" && key.value == "acct-1")
        );
        assert!(
            both.stable_keys
                .iter()
                .any(|key| key.namespace == "jwt-sub" && key.value == "subject-1")
        );

        let subject =
            CodexFileAdapter::identity(&auth_json(None, Some("subject-only"), None)).unwrap();
        assert_eq!(subject.stable_keys[0].namespace, "jwt-sub");
        assert!(
            CodexFileAdapter::identity(&auth_json(None, None, Some("email-only@example.com")))
                .is_err()
        );
    }

    #[test]
    fn complete_auth_json_is_the_only_adapter_artifact_and_debug_is_redacted() {
        let auth = auth_json(Some("acct-artifact"), Some("subject-artifact"), None);
        let bundle = CodexFileAdapter::credential_bundle(&auth).unwrap();

        assert_eq!(bundle.artifact_format.as_deref(), Some("codex-auth-json"));
        assert_eq!(bundle.artifact.as_deref(), Some(auth.as_slice()));
        assert!(bundle.api_key.is_none());
        let debug = format!("{bundle:?}");
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("refresh-secret"));

        let invalid = ProviderCredentialBundle {
            artifact_format: Some("codex-auth-json".into()),
            artifact: Some(b"{\"token\":\"credential-secret\"".to_vec()),
            ..Default::default()
        };
        let (_, adapter) = adapter_fixture(
            "cli_auth_credentials_store = \"file\"",
            &auth_json(Some("current"), None, None),
        );
        let error = adapter
            .validate_target(
                &CodexFileAdapter::identity(&auth_json(Some("target"), None, None)).unwrap(),
                &invalid,
            )
            .unwrap_err();
        for output in [
            error.to_string(),
            format!("{error:?}"),
            serde_json::to_string(&error).unwrap(),
        ] {
            assert!(!output.contains("credential-secret"));
            assert!(!output.contains("token"));
        }
    }

    #[test]
    fn login_command_is_fixed_no_shell_isolated_and_requests_hidden_console() {
        let home = Path::new("C:/temporary-codex-home");
        let invocation = CodexLoginInvocation::new(home);
        let command = invocation.command();

        assert_eq!(command.get_program(), OsStr::new("codex"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("login"),
                OsStr::new("-c"),
                OsStr::new("cli_auth_credentials_store=\"file\"")
            ]
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new("CODEX_HOME"))
                .and_then(|(_, value)| value),
            Some(home.as_os_str())
        );
        assert_eq!(invocation.timeout(), Duration::from_secs(600));
        assert!(invocation.hides_windows_console());
    }

    #[derive(Debug)]
    struct FakeChild {
        monitor_result: Result<Option<bool>, ()>,
        terminate_result: Result<(), ()>,
        reap_result: Result<(), ()>,
        terminate_calls: usize,
        reap_calls: usize,
    }

    impl CodexChildControl for FakeChild {
        fn try_wait(&mut self) -> Result<Option<bool>, ()> {
            self.monitor_result
        }

        fn terminate(&mut self) -> Result<(), ()> {
            self.terminate_calls += 1;
            self.terminate_result
        }

        fn reap(&mut self) -> Result<(), ()> {
            self.reap_calls += 1;
            self.reap_result
        }
    }

    fn fake_child(
        monitor_result: Result<Option<bool>, ()>,
        terminate_result: Result<(), ()>,
        reap_result: Result<(), ()>,
    ) -> FakeChild {
        FakeChild {
            monitor_result,
            terminate_result,
            reap_result,
            terminate_calls: 0,
            reap_calls: 0,
        }
    }

    #[test]
    fn monitor_error_terminates_and_reaps_child_before_returning() {
        let mut child = fake_child(Err(()), Ok(()), Ok(()));

        let error =
            monitor_codex_child(&mut child, &AtomicBool::new(false), || false, || {}).unwrap_err();

        assert!(matches!(error, CodexEnrollmentError::MonitorFailed));
        assert_eq!(child.terminate_calls, 1);
        assert_eq!(child.reap_calls, 1);
    }

    #[test]
    fn cancellation_reports_cleanup_failure_when_child_cannot_be_terminated() {
        let mut child = fake_child(Ok(None), Err(()), Ok(()));

        let error =
            monitor_codex_child(&mut child, &AtomicBool::new(true), || false, || {}).unwrap_err();

        assert!(matches!(error, CodexEnrollmentError::CleanupFailed));
        assert_eq!(child.terminate_calls, 1);
        assert_eq!(child.reap_calls, 1);
    }

    #[test]
    fn timeout_reports_cleanup_failure_when_child_cannot_be_reaped() {
        let mut child = fake_child(Ok(None), Ok(()), Err(()));

        let error =
            monitor_codex_child(&mut child, &AtomicBool::new(false), || true, || {}).unwrap_err();

        assert!(matches!(error, CodexEnrollmentError::CleanupFailed));
        assert_eq!(child.terminate_calls, 1);
        assert_eq!(child.reap_calls, 1);
    }

    #[derive(Debug)]
    struct FakeRunner {
        result: CodexLoginRunResult,
        captured_home: Arc<Mutex<Option<PathBuf>>>,
        auth: Vec<u8>,
    }

    impl CodexLoginRunner for FakeRunner {
        fn run(
            &self,
            invocation: &mut CodexLoginInvocation,
            cancellation: &AtomicBool,
        ) -> Result<CodexLoginRunResult, CodexEnrollmentError> {
            let home = invocation
                .command()
                .get_envs()
                .find(|(key, _)| *key == OsStr::new("CODEX_HOME"))
                .and_then(|(_, value)| value)
                .map(PathBuf::from)
                .unwrap();
            *self.captured_home.lock().unwrap() = Some(home.clone());
            assert_eq!(invocation.timeout(), Duration::from_secs(600));
            if self.result == CodexLoginRunResult::Succeeded {
                fs::write(home.join("auth.json"), &self.auth).unwrap();
            }
            if self.result == CodexLoginRunResult::Cancelled {
                assert!(cancellation.load(Ordering::SeqCst));
            }
            Ok(self.result)
        }
    }

    #[test]
    fn enrollment_uses_fake_runner_captures_complete_artifact_and_cleans_temporary_home() {
        let captured_home = Arc::new(Mutex::new(None));
        let auth = auth_json(Some("enrolled-account"), Some("enrolled-subject"), None);
        let runner = FakeRunner {
            result: CodexLoginRunResult::Succeeded,
            captured_home: captured_home.clone(),
            auth: auth.clone(),
        };

        let outcome = run_codex_enrollment(&runner, &AtomicBool::new(false)).unwrap();

        let CodexEnrollmentOutcome::Captured {
            identity,
            credentials,
        } = outcome
        else {
            panic!("expected captured enrollment");
        };
        assert!(identity.is_activation_eligible());
        assert_eq!(credentials.artifact.as_deref(), Some(auth.as_slice()));
        assert!(!captured_home.lock().unwrap().as_ref().unwrap().exists());
    }

    #[test]
    fn enrollment_propagates_cancellation_and_cleans_temporary_home() {
        let captured_home = Arc::new(Mutex::new(None));
        let runner = FakeRunner {
            result: CodexLoginRunResult::Cancelled,
            captured_home: captured_home.clone(),
            auth: Vec::new(),
        };
        let cancellation = AtomicBool::new(true);

        assert_eq!(
            run_codex_enrollment(&runner, &cancellation).unwrap(),
            CodexEnrollmentOutcome::Cancelled
        );
        assert!(!captured_home.lock().unwrap().as_ref().unwrap().exists());
    }

    #[test]
    fn file_adapter_captures_installs_verifies_and_restores_complete_auth_atomically() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, adapter) =
            adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        assert_eq!(adapter.support().kind, ActivationTargetKind::CliFile);
        let snapshot = adapter.capture().unwrap();
        let replacement_bundle = CodexFileAdapter::credential_bundle(&replacement).unwrap();
        let replacement_identity = CodexFileAdapter::identity(&replacement).unwrap();

        adapter
            .install(&replacement_bundle, &snapshot.fingerprint)
            .unwrap();
        adapter.verify(&replacement_identity).unwrap();
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            replacement
        );
        assert!(
            fs::read_dir(temporary.path())
                .unwrap()
                .flatten()
                .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp-"))
        );

        let installed = adapter.fingerprint().unwrap();
        adapter.restore(&snapshot, &installed).unwrap();
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
    }

    #[test]
    fn crash_after_stage_is_recovered_by_a_new_adapter_from_an_encrypted_journal() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterStage
                }));

        let error = crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        let transaction_dir = temporary.path().join(".codexbar-transactions");
        let journal_bytes = fs::read_dir(&transaction_dir)
            .unwrap()
            .flatten()
            .find(|entry| entry.file_name().to_string_lossy().ends_with(".journal"))
            .map(|entry| fs::read(entry.path()).unwrap())
            .unwrap();
        assert!(
            !journal_bytes
                .windows(b"original-account".len())
                .any(|window| { window == b"original-account" })
        );
        assert!(
            !journal_bytes
                .windows(b"access-secret".len())
                .any(|window| window == b"access-secret")
        );

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
        assert!(
            fs::read_dir(transaction_dir)
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn crash_before_swap_is_abandoned_by_a_new_adapter_without_changing_the_target() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::BeforeSwap
                }));

        let error = crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn staged_recovery_refuses_to_delete_a_unique_stage_after_a_newer_target_write() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let latest = auth_json(Some("latest-account"), Some("latest-subject"), None);
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterStage
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        fs::write(temporary.path().join("auth.json"), &latest).unwrap();

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let error = recovered.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            latest
        );
        assert!(tree_contains_file_bytes(temporary.path(), &replacement));
    }

    #[test]
    fn crash_after_replace_before_validation_completes_intended_install_on_recovery() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterReplaceBeforeValidation
                }));

        let error = crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            replacement
        );

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            replacement
        );
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn deleting_newest_journal_records_after_each_pre_cleanup_checkpoint_is_detected() {
        for checkpoint in [
            CodexTransactionCheckpoint::AfterStage,
            CodexTransactionCheckpoint::BeforeSwap,
            CodexTransactionCheckpoint::AfterReplaceBeforeValidation,
        ] {
            for journals_to_delete in 1..=3 {
                let original = auth_json(Some("original-account"), Some("original-subject"), None);
                let replacement = auth_json(
                    Some("replacement-account"),
                    Some("replacement-subject"),
                    None,
                );
                let (temporary, base) =
                    adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
                let snapshot = base.capture().unwrap();
                let codec = test_codec();
                let crashing = CodexFileAdapter::with_codec(
                    temporary.path().to_path_buf(),
                    Arc::clone(&codec),
                )
                .with_transaction_hook(Arc::new(move |current| current == checkpoint));
                let error = crashing
                    .install(
                        &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                        &snapshot.fingerprint,
                    )
                    .unwrap_err();
                assert_eq!(
                    error.code(),
                    ProviderAccountCommandErrorCode::RecoveryRequired
                );

                let transaction_directory = temporary.path().join(CODEX_TRANSACTION_DIRECTORY);
                let mut journals = fs::read_dir(&transaction_directory)
                    .unwrap()
                    .flatten()
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".journal"))
                    .map(|entry| entry.path())
                    .collect::<Vec<_>>();
                journals.sort();
                journals.reverse();
                for journal in journals.into_iter().take(journals_to_delete) {
                    fs::remove_file(journal).unwrap();
                }

                let recovered = CodexFileAdapter::with_codec(
                    temporary.path().to_path_buf(),
                    Arc::clone(&codec),
                );
                let recovery_error = recovered.recover_pending_transactions().unwrap_err();
                assert_eq!(
                    recovery_error.code(),
                    ProviderAccountCommandErrorCode::RecoveryRequired,
                    "{checkpoint:?} must detect deletion of {journals_to_delete} newest journal(s)"
                );
                assert!(tree_contains_file_bytes(temporary.path(), &original));
                assert!(tree_contains_file_bytes(temporary.path(), &replacement));
            }
        }
    }

    #[test]
    fn sealed_current_head_detects_deletion_of_both_newest_journal_and_generation_head() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::BeforeSwap
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let transaction_directory = temporary.path().join(CODEX_TRANSACTION_DIRECTORY);
        let newest_journal = fs::read_dir(&transaction_directory)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".journal"))
            .max_by_key(std::fs::DirEntry::file_name)
            .unwrap()
            .path();
        let newest_head = newest_journal.with_extension("head");
        fs::remove_file(newest_journal).unwrap();
        fs::remove_file(newest_head).unwrap();

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let error = recovered.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(tree_contains_file_bytes(temporary.path(), &original));
        assert!(tree_contains_file_bytes(temporary.path(), &replacement));
    }

    #[test]
    fn publisher_crashes_are_reconciled_for_initial_and_later_sequences() {
        let checkpoints = [
            CodexPublisherCheckpoint::TemporaryVerified {
                kind: CodexPublisherArtifactKind::Journal,
                sequence: 0,
            },
            CodexPublisherCheckpoint::JournalPublished { sequence: 0 },
            CodexPublisherCheckpoint::TemporaryVerified {
                kind: CodexPublisherArtifactKind::GenerationHead,
                sequence: 0,
            },
            CodexPublisherCheckpoint::GenerationHeadPublished { sequence: 0 },
            CodexPublisherCheckpoint::TemporaryVerified {
                kind: CodexPublisherArtifactKind::CurrentHead,
                sequence: 0,
            },
            CodexPublisherCheckpoint::TemporaryVerified {
                kind: CodexPublisherArtifactKind::Journal,
                sequence: 1,
            },
            CodexPublisherCheckpoint::JournalPublished { sequence: 1 },
            CodexPublisherCheckpoint::TemporaryVerified {
                kind: CodexPublisherArtifactKind::GenerationHead,
                sequence: 1,
            },
            CodexPublisherCheckpoint::GenerationHeadPublished { sequence: 1 },
            CodexPublisherCheckpoint::TemporaryVerified {
                kind: CodexPublisherArtifactKind::CurrentHead,
                sequence: 1,
            },
            CodexPublisherCheckpoint::CurrentReplaceBeforePreviousCleanup { sequence: 1 },
        ];
        for checkpoint in checkpoints {
            let original = auth_json(Some("original-account"), Some("original-subject"), None);
            let replacement = auth_json(
                Some("replacement-account"),
                Some("replacement-subject"),
                None,
            );
            let (temporary, base) =
                adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
            let snapshot = base.capture().unwrap();
            let codec = test_codec();
            let crashing =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                    .with_publisher_hook(Arc::new(move |current| current == checkpoint));

            let error = crashing
                .install(
                    &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                    &snapshot.fingerprint,
                )
                .unwrap_err();
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired,
                "{checkpoint:?}"
            );

            let recovered =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
            recovered.recover_pending_transactions().unwrap();
            assert_eq!(
                fs::read(temporary.path().join("auth.json")).unwrap(),
                original,
                "{checkpoint:?}"
            );
            assert!(
                fs::read_dir(temporary.path().join(CODEX_TRANSACTION_DIRECTORY))
                    .unwrap()
                    .flatten()
                    .all(|entry| entry.file_name() == ".lock"),
                "{checkpoint:?}"
            );
        }
    }

    #[test]
    fn publisher_current_error_1177_is_reconciled_from_new_and_previous_heads() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_publisher_ops(Arc::new(PublisherReplace1177Ops));

        let error = crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        let transaction_directory = temporary.path().join(CODEX_TRANSACTION_DIRECTORY);
        let names = fs::read_dir(&transaction_directory)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            names
                .iter()
                .any(|name| name.ends_with(".current-publishing"))
        );
        assert!(names.iter().any(|name| name.ends_with(".current-previous")));
        assert!(!names.iter().any(|name| name.ends_with(".head-current")));

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
        assert!(
            fs::read_dir(transaction_directory)
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn publisher_reconciliation_survives_a_second_crash() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let first =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_publisher_hook(Arc::new(|checkpoint| {
                    checkpoint
                        == CodexPublisherCheckpoint::TemporaryVerified {
                            kind: CodexPublisherArtifactKind::Journal,
                            sequence: 0,
                        }
                }));
        first
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        let second =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_publisher_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexPublisherCheckpoint::ArtifactReconciled
                }));
        let error = second.recover_pending_transactions().unwrap_err();
        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );

        let third =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        third.recover_pending_transactions().unwrap();
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
    }

    #[test]
    fn conflicting_publisher_artifact_fails_closed_without_deletion() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let first =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_publisher_hook(Arc::new(|checkpoint| {
                    checkpoint
                        == CodexPublisherCheckpoint::TemporaryVerified {
                            kind: CodexPublisherArtifactKind::Journal,
                            sequence: 0,
                        }
                }));
        first
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let publishing = fs::read_dir(temporary.path().join(CODEX_TRANSACTION_DIRECTORY))
            .unwrap()
            .flatten()
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".journal-publishing")
            })
            .unwrap()
            .path();
        let conflicting = b"conflicting publisher artifact";
        fs::write(&publishing, conflicting).unwrap();

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let error = recovered.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(fs::read(publishing).unwrap(), conflicting);
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
    }

    #[test]
    fn crash_after_capturing_a_mismatched_backup_restores_the_external_login_on_recovery() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let external = auth_json(Some("external-account"), Some("external-subject"), None);
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let auth_path = temporary.path().join("auth.json");
        let external_for_hook = external.clone();
        let external_written = Arc::new(AtomicBool::new(false));
        let external_written_for_hook = Arc::clone(&external_written);
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(move |checkpoint| {
                    if checkpoint == CodexTransactionCheckpoint::BeforeSwap
                        && !external_written_for_hook.swap(true, Ordering::SeqCst)
                    {
                        fs::write(&auth_path, &external_for_hook).unwrap();
                    }
                    checkpoint == CodexTransactionCheckpoint::MismatchBeforeRestore
                }));

        let error = crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(external_written.load(Ordering::SeqCst));
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            replacement
        );

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn crash_after_recovery_swap_is_finished_by_a_third_adapter() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let external = auth_json(Some("external-account"), Some("external-subject"), None);
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let auth_path = temporary.path().join("auth.json");
        let external_for_hook = external.clone();
        let first =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(move |checkpoint| {
                    if checkpoint == CodexTransactionCheckpoint::BeforeSwap {
                        fs::write(&auth_path, &external_for_hook).unwrap();
                    }
                    checkpoint == CodexTransactionCheckpoint::MismatchBeforeRestore
                }));
        first
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        let second =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterRecoverySwapBeforeValidation
                }));
        let error = second.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );

        let third =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        third.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn replace_error_1177_restores_the_missing_target_from_expected_or_external_backup() {
        for use_external in [false, true] {
            let original = auth_json(Some("original-account"), Some("original-subject"), None);
            let replacement = auth_json(
                Some("replacement-account"),
                Some("replacement-subject"),
                None,
            );
            let external = auth_json(Some("external-account"), Some("external-subject"), None);
            let (temporary, base) =
                adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
            let snapshot = base.capture().unwrap();
            let codec = test_codec();
            let auth_path = temporary.path().join("auth.json");
            let external_for_hook = external.clone();
            let failing =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                    .with_file_ops(Arc::new(ReplaceErrorFileOps { error: 1177 }))
                    .with_transaction_hook(Arc::new(move |checkpoint| {
                        if use_external && checkpoint == CodexTransactionCheckpoint::BeforeSwap {
                            fs::write(&auth_path, &external_for_hook).unwrap();
                        }
                        false
                    }));

            let error = failing
                .install(
                    &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                    &snapshot.fingerprint,
                )
                .unwrap_err();
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired
            );
            assert!(!temporary.path().join("auth.json").exists());

            let recovered =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
            recovered.recover_pending_transactions().unwrap();
            assert_eq!(
                fs::read(temporary.path().join("auth.json")).unwrap(),
                if use_external {
                    external.clone()
                } else {
                    original.clone()
                }
            );
            assert!(
                fs::read_dir(temporary.path().join(CODEX_TRANSACTION_DIRECTORY))
                    .unwrap()
                    .flatten()
                    .all(|entry| entry.file_name() == ".lock")
            );
        }
    }

    #[test]
    fn replace_error_1177_during_recovery_swap_is_recovered_after_a_second_crash() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let external = auth_json(Some("external-account"), Some("external-subject"), None);
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let auth_path = temporary.path().join("auth.json");
        let external_for_hook = external.clone();
        let first =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(move |checkpoint| {
                    if checkpoint == CodexTransactionCheckpoint::BeforeSwap {
                        fs::write(&auth_path, &external_for_hook).unwrap();
                    }
                    checkpoint == CodexTransactionCheckpoint::MismatchBeforeRestore
                }));
        first
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        let second =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_file_ops(Arc::new(ReplaceErrorFileOps { error: 1177 }));
        let error = second.recover_pending_transactions().unwrap_err();
        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(!temporary.path().join("auth.json").exists());

        let third =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        third.recover_pending_transactions().unwrap();
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
    }

    #[test]
    fn replace_errors_1175_and_1176_leave_the_unchanged_state_recoverable() {
        for error_code in [1175, 1176] {
            let original = auth_json(Some("original-account"), Some("original-subject"), None);
            let replacement = auth_json(
                Some("replacement-account"),
                Some("replacement-subject"),
                None,
            );
            let (temporary, base) =
                adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
            let snapshot = base.capture().unwrap();
            let codec = test_codec();
            let failing =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                    .with_file_ops(Arc::new(ReplaceErrorFileOps { error: error_code }));

            let error = failing
                .install(
                    &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                    &snapshot.fingerprint,
                )
                .unwrap_err();
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired
            );
            assert_eq!(
                fs::read(temporary.path().join("auth.json")).unwrap(),
                original
            );

            let recovered =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
            recovered.recover_pending_transactions().unwrap();
            assert_eq!(
                fs::read(temporary.path().join("auth.json")).unwrap(),
                original
            );
        }
    }

    #[test]
    fn a_later_target_write_wins_after_replace_error_1177() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let external = auth_json(Some("external-account"), Some("external-subject"), None);
        let latest = auth_json(Some("latest-account"), Some("latest-subject"), None);
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let auth_path = temporary.path().join("auth.json");
        let external_for_hook = external.clone();
        let failing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_file_ops(Arc::new(ReplaceErrorFileOps { error: 1177 }))
                .with_transaction_hook(Arc::new(move |checkpoint| {
                    if checkpoint == CodexTransactionCheckpoint::BeforeSwap {
                        fs::write(&auth_path, &external_for_hook).unwrap();
                    }
                    false
                }));
        failing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        fs::write(temporary.path().join("auth.json"), &latest).unwrap();

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            latest
        );
    }

    #[test]
    fn unknown_replace_error_with_missing_target_fails_closed_without_deleting_stage() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let failing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_file_ops(Arc::new(MissingTargetReplaceErrorFileOps));
        failing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let error = recovered.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(!temporary.path().join("auth.json").exists());
        assert!(tree_contains_file_bytes(temporary.path(), &replacement));
    }

    #[test]
    fn external_login_after_recovery_swap_wins_and_is_not_overwritten() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let displaced = auth_json(Some("displaced-account"), Some("displaced-subject"), None);
        let latest = auth_json(Some("latest-account"), Some("latest-subject"), None);
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let auth_path = temporary.path().join("auth.json");
        let displaced_for_hook = displaced.clone();
        let first =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(move |checkpoint| {
                    if checkpoint == CodexTransactionCheckpoint::BeforeSwap {
                        fs::write(&auth_path, &displaced_for_hook).unwrap();
                    }
                    checkpoint == CodexTransactionCheckpoint::MismatchBeforeRestore
                }));
        first
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        let auth_path = temporary.path().join("auth.json");
        let latest_for_hook = latest.clone();
        let second =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(move |checkpoint| {
                    if checkpoint == CodexTransactionCheckpoint::AfterRecoverySwapBeforeValidation {
                        fs::write(&auth_path, &latest_for_hook).unwrap();
                        return true;
                    }
                    false
                }));
        let error = second.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            latest
        );

        let third =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        third.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            latest
        );
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn crash_after_delete_tombstone_move_is_cleaned_by_a_new_adapter() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let temporary = tempfile::tempdir().unwrap();
        fs::write(
            temporary.path().join("config.toml"),
            "cli_auth_credentials_store = \"file\"",
        )
        .unwrap();
        let codec = test_codec();
        let base = CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let absent_snapshot = base.capture().unwrap();
        fs::write(temporary.path().join("auth.json"), &original).unwrap();
        let current = base.fingerprint().unwrap();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterDeleteTombstoneMove
                }));

        let error = crashing.restore(&absent_snapshot, &current).unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(!temporary.path().join("auth.json").exists());

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert!(!temporary.path().join("auth.json").exists());
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn delete_move_checkpoint_precedes_read_and_recovery_restores_displaced_external_bytes() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let external = auth_json(Some("external-account"), Some("external-subject"), None);
        let temporary = tempfile::tempdir().unwrap();
        fs::write(
            temporary.path().join("config.toml"),
            "cli_auth_credentials_store = \"file\"",
        )
        .unwrap();
        let codec = test_codec();
        let base = CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let absent_snapshot = base.capture().unwrap();
        fs::write(temporary.path().join("auth.json"), &original).unwrap();
        let current = base.fingerprint().unwrap();
        let transaction_directory = temporary.path().join(CODEX_TRANSACTION_DIRECTORY);
        let external_for_hook = external.clone();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(move |checkpoint| {
                    if checkpoint == CodexTransactionCheckpoint::AfterDeleteTombstoneMove {
                        let removed = fs::read_dir(&transaction_directory)
                            .unwrap()
                            .flatten()
                            .find(|entry| entry.file_name().to_string_lossy().ends_with(".removed"))
                            .unwrap();
                        fs::write(removed.path(), &external_for_hook).unwrap();
                        return true;
                    }
                    false
                }));

        let error = crashing.restore(&absent_snapshot, &current).unwrap_err();
        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(!temporary.path().join("auth.json").exists());

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
    }

    #[test]
    fn failed_delete_move_with_tombstone_still_installed_retains_recovery_journal() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let temporary = tempfile::tempdir().unwrap();
        fs::write(
            temporary.path().join("config.toml"),
            "cli_auth_credentials_store = \"file\"",
        )
        .unwrap();
        let codec = test_codec();
        let base = CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let absent_snapshot = base.capture().unwrap();
        fs::write(temporary.path().join("auth.json"), &original).unwrap();
        let current = base.fingerprint().unwrap();
        let failing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_file_ops(Arc::new(DeleteMoveErrorFileOps));

        let error = failing.restore(&absent_snapshot, &current).unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(temporary.path().join("auth.json").exists());
        assert!(
            fs::read_dir(temporary.path().join(CODEX_TRANSACTION_DIRECTORY))
                .unwrap()
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".journal"))
        );
    }

    #[test]
    fn restored_removed_external_survives_a_second_crash_and_a_later_write_wins() {
        for install_latest in [false, true] {
            let original = auth_json(Some("original-account"), Some("original-subject"), None);
            let external = auth_json(Some("external-account"), Some("external-subject"), None);
            let latest = auth_json(Some("latest-account"), Some("latest-subject"), None);
            let temporary = tempfile::tempdir().unwrap();
            fs::write(
                temporary.path().join("config.toml"),
                "cli_auth_credentials_store = \"file\"",
            )
            .unwrap();
            let codec = test_codec();
            let base =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
            let absent_snapshot = base.capture().unwrap();
            fs::write(temporary.path().join("auth.json"), &original).unwrap();
            let current = base.fingerprint().unwrap();
            let transaction_directory = temporary.path().join(CODEX_TRANSACTION_DIRECTORY);
            let external_for_hook = external.clone();
            let first =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                    .with_transaction_hook(Arc::new(move |checkpoint| {
                        if checkpoint == CodexTransactionCheckpoint::AfterDeleteTombstoneMove {
                            let removed = fs::read_dir(&transaction_directory)
                                .unwrap()
                                .flatten()
                                .find(|entry| {
                                    entry.file_name().to_string_lossy().ends_with(".removed")
                                })
                                .unwrap();
                            fs::write(removed.path(), &external_for_hook).unwrap();
                            return true;
                        }
                        false
                    }));
            first.restore(&absent_snapshot, &current).unwrap_err();

            if install_latest {
                fs::write(temporary.path().join("auth.json"), &latest).unwrap();
            }
            let second =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                    .with_transaction_hook(Arc::new(move |checkpoint| {
                        !install_latest
                    && checkpoint
                        == CodexTransactionCheckpoint::AfterRemovedExternalRestoreBeforeValidation
                    }));
            if install_latest {
                second.recover_pending_transactions().unwrap();
            } else {
                let error = second.recover_pending_transactions().unwrap_err();
                assert_eq!(
                    error.code(),
                    ProviderAccountCommandErrorCode::RecoveryRequired
                );
            }

            let third =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
            third.recover_pending_transactions().unwrap();
            assert_eq!(
                fs::read(temporary.path().join("auth.json")).unwrap(),
                if install_latest {
                    latest.clone()
                } else {
                    external.clone()
                }
            );
        }
    }

    #[test]
    fn crash_before_cleanup_is_finished_by_a_new_adapter() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::BeforeCleanup
                }));

        let error = crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            replacement
        );

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            replacement
        );
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn cleanup_recovery_refuses_to_delete_unknown_sidecar_credentials() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let unknown = auth_json(Some("unknown-account"), Some("unknown-subject"), None);
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::BeforeCleanup
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let backup = fs::read_dir(temporary.path().join(CODEX_TRANSACTION_DIRECTORY))
            .unwrap()
            .flatten()
            .find(|entry| entry.file_name().to_string_lossy().ends_with(".backup"))
            .unwrap();
        fs::write(backup.path(), &unknown).unwrap();

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let error = recovered.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(tree_contains_file_bytes(temporary.path(), &unknown));
    }

    #[test]
    fn restart_finishes_cleanup_after_an_older_journal_record_was_already_deleted() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::BeforeCleanup
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let transaction_directory = temporary.path().join(".codexbar-transactions");
        let oldest = fs::read_dir(&transaction_directory)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".journal"))
            .min_by_key(std::fs::DirEntry::file_name)
            .unwrap();
        fs::remove_file(oldest.path()).unwrap();

        let recovered =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        recovered.recover_pending_transactions().unwrap();

        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            replacement
        );
        assert!(
            fs::read_dir(transaction_directory)
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn unrecoverable_pending_transaction_blocks_every_normal_adapter_operation() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterStage
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let journal = fs::read_dir(temporary.path().join(".codexbar-transactions"))
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".journal"))
            .min_by_key(std::fs::DirEntry::file_name)
            .unwrap();
        fs::write(journal.path(), b"tampered journal").unwrap();

        let adapter =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let original_bundle = CodexFileAdapter::credential_bundle(&original).unwrap();
        let original_identity = CodexFileAdapter::identity(&original).unwrap();
        let replacement_bundle = CodexFileAdapter::credential_bundle(&replacement).unwrap();

        assert_eq!(
            adapter.support().kind,
            ActivationTargetKind::Unsupported,
            "support must not advertise an adapter with unrecovered credentials"
        );
        for error in [
            adapter.capture().unwrap_err(),
            adapter.fingerprint().unwrap_err(),
            adapter.target_fingerprint(&replacement_bundle).unwrap_err(),
            adapter.current_identity().unwrap_err(),
            adapter
                .validate_target(&original_identity, &original_bundle)
                .unwrap_err(),
            adapter
                .install(&replacement_bundle, &snapshot.fingerprint)
                .unwrap_err(),
            adapter.verify(&original_identity).unwrap_err(),
            adapter
                .restore(&snapshot, &snapshot.fingerprint)
                .unwrap_err(),
        ] {
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired
            );
        }
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
    }

    #[test]
    fn capture_recovers_a_healthy_pending_transaction_before_reading_credentials() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterStage
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let fresh =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));

        let recovered_snapshot = fresh.capture().unwrap();

        assert_eq!(recovered_snapshot, snapshot);
        assert!(
            fs::read_dir(temporary.path().join(".codexbar-transactions"))
                .unwrap()
                .flatten()
                .all(|entry| entry.file_name() == ".lock")
        );
    }

    #[test]
    fn verified_registry_construction_rejects_an_unrecoverable_codex_transaction() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterStage
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let journal = fs::read_dir(temporary.path().join(".codexbar-transactions"))
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".journal"))
            .min_by_key(std::fs::DirEntry::file_name)
            .unwrap();
        fs::write(journal.path(), b"tampered journal").unwrap();
        let codex =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));
        let claude = crate::provider_accounts::claude::ClaudeFileAdapter::new(
            temporary.path().join("claude"),
        );

        let result = ProviderAdapterRegistry::verified_file_adapters(codex, claude);

        assert!(matches!(
            result,
            Err(ProviderAdapterRegistryError::AdapterInitializationFailed {
                provider: ProviderId::Codex,
                code: ProviderAccountCommandErrorCode::RecoveryRequired,
            })
        ));
    }

    #[test]
    fn orphan_raw_transaction_sidecar_blocks_normal_operations() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let (temporary, adapter) =
            adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        adapter.recover_pending_transactions().unwrap();
        let transaction_directory = temporary.path().join(".codexbar-transactions");
        fs::create_dir(&transaction_directory).unwrap();
        let orphan = transaction_directory.join("codexbar-txn-orphan.stage");
        fs::write(&orphan, b"orphan credential bytes").unwrap();

        let error = CodexFileAdapter::new(temporary.path().to_path_buf())
            .capture()
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(fs::read(orphan).unwrap(), b"orphan credential bytes");
    }

    #[test]
    fn hardlinked_transaction_lock_is_rejected_without_touching_the_link_target() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let (temporary, adapter) =
            adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        adapter.recover_pending_transactions().unwrap();
        let transaction_directory = temporary.path().join(".codexbar-transactions");
        fs::create_dir(&transaction_directory).unwrap();
        fs::write(transaction_directory.join(".lock"), b"").unwrap();
        fs::remove_file(transaction_directory.join(".lock")).unwrap();
        let outside = temporary.path().join("outside-lock-target");
        fs::write(&outside, b"outside bytes").unwrap();
        fs::hard_link(&outside, transaction_directory.join(".lock")).unwrap();

        let error = CodexFileAdapter::new(temporary.path().to_path_buf())
            .capture()
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert_eq!(fs::read(outside).unwrap(), b"outside bytes");
    }

    #[cfg(windows)]
    #[test]
    fn reparse_transaction_directory_is_rejected_without_following_it() {
        use std::os::windows::fs::symlink_dir;

        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let temporary = tempfile::tempdir().unwrap();
        fs::write(
            temporary.path().join("config.toml"),
            "cli_auth_credentials_store = \"file\"",
        )
        .unwrap();
        fs::write(temporary.path().join("auth.json"), &original).unwrap();
        let redirected = tempfile::tempdir().unwrap();
        let transaction_directory = temporary.path().join(".codexbar-transactions");
        if let Err(error) = symlink_dir(redirected.path(), &transaction_directory) {
            assert_eq!(error.raw_os_error(), Some(1314));
            let status = Command::new("cmd.exe")
                .arg("/c")
                .arg("mklink")
                .arg("/J")
                .arg(&transaction_directory)
                .arg(redirected.path())
                .status()
                .unwrap();
            assert!(status.success());
        }

        let error = CodexFileAdapter::new(temporary.path().to_path_buf())
            .capture()
            .unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(fs::read_dir(redirected.path()).unwrap().next().is_none());
    }

    #[test]
    fn active_transaction_lock_reports_operation_in_progress() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let (temporary, first) =
            adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let _guard = first.acquire_transaction_guard().unwrap();
        let second = CodexFileAdapter::new(temporary.path().to_path_buf());

        let error = second.capture().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::OperationInProgress
        );
    }

    #[test]
    fn hardlinked_raw_sidecar_blocks_recovery_without_deleting_either_link() {
        let original = auth_json(Some("original-account"), Some("original-subject"), None);
        let replacement = auth_json(
            Some("replacement-account"),
            Some("replacement-subject"),
            None,
        );
        let (temporary, base) = adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = base.capture().unwrap();
        let codec = test_codec();
        let crashing =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                .with_transaction_hook(Arc::new(|checkpoint| {
                    checkpoint == CodexTransactionCheckpoint::AfterStage
                }));
        crashing
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();
        let stage = fs::read_dir(temporary.path().join(".codexbar-transactions"))
            .unwrap()
            .flatten()
            .find(|entry| entry.file_name().to_string_lossy().ends_with(".stage"))
            .unwrap()
            .path();
        let outside = temporary.path().join("outside-stage-link");
        fs::hard_link(&stage, &outside).unwrap();
        let recovering =
            CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec));

        let error = recovering.recover_pending_transactions().unwrap_err();

        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::RecoveryRequired
        );
        assert!(stage.exists());
        assert_eq!(fs::read(outside).unwrap(), replacement);
    }

    #[test]
    fn expected_fingerprint_mismatch_preserves_external_login_bytes() {
        let original = auth_json(Some("original"), None, None);
        let external = auth_json(Some("external-login"), None, None);
        let target = auth_json(Some("target"), None, None);
        let (temporary, adapter) =
            adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = adapter.capture().unwrap();
        fs::write(temporary.path().join("auth.json"), &external).unwrap();

        let error = adapter
            .install(
                &CodexFileAdapter::credential_bundle(&target).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
    }

    #[test]
    fn install_final_window_external_write_wins_without_transaction_residue() {
        let original = auth_json(Some("original"), None, None);
        let external = auth_json(Some("external-final-window"), None, None);
        let target = auth_json(Some("target"), None, None);
        let (temporary, adapter) =
            adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = adapter.capture().unwrap();
        let auth_path = temporary.path().join("auth.json");
        let hook_ran = Arc::new(AtomicBool::new(false));
        let hook_flag = Arc::clone(&hook_ran);
        let external_for_hook = external.clone();
        let adapter = adapter.with_before_commit_hook(Arc::new(move || {
            if !hook_flag.swap(true, Ordering::SeqCst) {
                fs::write(&auth_path, &external_for_hook).unwrap();
            }
        }));

        let error = adapter
            .install(
                &CodexFileAdapter::credential_bundle(&target).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
        assert!(hook_ran.load(Ordering::SeqCst));
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
        assert!(transaction_residue(temporary.path()).is_empty());
    }

    #[test]
    fn install_into_expected_missing_target_never_overwrites_a_final_window_create() {
        let external = auth_json(Some("external-final-window"), None, None);
        let target = auth_json(Some("target"), None, None);
        let temporary = tempfile::tempdir().unwrap();
        fs::write(
            temporary.path().join("config.toml"),
            "cli_auth_credentials_store = \"file\"",
        )
        .unwrap();
        let adapter = CodexFileAdapter::new(temporary.path().to_path_buf());
        let snapshot = adapter.capture().unwrap();
        let auth_path = temporary.path().join("auth.json");
        let external_for_hook = external.clone();
        let adapter = adapter.with_before_commit_hook(Arc::new(move || {
            fs::write(&auth_path, &external_for_hook).unwrap();
        }));

        let error = adapter
            .install(
                &CodexFileAdapter::credential_bundle(&target).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
        assert!(transaction_residue(temporary.path()).is_empty());
    }

    #[test]
    fn delete_final_window_external_write_wins_without_transaction_residue() {
        let original = auth_json(Some("original"), None, None);
        let external = auth_json(Some("external-final-window"), None, None);
        let temporary = tempfile::tempdir().unwrap();
        fs::write(
            temporary.path().join("config.toml"),
            "cli_auth_credentials_store = \"file\"",
        )
        .unwrap();
        let adapter = CodexFileAdapter::new(temporary.path().to_path_buf());
        let absent_snapshot = adapter.capture().unwrap();
        fs::write(temporary.path().join("auth.json"), &original).unwrap();
        let current = adapter.fingerprint().unwrap();
        let auth_path = temporary.path().join("auth.json");
        let hook_ran = Arc::new(AtomicBool::new(false));
        let hook_flag = Arc::clone(&hook_ran);
        let external_for_hook = external.clone();
        let adapter = adapter.with_before_commit_hook(Arc::new(move || {
            if !hook_flag.swap(true, Ordering::SeqCst) {
                fs::write(&auth_path, &external_for_hook).unwrap();
            }
        }));

        let error = adapter.restore(&absent_snapshot, &current).unwrap_err();

        assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
        assert!(hook_ran.load(Ordering::SeqCst));
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            external
        );
        assert!(transaction_residue(temporary.path()).is_empty());
    }

    #[test]
    fn install_rolls_back_auth_when_mode_flips_after_staging_and_preserves_config_write() {
        let original = auth_json(Some("original"), None, None);
        let target = auth_json(Some("target"), None, None);
        let (temporary, adapter) =
            adapter_fixture("cli_auth_credentials_store = \"file\"", &original);
        let snapshot = adapter.capture().unwrap();
        let config_path = temporary.path().join("config.toml");
        let hook_ran = Arc::new(AtomicBool::new(false));
        let hook_flag = Arc::clone(&hook_ran);
        let adapter = adapter.with_before_commit_hook(Arc::new(move || {
            if !hook_flag.swap(true, Ordering::SeqCst) {
                fs::write(
                    &config_path,
                    "# external mode change\ncli_auth_credentials_store = \"keyring\"\n",
                )
                .unwrap();
            }
        }));

        let error = adapter
            .install(
                &CodexFileAdapter::credential_bundle(&target).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
        assert_eq!(
            fs::read_to_string(temporary.path().join("config.toml")).unwrap(),
            "# external mode change\ncli_auth_credentials_store = \"keyring\"\n"
        );
        assert!(transaction_residue(temporary.path()).is_empty());
    }

    #[test]
    fn capture_fingerprint_fences_exact_config_bytes_as_well_as_auth() {
        let original = auth_json(Some("original"), None, None);
        let target = auth_json(Some("target"), None, None);
        let (temporary, adapter) =
            adapter_fixture("cli_auth_credentials_store = \"file\"\n", &original);
        let snapshot = adapter.capture().unwrap();
        fs::write(
            temporary.path().join("config.toml"),
            "# external edit\ncli_auth_credentials_store = \"file\"\n",
        )
        .unwrap();

        let error = adapter
            .install(
                &CodexFileAdapter::credential_bundle(&target).unwrap(),
                &snapshot.fingerprint,
            )
            .unwrap_err();

        assert_eq!(error.code(), ProviderAccountCommandErrorCode::ExternalWrite);
        assert_eq!(
            fs::read(temporary.path().join("auth.json")).unwrap(),
            original
        );
    }

    #[test]
    fn registry_keeps_conditional_codex_adapter_and_rechecks_mode_dynamically() {
        let auth = auth_json(Some("current"), None, None);
        let (temporary, codex) = adapter_fixture("cli_auth_credentials_store = \"auto\"\n", &auth);
        let claude = super::super::claude::ClaudeFileAdapter::new(
            temporary.path().join("claude-credentials.json"),
        );
        let registry = ProviderAdapterRegistry::verified_file_adapters(codex, claude).unwrap();

        assert!(registry.adapter(ProviderId::Codex).is_some());
        assert_eq!(
            registry.activation_support(ProviderId::Codex).kind,
            ActivationTargetKind::Unsupported
        );

        fs::write(
            temporary.path().join("config.toml"),
            "cli_auth_credentials_store = \"file\"\n",
        )
        .unwrap();

        assert_eq!(
            registry.activation_support(ProviderId::Codex).kind,
            ActivationTargetKind::CliFile
        );
    }

    #[test]
    fn read_only_codex_operations_do_not_create_a_missing_home_or_transaction_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let codex_home = temporary.path().join("missing-codex-home");
        let adapter =
            CodexFileAdapter::with_codec(codex_home.clone(), Arc::new(AuthenticatedTestCodec));

        adapter.recover_pending_transactions().unwrap();
        assert_eq!(adapter.support().kind, ActivationTargetKind::Unsupported);
        assert!(adapter.capture().unwrap().credentials.is_none());
        assert!(adapter.fingerprint().unwrap().is_some());

        let registry = ProviderAdapterRegistry::verified_file_adapters(
            adapter,
            super::super::claude::ClaudeFileAdapter::new(
                temporary.path().join("missing-claude-credentials.json"),
            ),
        )
        .unwrap();
        assert!(registry.adapter(ProviderId::Codex).is_some());
        assert_eq!(
            registry.activation_support(ProviderId::Codex).kind,
            ActivationTargetKind::Unsupported
        );
        assert!(!codex_home.exists());
    }

    #[test]
    fn absent_directory_reader_discards_transient_results_when_a_transaction_appears() {
        for reader_kind in 0..3 {
            let original = auth_json(Some("original-account"), Some("original-subject"), None);
            let replacement = auth_json(
                Some("replacement-account"),
                Some("replacement-subject"),
                None,
            );
            let config = b"cli_auth_credentials_store = \"file\"\n";
            let (temporary, base) =
                adapter_fixture(std::str::from_utf8(config).unwrap(), &original);
            let snapshot = base.capture().unwrap();
            let codec = test_codec();
            let after_unlocked_read = Arc::new(Barrier::new(2));
            let writer_finished = Arc::new(Barrier::new(2));
            let reader_after_unlocked_read = Arc::clone(&after_unlocked_read);
            let reader_writer_finished = Arc::clone(&writer_finished);
            let reader =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                    .with_read_recovery_hook(Arc::new(move |checkpoint| {
                        if checkpoint == CodexReadRecoveryCheckpoint::AfterUnlockedOperation {
                            reader_after_unlocked_read.wait();
                            reader_writer_finished.wait();
                        }
                    }));
            let reader_thread = thread::spawn(move || match reader_kind {
                0 => reader
                    .capture()
                    .unwrap()
                    .credentials
                    .unwrap()
                    .artifact
                    .unwrap(),
                1 => reader
                    .current_identity()
                    .unwrap()
                    .unwrap()
                    .stable_keys
                    .into_iter()
                    .find(|key| key.namespace == "codex-account-id")
                    .unwrap()
                    .value
                    .into_bytes(),
                _ => reader.fingerprint().unwrap().unwrap().into_bytes(),
            });

            after_unlocked_read.wait();
            let writer =
                CodexFileAdapter::with_codec(temporary.path().to_path_buf(), Arc::clone(&codec))
                    .with_transaction_hook(Arc::new(|checkpoint| {
                        checkpoint == CodexTransactionCheckpoint::AfterReplaceBeforeValidation
                    }));
            let error = writer
                .install(
                    &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                    &snapshot.fingerprint,
                )
                .unwrap_err();
            assert_eq!(
                error.code(),
                ProviderAccountCommandErrorCode::RecoveryRequired
            );
            writer_finished.wait();

            let result = reader_thread.join().unwrap();
            let expected = match reader_kind {
                0 => replacement.clone(),
                1 => b"replacement-account".to_vec(),
                _ => target_fingerprint(
                    Some(&replacement),
                    Some(config),
                    CodexCredentialStoreMode::File,
                )
                .unwrap()
                .into_bytes(),
            };
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn read_only_codex_operations_preserve_auto_keyring_and_unset_trees_byte_for_byte() {
        for config in [
            Some("cli_auth_credentials_store = \"auto\"\n"),
            Some("cli_auth_credentials_store = \"keyring\"\n"),
            None,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let auth = auth_json(Some("current"), None, None);
            fs::write(temporary.path().join("auth.json"), &auth).unwrap();
            if let Some(config) = config {
                fs::write(temporary.path().join("config.toml"), config).unwrap();
            }
            let before = directory_tree(temporary.path());
            let adapter = CodexFileAdapter::with_codec(
                temporary.path().to_path_buf(),
                Arc::new(AuthenticatedTestCodec),
            );

            adapter.recover_pending_transactions().unwrap();
            assert_eq!(adapter.support().kind, ActivationTargetKind::Unsupported);
            let snapshot = adapter.capture().unwrap();
            assert_eq!(
                snapshot.credentials.as_ref().unwrap().artifact.as_deref(),
                Some(auth.as_slice())
            );
            assert!(adapter.fingerprint().unwrap().is_some());
            assert!(adapter.current_identity().unwrap().is_some());

            let registry = ProviderAdapterRegistry::verified_file_adapters(
                adapter,
                super::super::claude::ClaudeFileAdapter::new(
                    temporary.path().join("missing-claude-credentials.json"),
                ),
            )
            .unwrap();
            assert_eq!(
                registry.activation_support(ProviderId::Codex).kind,
                ActivationTargetKind::Unsupported
            );
            assert_eq!(directory_tree(temporary.path()), before);

            fs::write(
                temporary.path().join("config.toml"),
                "cli_auth_credentials_store = \"file\"\n",
            )
            .unwrap();
            assert_eq!(
                registry.activation_support(ProviderId::Codex).kind,
                ActivationTargetKind::CliFile
            );
        }
    }

    #[test]
    fn rejected_or_noop_install_does_not_begin_a_transaction() {
        let original = auth_json(Some("original"), None, None);
        let replacement = auth_json(Some("replacement"), None, None);

        let (unsupported_home, unsupported) =
            adapter_fixture("cli_auth_credentials_store = \"auto\"\n", &original);
        let unsupported_snapshot = unsupported.capture().unwrap();
        let unsupported_before = directory_tree(unsupported_home.path());
        let error = unsupported
            .install(
                &CodexFileAdapter::credential_bundle(&replacement).unwrap(),
                &unsupported_snapshot.fingerprint,
            )
            .unwrap_err();
        assert_eq!(
            error.code(),
            ProviderAccountCommandErrorCode::UnsupportedActivation
        );
        assert_eq!(directory_tree(unsupported_home.path()), unsupported_before);

        let (noop_home, noop) =
            adapter_fixture("cli_auth_credentials_store = \"file\"\n", &original);
        let noop_snapshot = noop.capture().unwrap();
        let noop_before = directory_tree(noop_home.path());
        noop.install(
            &CodexFileAdapter::credential_bundle(&original).unwrap(),
            &noop_snapshot.fingerprint,
        )
        .unwrap();
        assert_eq!(directory_tree(noop_home.path()), noop_before);
    }

    #[test]
    fn codex_restart_hint_is_explicit_and_required() {
        let (_, adapter) = adapter_fixture(
            "cli_auth_credentials_store = \"file\"",
            &auth_json(Some("current"), None, None),
        );
        let hint = adapter.restart_hint();

        assert!(hint.required);
        assert_eq!(hint.client_name.as_deref(), Some("Codex"));
        assert!(hint.message.as_deref().unwrap().contains("Codex"));
    }
}
