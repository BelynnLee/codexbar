use crate::{
    accounts::{
        CredentialMigration, CredentialVaultError, ProviderAccountIdentity,
        ProviderCredentialBundle, ProviderCredentialVault, ProviderIdentityKey,
    },
    auth::{
        credentials::{CodexCredentials, managed_credential_path},
        dpapi::{SecretCodec, SecretError},
    },
    model::ProviderId,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

const VAULT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexProfileIdentity {
    pub account_id: Option<String>,
    pub subject: Option<String>,
    pub email: Option<String>,
}

impl CodexProfileIdentity {
    pub fn from_auth_json(auth_json: &[u8]) -> Result<Self, ProfileVaultError> {
        parse_identity(auth_json)
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.account_id
            .as_ref()
            .zip(other.account_id.as_ref())
            .is_some_and(|(left, right)| left == right)
            || self
                .subject
                .as_ref()
                .zip(other.subject.as_ref())
                .is_some_and(|(left, right)| left == right)
    }
}

#[derive(Clone)]
pub struct LoadedCodexProfile {
    pub auth_json: Vec<u8>,
    pub identity: CodexProfileIdentity,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for LoadedCodexProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedCodexProfile")
            .field("has_auth_json", &true)
            .field("identity", &self.identity)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct SavedCodexProfile {
    pub path: PathBuf,
    pub identity: CodexProfileIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyMigration {
    NotFound,
    AlreadyMigrated,
    Migrated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CodexCredentialStoreMode {
    File,
    Keyring,
    Auto,
    Unset,
    Invalid,
}

impl CodexCredentialStoreMode {
    pub const fn is_switchable(self) -> bool {
        matches!(self, Self::File)
    }
}

#[derive(Debug, Error)]
pub enum ProfileVaultError {
    #[error("Codex profile id was rejected")]
    UnsafeProfileId,
    #[error("Codex profile credentials have no stable account identity")]
    MissingIdentity,
    #[error("Codex profile vault could not be read or written: {0}")]
    Io(#[from] std::io::Error),
    #[error("Codex profile vault encryption failed: {0}")]
    Secret(#[from] SecretError),
    #[error("Codex profile vault data is invalid")]
    InvalidData,
    #[error("Codex profile identity changed while saving")]
    IdentityMismatch,
}

#[derive(Serialize, Deserialize)]
struct LegacyVaultEnvelope {
    version: u8,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyVaultPayload {
    auth_json: Vec<u8>,
    identity: CodexProfileIdentity,
    updated_at: DateTime<Utc>,
}

pub struct CodexProfileVault<'a> {
    config_dir: &'a Path,
    codec: &'a dyn SecretCodec,
}

impl fmt::Debug for CodexProfileVault<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexProfileVault")
            .field("config_dir", &self.config_dir)
            .field("codec", &"<redacted>")
            .finish()
    }
}

impl<'a> CodexProfileVault<'a> {
    pub const fn new(config_dir: &'a Path, codec: &'a dyn SecretCodec) -> Self {
        Self { config_dir, codec }
    }

    pub fn path(&self, profile_id: &str) -> Result<PathBuf, ProfileVaultError> {
        self.generic()
            .path(ProviderId::Codex, profile_id)
            .map_err(map_vault_error)
    }

    pub fn save(
        &self,
        profile_id: &str,
        auth_json: &[u8],
    ) -> Result<SavedCodexProfile, ProfileVaultError> {
        let identity = parse_identity(auth_json)?;
        let provider_identity = provider_identity(&identity);
        let credentials = codex_bundle(auth_json);
        let path = self
            .generic()
            .save(
                ProviderId::Codex,
                profile_id,
                &provider_identity,
                &credentials,
            )
            .map_err(map_vault_error)?;
        Ok(SavedCodexProfile { path, identity })
    }

    pub fn load(&self, profile_id: &str) -> Result<LoadedCodexProfile, ProfileVaultError> {
        match self.generic().load(ProviderId::Codex, profile_id) {
            Ok(loaded) => loaded_codex_profile(loaded),
            Err(CredentialVaultError::InvalidData) => {
                self.migrate_legacy_vault_in_place(profile_id)?;
                loaded_codex_profile(
                    self.generic()
                        .load(ProviderId::Codex, profile_id)
                        .map_err(map_vault_error)?,
                )
            }
            Err(error) => Err(map_vault_error(error)),
        }
    }

    pub fn migrate_legacy(&self, profile_id: &str) -> Result<LegacyMigration, ProfileVaultError> {
        let legacy = managed_codex_legacy_path(self.config_dir, profile_id)?;
        if self.path(profile_id)?.exists() {
            self.load(profile_id)?;
        }
        self.generic()
            .migrate_file(
                ProviderId::Codex,
                profile_id,
                &legacy,
                |auth_json| {
                    parse_identity(auth_json)
                        .map(|identity| provider_identity(&identity))
                        .map_err(|_| CredentialVaultError::InvalidData)
                },
                |auth_json| Ok(codex_bundle(auth_json)),
            )
            .map(|outcome| match outcome {
                CredentialMigration::NotFound => LegacyMigration::NotFound,
                CredentialMigration::AlreadyMigrated => LegacyMigration::AlreadyMigrated,
                CredentialMigration::Migrated => LegacyMigration::Migrated,
            })
            .map_err(map_vault_error)
    }

    pub fn delete(&self, profile_id: &str) -> Result<(), ProfileVaultError> {
        self.generic()
            .delete(ProviderId::Codex, profile_id)
            .map_err(map_vault_error)
    }

    const fn generic(&self) -> ProviderCredentialVault<'_> {
        ProviderCredentialVault::new(self.config_dir, self.codec)
    }

    fn migrate_legacy_vault_in_place(&self, profile_id: &str) -> Result<(), ProfileVaultError> {
        let path = self.path(profile_id)?;
        let bytes = fs::read(&path)?;
        let envelope: LegacyVaultEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| ProfileVaultError::InvalidData)?;
        if envelope.version != VAULT_VERSION {
            return Err(ProfileVaultError::InvalidData);
        }
        let ciphertext = STANDARD
            .decode(envelope.ciphertext)
            .map_err(|_| ProfileVaultError::InvalidData)?;
        let plaintext = self
            .codec
            .unprotect(&ciphertext)
            .map_err(sanitized_secret)?;
        let payload: LegacyVaultPayload =
            serde_json::from_slice(&plaintext).map_err(|_| ProfileVaultError::InvalidData)?;
        let parsed_identity = parse_identity(&payload.auth_json)?;
        if !payload.identity.matches(&parsed_identity) {
            return Err(ProfileVaultError::IdentityMismatch);
        }
        self.save(profile_id, &payload.auth_json)?;
        Ok(())
    }
}

pub fn managed_codex_legacy_path(
    config_dir: &Path,
    profile_id: &str,
) -> Result<PathBuf, ProfileVaultError> {
    managed_credential_path(config_dir, "codex", profile_id)
        .ok_or(ProfileVaultError::UnsafeProfileId)
}

pub fn parse_codex_credential_store_mode(contents: &str) -> CodexCredentialStoreMode {
    let mut in_root = true;
    let mut found = None;
    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return CodexCredentialStoreMode::Invalid;
            }
            in_root = false;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return CodexCredentialStoreMode::Invalid;
        };
        if in_root && key.trim() == "cli_auth_credentials_store" {
            if found.is_some() {
                return CodexCredentialStoreMode::Invalid;
            }
            found = Some(value.trim());
        }
    }
    match found {
        None => CodexCredentialStoreMode::Unset,
        Some("\"file\"") => CodexCredentialStoreMode::File,
        Some("\"keyring\"") => CodexCredentialStoreMode::Keyring,
        Some("\"auto\"") => CodexCredentialStoreMode::Auto,
        Some(_) => CodexCredentialStoreMode::Invalid,
    }
}

fn loaded_codex_profile(
    loaded: crate::accounts::LoadedProviderCredential,
) -> Result<LoadedCodexProfile, ProfileVaultError> {
    if loaded.credentials.artifact_format.as_deref() != Some("codex-auth-json") {
        return Err(ProfileVaultError::InvalidData);
    }
    let auth_json = loaded
        .credentials
        .artifact
        .ok_or(ProfileVaultError::InvalidData)?;
    let identity = parse_identity(&auth_json)?;
    if !provider_identity(&identity).matches_stable(&loaded.identity) {
        return Err(ProfileVaultError::IdentityMismatch);
    }
    Ok(LoadedCodexProfile {
        auth_json,
        identity,
        updated_at: loaded.updated_at,
    })
}

fn provider_identity(identity: &CodexProfileIdentity) -> ProviderAccountIdentity {
    let mut stable_keys = Vec::new();
    if let Some(account_id) = &identity.account_id {
        stable_keys.push(ProviderIdentityKey::new("codex-account-id", account_id));
    }
    if let Some(subject) = &identity.subject {
        stable_keys.push(ProviderIdentityKey::new("jwt-sub", subject));
    }
    ProviderAccountIdentity::new(ProviderId::Codex, stable_keys, identity.email.clone(), None)
}

fn codex_bundle(auth_json: &[u8]) -> ProviderCredentialBundle {
    ProviderCredentialBundle {
        artifact_format: Some("codex-auth-json".into()),
        artifact: Some(auth_json.to_vec()),
        ..Default::default()
    }
}

fn sanitized_secret(_error: SecretError) -> ProfileVaultError {
    ProfileVaultError::Secret(SecretError::Platform(
        "Provider credential vault cryptography failed".into(),
    ))
}

fn map_vault_error(error: CredentialVaultError) -> ProfileVaultError {
    match error {
        CredentialVaultError::UnsafeAccountId => ProfileVaultError::UnsafeProfileId,
        CredentialVaultError::Io(error) => ProfileVaultError::Io(error),
        CredentialVaultError::EncryptionFailed | CredentialVaultError::DecryptionFailed => {
            sanitized_secret(SecretError::UnsupportedPlatform)
        }
        CredentialVaultError::ProviderMismatch
        | CredentialVaultError::AccountMismatch
        | CredentialVaultError::IdentityMismatch => ProfileVaultError::IdentityMismatch,
        CredentialVaultError::MissingStableIdentity => ProfileVaultError::MissingIdentity,
        CredentialVaultError::InvalidData
        | CredentialVaultError::MigrationParseFailed
        | CredentialVaultError::SourceTargetConflict
        | CredentialVaultError::RollbackFailed
        | CredentialVaultError::ExternalModification
        | CredentialVaultError::TransactionFailed => ProfileVaultError::InvalidData,
    }
}

fn parse_identity(auth_json: &[u8]) -> Result<CodexProfileIdentity, ProfileVaultError> {
    let credentials = CodexCredentials::parse(auth_json, PathBuf::from("auth.json"))
        .map_err(|_| ProfileVaultError::InvalidData)?;
    let identity = CodexProfileIdentity {
        account_id: credentials.account_id,
        subject: credentials
            .id_token
            .as_deref()
            .and_then(parse_id_token_subject),
        email: credentials.email,
    };
    if identity.account_id.is_none() && identity.subject.is_none() {
        return Err(ProfileVaultError::MissingIdentity);
    }
    Ok(identity)
}

fn parse_id_token_subject(id_token: &str) -> Option<String> {
    let claims = id_token.split('.').nth(1)?;
    let claims = URL_SAFE_NO_PAD.decode(claims).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&claims).ok()?;
    claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|subject| !subject.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounts::ProviderCredentialVault,
        auth::dpapi::{SecretCodec, SecretError},
        model::ProviderId,
    };
    use std::fs;

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

    struct SensitiveDebugCodec;

    impl fmt::Debug for SensitiveDebugCodec {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("codec-private-value")
        }
    }

    impl SecretCodec for SensitiveDebugCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.to_vec())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(ciphertext.to_vec())
        }
    }

    fn auth_json(account_id: &str, email: &str) -> String {
        auth_json_with_subject(account_id, "subject-1", email)
    }

    fn auth_json_with_subject(account_id: &str, subject: &str, email: &str) -> String {
        format!(
            r#"{{"tokens":{{"access_token":"secret-access","refresh_token":"secret-refresh","account_id":"{account_id}","id_token":"{}"}},"last_refresh":"2026-07-20T00:00:00Z"}}"#,
            jwt_with_claims(&format!(r#"{{"sub":"{subject}","email":"{email}"}}"#))
        )
    }

    fn jwt_with_claims(claims: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        format!("header.{}.signature", URL_SAFE_NO_PAD.encode(claims))
    }

    #[test]
    fn compatibility_extracts_subject_from_id_token_without_extended_credentials_api() {
        let id_token = jwt_with_claims(r#"{"sub":"compat-subject"}"#);

        assert_eq!(
            parse_id_token_subject(&id_token).as_deref(),
            Some("compat-subject")
        );
        assert!(parse_id_token_subject("malformed").is_none());
    }

    #[test]
    fn vault_round_trip_keeps_auth_and_identity_out_of_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let vault = CodexProfileVault::new(directory.path(), &XorCodec);
        let auth = auth_json("acct-work", "work@example.com");

        let saved = vault.save("acc_work", auth.as_bytes()).unwrap();
        let on_disk = fs::read_to_string(saved.path).unwrap();

        for secret in ["secret-access", "work@example.com"] {
            assert!(!on_disk.contains(secret));
        }
        let loaded = vault.load("acc_work").unwrap();
        assert_eq!(loaded.auth_json, auth.as_bytes());
        assert_eq!(loaded.identity.account_id.as_deref(), Some("acct-work"));
        assert_eq!(loaded.identity.subject.as_deref(), Some("subject-1"));
        assert_eq!(loaded.identity.email.as_deref(), Some("work@example.com"));
    }

    #[test]
    fn compatibility_writer_uses_generic_vault_and_redacts_loaded_debug() {
        let directory = tempfile::tempdir().unwrap();
        let compatibility = CodexProfileVault::new(directory.path(), &XorCodec);
        let auth = auth_json("acct-work", "work@example.com");
        compatibility.save("acc_work", auth.as_bytes()).unwrap();

        let generic = ProviderCredentialVault::new(directory.path(), &XorCodec);
        let loaded = generic.load(ProviderId::Codex, "acc_work").unwrap();
        assert_eq!(
            loaded.credentials.artifact_format.as_deref(),
            Some("codex-auth-json")
        );
        assert_eq!(
            loaded.credentials.artifact.as_deref(),
            Some(auth.as_bytes())
        );

        let compatibility_debug = format!("{:?}", compatibility.load("acc_work").unwrap());
        for secret in ["secret-access", "secret-refresh"] {
            assert!(!compatibility_debug.contains(secret));
        }

        let vault_debug = format!(
            "{:?}",
            CodexProfileVault::new(directory.path(), &SensitiveDebugCodec)
        );
        assert!(!vault_debug.contains("codec-private-value"));
    }

    #[test]
    fn legacy_json_is_removed_only_after_verified_vault_migration() {
        let directory = tempfile::tempdir().unwrap();
        let vault = CodexProfileVault::new(directory.path(), &XorCodec);
        let legacy = managed_codex_legacy_path(directory.path(), "acc_work").unwrap();
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, auth_json("acct-work", "work@example.com")).unwrap();

        let result = vault.migrate_legacy("acc_work").unwrap();

        assert_eq!(result, LegacyMigration::Migrated);
        assert!(!legacy.exists());
        assert_eq!(
            vault
                .load("acc_work")
                .unwrap()
                .identity
                .account_id
                .as_deref(),
            Some("acct-work")
        );
    }

    #[test]
    fn invalid_legacy_json_is_preserved_and_does_not_create_a_vault() {
        let directory = tempfile::tempdir().unwrap();
        let vault = CodexProfileVault::new(directory.path(), &XorCodec);
        let legacy = managed_codex_legacy_path(directory.path(), "acc_work").unwrap();
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, b"not-json").unwrap();

        assert!(vault.migrate_legacy("acc_work").is_err());
        assert!(legacy.exists());
        assert!(!vault.path("acc_work").unwrap().exists());
    }

    #[test]
    fn migration_does_not_replace_a_vault_for_another_identity() {
        let directory = tempfile::tempdir().unwrap();
        let vault = CodexProfileVault::new(directory.path(), &XorCodec);
        vault
            .save(
                "acc_work",
                auth_json("acct-first", "first@example.com").as_bytes(),
            )
            .unwrap();
        let legacy = managed_codex_legacy_path(directory.path(), "acc_work").unwrap();
        fs::write(
            &legacy,
            auth_json_with_subject("acct-second", "subject-2", "second@example.com"),
        )
        .unwrap();

        assert!(matches!(
            vault.migrate_legacy("acc_work"),
            Err(ProfileVaultError::IdentityMismatch)
        ));
        assert!(legacy.exists());
        assert_eq!(
            vault
                .load("acc_work")
                .unwrap()
                .identity
                .account_id
                .as_deref(),
            Some("acct-first")
        );
    }

    #[test]
    fn vault_paths_reject_traversal() {
        let directory = tempfile::tempdir().unwrap();
        let vault = CodexProfileVault::new(directory.path(), &XorCodec);
        for profile_id in [
            "../escape",
            "acc_a/../../escape",
            "C:\\escape",
            "acc_a.vault",
        ] {
            assert!(matches!(
                vault.path(profile_id),
                Err(ProfileVaultError::UnsafeProfileId)
            ));
        }
    }

    #[test]
    fn only_explicit_file_store_is_switchable() {
        assert_eq!(
            parse_codex_credential_store_mode("cli_auth_credentials_store = \"file\""),
            CodexCredentialStoreMode::File
        );
        assert_eq!(
            parse_codex_credential_store_mode("cli_auth_credentials_store = \"keyring\""),
            CodexCredentialStoreMode::Keyring
        );
        assert_eq!(
            parse_codex_credential_store_mode("cli_auth_credentials_store = \"auto\""),
            CodexCredentialStoreMode::Auto
        );
        assert_eq!(
            parse_codex_credential_store_mode("model = \"fictional\""),
            CodexCredentialStoreMode::Unset
        );
        assert_eq!(
            parse_codex_credential_store_mode("cli_auth_credentials_store = ["),
            CodexCredentialStoreMode::Invalid
        );
        assert!(CodexCredentialStoreMode::File.is_switchable());
        assert!(!CodexCredentialStoreMode::Auto.is_switchable());
    }
}
