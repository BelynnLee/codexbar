use crate::{
    accounts::{
        CredentialVaultError, LoadedProviderCredential, ManagedCredentialState,
        ProviderAccountIdentity, ProviderCredentialBundle,
    },
    config::ProviderAccount,
    model::ProviderId,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialMigrationReport {
    pub migrated: Vec<(ProviderId, String)>,
    pub failed: Vec<(ProviderId, String, ManagedCredentialState)>,
}

impl CredentialMigrationReport {
    pub(crate) fn record_failure(
        &mut self,
        provider: ProviderId,
        account_id: &str,
        state: ManagedCredentialState,
    ) {
        let entry = (provider, account_id.to_owned(), state);
        if !self.failed.contains(&entry) {
            self.failed.push(entry);
        }
    }
}

pub(crate) fn credential_bundle(account: &ProviderAccount) -> ProviderCredentialBundle {
    let mut credentials = account.managed_credentials.clone().unwrap_or_default();
    credentials.api_key.clone_from(&account.api_key);
    credentials.secret_key.clone_from(&account.secret_key);
    credentials.cookie_header.clone_from(&account.cookie_header);
    credentials
}

pub(crate) fn apply_credential_bundle(
    account: &mut ProviderAccount,
    credentials: &ProviderCredentialBundle,
) {
    account.apply_managed_credential_bundle(credentials);
}

pub(crate) fn clear_credentials(account: &mut ProviderAccount) {
    account.api_key = None;
    account.secret_key = None;
    account.cookie_header = None;
    account.managed_credentials = None;
}

pub(crate) fn has_credentials(credentials: &ProviderCredentialBundle) -> bool {
    credentials.api_key.is_some()
        || credentials.secret_key.is_some()
        || credentials.cookie_header.is_some()
        || credentials.artifact.is_some()
}

pub(crate) fn resolved_identity(
    provider: ProviderId,
    metadata: Option<&ProviderAccountIdentity>,
    existing: Option<&LoadedProviderCredential>,
) -> Result<ProviderAccountIdentity, CredentialVaultError> {
    if metadata.is_some_and(|identity| identity.provider != provider) {
        return Err(CredentialVaultError::ProviderMismatch);
    }
    let existing_identity = existing.map(|loaded| &loaded.identity);
    if let Some(existing_identity) = existing_identity {
        if existing_identity.provider != provider {
            return Err(CredentialVaultError::ProviderMismatch);
        }
    }

    match (metadata, existing_identity) {
        (Some(metadata), Some(existing))
            if metadata.is_activation_eligible()
                && existing.is_activation_eligible()
                && !metadata.matches_stable(existing) =>
        {
            Err(CredentialVaultError::IdentityMismatch)
        }
        (Some(metadata), Some(existing))
            if !metadata.is_activation_eligible() && existing.is_activation_eligible() =>
        {
            Ok(existing.clone())
        }
        (Some(metadata), _) => Ok(metadata.clone()),
        (None, Some(existing)) => Ok(existing.clone()),
        (None, None) => Ok(ProviderAccountIdentity::unverified(provider)),
    }
}

pub(crate) fn credential_state(error: &CredentialVaultError) -> ManagedCredentialState {
    match error {
        CredentialVaultError::Io(source) if source.kind() == std::io::ErrorKind::NotFound => {
            ManagedCredentialState::Missing
        }
        CredentialVaultError::DecryptionFailed => ManagedCredentialState::Undecryptable,
        _ => ManagedCredentialState::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        accounts::{
            ManagedCredentialState, ProviderAccountIdentity, ProviderCredentialBundle,
            ProviderCredentialVault, ProviderIdentityKey,
        },
        auth::dpapi::{SecretCodec, SecretError, encode_secret},
        config::{AppConfig, ConfigStore, CredentialField, ProviderAccount},
        model::ProviderId,
    };
    use std::{
        fs,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
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
            Err(SecretError::Platform("fixture-secret-must-not-leak".into()))
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(ciphertext.to_vec())
        }
    }

    #[derive(Debug, Default)]
    struct FailProtectAt {
        call: AtomicUsize,
        fail_at: AtomicUsize,
    }

    impl FailProtectAt {
        fn arm(&self, call: usize) {
            self.call.store(0, Ordering::SeqCst);
            self.fail_at.store(call, Ordering::SeqCst);
        }
    }

    impl SecretCodec for FailProtectAt {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            let call = self.call.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_at.load(Ordering::SeqCst) == call {
                return Err(SecretError::Platform("rollback-fixture-secret".into()));
            }
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(ciphertext.iter().map(|byte| byte ^ 0x5a).collect())
        }
    }

    struct BlockingProtectCodec {
        blocked: Mutex<bool>,
        blocked_changed: Condvar,
        released: Mutex<bool>,
        released_changed: Condvar,
    }

    impl std::fmt::Debug for BlockingProtectCodec {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            Some("safe@example.com".into()),
            None,
        )
    }

    #[test]
    fn visible_credentials_override_managed_fields_without_dropping_opaque_artifact() {
        let account = ProviderAccount {
            api_key: Some("visible-api".into()),
            secret_key: Some("visible-secret".into()),
            cookie_header: Some("visible-cookie".into()),
            managed_credentials: Some(ProviderCredentialBundle {
                api_key: Some("managed-api".into()),
                secret_key: Some("managed-secret".into()),
                cookie_header: Some("managed-cookie".into()),
                artifact_format: Some("fixture-json".into()),
                artifact: Some(b"opaque-artifact".to_vec()),
            }),
            ..ProviderAccount::default()
        };

        let credentials = super::credential_bundle(&account);

        assert_eq!(credentials.api_key.as_deref(), Some("visible-api"));
        assert_eq!(credentials.secret_key.as_deref(), Some("visible-secret"));
        assert_eq!(credentials.cookie_header.as_deref(), Some("visible-cookie"));
        assert_eq!(credentials.artifact_format.as_deref(), Some("fixture-json"));
        assert_eq!(
            credentials.artifact.as_deref(),
            Some(&b"opaque-artifact"[..])
        );
    }

    #[test]
    fn legacy_plaintext_and_protected_secrets_migrate_once_after_verified_readback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let protected = encode_secret(&XorCodec, "protected-cookie-secret").unwrap();
        let original = format!(
            r#"{{"version":3,"providers":{{"openrouter":{{"accounts":[{{"id":"acc_api","apiKey":"plaintext-api-secret"}}]}},"cursor":{{"accounts":[{{"id":"acc_cookie","cookieHeader":"{protected}"}}]}}}}}}"#
        );
        fs::write(&path, original).unwrap();
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));

        let (loaded, report) = store.load_with_migration_report().unwrap();

        assert_eq!(report.migrated.len(), 2);
        assert!(
            report
                .migrated
                .contains(&(ProviderId::Openrouter, "acc_api".into()))
        );
        assert!(
            report
                .migrated
                .contains(&(ProviderId::Cursor, "acc_cookie".into()))
        );
        assert!(report.failed.is_empty());
        assert_eq!(
            loaded.provider(ProviderId::Openrouter).accounts[0]
                .api_key
                .as_deref(),
            Some("plaintext-api-secret")
        );
        assert_eq!(
            loaded.provider(ProviderId::Cursor).accounts[0]
                .cookie_header
                .as_deref(),
            Some("protected-cookie-secret")
        );
        assert!(
            !loaded.provider(ProviderId::Openrouter).accounts[0]
                .identity
                .as_ref()
                .unwrap()
                .is_activation_eligible()
        );
        let migrated_bytes = fs::read(&path).unwrap();
        let migrated_text = String::from_utf8_lossy(&migrated_bytes);
        for secret in ["plaintext-api-secret", "protected-cookie-secret", "enc:v1:"] {
            assert!(!migrated_text.contains(secret));
        }

        let (_, second_report) = store.load_with_migration_report().unwrap();
        assert!(second_report.migrated.is_empty());
        assert!(second_report.failed.is_empty());
        assert_eq!(fs::read(path).unwrap(), migrated_bytes);
    }

    #[test]
    fn legacy_migration_always_hydrates_non_legacy_vault_accounts() {
        for fail_migration in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.json");
            ProviderCredentialVault::new(directory.path(), &XorCodec)
                .save(
                    ProviderId::Openrouter,
                    "acc_normal",
                    &identity(ProviderId::Openrouter, "normal-official"),
                    &ProviderCredentialBundle {
                        api_key: Some("normal-vault-private".into()),
                        ..Default::default()
                    },
                )
                .unwrap();
            let original = br#"{"version":3,"providers":{"cursor":{"accounts":[{"id":"acc_legacy","cookieHeader":"legacy-private"}]},"openrouter":{"accounts":[{"id":"acc_normal","label":"Normal"}]}}}"#.to_vec();
            fs::write(&path, &original).unwrap();
            let codec = Arc::new(FailProtectAt::default());
            if fail_migration {
                codec.arm(1);
            }
            let store = ConfigStore::at_with_codec(path.clone(), codec);

            let (loaded, report) = store.load_with_migration_report().unwrap();

            assert_eq!(
                loaded.provider(ProviderId::Openrouter).accounts[0]
                    .api_key
                    .as_deref(),
                Some("normal-vault-private"),
                "non-legacy account was not hydrated when fail_migration={fail_migration}"
            );
            if fail_migration {
                assert_eq!(fs::read(&path).unwrap(), original);
                assert!(report.failed.contains(&(
                    ProviderId::Cursor,
                    "acc_legacy".into(),
                    ManagedCredentialState::MigrationFailed,
                )));
                assert_eq!(
                    loaded.provider(ProviderId::Cursor).accounts[0]
                        .cookie_header
                        .as_deref(),
                    Some("legacy-private")
                );
            } else {
                assert!(report.failed.is_empty());
                assert!(
                    report
                        .migrated
                        .contains(&(ProviderId::Cursor, "acc_legacy".into()))
                );
            }
        }
    }

    #[test]
    fn config_save_detects_external_change_before_final_replace_and_rolls_back_vaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let original = b"original-config-private".to_vec();
        fs::write(&path, &original).unwrap();
        let codec = Arc::new(BlockingProtectCodec::new());
        let writer_codec = Arc::clone(&codec);
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            let store = ConfigStore::at_with_codec(writer_path, writer_codec);
            let mut config = AppConfig::default();
            config
                .providers
                .get_mut(&ProviderId::Openrouter)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: "acc_race".into(),
                    api_key: Some("replacement-private".into()),
                    ..Default::default()
                });
            store.save(&config)
        });
        codec.wait_until_blocked();
        fs::write(&path, b"external-config-private").unwrap();
        codec.release();

        let error = writer.join().unwrap().unwrap_err();

        assert!(matches!(
            error,
            crate::config::ConfigError::ConcurrentModification
        ));
        assert_eq!(fs::read(&path).unwrap(), b"external-config-private");
        assert!(
            !directory
                .path()
                .join("accounts/openrouter/acc_race.vault")
                .exists()
        );
        let debug = format!("{error:?}");
        for forbidden in [
            "original-config-private",
            "replacement-private",
            "external-config-private",
        ] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[test]
    fn legacy_migration_detects_external_config_change_and_rolls_back_vault() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(
            &path,
            br#"{"version":3,"providers":{"openrouter":{"accounts":[{"id":"acc_legacy","apiKey":"legacy-private"}]}}}"#,
        )
        .unwrap();
        let codec = Arc::new(BlockingProtectCodec::new());
        let loader_codec = Arc::clone(&codec);
        let loader_path = path.clone();
        let loader = thread::spawn(move || {
            ConfigStore::at_with_codec(loader_path, loader_codec).load_with_migration_report()
        });
        codec.wait_until_blocked();
        fs::write(&path, b"external-login-private").unwrap();
        codec.release();

        let error = loader.join().unwrap().unwrap_err();

        assert!(matches!(
            error,
            crate::config::ConfigError::ConcurrentModification
        ));
        assert_eq!(fs::read(&path).unwrap(), b"external-login-private");
        assert!(
            !directory
                .path()
                .join("accounts/openrouter/acc_legacy.vault")
                .exists()
        );
        assert!(!format!("{error:?}").contains("legacy-private"));
        assert!(!format!("{error:?}").contains("external-login-private"));
    }

    #[test]
    fn persistence_disabled_save_and_load_still_wait_for_the_vault_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let mut config = AppConfig::default();
        config.security.persist_credentials = false;
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let vault = ProviderCredentialVault::new(directory.path(), &XorCodec);

        let held = vault.transaction().unwrap();
        let save_path = path.clone();
        let save_config = config.clone();
        let (save_tx, save_rx) = mpsc::channel();
        let save = thread::spawn(move || {
            let result =
                ConfigStore::at_with_codec(save_path, Arc::new(XorCodec)).save(&save_config);
            save_tx.send(result).unwrap();
        });
        assert!(save_rx.recv_timeout(Duration::from_millis(200)).is_err());
        drop(held);
        save_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        save.join().unwrap();

        let held = vault.transaction().unwrap();
        let load_path = path.clone();
        let (load_tx, load_rx) = mpsc::channel();
        let load = thread::spawn(move || {
            let result = ConfigStore::at_with_codec(load_path, Arc::new(XorCodec)).load();
            load_tx.send(result).unwrap();
        });
        assert!(load_rx.recv_timeout(Duration::from_millis(200)).is_err());
        drop(held);
        load_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        load.join().unwrap();
    }

    #[test]
    fn migration_failure_preserves_exact_config_bytes_and_all_legacy_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let original = br#"{"version":3,"providers":{"openrouter":{"accounts":[{"id":"acc_api","apiKey":"first-private-secret"}]},"cursor":{"accounts":[{"id":"acc_cookie","cookieHeader":"second-private-secret"}]}}}"#.to_vec();
        fs::write(&path, &original).unwrap();
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(RejectProtect));

        let (loaded, report) = store.load_with_migration_report().unwrap();

        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(directory.path().join("accounts").read_dir().is_err());
        assert_eq!(report.migrated, Vec::new());
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, ProviderId::Cursor);
        assert_eq!(report.failed[0].1, "acc_cookie");
        assert_eq!(report.failed[0].2, ManagedCredentialState::MigrationFailed);
        assert_eq!(
            loaded.provider(ProviderId::Openrouter).accounts[0]
                .api_key
                .as_deref(),
            Some("first-private-secret")
        );
        let debug = format!("{report:?}");
        for forbidden in [
            "first-private-secret",
            "second-private-secret",
            "fixture-secret-must-not-leak",
        ] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[test]
    fn save_failure_after_a_vault_replacement_restores_all_exact_previous_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let vault = ProviderCredentialVault::new(directory.path(), &XorCodec);
        for (id, secret) in [("acc_a", "old-a"), ("acc_b", "old-b")] {
            vault
                .save(
                    ProviderId::Openrouter,
                    id,
                    &ProviderAccountIdentity::unverified(ProviderId::Openrouter),
                    &ProviderCredentialBundle {
                        api_key: Some(secret.into()),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let vault_a = vault.path(ProviderId::Openrouter, "acc_a").unwrap();
        let vault_b = vault.path(ProviderId::Openrouter, "acc_b").unwrap();
        let vault_a_before = fs::read(&vault_a).unwrap();
        let vault_b_before = fs::read(&vault_b).unwrap();
        let config_before = b"exact-previous-config-bytes".to_vec();
        fs::write(&path, &config_before).unwrap();
        let codec = Arc::new(FailProtectAt::default());
        codec.arm(2);
        let store = ConfigStore::at_with_codec(path.clone(), codec);
        let mut config = AppConfig::default();
        for (id, secret) in [("acc_a", "new-a"), ("acc_b", "new-b")] {
            config
                .providers
                .get_mut(&ProviderId::Openrouter)
                .unwrap()
                .accounts
                .push(ProviderAccount {
                    id: id.into(),
                    label: Some(id.into()),
                    api_key: Some(secret.into()),
                    ..Default::default()
                });
        }

        let error = store.save(&config).unwrap_err();

        assert_eq!(fs::read(path).unwrap(), config_before);
        assert_eq!(fs::read(vault_a).unwrap(), vault_a_before);
        assert_eq!(fs::read(vault_b).unwrap(), vault_b_before);
        let debug = format!("{error:?}");
        for forbidden in ["new-a", "new-b", "rollback-fixture-secret"] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[cfg(windows)]
    #[test]
    fn final_config_replace_failure_restores_exact_config_and_vault_bytes() {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let mut previous_config = AppConfig::default();
        previous_config.security.persist_credentials = false;
        let previous_config_bytes = serde_json::to_vec_pretty(&previous_config).unwrap();
        fs::write(&path, &previous_config_bytes).unwrap();
        let vault = ProviderCredentialVault::new(directory.path(), &XorCodec);
        let vault_path = vault
            .save(
                ProviderId::Openrouter,
                "acc_existing",
                &ProviderAccountIdentity::unverified(ProviderId::Openrouter),
                &ProviderCredentialBundle {
                    api_key: Some("old-vault-private".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let previous_vault_bytes = fs::read(&vault_path).unwrap();
        let mut replacement = AppConfig::default();
        replacement
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_existing".into(),
                api_key: Some("new-vault-private".into()),
                ..Default::default()
            });
        let locked_config = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();

        let error = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec))
            .save(&replacement)
            .unwrap_err();
        drop(locked_config);

        assert!(matches!(error, crate::config::ConfigError::Write(_)));
        assert_eq!(fs::read(path).unwrap(), previous_config_bytes);
        assert_eq!(fs::read(vault_path).unwrap(), previous_vault_bytes);
        let debug = format!("{error:?}");
        assert!(!debug.contains("old-vault-private"));
        assert!(!debug.contains("new-vault-private"));
    }

    #[test]
    fn verified_vault_identity_hydrates_missing_metadata_but_conflict_is_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let vault = ProviderCredentialVault::new(directory.path(), &XorCodec);
        let verified = identity(ProviderId::Openrouter, "official-a");
        vault
            .save(
                ProviderId::Openrouter,
                "acc_api",
                &verified,
                &ProviderCredentialBundle {
                    api_key: Some("vault-private-secret".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        fs::write(
            &path,
            br#"{"version":4,"providers":{"openrouter":{"accounts":[{"id":"acc_api","label":"Work"}]}}}"#,
        )
        .unwrap();
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));

        let hydrated = store.load().unwrap();
        let account = &hydrated.provider(ProviderId::Openrouter).accounts[0];
        assert_eq!(account.identity.as_ref(), Some(&verified));
        assert_eq!(account.api_key.as_deref(), Some("vault-private-secret"));

        let mut conflicting = AppConfig::default();
        conflicting
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_api".into(),
                label: Some("Work".into()),
                identity: Some(identity(ProviderId::Openrouter, "official-b")),
                ..Default::default()
            });
        fs::write(&path, serde_json::to_vec(&conflicting).unwrap()).unwrap();

        let (loaded, report) = store.load_with_migration_report().unwrap();

        let account = &loaded.provider(ProviderId::Openrouter).accounts[0];
        assert_eq!(
            account.identity.as_ref().unwrap().stable_keys[0].value,
            "official-b"
        );
        assert_eq!(account.api_key, None);
        assert_eq!(
            report.failed,
            vec![(
                ProviderId::Openrouter,
                "acc_api".into(),
                ManagedCredentialState::Invalid,
            )]
        );
    }

    #[test]
    fn corrupt_missing_and_sibling_vaults_never_cross_hydrate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));
        let mut config = AppConfig::default();
        let openrouter = config.providers.get_mut(&ProviderId::Openrouter).unwrap();
        for (id, secret) in [("acc_good", "good-private"), ("acc_bad", "bad-private")] {
            openrouter.accounts.push(ProviderAccount {
                id: id.into(),
                label: Some(id.into()),
                api_key: Some(secret.into()),
                ..Default::default()
            });
        }
        config
            .providers
            .get_mut(&ProviderId::Cursor)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_missing".into(),
                label: Some("Missing".into()),
                ..Default::default()
            });
        store.save(&config).unwrap();
        fs::write(
            directory.path().join("accounts/openrouter/acc_bad.vault"),
            b"corrupt-vault-private",
        )
        .unwrap();

        let (loaded, report) = store.load_with_migration_report().unwrap();

        let openrouter = loaded.provider(ProviderId::Openrouter);
        assert_eq!(
            openrouter.accounts[0].api_key.as_deref(),
            Some("good-private")
        );
        assert_eq!(openrouter.accounts[1].api_key, None);
        assert_eq!(
            loaded.provider(ProviderId::Cursor).accounts[0].cookie_header,
            None
        );
        assert!(report.failed.contains(&(
            ProviderId::Openrouter,
            "acc_bad".into(),
            ManagedCredentialState::Invalid,
        )));
        assert!(report.failed.contains(&(
            ProviderId::Cursor,
            "acc_missing".into(),
            ManagedCredentialState::Missing,
        )));
        assert_eq!(loaded.credential_issues.len(), 2);
        assert!(loaded.credential_issues.iter().all(|issue| {
            issue.field == CredentialField::Vault
                && !issue.message.contains("corrupt-vault-private")
                && !issue.message.contains("bad-private")
        }));
    }

    #[test]
    fn disabled_persistence_neither_writes_nor_hydrates_vault_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let vault = ProviderCredentialVault::new(directory.path(), &XorCodec);
        vault
            .save(
                ProviderId::Openrouter,
                "acc_api",
                &identity(ProviderId::Openrouter, "official-a"),
                &ProviderCredentialBundle {
                    api_key: Some("existing-vault-private".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let vault_path = vault.path(ProviderId::Openrouter, "acc_api").unwrap();
        let vault_before = fs::read(&vault_path).unwrap();
        let mut config = AppConfig::default();
        config.security.persist_credentials = false;
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_api".into(),
                label: Some("Work".into()),
                api_key: Some("new-private".into()),
                ..Default::default()
            });
        let store = ConfigStore::at_with_codec(path.clone(), Arc::new(XorCodec));

        store.save(&config).unwrap();
        let loaded = store.load().unwrap();

        assert_eq!(
            loaded.provider(ProviderId::Openrouter).accounts[0].api_key,
            None
        );
        assert_eq!(fs::read(vault_path).unwrap(), vault_before);
        let raw = fs::read_to_string(path).unwrap();
        assert!(!raw.contains("new-private"));
        assert!(!raw.contains("enc:v1:"));
    }
}
