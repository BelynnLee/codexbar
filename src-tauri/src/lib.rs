use chrono::{DateTime, Local, Timelike, Utc};
use codexbar_engine::accounts::CredentialMigrationReport;
use codexbar_engine::auth::credentials::{
    ClaudeCredentials, CodexCredentials, is_safe_managed_account_id, managed_credential_path,
};
use codexbar_engine::{
    ActivationTargetKind, AppConfig, BrowserPreference, ConfigStore, CostBreakdown, CostProvider,
    CostRange, CostScanner, Engine, HistoryPoint, HistoryRange, HistoryStore, LocalePreference,
    ManagedCredentialState, MenuBarDisplayMode, ProviderAccount, ProviderAccountIdentity,
    ProviderAuthActionKind, ProviderConfig, ProviderDescriptor, ProviderErrorKind,
    ProviderFetchAttempt, ProviderId, ProviderSettingDescriptor, ProviderSettingKey,
    ProviderSettingKind, ProviderSourceMode, ProviderState, ProviderStatus, RefreshSignals,
    ServiceIndicator, ServiceStatus, ShortcutConfig, Warning, WarningTracker, WidgetSnapshot,
    WidgetSnapshotWriter, evaluate_pace_warnings, evaluate_warnings, next_refresh,
    provider_capabilities, retry_delay, select_tray_metric, status_polled_providers,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::{
    Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_opener::OpenerExt;
use tokio::sync::{Mutex, RwLock};

mod autostart;
mod codex_profiles;
mod copilot_login;
mod notifications;
pub mod provider_accounts;
mod shortcuts;
mod tray_icon;
mod window_activation;

use autostart::{get_launch_at_startup, set_launch_at_startup};
use codex_profiles::CodexProfileManager;
use provider_accounts::{
    ProviderAccountCommandError, ProviderAccountLoginEvent, ProviderAccountLoginStarted,
    ProviderAccountLoginStatus, ProviderAccountManager, ProviderAccountPoolView,
    ProviderAccountStatus, ProviderAdapterRegistry, ProviderRecoveryState,
};
use window_activation::show_main_window;

#[derive(Clone)]
struct AppState {
    engine: Arc<Engine>,
    config_store: ConfigStore,
    states: Arc<RwLock<Vec<ProviderState>>>,
    // Serializes refreshes so the background loop, the tray "Refresh", and save_settings cannot
    // run overlapping fetches and clobber each other's results.
    refresh_lock: Arc<Mutex<()>>,
    // Cross-refresh memory of which threshold warnings already fired, plus the warnings produced by
    // the most recent refresh (broadcast after "usage-updated").
    warning_tracker: Arc<Mutex<WarningTracker>>,
    last_warnings: Arc<RwLock<Vec<Warning>>>,
    // Latest service-incident status per provider, refreshed independently of usage on its own
    // interval and merged into every provider state before it is published.
    service_status: Arc<RwLock<HashMap<ProviderId, ServiceStatus>>>,
    shortcut_error: Arc<RwLock<Option<String>>>,
    provider_accounts: Arc<ProviderAccountManager>,
    provider_adapters: ProviderAdapterRegistry,
    provider_login_runner: Arc<dyn provider_accounts::codex::CodexLoginRunner>,
    // Kept temporarily only for legacy on-disk migration; public/runtime account APIs are generic.
    codex_profiles: Arc<CodexProfileManager>,
}

#[cfg(test)]
mod provider_account_api_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use codexbar_engine::{
        ActivationTargetKind, ManagedCredentialState, ProviderAccountIdentity,
        ProviderEnrollmentKind, ProviderIdentityKey,
        auth::dpapi::{SecretCodec, SecretError},
    };
    use provider_accounts::{
        ActivationSupport, ProviderAccountCommandError, ProviderAccountLoginEvent,
        ProviderAccountLoginStatus, ProviderAccountStatus, ProviderRecoveryState,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct TestCodec;

    impl SecretCodec for TestCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            self.protect(ciphertext)
        }
    }

    #[derive(Debug)]
    struct CancellationRunner {
        observed: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct CapturedRunner;

    #[derive(Debug)]
    struct CapturedAfterCancellationRunner {
        captured: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct TimedOutAfterCancellationRunner {
        ready: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    struct PanicAfterCancellationRunner;

    impl provider_accounts::codex::CodexLoginRunner for CapturedRunner {
        fn run(
            &self,
            invocation: &mut provider_accounts::codex::CodexLoginInvocation,
            _cancellation: &AtomicBool,
        ) -> Result<
            provider_accounts::codex::CodexLoginRunResult,
            provider_accounts::codex::CodexEnrollmentError,
        > {
            let home = invocation
                .command()
                .get_envs()
                .find(|(key, _)| *key == "CODEX_HOME")
                .and_then(|(_, value)| value)
                .map(std::path::PathBuf::from)
                .unwrap();
            std::fs::write(home.join("auth.json"), synthetic_codex_auth_json()).unwrap();
            Ok(provider_accounts::codex::CodexLoginRunResult::Succeeded)
        }
    }

    impl provider_accounts::codex::CodexLoginRunner for CapturedAfterCancellationRunner {
        fn run(
            &self,
            invocation: &mut provider_accounts::codex::CodexLoginInvocation,
            _cancellation: &AtomicBool,
        ) -> Result<
            provider_accounts::codex::CodexLoginRunResult,
            provider_accounts::codex::CodexEnrollmentError,
        > {
            let home = invocation
                .command()
                .get_envs()
                .find(|(key, _)| *key == "CODEX_HOME")
                .and_then(|(_, value)| value)
                .map(std::path::PathBuf::from)
                .unwrap();
            std::fs::write(home.join("auth.json"), synthetic_codex_auth_json()).unwrap();
            self.captured.store(true, Ordering::Release);
            while !self.release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            Ok(provider_accounts::codex::CodexLoginRunResult::Succeeded)
        }
    }

    impl provider_accounts::codex::CodexLoginRunner for TimedOutAfterCancellationRunner {
        fn run(
            &self,
            _invocation: &mut provider_accounts::codex::CodexLoginInvocation,
            _cancellation: &AtomicBool,
        ) -> Result<
            provider_accounts::codex::CodexLoginRunResult,
            provider_accounts::codex::CodexEnrollmentError,
        > {
            self.ready.store(true, Ordering::Release);
            while !self.release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            Ok(provider_accounts::codex::CodexLoginRunResult::TimedOut)
        }
    }

    impl provider_accounts::codex::CodexLoginRunner for PanicAfterCancellationRunner {
        fn run(
            &self,
            _invocation: &mut provider_accounts::codex::CodexLoginInvocation,
            cancellation: &AtomicBool,
        ) -> Result<
            provider_accounts::codex::CodexLoginRunResult,
            provider_accounts::codex::CodexEnrollmentError,
        > {
            while !cancellation.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            panic!("synthetic login runner panic after cancellation")
        }
    }

    fn synthetic_codex_auth_json() -> Vec<u8> {
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "sub": "synthetic-login-subject",
                "email": "synthetic@example.test",
            }))
            .unwrap(),
        );
        serde_json::to_vec(&serde_json::json!({
            "tokens": {
                "access_token": "synthetic-access",
                "refresh_token": "synthetic-refresh",
                "id_token": format!("header.{claims}.signature"),
                "account_id": "synthetic-login-account",
            }
        }))
        .unwrap()
    }

    impl provider_accounts::codex::CodexLoginRunner for CancellationRunner {
        fn run(
            &self,
            _invocation: &mut provider_accounts::codex::CodexLoginInvocation,
            cancellation: &AtomicBool,
        ) -> Result<
            provider_accounts::codex::CodexLoginRunResult,
            provider_accounts::codex::CodexEnrollmentError,
        > {
            while !cancellation.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            self.observed.store(true, Ordering::Release);
            Ok(provider_accounts::codex::CodexLoginRunResult::Cancelled)
        }
    }

    fn manager_fixture() -> (tempfile::TempDir, Arc<ProviderAccountManager>, ConfigStore) {
        let temporary = tempfile::tempdir().unwrap();
        let codec: Arc<dyn SecretCodec> = Arc::new(TestCodec);
        let store =
            ConfigStore::at_with_codec(temporary.path().join("config.json"), Arc::clone(&codec));
        let manager = Arc::new(ProviderAccountManager::new(
            temporary.path().to_path_buf(),
            codec,
            ProviderAdapterRegistry::empty(),
        ));
        (temporary, manager, store)
    }

    fn unsupported_status(provider: ProviderId) -> ProviderAccountStatus {
        ProviderAccountStatus {
            provider_id: provider,
            enrollment: Vec::new(),
            activation: ActivationSupport {
                kind: ActivationTargetKind::Unsupported,
                target_description: None,
                blocked_reason: Some("Monitoring only.".into()),
            },
            active_account_id: None,
            external_identity: None,
            recovery: ProviderRecoveryState::None,
            operation_in_progress: false,
        }
    }

    #[test]
    fn bootstrap_projects_an_account_pool_for_every_provider() {
        let config = AppConfig::default();
        let statuses = ProviderId::ALL
            .into_iter()
            .map(|provider| (provider, unsupported_status(provider)))
            .collect();
        let pools = project_provider_account_pools(&config, &statuses, None);
        for provider in ProviderId::ALL {
            assert!(pools.contains_key(&provider));
            let pool = &pools[&provider];
            assert!(!pool.state_unavailable);
            assert_eq!(
                serde_json::to_value(pool).unwrap()["stateUnavailable"],
                serde_json::json!(false)
            );
        }
    }

    #[test]
    fn unsupported_provider_has_a_safe_reason_and_no_fake_active_marker() {
        let mut config = AppConfig::default();
        let claude = config.providers.get_mut(&ProviderId::Claude).unwrap();
        claude.active_account_id = Some("acc_stale".into());
        claude.accounts = vec![ProviderAccount {
            id: "acc_stale".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Claude,
                [ProviderIdentityKey::new("official-id", "safe-identity")],
                None,
                None,
            )),
            ..Default::default()
        }];
        let mut status = unsupported_status(ProviderId::Claude);
        status.active_account_id = Some("acc_stale".into());
        let statuses = HashMap::from([(ProviderId::Claude, status)]);
        let pool = &project_provider_account_pools(&config, &statuses, None)[&ProviderId::Claude];
        assert_eq!(pool.active_account_id, None);
        assert!(pool.activation.blocked_reason.is_some());
        assert!(!pool.accounts[0].is_active);
        assert!(!pool.accounts[0].can_activate);
    }
    #[test]
    fn busy_and_recovery_pools_do_not_claim_global_state_unavailability() {
        let config = AppConfig::default();
        let mut busy = unsupported_status(ProviderId::Codex);
        busy.operation_in_progress = true;
        let mut recovery = unsupported_status(ProviderId::Claude);
        recovery.recovery = ProviderRecoveryState::Required;
        let pools = project_provider_account_pools(
            &config,
            &HashMap::from([(ProviderId::Codex, busy), (ProviderId::Claude, recovery)]),
            None,
        );

        for provider in [ProviderId::Codex, ProviderId::Claude] {
            let pool = &pools[&provider];
            assert!(!pool.state_unavailable);
            assert_eq!(
                serde_json::to_value(pool).unwrap()["stateUnavailable"],
                serde_json::json!(false)
            );
        }
    }

    #[test]
    fn declared_generic_enrollment_serializes_independently_from_activation() {
        let config = AppConfig::default();
        let mut status = unsupported_status(ProviderId::Codex);
        status.enrollment = vec![
            ProviderEnrollmentKind::CliLogin,
            ProviderEnrollmentKind::ImportCurrent,
        ];
        let pools = project_provider_account_pools(
            &config,
            &HashMap::from([(ProviderId::Codex, status)]),
            None,
        );
        let pool = &pools[&ProviderId::Codex];

        assert_eq!(pool.activation.kind, ActivationTargetKind::Unsupported);
        assert_eq!(
            pool.enrollment,
            vec![
                ProviderEnrollmentKind::CliLogin,
                ProviderEnrollmentKind::ImportCurrent
            ]
        );
        assert_eq!(
            serde_json::to_value(pool).unwrap()["enrollment"],
            serde_json::json!(["cliLogin", "importCurrent"])
        );
    }

    #[test]
    fn generic_settings_save_cannot_remove_or_pause_any_active_official_account() {
        for provider in [
            ProviderId::Codex,
            ProviderId::Claude,
            ProviderId::Openrouter,
        ] {
            let current = ProviderConfig {
                active_account_id: Some("acc_active".into()),
                accounts: vec![ProviderAccount {
                    id: "acc_active".into(),
                    identity: Some(ProviderAccountIdentity::new(
                        provider,
                        [ProviderIdentityKey::new("official-id", "stable-account")],
                        None,
                        None,
                    )),
                    ..Default::default()
                }],
                ..Default::default()
            };
            for accounts in [
                Vec::new(),
                vec![AccountUpdate {
                    id: Some("acc_active".into()),
                    label: None,
                    enabled: false,
                    values: HashMap::new(),
                    secrets: HashMap::new(),
                    clear_secrets: Vec::new(),
                }],
            ] {
                let update = ProviderSettingsUpdate {
                    enabled: true,
                    source_mode: current.source_mode,
                    accounts,
                };
                let error = merge_provider_settings(provider, &current, &update).unwrap_err();
                assert!(error.contains("provider account lifecycle command"));
            }
        }
    }

    #[test]
    fn command_merge_does_not_treat_stale_raw_active_as_authoritative() {
        let current = ProviderConfig {
            active_account_id: Some("acc_old".into()),
            accounts: ["acc_old", "acc_new"]
                .into_iter()
                .map(|account_id| ProviderAccount {
                    id: account_id.into(),
                    identity: Some(ProviderAccountIdentity::new(
                        ProviderId::Codex,
                        [ProviderIdentityKey::new("official-id", account_id)],
                        None,
                        None,
                    )),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let update = ProviderSettingsUpdate {
            enabled: true,
            source_mode: current.source_mode,
            accounts: [("acc_old", false), ("acc_new", true)]
                .into_iter()
                .map(|(id, enabled)| AccountUpdate {
                    id: Some(id.into()),
                    label: None,
                    enabled,
                    values: HashMap::new(),
                    secrets: HashMap::new(),
                    clear_secrets: Vec::new(),
                })
                .collect(),
        };

        let merged = merge_provider_settings_for_command(ProviderId::Codex, &current, &update)
            .expect("locked manager authorization decides the actual active account");

        assert!(!merged.accounts[0].enabled);
        assert!(merged.accounts[1].enabled);
        assert_eq!(merged.active_account_id, None);
    }

    #[test]
    fn generic_event_and_error_serialization_is_camel_case_and_secret_free() {
        let event = ProviderAccountLoginEvent {
            session_id: "login_0000000000000001".into(),
            provider_id: ProviderId::Codex,
            status: ProviderAccountLoginStatus::TimedOut,
            account_id: Some("acc_safe".into()),
            error: Some(ProviderAccountCommandError::login_failure(
                ProviderId::Codex,
                Some("acc_safe"),
            )),
        };
        let serialized = serde_json::to_value(&event).unwrap();
        assert_eq!(serialized["providerId"], "codex");
        assert_eq!(serialized["status"], "timedOut");
        let serialized = serialized.to_string();
        for forbidden in [
            "credentialBundle",
            "artifact",
            "accessToken",
            "refreshToken",
            "cookieHeader",
            "apiKey",
            "secretKey",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn reconciliation_is_provider_siloed_and_skips_recovery() {
        let statuses = HashMap::from([
            (
                ProviderId::Codex,
                ProviderAccountStatus {
                    activation: ActivationSupport {
                        kind: ActivationTargetKind::CliFile,
                        target_description: Some("Codex auth file".into()),
                        blocked_reason: None,
                    },
                    ..unsupported_status(ProviderId::Codex)
                },
            ),
            (
                ProviderId::Claude,
                ProviderAccountStatus {
                    recovery: ProviderRecoveryState::Required,
                    ..unsupported_status(ProviderId::Claude)
                },
            ),
        ]);
        assert_eq!(
            providers_requiring_reconciliation(&statuses),
            vec![ProviderId::Codex]
        );
    }

    #[test]
    fn recovery_state_never_projects_an_unverified_active_marker() {
        let mut config = AppConfig::default();
        let codex = config.providers.get_mut(&ProviderId::Codex).unwrap();
        codex.active_account_id = Some("acc_stale".into());
        codex.accounts = vec![ProviderAccount {
            id: "acc_stale".into(),
            ..Default::default()
        }];
        let status = ProviderAccountStatus {
            provider_id: ProviderId::Codex,
            enrollment: Vec::new(),
            activation: ActivationSupport {
                kind: ActivationTargetKind::CliFile,
                target_description: Some("Codex auth file".into()),
                blocked_reason: None,
            },
            active_account_id: Some("acc_stale".into()),
            external_identity: None,
            recovery: ProviderRecoveryState::Required,
            operation_in_progress: false,
        };
        let pools = project_provider_account_pools(
            &config,
            &HashMap::from([(ProviderId::Codex, status)]),
            None,
        );
        assert_eq!(pools[&ProviderId::Codex].active_account_id, None);
        assert!(!pools[&ProviderId::Codex].accounts[0].is_active);
    }

    #[test]
    fn account_view_pool_and_card_share_safe_active_projection() {
        let mut config = AppConfig::default();
        let settings = config.providers.get_mut(&ProviderId::Codex).unwrap();
        settings.active_account_id = Some("acc_stale".into());
        settings.accounts = vec![ProviderAccount {
            id: "acc_stale".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Codex,
                [ProviderIdentityKey::new("official-id", "stale")],
                None,
                None,
            )),
            ..Default::default()
        }];
        let status = ProviderAccountStatus {
            provider_id: ProviderId::Codex,
            enrollment: Vec::new(),
            activation: ActivationSupport {
                kind: ActivationTargetKind::CliFile,
                target_description: Some("Codex auth file".into()),
                blocked_reason: None,
            },
            active_account_id: Some("acc_stale".into()),
            external_identity: None,
            recovery: ProviderRecoveryState::Required,
            operation_in_progress: false,
        };
        let statuses = HashMap::from([(ProviderId::Codex, status)]);
        let credential_states = HashMap::from([(
            (ProviderId::Codex, "acc_stale".into()),
            ManagedCredentialState::Available,
        )]);
        let descriptor = Engine::new()
            .unwrap()
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.id == ProviderId::Codex)
            .unwrap();
        let states = vec![ProviderState::loading(descriptor).with_account("acc_stale", None)];

        let config_view = config_view_with_profiles(&config, None, &credential_states);
        let pools =
            project_provider_account_pools_with_states(&config, &statuses, &credential_states);
        let cards = stamp_cards_with_states(states, &config, None, &statuses, &credential_states);

        assert!(!config_view.providers[&ProviderId::Codex].accounts[0].is_active);
        assert!(!pools[&ProviderId::Codex].accounts[0].is_active);
        assert!(!cards[0].is_active);
    }

    #[test]
    fn corrupt_vault_is_invalid_and_never_activatable() {
        let (temporary, _manager, store) = manager_fixture();
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .accounts = vec![ProviderAccount {
            id: "acc_corrupt".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Codex,
                [ProviderIdentityKey::new("official-id", "stable-account")],
                None,
                None,
            )),
            ..Default::default()
        }];
        store.save(&config).unwrap();
        let vault_path = temporary
            .path()
            .join("accounts")
            .join("codex")
            .join("acc_corrupt.vault");
        std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();
        std::fs::write(vault_path, b"not-a-vault-envelope").unwrap();
        let (loaded, report) = store.load_with_migration_report().unwrap();
        let credential_states = credential_states_for_projection(&loaded, &report);
        let status = ProviderAccountStatus {
            provider_id: ProviderId::Codex,
            enrollment: Vec::new(),
            activation: ActivationSupport {
                kind: ActivationTargetKind::CliFile,
                target_description: Some("Codex auth file".into()),
                blocked_reason: None,
            },
            active_account_id: None,
            external_identity: None,
            recovery: ProviderRecoveryState::None,
            operation_in_progress: false,
        };
        let pools = project_provider_account_pools_with_states(
            &loaded,
            &HashMap::from([(ProviderId::Codex, status)]),
            &credential_states,
        );
        let account = &pools[&ProviderId::Codex].accounts[0];
        assert_eq!(
            account.managed_credential_state,
            ManagedCredentialState::Invalid
        );
        assert!(!account.can_activate);

        let settings = config_view_with_profiles(&loaded, None, &credential_states);
        let account = &settings.providers[&ProviderId::Codex].accounts[0];
        assert_eq!(
            account.managed_credential_state,
            ManagedCredentialState::Invalid
        );
        assert!(!account.has_managed_credential);
    }

    #[test]
    fn refresh_usage_cards_reuse_accurate_status_instead_of_forcing_busy() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .accounts = vec![ProviderAccount {
            id: "acc_target".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Codex,
                [ProviderIdentityKey::new("official-id", "stable-account")],
                None,
                None,
            )),
            ..Default::default()
        }];
        let status = ProviderAccountStatus {
            provider_id: ProviderId::Codex,
            enrollment: Vec::new(),
            activation: ActivationSupport {
                kind: ActivationTargetKind::CliFile,
                target_description: Some("Codex auth file".into()),
                blocked_reason: None,
            },
            active_account_id: None,
            external_identity: None,
            recovery: ProviderRecoveryState::None,
            operation_in_progress: false,
        };
        let descriptor = Engine::new()
            .unwrap()
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.id == ProviderId::Codex)
            .unwrap();
        let states = vec![
            ProviderState::loading(descriptor).with_account("acc_target", Some("Target".into())),
        ];
        let credential_states = HashMap::from([(
            (ProviderId::Codex, "acc_target".into()),
            ManagedCredentialState::Available,
        )]);
        let cards = refresh_usage_cards(
            &states,
            &config,
            &HashMap::from([(ProviderId::Codex, status)]),
            &credential_states,
        );
        assert!(cards[0].can_activate);
        assert_eq!(cards[0].activation_blocked_reason, None);
    }

    #[test]
    fn refresh_and_service_publications_share_one_accurate_account_projection() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .accounts = vec![ProviderAccount {
            id: "acc_target".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Codex,
                [ProviderIdentityKey::new("official-id", "target")],
                None,
                None,
            )),
            ..Default::default()
        }];
        let status = ProviderAccountStatus {
            provider_id: ProviderId::Codex,
            enrollment: Vec::new(),
            activation: ActivationSupport {
                kind: ActivationTargetKind::CliFile,
                target_description: Some("Codex auth file".into()),
                blocked_reason: None,
            },
            active_account_id: None,
            external_identity: None,
            recovery: ProviderRecoveryState::None,
            operation_in_progress: false,
        };
        let statuses = HashMap::from([(ProviderId::Codex, status)]);
        let credential_states = HashMap::from([(
            (ProviderId::Codex, "acc_target".into()),
            ManagedCredentialState::Available,
        )]);
        let descriptor = Engine::new()
            .unwrap()
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.id == ProviderId::Codex)
            .unwrap();
        let states = vec![ProviderState::loading(descriptor).with_account("acc_target", None)];

        let projection =
            project_provider_surfaces(states, &config, None, &statuses, &credential_states);

        assert!(projection.cards[0].can_activate);
        assert!(!projection.cards[0].is_active);
        assert!(projection.pools[&ProviderId::Codex].accounts[0].can_activate);
        assert!(!projection.config.providers[&ProviderId::Codex].accounts[0].is_active);
    }

    #[test]
    fn account_rows_expose_generic_managed_credential_state_without_material() {
        let row = provider_accounts::ProviderAccountView {
            account_id: "acc_safe".into(),
            label: Some("Work".into()),
            enabled: true,
            identity: None,
            managed_credential_state: ManagedCredentialState::Missing,
            is_active: false,
            can_activate: false,
            activation_blocked_reason: Some("Monitoring only.".into()),
        };
        let value = serde_json::to_value(row).unwrap();
        assert_eq!(value["managedCredentialState"], "missing");
        assert!(value.get("credentials").is_none());
    }

    #[test]
    fn unsupported_provider_command_returns_structured_provider_and_account() {
        let registry = ProviderAdapterRegistry::empty();
        let error = ensure_provider_cli_login_supported(
            &registry,
            ProviderId::Openrouter,
            Some("acc_safe"),
        )
        .unwrap_err();
        assert_eq!(
            error.code(),
            provider_accounts::ProviderAccountCommandErrorCode::UnsupportedActivation
        );
        assert_eq!(error.provider(), Some(ProviderId::Openrouter));
        assert_eq!(error.account_id(), Some("acc_safe"));
    }

    #[test]
    fn untrusted_login_account_ids_are_rejected_before_waiting_or_terminal_events() {
        let (_temporary, _manager, store) = manager_fixture();
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts = vec![ProviderAccount {
            id: "acc_access_token_synthetic".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Claude,
                [ProviderIdentityKey::new("official-id", "foreign")],
                None,
                None,
            )),
            ..Default::default()
        }];
        store.save(&config).unwrap();

        for (raw_account_id, status) in [
            (
                "access_token=synthetic",
                ProviderAccountLoginStatus::Waiting,
            ),
            (
                "acc_access_token_synthetic",
                ProviderAccountLoginStatus::Cancelled,
            ),
            (
                "acc_refresh_token_synthetic",
                ProviderAccountLoginStatus::TimedOut,
            ),
        ] {
            let error = validated_provider_login_account_id(
                &store,
                ProviderId::Codex,
                Some(raw_account_id),
            )
            .unwrap_err();
            assert_eq!(error.account_id(), None, "status: {status:?}");
            assert!(
                !serde_json::to_string(&error)
                    .unwrap()
                    .contains(raw_account_id)
            );
        }
    }

    #[test]
    fn login_events_echo_only_an_existing_account_of_the_exact_provider() {
        let (_temporary, _manager, store) = manager_fixture();
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .accounts = vec![ProviderAccount {
            id: "acc_existing".into(),
            identity: Some(ProviderAccountIdentity::new(
                ProviderId::Codex,
                [ProviderIdentityKey::new("official-id", "existing")],
                None,
                None,
            )),
            ..Default::default()
        }];
        store.save(&config).unwrap();

        let account_id =
            validated_provider_login_account_id(&store, ProviderId::Codex, Some("acc_existing"))
                .unwrap();
        for status in [
            ProviderAccountLoginStatus::Waiting,
            ProviderAccountLoginStatus::Cancelled,
            ProviderAccountLoginStatus::TimedOut,
        ] {
            let event = ProviderAccountLoginEvent {
                session_id: "login_0000000000000001".into(),
                provider_id: ProviderId::Codex,
                status,
                account_id: account_id.clone(),
                error: None,
            };
            assert_eq!(event.account_id.as_deref(), Some("acc_existing"));
        }
    }

    #[test]
    fn activation_transaction_routes_exact_provider_account_and_safe_expected_identity() {
        let (_temporary, manager, store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let expected_current_identity = ProviderAccountIdentity::new(
            ProviderId::Openrouter,
            [ProviderIdentityKey::new("official-id", "observed-account")],
            Some("observed@example.com".into()),
            Some("Observed account".into()),
        );
        let serialized = serde_json::to_value(&expected_current_identity).unwrap();
        assert_eq!(serialized["provider"], serde_json::json!("openrouter"));
        assert_eq!(
            serialized["stableKeys"][0]["value"],
            serde_json::json!("observed-account")
        );
        let serialized_text = serialized.to_string();
        for forbidden in ["apiKey", "artifact", "authJson", "credentials", "token"] {
            assert!(!serialized_text.contains(forbidden));
        }

        let error = runtime
            .block_on(activate_provider_account_transaction(
                &manager,
                &store,
                ProviderId::Openrouter,
                "acc_safe",
                Some(expected_current_identity),
            ))
            .unwrap_err();
        assert_eq!(error.provider(), Some(ProviderId::Openrouter));
        assert_eq!(error.account_id(), Some("acc_safe"));
    }

    #[test]
    fn unknown_login_session_returns_ok_false() {
        let (_temporary, manager, _store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(
            !runtime
                .block_on(cancel_provider_account_login_inner(
                    &manager,
                    "login_ffffffffffffffff",
                ))
                .unwrap()
        );
    }

    #[test]
    fn generic_login_cancellation_reaches_fake_runner_and_cleans_session() {
        let (_temporary, manager, store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (session_id, cancellation) = manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let observed = Arc::new(AtomicBool::new(false));
            let runner: Arc<dyn provider_accounts::codex::CodexLoginRunner> =
                Arc::new(CancellationRunner {
                    observed: Arc::clone(&observed),
                });
            let task = tokio::spawn(execute_provider_login_session(
                ProviderLoginSessionRequest {
                    manager: Arc::clone(&manager),
                    runner,
                    config_store: store,
                    provider: ProviderId::Codex,
                    session_id: session_id.clone(),
                    cancellation,
                    requested_account_id: Some("acc_safe".into()),
                    label: Some("must-not-appear".into()),
                },
            ));
            assert!(manager.cancel_login_session(&session_id).await);
            let event = task.await.unwrap();
            assert_eq!(event.status, ProviderAccountLoginStatus::Cancelled);
            assert!(observed.load(Ordering::Acquire));
            assert!(!manager.cancel_login_session(&session_id).await);
            let serialized = serde_json::to_string(&event).unwrap();
            assert!(!serialized.contains("must-not-appear"));
            assert!(!serialized.contains("credential"));
        });
    }

    #[test]
    fn captured_login_atomically_imports_and_cleans_exact_session() {
        let (_temporary, manager, store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (session_id, cancellation) = manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let request_session_id = session_id.clone();
            let event = execute_provider_login_session(ProviderLoginSessionRequest {
                manager: Arc::clone(&manager),
                runner: Arc::new(CapturedRunner),
                config_store: store.clone(),
                provider: ProviderId::Codex,
                session_id: request_session_id,
                cancellation,
                requested_account_id: None,
                label: Some("Synthetic".into()),
            })
            .await;

            assert_eq!(event.status, ProviderAccountLoginStatus::Succeeded);
            let account_id = event.account_id.as_deref().expect("imported account id");
            let config = store.load().unwrap();
            let settings = config.provider(ProviderId::Codex);
            let account = settings
                .accounts
                .iter()
                .find(|account| account.id == account_id)
                .expect("imported config account");
            assert!(account.managed_credentials.is_some());
            assert!(!manager.cancel_login_session(&session_id).await);
        });
    }

    #[test]
    fn successful_cancel_after_runner_capture_wins_before_login_import() {
        let (_temporary, manager, store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (session_id, cancellation) = manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let (other_session_id, _) = manager
                .begin_login_session(ProviderId::Claude)
                .await
                .unwrap();
            let captured = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let task = tokio::spawn(execute_provider_login_session(
                ProviderLoginSessionRequest {
                    manager: Arc::clone(&manager),
                    runner: Arc::new(CapturedAfterCancellationRunner {
                        captured: Arc::clone(&captured),
                        release: Arc::clone(&release),
                    }),
                    config_store: store.clone(),
                    provider: ProviderId::Codex,
                    session_id: session_id.clone(),
                    cancellation,
                    requested_account_id: None,
                    label: Some("Must not import".into()),
                },
            ));
            while !captured.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            assert!(manager.cancel_login_session(&session_id).await);
            release.store(true, Ordering::Release);

            let event = task.await.unwrap();
            assert_eq!(event.status, ProviderAccountLoginStatus::Cancelled);
            assert_eq!(event.account_id, None);
            assert!(
                store
                    .load()
                    .unwrap()
                    .provider(ProviderId::Codex)
                    .accounts
                    .is_empty()
            );
            assert!(!manager.cancel_login_session(&session_id).await);
            assert!(manager.cancel_login_session(&other_session_id).await);
            assert!(
                manager
                    .finish_login_session(ProviderId::Claude, &other_session_id)
                    .await
                    .is_some()
            );
        });
    }

    #[test]
    fn successful_cancel_overrides_a_timed_out_runner_terminal_result() {
        let (_temporary, manager, store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (session_id, cancellation) = manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let ready = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let task = tokio::spawn(execute_provider_login_session(
                ProviderLoginSessionRequest {
                    manager: Arc::clone(&manager),
                    runner: Arc::new(TimedOutAfterCancellationRunner {
                        ready: Arc::clone(&ready),
                        release: Arc::clone(&release),
                    }),
                    config_store: store,
                    provider: ProviderId::Codex,
                    session_id: session_id.clone(),
                    cancellation,
                    requested_account_id: Some("acc_target".into()),
                    label: None,
                },
            ));
            while !ready.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            assert!(manager.cancel_login_session(&session_id).await);
            release.store(true, Ordering::Release);

            let event = task.await.unwrap();
            assert_eq!(event.status, ProviderAccountLoginStatus::Cancelled);
            assert_eq!(event.account_id.as_deref(), Some("acc_target"));
            assert_eq!(event.error, None);
            assert!(!manager.cancel_login_session(&session_id).await);
        });
    }

    #[test]
    fn successful_cancel_overrides_a_spawn_join_failure() {
        let (_temporary, manager, store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (session_id, cancellation) = manager
                .begin_login_session(ProviderId::Codex)
                .await
                .unwrap();
            let task = tokio::spawn(execute_provider_login_session(
                ProviderLoginSessionRequest {
                    manager: Arc::clone(&manager),
                    runner: Arc::new(PanicAfterCancellationRunner),
                    config_store: store,
                    provider: ProviderId::Codex,
                    session_id: session_id.clone(),
                    cancellation,
                    requested_account_id: None,
                    label: None,
                },
            ));
            assert!(manager.cancel_login_session(&session_id).await);

            let event = task.await.unwrap();
            assert_eq!(event.status, ProviderAccountLoginStatus::Cancelled);
            assert_eq!(event.account_id, None);
            assert_eq!(event.error, None);
            assert!(!manager.cancel_login_session(&session_id).await);
        });
    }

    #[test]
    fn mismatched_login_completion_never_consumes_the_foreign_provider_session() {
        let (_temporary, manager, store) = manager_fixture();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (claude_session_id, cancellation) = manager
                .begin_login_session(ProviderId::Claude)
                .await
                .unwrap();

            let event = execute_provider_login_session(ProviderLoginSessionRequest {
                manager: Arc::clone(&manager),
                runner: Arc::new(CapturedRunner),
                config_store: store,
                provider: ProviderId::Codex,
                session_id: claude_session_id.clone(),
                cancellation,
                requested_account_id: None,
                label: None,
            })
            .await;

            assert_eq!(event.status, ProviderAccountLoginStatus::Failed);
            assert!(manager.cancel_login_session(&claude_session_id).await);
            assert!(
                manager
                    .finish_login_session(ProviderId::Claude, &claude_session_id)
                    .await
                    .is_some()
            );
        });
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Bootstrap {
    descriptors: Vec<ProviderDescriptor>,
    config: ConfigView,
    config_path: String,
    states: Vec<ProviderCard>,
    shortcut_error: Option<String>,
    provider_account_pools: HashMap<ProviderId, ProviderAccountPoolView>,
}

/// A `ProviderState` plus a computed `configured` flag for the usage page. The home view renders only
/// configured cards. The flag is derived at the serialization boundary so the engine's internal
/// `ProviderState` (still used by tray/warnings/history) stays untouched.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderCard {
    #[serde(flatten)]
    state: ProviderState,
    configured: bool,
    is_active: bool,
    can_activate: bool,
    activation_blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigView {
    refresh_interval_minutes: u64,
    locale: LocalePreference,
    menu_bar: MenuBarView,
    notifications: NotificationsView,
    shortcuts: ShortcutsView,
    providers: HashMap<ProviderId, ProviderSettingsView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShortcutsView {
    toggle_window: Option<String>,
    refresh: Option<String>,
    next_provider: Option<String>,
}

impl From<&ShortcutConfig> for ShortcutsView {
    fn from(config: &ShortcutConfig) -> Self {
        Self {
            toggle_window: config.toggle_window.clone(),
            refresh: config.refresh.clone(),
            next_provider: config.next_provider.clone(),
        }
    }
}

impl From<ShortcutsView> for ShortcutConfig {
    fn from(view: ShortcutsView) -> Self {
        Self {
            toggle_window: clean(view.toggle_window),
            refresh: clean(view.refresh),
            next_provider: clean(view.next_provider),
        }
    }
}

/// Editable subset of the menu-bar config. Pinning is preserved across saves but not edited here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MenuBarView {
    display_mode: MenuBarDisplayMode,
    highest_usage: bool,
    show_percentage: bool,
}

/// Editable subset of notification config: window toggles and predictive pace are preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationsView {
    enabled: bool,
    thresholds: Vec<f64>,
    predictive_pace: bool,
    quiet_start: Option<String>,
    quiet_end: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderSettingsView {
    enabled: bool,
    source_mode: ProviderSourceMode,
    accounts: Vec<AccountView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountView {
    id: String,
    label: Option<String>,
    enabled: bool,
    values: HashMap<ProviderSettingKey, ProviderSettingValue>,
    configured_secrets: Vec<ProviderSettingKey>,
    /// Whether an OAuth account (Claude/Codex) has a managed credential slot imported on disk.
    has_managed_credential: bool,
    identity: Option<ProviderAccountIdentity>,
    managed_credential_state: ManagedCredentialState,
    is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum ProviderSettingValue {
    Text(String),
    MultiValue(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsUpdate {
    refresh_interval_minutes: u64,
    locale: LocalePreference,
    menu_bar: MenuBarView,
    notifications: NotificationsView,
    shortcuts: ShortcutsView,
    providers: HashMap<ProviderId, ProviderSettingsUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderSettingsUpdate {
    enabled: bool,
    source_mode: ProviderSourceMode,
    accounts: Vec<AccountUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountUpdate {
    /// Empty/absent for a newly added account; `normalize` assigns an id on save.
    id: Option<String>,
    label: Option<String>,
    enabled: bool,
    #[serde(default)]
    values: HashMap<ProviderSettingKey, ProviderSettingValue>,
    #[serde(default)]
    secrets: HashMap<ProviderSettingKey, String>,
    #[serde(default)]
    clear_secrets: Vec<ProviderSettingKey>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderAccountSwitchResult {
    bootstrap: Bootstrap,
    provider_id: ProviderId,
    previous_account_id: Option<String>,
    active_account_id: String,
    restart_hint: provider_accounts::RestartHint,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderAccountImportCommandResult {
    bootstrap: Bootstrap,
    provider_id: ProviderId,
    account_id: String,
    updated_existing: bool,
}

#[tauri::command]
async fn bootstrap(state: tauri::State<'_, AppState>) -> Result<Bootstrap, String> {
    build_bootstrap(&state).await
}

fn capture_current_provider_account(
    state: &AppState,
    provider: ProviderId,
) -> Result<
    (
        ProviderAccountIdentity,
        codexbar_engine::ProviderCredentialBundle,
    ),
    ProviderAccountCommandError,
> {
    let adapter = state
        .provider_adapters
        .adapter(provider)
        .ok_or_else(|| ProviderAccountCommandError::unsupported_activation(provider, None))?;
    let before = adapter.fingerprint()?;
    let snapshot = adapter.capture()?;
    let identity = adapter
        .current_identity()?
        .filter(|identity| identity.provider == provider && identity.is_activation_eligible())
        .ok_or_else(|| ProviderAccountCommandError::invalid_credential(provider, None))?;
    if adapter.fingerprint()? != before || snapshot.fingerprint != before {
        return Err(ProviderAccountCommandError::external_write(provider, None));
    }
    let credentials = snapshot
        .credentials
        .ok_or_else(|| ProviderAccountCommandError::invalid_credential(provider, None))?;
    adapter.validate_target(&identity, &credentials)?;
    Ok((identity, credentials))
}

fn ensure_provider_cli_login_supported(
    adapters: &ProviderAdapterRegistry,
    provider: ProviderId,
    account_id: Option<&str>,
) -> Result<(), ProviderAccountCommandError> {
    let supported = provider == ProviderId::Codex
        && adapters.enrollment(provider).is_some_and(|kinds| {
            kinds.contains(&codexbar_engine::ProviderEnrollmentKind::CliLogin)
        });
    if supported {
        Ok(())
    } else {
        Err(ProviderAccountCommandError::unsupported_activation(
            provider, account_id,
        ))
    }
}

#[cfg(test)]
fn validated_provider_login_account_id(
    config_store: &ConfigStore,
    provider: ProviderId,
    account_id: Option<&str>,
) -> Result<Option<String>, ProviderAccountCommandError> {
    let Some(account_id) = account_id else {
        return Ok(None);
    };
    if !is_safe_managed_account_id(account_id) {
        return Err(ProviderAccountCommandError::account_not_found(
            provider, None,
        ));
    }
    let config = config_store
        .load()
        .map_err(|_| ProviderAccountCommandError::internal(provider, None))?;
    config
        .provider(provider)
        .accounts
        .iter()
        .any(|account| account.id == account_id)
        .then(|| account_id.to_owned())
        .map(Some)
        .ok_or_else(|| ProviderAccountCommandError::account_not_found(provider, None))
}

async fn activate_provider_account_transaction(
    manager: &ProviderAccountManager,
    config_store: &ConfigStore,
    provider: ProviderId,
    account_id: &str,
    expected_current_identity: Option<ProviderAccountIdentity>,
) -> Result<provider_accounts::ProviderActivationResult, ProviderAccountCommandError> {
    manager
        .activate(
            provider,
            account_id,
            expected_current_identity,
            config_store,
        )
        .await
}

#[tauri::command]
async fn import_current_provider_account(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    provider_id: ProviderId,
    label: Option<String>,
) -> Result<ProviderAccountImportCommandResult, ProviderAccountCommandError> {
    let (identity, credentials) = capture_current_provider_account(&state, provider_id)?;
    let imported = state
        .provider_accounts
        .import_bundle(
            provider_id,
            None,
            clean(label),
            identity,
            credentials,
            &state.config_store,
        )
        .await?;
    refresh_and_publish(&app, &state).await.map_err(|_| {
        ProviderAccountCommandError::internal(provider_id, Some(&imported.account_id))
    })?;
    Ok(ProviderAccountImportCommandResult {
        bootstrap: build_bootstrap(&state).await.map_err(|_| {
            ProviderAccountCommandError::internal(provider_id, Some(&imported.account_id))
        })?,
        provider_id,
        account_id: imported.account_id,
        updated_existing: imported.updated_existing,
    })
}

#[tauri::command]
async fn activate_provider_account(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    provider_id: ProviderId,
    account_id: String,
    expected_current_identity: Option<ProviderAccountIdentity>,
) -> Result<ProviderAccountSwitchResult, ProviderAccountCommandError> {
    let activation = activate_provider_account_transaction(
        &state.provider_accounts,
        &state.config_store,
        provider_id,
        &account_id,
        expected_current_identity,
    )
    .await?;
    refresh_and_publish(&app, &state)
        .await
        .map_err(|_| ProviderAccountCommandError::internal(provider_id, Some(&account_id)))?;
    Ok(ProviderAccountSwitchResult {
        bootstrap: build_bootstrap(&state)
            .await
            .map_err(|_| ProviderAccountCommandError::internal(provider_id, Some(&account_id)))?,
        provider_id,
        previous_account_id: activation.previous_account_id,
        active_account_id: activation.active_account_id,
        restart_hint: activation.restart_hint,
    })
}

#[tauri::command]
async fn delete_provider_account(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    provider_id: ProviderId,
    account_id: String,
) -> Result<Bootstrap, ProviderAccountCommandError> {
    let base = state
        .config_store
        .path()
        .parent()
        .ok_or_else(|| ProviderAccountCommandError::internal(provider_id, Some(&account_id)))?;
    let history = HistoryStore::at(base.join("history"));
    state
        .provider_accounts
        .delete(provider_id, &account_id, &state.config_store, &history)
        .await?;
    refresh_and_publish(&app, &state)
        .await
        .map_err(|_| ProviderAccountCommandError::internal(provider_id, Some(&account_id)))?;
    build_bootstrap(&state)
        .await
        .map_err(|_| ProviderAccountCommandError::internal(provider_id, Some(&account_id)))
}

#[tauri::command]
async fn recover_provider_auth(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    provider_id: ProviderId,
    action: provider_accounts::RecoveryAction,
) -> Result<Bootstrap, ProviderAccountCommandError> {
    state
        .provider_accounts
        .recover(provider_id, action, &state.config_store)
        .await?;
    refresh_and_publish(&app, &state)
        .await
        .map_err(|_| ProviderAccountCommandError::internal(provider_id, None))?;
    build_bootstrap(&state)
        .await
        .map_err(|_| ProviderAccountCommandError::internal(provider_id, None))
}

#[tauri::command]
async fn cancel_provider_account_login(
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> Result<bool, ProviderAccountCommandError> {
    cancel_provider_account_login_inner(&state.provider_accounts, &session_id).await
}

async fn cancel_provider_account_login_inner(
    manager: &ProviderAccountManager,
    session_id: &str,
) -> Result<bool, ProviderAccountCommandError> {
    Ok(manager.cancel_login_session(session_id).await)
}

struct ProviderLoginSessionRequest {
    manager: Arc<ProviderAccountManager>,
    runner: Arc<dyn provider_accounts::codex::CodexLoginRunner>,
    config_store: ConfigStore,
    provider: ProviderId,
    session_id: String,
    cancellation: Arc<std::sync::atomic::AtomicBool>,
    requested_account_id: Option<String>,
    label: Option<String>,
}

async fn execute_provider_login_session(
    request: ProviderLoginSessionRequest,
) -> ProviderAccountLoginEvent {
    let ProviderLoginSessionRequest {
        manager,
        runner,
        config_store,
        provider,
        session_id,
        cancellation,
        requested_account_id,
        label,
    } = request;
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        provider_accounts::codex::run_codex_enrollment(runner.as_ref(), &cancellation)
    })
    .await;
    let (result, needs_terminal_cleanup) = match outcome {
        Ok(Ok(provider_accounts::codex::CodexEnrollmentOutcome::Captured {
            identity,
            credentials,
        })) => (
            manager
                .complete_login_import(
                    provider_accounts::ProviderLoginImportRequest {
                        session_id: session_id.clone(),
                        provider,
                        requested_account_id: requested_account_id.clone(),
                        label: clean(label),
                        identity,
                        credentials,
                    },
                    &config_store,
                )
                .await
                .map(|imported| match imported {
                    Some(imported) => (
                        ProviderAccountLoginStatus::Succeeded,
                        Some(imported.account_id),
                        None,
                    ),
                    None => (
                        ProviderAccountLoginStatus::Cancelled,
                        requested_account_id.clone(),
                        None,
                    ),
                }),
            false,
        ),
        Ok(Ok(provider_accounts::codex::CodexEnrollmentOutcome::Cancelled)) => (
            Ok((
                ProviderAccountLoginStatus::Cancelled,
                requested_account_id.clone(),
                None,
            )),
            true,
        ),
        Ok(Ok(provider_accounts::codex::CodexEnrollmentOutcome::TimedOut)) => (
            Ok((
                ProviderAccountLoginStatus::TimedOut,
                requested_account_id.clone(),
                None,
            )),
            true,
        ),
        Ok(Err(_)) | Err(_) => (
            Err(ProviderAccountCommandError::login_failure(
                provider,
                requested_account_id.as_deref(),
            )),
            true,
        ),
    };
    let cancellation_won = if needs_terminal_cleanup {
        manager.finish_login_session(provider, &session_id).await == Some(true)
    } else {
        false
    };
    let (status, account_id, error) = if cancellation_won {
        (
            ProviderAccountLoginStatus::Cancelled,
            requested_account_id.clone(),
            None,
        )
    } else {
        match result {
            Ok(result) => result,
            Err(error) => (
                ProviderAccountLoginStatus::Failed,
                error.account_id().map(str::to_owned),
                Some(error),
            ),
        }
    };
    ProviderAccountLoginEvent {
        session_id,
        provider_id: provider,
        status,
        account_id,
        error,
    }
}

#[tauri::command]
async fn begin_provider_account_login(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    provider_id: ProviderId,
    account_id: Option<String>,
    label: Option<String>,
) -> Result<ProviderAccountLoginStarted, ProviderAccountCommandError> {
    ensure_provider_cli_login_supported(&state.provider_adapters, provider_id, None)?;
    let (session_id, cancellation, account_id) = state
        .provider_accounts
        .begin_login_session_for_account(provider_id, account_id.as_deref(), &state.config_store)
        .await?;
    let _ = app.emit(
        "provider-account-login-updated",
        ProviderAccountLoginEvent {
            session_id: session_id.clone(),
            provider_id,
            status: ProviderAccountLoginStatus::Waiting,
            account_id: account_id.clone(),
            error: None,
        },
    );

    let task_app = app.clone();
    let task_state = state.inner().clone();
    let task_session_id = session_id.clone();
    let runner = Arc::clone(&state.provider_login_runner);
    tauri::async_runtime::spawn(async move {
        let event = execute_provider_login_session(ProviderLoginSessionRequest {
            manager: Arc::clone(&task_state.provider_accounts),
            runner,
            config_store: task_state.config_store.clone(),
            provider: provider_id,
            session_id: task_session_id,
            cancellation,
            requested_account_id: account_id,
            label,
        })
        .await;
        if event.status == ProviderAccountLoginStatus::Succeeded {
            let _ = refresh_and_publish(&task_app, &task_state).await;
        }
        let _ = task_app.emit("provider-account-login-updated", event);
    });

    Ok(ProviderAccountLoginStarted { session_id })
}

#[tauri::command]
async fn refresh_all(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ProviderCard>, String> {
    refresh_and_publish(&app, &state).await
}

#[tauri::command]
async fn save_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    update: SettingsUpdate,
) -> Result<Bootstrap, String> {
    let touched_providers = update.providers.keys().copied().collect::<Vec<_>>();
    let (mut config, config_revision) = state
        .config_store
        .load_with_revision()
        .map_err(|error| error.to_string())?;
    config.refresh_interval_minutes = update.refresh_interval_minutes;
    config.locale = update.locale;
    config.menu_bar.display_mode = update.menu_bar.display_mode;
    config.menu_bar.highest_usage = update.menu_bar.highest_usage;
    config.menu_bar.show_percentage = update.menu_bar.show_percentage;
    config.notifications.enabled = update.notifications.enabled;
    config.notifications.thresholds = update.notifications.thresholds;
    config.notifications.predictive_pace = update.notifications.predictive_pace;
    config.notifications.quiet_start = clean(update.notifications.quiet_start);
    config.notifications.quiet_end = clean(update.notifications.quiet_end);
    config.shortcuts = update.shortcuts.into();
    for provider in ProviderId::ALL {
        let Some(update) = update.providers.get(&provider) else {
            continue;
        };
        let current = config.provider(provider);
        // The frontend sends the full desired account list. Index the existing accounts by id so an
        // update that omits a secret (e.g. the user only renamed a key) keeps the stored value, and
        // accounts absent from the list are dropped. save() → normalize() assigns ids to new rows
        // and discards blank ones.
        let merged = merge_provider_settings_for_command(provider, &current, update)?;
        config.providers.insert(provider, merged);
    }
    let registry = app.state::<shortcuts::ShortcutRegistry>();
    let old_actions = match registry.replace_config(&app, &config.shortcuts) {
        Ok(actions) => actions,
        Err(error) => {
            *state.shortcut_error.write().await = Some(error.clone());
            return Err(error);
        }
    };
    if let Err(error) = state
        .provider_accounts
        .save_settings_if_authorized(
            &touched_providers,
            &config,
            &config_revision,
            &state.config_store,
        )
        .await
    {
        let save_error = error.to_string();
        let rollback_error = registry.replace_actions(&app, old_actions).err();
        let message = rollback_error.map_or_else(
            || save_error.clone(),
            |rollback| format!("{save_error}; shortcut rollback failed: {rollback}"),
        );
        *state.shortcut_error.write().await = Some(message.clone());
        return Err(message);
    }
    *state.shortcut_error.write().await = None;
    refresh_and_publish(&app, &state).await?;
    build_bootstrap(&state).await
}

fn merge_account(
    existing: &HashMap<String, ProviderAccount>,
    update: &AccountUpdate,
    provider: ProviderId,
) -> Result<ProviderAccount, String> {
    let existing_id = update
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let mut account = if let Some(id) = existing_id {
        if !is_safe_managed_account_id(id) {
            return Err("Account id is not a valid server-generated id".to_owned());
        }
        existing
            .get(id)
            .cloned()
            .ok_or_else(|| "Account id does not belong to this provider".to_owned())?
    } else {
        ProviderAccount::default()
    };
    if let Some(id) = existing_id {
        account.id = id.to_owned();
    }
    account.label = clean(update.label.clone());
    account.enabled = update.enabled;
    let capabilities = provider_capabilities(provider);
    for (key, value) in &update.values {
        let descriptor = supported_setting(capabilities.settings, *key)?;
        apply_setting_value(&mut account, descriptor, value.clone())?;
    }
    for (key, value) in &update.secrets {
        let descriptor = supported_setting(capabilities.settings, *key)?;
        if descriptor.kind != ProviderSettingKind::Secret {
            return Err(format!("Setting {key:?} is not a secret"));
        }
        set_secret(&mut account, *key, clean(Some(value.clone())));
    }
    for key in &update.clear_secrets {
        let descriptor = supported_setting(capabilities.settings, *key)?;
        if descriptor.kind != ProviderSettingKind::Secret {
            return Err(format!("Setting {key:?} is not a secret"));
        }
        if update.secrets.contains_key(key) {
            continue;
        }
        set_secret(&mut account, *key, None);
    }
    Ok(account)
}

fn merge_provider_settings(
    provider: ProviderId,
    current: &ProviderConfig,
    update: &ProviderSettingsUpdate,
) -> Result<ProviderConfig, String> {
    let lifecycle_error =
        || "Use the provider account lifecycle command for official account changes.".to_owned();
    if let Some(active_id) = current.active_account_id.as_deref() {
        let active_update = update
            .accounts
            .iter()
            .find(|account| account.id.as_deref().map(str::trim) == Some(active_id))
            .ok_or_else(lifecycle_error)?;
        if !active_update.enabled || !update.enabled {
            return Err(lifecycle_error());
        }
    }
    if current.accounts.iter().any(|current_account| {
        (current_account.identity.is_some() || provider == ProviderId::Codex)
            && !update.accounts.iter().any(|account| {
                account.id.as_deref().map(str::trim) == Some(current_account.id.as_str())
            })
    }) {
        return Err(lifecycle_error());
    }
    let provider_uses_official_lifecycle = provider == ProviderId::Codex
        || current.active_account_id.is_some()
        || current
            .accounts
            .iter()
            .any(|account| account.identity.is_some());
    if provider_uses_official_lifecycle
        && update.accounts.iter().any(|account| {
            account
                .id
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty)
        })
    {
        return Err(lifecycle_error());
    }
    let capabilities = provider_capabilities(provider);
    if !capabilities.source_modes.contains(&update.source_mode) {
        return Err(format!(
            "Source mode {:?} is not supported by {provider}",
            update.source_mode
        ));
    }
    let existing: HashMap<String, ProviderAccount> = current
        .accounts
        .iter()
        .cloned()
        .map(|account| (account.id.clone(), account))
        .collect();
    let mut seen_ids = HashSet::new();
    for account in &update.accounts {
        let Some(id) = account
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        if !seen_ids.insert(id) {
            return Err("Duplicate account id in provider update".to_owned());
        }
    }
    let accounts = update
        .accounts
        .iter()
        .map(|account| merge_account(&existing, account, provider))
        .collect::<Result<Vec<_>, _>>()?;
    let mut merged = current.clone();
    merged.enabled = update.enabled;
    merged.source_mode = update.source_mode;
    merged.accounts = accounts;
    Ok(merged)
}

fn merge_provider_settings_for_command(
    provider: ProviderId,
    current: &ProviderConfig,
    update: &ProviderSettingsUpdate,
) -> Result<ProviderConfig, String> {
    let mut authorization_neutral = current.clone();
    authorization_neutral.active_account_id = None;
    merge_provider_settings(provider, &authorization_neutral, update)
}

fn supported_setting(
    settings: &[ProviderSettingDescriptor],
    key: ProviderSettingKey,
) -> Result<ProviderSettingDescriptor, String> {
    settings
        .iter()
        .copied()
        .find(|setting| setting.key == key)
        .ok_or_else(|| format!("Setting {key:?} is not supported by this provider"))
}

fn apply_setting_value(
    account: &mut ProviderAccount,
    descriptor: ProviderSettingDescriptor,
    value: ProviderSettingValue,
) -> Result<(), String> {
    let normalized_text = match (&value, descriptor.kind) {
        (ProviderSettingValue::Text(value), ProviderSettingKind::Plain) => {
            clean(Some(value.clone()))
        }
        (ProviderSettingValue::Text(value), ProviderSettingKind::Select) => {
            let value = clean(Some(value.clone()));
            if let (Some(value), Some(choices)) = (value.as_deref(), descriptor.choices) {
                if !choices.contains(&value) {
                    return Err(format!("Invalid value for setting {:?}", descriptor.key));
                }
            }
            value
        }
        (ProviderSettingValue::MultiValue(values), ProviderSettingKind::MultiValue) => {
            let mut values = values
                .iter()
                .filter_map(|value| clean(Some(value.clone())))
                .collect::<Vec<_>>();
            values.sort();
            values.dedup();
            account.kilo_organization_ids = values;
            return Ok(());
        }
        _ => return Err(format!("Setting kind mismatch for {:?}", descriptor.key)),
    };

    match descriptor.key {
        ProviderSettingKey::Browser => {
            account.browser = match normalized_text.as_deref() {
                None | Some("auto") => BrowserPreference::Auto,
                Some("chrome") => BrowserPreference::Chrome,
                Some("edge") => BrowserPreference::Edge,
                Some(_) => return Err("Invalid browser setting".to_owned()),
            };
        }
        ProviderSettingKey::BaseUrl => account.base_url = normalized_text,
        ProviderSettingKey::Region => account.region = normalized_text,
        ProviderSettingKey::WorkspaceId => account.workspace_id = normalized_text,
        ProviderSettingKey::OrganizationId => account.organization_id = normalized_text,
        ProviderSettingKey::ProjectId => account.project_id = normalized_text,
        ProviderSettingKey::Deployment => account.deployment = normalized_text,
        ProviderSettingKey::EnterpriseHost => account.enterprise_host = normalized_text,
        ProviderSettingKey::UsageScope => account.usage_scope = normalized_text,
        ProviderSettingKey::AwsProfile => account.aws_profile = normalized_text,
        ProviderSettingKey::AwsAuthMode => account.aws_auth_mode = normalized_text,
        ProviderSettingKey::ApiKey
        | ProviderSettingKey::SecretKey
        | ProviderSettingKey::CookieHeader
        | ProviderSettingKey::KiloOrganizationIds => {
            return Err(format!("Setting kind mismatch for {:?}", descriptor.key));
        }
    }
    Ok(())
}

fn setting_value(
    account: &ProviderAccount,
    key: ProviderSettingKey,
) -> Option<ProviderSettingValue> {
    let text = match key {
        ProviderSettingKey::Browser => Some(match account.browser {
            BrowserPreference::Auto => "auto".to_owned(),
            BrowserPreference::Chrome => "chrome".to_owned(),
            BrowserPreference::Edge => "edge".to_owned(),
        }),
        ProviderSettingKey::BaseUrl => account.base_url.clone(),
        ProviderSettingKey::Region => account.region.clone(),
        ProviderSettingKey::WorkspaceId => account.workspace_id.clone(),
        ProviderSettingKey::OrganizationId => account.organization_id.clone(),
        ProviderSettingKey::ProjectId => account.project_id.clone(),
        ProviderSettingKey::Deployment => account.deployment.clone(),
        ProviderSettingKey::EnterpriseHost => account.enterprise_host.clone(),
        ProviderSettingKey::UsageScope => account.usage_scope.clone(),
        ProviderSettingKey::AwsProfile => account.aws_profile.clone(),
        ProviderSettingKey::AwsAuthMode => account.aws_auth_mode.clone(),
        ProviderSettingKey::KiloOrganizationIds => {
            return (!account.kilo_organization_ids.is_empty())
                .then(|| ProviderSettingValue::MultiValue(account.kilo_organization_ids.clone()));
        }
        ProviderSettingKey::ApiKey
        | ProviderSettingKey::SecretKey
        | ProviderSettingKey::CookieHeader => None,
    };
    text.map(ProviderSettingValue::Text)
}

fn set_secret(account: &mut ProviderAccount, key: ProviderSettingKey, value: Option<String>) {
    match key {
        ProviderSettingKey::ApiKey => account.api_key = value,
        ProviderSettingKey::SecretKey => account.secret_key = value,
        ProviderSettingKey::CookieHeader => account.cookie_header = value,
        _ => {}
    }
}

/// Return recorded usage history for one provider/account within a range (`24h`, `7d`, `30d`,
/// `90d`). Reads the same `history\` store the refresh coordinator writes; an empty account id means
/// "any account". Missing history is an empty list, not an error.
#[tauri::command]
fn provider_history(
    state: tauri::State<'_, AppState>,
    provider: ProviderId,
    account_id: Option<String>,
    range: Option<String>,
) -> Result<Vec<HistoryPoint>, String> {
    let base = state
        .config_store
        .path()
        .parent()
        .ok_or_else(|| "Could not resolve the config directory".to_owned())?
        .to_path_buf();
    let range = match range.as_deref() {
        Some("24h") => HistoryRange::Hours24,
        None | Some("7d") => HistoryRange::Days7,
        Some("30d") => HistoryRange::Days30,
        Some("90d") => HistoryRange::Days90,
        Some(other) => return Err(format!("Unknown history range '{other}'")),
    };
    let account = account_id.filter(|id| !id.is_empty());
    HistoryStore::at(base.join("history"))
        .query(provider, account.as_deref(), range, Utc::now())
        .map_err(|error| error.to_string())
}

/// On-demand local cost scan for Codex/Claude session logs. `provider` is `codex`, `claude`, or
/// `both`; `range` is `today`, `7d`, or `30d`. Honors the same `history.codexPath`/`claudePath`
/// overrides as the CLI. This reads only local JSONL logs — never provider network endpoints.
#[tauri::command]
fn scan_cost(
    state: tauri::State<'_, AppState>,
    provider: String,
    range: Option<String>,
) -> Result<CostBreakdown, String> {
    let config = state
        .config_store
        .load()
        .map_err(|error| error.to_string())?;
    let cost_provider = match provider.as_str() {
        "codex" => CostProvider::Codex,
        "claude" => CostProvider::Claude,
        "both" => CostProvider::Both,
        other => return Err(format!("Unknown cost provider '{other}'")),
    };
    let cost_range = match range.as_deref() {
        None | Some("today") => CostRange::Today,
        Some("7d") => CostRange::Days7,
        Some("30d") => CostRange::Days30,
        Some(other) => return Err(format!("Unknown cost range '{other}'")),
    };
    let scanner = CostScanner::resolve(
        config.history.codex_path.clone(),
        config.history.claude_path.clone(),
    )
    .map_err(|error| error.to_string())?;
    scanner
        .scan(cost_provider, cost_range, Utc::now())
        .map_err(|error| error.to_string())
}

#[derive(Clone, Copy)]
struct ManagedCredentialSpec {
    provider: ProviderId,
    provider_key: &'static str,
    default_path: fn() -> Result<std::path::PathBuf, String>,
}

const MANAGED_CREDENTIAL_SPECS: &[ManagedCredentialSpec] = &[
    ManagedCredentialSpec {
        provider: ProviderId::Claude,
        provider_key: "claude",
        default_path: claude_credential_path,
    },
    ManagedCredentialSpec {
        provider: ProviderId::Codex,
        provider_key: "codex",
        default_path: codex_credential_path,
    },
];

fn claude_credential_path() -> Result<std::path::PathBuf, String> {
    ClaudeCredentials::default_path().map_err(|error| error.to_string())
}

fn codex_credential_path() -> Result<std::path::PathBuf, String> {
    CodexCredentials::default_path().map_err(|error| error.to_string())
}

fn managed_credential_spec(provider: ProviderId) -> Option<ManagedCredentialSpec> {
    MANAGED_CREDENTIAL_SPECS
        .iter()
        .copied()
        .find(|spec| spec.provider == provider)
}

/// Provider key + default CLI credential path for providers with managed per-account slots.
fn oauth_credential_source(
    provider: ProviderId,
) -> Result<(&'static str, std::path::PathBuf), String> {
    let spec = managed_credential_spec(provider)
        .ok_or_else(|| "This provider does not support managed CLI credential import".to_owned())?;
    Ok((spec.provider_key, (spec.default_path)()?))
}

/// Copy the current CLI credential (`~/.claude/.credentials.json` or `~/.codex/auth.json`) into a
/// managed slot for `account_id`. That account then refreshes only its own copy, isolated from the
/// CLI file and other accounts.
#[tauri::command]
fn import_cli_credential(
    state: tauri::State<'_, AppState>,
    provider: ProviderId,
    account_id: String,
) -> Result<(), String> {
    import_cli_credential_data(&state, provider, &account_id)
}

fn import_cli_credential_data(
    state: &AppState,
    provider: ProviderId,
    account_id: &str,
) -> Result<(), String> {
    let config = state
        .config_store
        .load()
        .map_err(|error| error.to_string())?;
    let account_id = require_managed_account(&config, provider, account_id)?;
    if provider == ProviderId::Codex {
        if !state.codex_profiles.credential_store_mode().is_switchable() {
            return Err(
                "Set cli_auth_credentials_store = \"file\" before importing a Codex Profile."
                    .into(),
            );
        }
        let data = std::fs::read(codex_credential_path()?)
            .map_err(|_| "Could not read the current Codex auth.json".to_owned())?;
        state
            .codex_profiles
            .import_auth_data(&state.config_store, Some(&account_id), None, &data)
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    let base = state
        .config_store
        .path()
        .parent()
        .ok_or_else(|| "Could not resolve the config directory".to_owned())?
        .to_path_buf();
    let (provider_key, default_path) = oauth_credential_source(provider)?;
    let data = std::fs::read(&default_path).map_err(|error| {
        format!(
            "Could not read the CLI credential at {} ({error})",
            default_path.display()
        )
    })?;
    let slot = managed_credential_path(&base, provider_key, &account_id)
        .ok_or_else(|| "Managed credential path was rejected".to_owned())?;
    if let Some(dir) = slot.parent() {
        std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    }
    std::fs::write(&slot, data).map_err(|error| error.to_string())
}

/// Remove an account's managed credential slot (used before/after deleting the account). The account
/// then falls back to the implicit default CLI credential.
#[tauri::command]
fn delete_managed_credential(
    state: tauri::State<'_, AppState>,
    provider: ProviderId,
    account_id: String,
) -> Result<(), String> {
    if provider == ProviderId::Codex {
        return Err(
            "Use the Codex Profile delete command so credentials and history stay consistent."
                .into(),
        );
    }
    let config = state
        .config_store
        .load()
        .map_err(|error| error.to_string())?;
    let account_id = require_managed_account(&config, provider, &account_id)?;
    let base = state
        .config_store
        .path()
        .parent()
        .ok_or_else(|| "Could not resolve the config directory".to_owned())?
        .to_path_buf();
    let (provider_key, _) = oauth_credential_source(provider)?;
    let slot = managed_credential_path(&base, provider_key, &account_id)
        .ok_or_else(|| "Managed credential path was rejected".to_owned())?;
    if slot.exists() {
        std::fs::remove_file(&slot).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn require_managed_account(
    config: &AppConfig,
    provider: ProviderId,
    account_id: &str,
) -> Result<String, String> {
    let account_id = account_id.trim();
    if !is_safe_managed_account_id(account_id) {
        return Err("Save the account first so it has a valid id, then retry".to_owned());
    }
    config
        .provider(provider)
        .accounts
        .iter()
        .find(|account| account.id == account_id)
        .map(|account| account.id.clone())
        .ok_or_else(|| "The selected account does not belong to this provider".to_owned())
}

#[tauri::command]
fn open_dashboard(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    provider: ProviderId,
) -> Result<(), String> {
    let descriptor = state
        .engine
        .descriptors()
        .into_iter()
        .find(|descriptor| descriptor.id == provider)
        .ok_or_else(|| "Unknown provider".to_owned())?;
    app.opener()
        .open_url(descriptor.dashboard_url, None::<&str>)
        .map_err(|error| error.to_string())
}

/// Opens an embedded `WebView2` window at a provider's login page, then reads the session cookie back
/// through the webview's own cookie store — the same engine the browser uses. This sidesteps the two
/// Windows walls that break automatic import from Chrome/Edge (App-Bound `v20` cookie encryption and
/// a live browser locking its cookie database): we never touch the other browser's store at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthActionHandler {
    WebView2Login,
    BrowserCookieImport,
    ManagedCliImport,
    CopilotDeviceOAuth,
}

#[derive(Clone, Copy)]
struct AuthActionHandlerEntry {
    provider: ProviderId,
    action: ProviderAuthActionKind,
    handler: AuthActionHandler,
}

const AUTH_ACTION_HANDLERS: &[AuthActionHandlerEntry] = &[
    AuthActionHandlerEntry {
        provider: ProviderId::Claude,
        action: ProviderAuthActionKind::BrowserLogin,
        handler: AuthActionHandler::WebView2Login,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Claude,
        action: ProviderAuthActionKind::CookieImport,
        handler: AuthActionHandler::BrowserCookieImport,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Cursor,
        action: ProviderAuthActionKind::BrowserLogin,
        handler: AuthActionHandler::WebView2Login,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Cursor,
        action: ProviderAuthActionKind::CookieImport,
        handler: AuthActionHandler::BrowserCookieImport,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Opencode,
        action: ProviderAuthActionKind::BrowserLogin,
        handler: AuthActionHandler::WebView2Login,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Opencode,
        action: ProviderAuthActionKind::CookieImport,
        handler: AuthActionHandler::BrowserCookieImport,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Claude,
        action: ProviderAuthActionKind::CliImport,
        handler: AuthActionHandler::ManagedCliImport,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Codex,
        action: ProviderAuthActionKind::CliImport,
        handler: AuthActionHandler::ManagedCliImport,
    },
    AuthActionHandlerEntry {
        provider: ProviderId::Copilot,
        action: ProviderAuthActionKind::DeviceOAuth,
        handler: AuthActionHandler::CopilotDeviceOAuth,
    },
];

fn resolve_auth_action(
    provider: ProviderId,
    action: ProviderAuthActionKind,
) -> Result<AuthActionHandler, String> {
    if !provider_capabilities(provider)
        .auth_actions
        .contains(&action)
    {
        return Err(format!("Action {action:?} is not advertised by {provider}"));
    }
    AUTH_ACTION_HANDLERS
        .iter()
        .find(|entry| entry.provider == provider && entry.action == action)
        .map(|entry| entry.handler)
        .ok_or_else(|| {
            format!(
                "{provider} action {action:?} is experimental and its handler is not implemented"
            )
        })
}

async fn execute_auth_action(
    app: &tauri::AppHandle,
    state: &AppState,
    provider: ProviderId,
    account_id: Option<String>,
    action: ProviderAuthActionKind,
) -> Result<Bootstrap, String> {
    match resolve_auth_action(provider, action)? {
        AuthActionHandler::WebView2Login => {
            run_login(app, state, provider, account_id.as_deref(), true).await?;
        }
        AuthActionHandler::BrowserCookieImport => {
            import_browser_cookie(state, provider, account_id.as_deref())?;
        }
        AuthActionHandler::ManagedCliImport => {
            import_cli_credential_data(state, provider, account_id.as_deref().unwrap_or_default())?;
        }
        AuthActionHandler::CopilotDeviceOAuth => {
            copilot_login::connect(app, &state.config_store).await?;
        }
    }
    refresh_and_publish(app, state).await?;
    build_bootstrap(state).await
}

macro_rules! auth_command {
    ($name:ident, $action:expr) => {
        #[tauri::command]
        async fn $name(
            app: tauri::AppHandle,
            state: tauri::State<'_, AppState>,
            provider: ProviderId,
            account_id: Option<String>,
        ) -> Result<Bootstrap, String> {
            execute_auth_action(&app, &state, provider, account_id, $action).await
        }
    };
}

auth_command!(browser_login, ProviderAuthActionKind::BrowserLogin);
auth_command!(cookie_import, ProviderAuthActionKind::CookieImport);
auth_command!(cli_import, ProviderAuthActionKind::CliImport);
auth_command!(device_oauth, ProviderAuthActionKind::DeviceOAuth);
auth_command!(oauth_connect, ProviderAuthActionKind::OAuthConnect);
fn compatibility_account_id(config: &AppConfig, provider: ProviderId) -> Option<String> {
    let provider_config = config.provider(provider);
    provider_config
        .active_account_id
        .as_ref()
        .filter(|active_id| {
            provider_config
                .accounts
                .iter()
                .any(|account| account.id == active_id.as_str())
        })
        .cloned()
        .or_else(|| {
            provider_config
                .accounts
                .first()
                .map(|account| account.id.clone())
        })
}

fn preferred_connect_action(provider: ProviderId) -> Option<ProviderAuthActionKind> {
    let advertised = provider_capabilities(provider).auth_actions;
    [
        ProviderAuthActionKind::DeviceOAuth,
        ProviderAuthActionKind::BrowserLogin,
        ProviderAuthActionKind::CliImport,
        ProviderAuthActionKind::CookieImport,
        ProviderAuthActionKind::OAuthConnect,
    ]
    .into_iter()
    .find(|action| advertised.contains(action))
}

/// Compatibility command for older frontend bundles. New UI uses action-specific commands.
#[tauri::command]
async fn connect_provider(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    provider: ProviderId,
) -> Result<Bootstrap, String> {
    let action = preferred_connect_action(provider).ok_or_else(|| {
        format!("{provider} does not expose an interactive authentication action")
    })?;
    let account_id = if action == ProviderAuthActionKind::CliImport {
        let config = state
            .config_store
            .load()
            .map_err(|error| error.to_string())?;
        compatibility_account_id(&config, provider)
    } else {
        None
    };
    execute_auth_action(&app, &state, provider, account_id, action).await
}

/// Static description of how to sign a cookie provider in and which cookies prove a live session.
#[derive(Clone, Copy)]
struct LoginSpec {
    provider: ProviderId,
    display: &'static str,
    /// Page to open; when the session is already live the cookies are read without any interaction.
    login_url: &'static str,
    /// URLs whose cookie jars are inspected (a domain can serve cookies under several hosts).
    cookie_urls: &'static [&'static str],
    /// Domain suffixes used by Chrome/Edge cookie import.
    cookie_domains: &'static [&'static str],
    /// Cookie names the provider's fetcher recognizes, in the order they should appear in the header.
    /// Presence of any one of these is treated as "signed in".
    cookie_names: &'static [&'static str],
}

const LOGIN_SPECS: &[LoginSpec] = &[
    LoginSpec {
        provider: ProviderId::Claude,
        display: "Claude",
        login_url: "https://claude.ai",
        cookie_urls: &["https://claude.ai"],
        cookie_domains: &["claude.ai"],
        cookie_names: &["sessionKey"],
    },
    LoginSpec {
        provider: ProviderId::Cursor,
        display: "Cursor",
        login_url: "https://cursor.com/dashboard?tab=usage",
        cookie_urls: &["https://cursor.com", "https://www.cursor.com"],
        cookie_domains: &["cursor.com"],
        cookie_names: &[
            "WorkosCursorSessionToken",
            "__Secure-next-auth.session-token",
            "next-auth.session-token",
            "wos-session",
            "__Secure-wos-session",
            "authjs.session-token",
            "__Secure-authjs.session-token",
        ],
    },
    LoginSpec {
        provider: ProviderId::Opencode,
        display: "OpenCode",
        login_url: "https://opencode.ai",
        cookie_urls: &["https://opencode.ai"],
        cookie_domains: &["opencode.ai"],
        cookie_names: &["auth", "__Host-auth"],
    },
];

fn login_spec(provider: ProviderId) -> Option<LoginSpec> {
    LOGIN_SPECS
        .iter()
        .copied()
        .find(|spec| spec.provider == provider)
}

fn import_browser_cookie(
    state: &AppState,
    provider: ProviderId,
    account_id: Option<&str>,
) -> Result<(), String> {
    let spec = login_spec(provider)
        .ok_or_else(|| "This provider has no browser cookie import metadata".to_owned())?;
    let mut config = state
        .config_store
        .load()
        .map_err(|error| error.to_string())?;
    let settings = config.providers.entry(provider).or_default();
    let selected = auth_account_index(&settings.accounts, account_id)?;
    let account = &mut settings.accounts[selected];
    replace_cookie_from_import(account, |browser| {
        codexbar_engine::auth::chromium::find_cookie_header(
            browser,
            spec.cookie_domains,
            spec.cookie_names,
        )
        .map(|imported| imported.value)
        .map_err(|error| error.to_string())
    })?;
    account.enabled = true;
    settings.enabled = true;
    state
        .config_store
        .save(&config)
        .map_err(|error| error.to_string())
}

fn replace_cookie_from_import(
    account: &mut ProviderAccount,
    importer: impl FnOnce(BrowserPreference) -> Result<String, String>,
) -> Result<(), String> {
    let imported = importer(account.browser)?;
    account.cookie_header = Some(imported);
    Ok(())
}

fn auth_account_index(
    accounts: &[ProviderAccount],
    account_id: Option<&str>,
) -> Result<usize, String> {
    let Some(account_id) = account_id.map(str::trim).filter(|id| !id.is_empty()) else {
        return Err(
            "Save and select an account before using this authentication action".to_owned(),
        );
    };
    if !is_safe_managed_account_id(account_id) {
        return Err("The selected account id is invalid".to_owned());
    }
    accounts
        .iter()
        .position(|account| account.id == account_id)
        .ok_or_else(|| "The selected account no longer exists; save settings and retry".to_owned())
}

/// Drives one login/refresh cycle for a cookie provider.
///
/// `interactive == true` (user pressed "Connect"): the window stays hidden while we check for an
/// already-live session, then reveals itself so the user can sign in if none is found. `false`
/// (background re-sync of a previously connected provider): the window is never shown; if no live
/// session yields cookies quickly we give up silently. Returns whether a cookie header was stored.
async fn run_login(
    app: &tauri::AppHandle,
    state: &AppState,
    provider: ProviderId,
    account_id: Option<&str>,
    interactive: bool,
) -> Result<bool, String> {
    let Some(spec) = login_spec(provider) else {
        return Err("This provider does not use browser login".into());
    };
    let config = state
        .config_store
        .load()
        .map_err(|error| error.to_string())?;
    auth_account_index(&config.provider(provider).accounts, account_id)?;
    let label = format!("login-{provider}");
    let url = spec
        .login_url
        .parse::<tauri::Url>()
        .map_err(|error| error.to_string())?;

    let window = match app.get_webview_window(&label) {
        Some(window) => window,
        None => WebviewWindowBuilder::new(app, &label, WebviewUrl::External(url))
            .title(format!("登录 {} — CodexBar", spec.display))
            .inner_size(480.0, 720.0)
            .center()
            .visible(false)
            .build()
            .map_err(|error| error.to_string())?,
    };

    let start = Instant::now();
    // Give an existing session a moment to load before bothering the user with a window.
    let silent_phase = Duration::from_millis(if interactive { 2500 } else { 4000 });
    let hard_deadline = Duration::from_secs(if interactive { 180 } else { 6 });
    let mut shown = false;

    let header = loop {
        if let Some(header) = read_cookie_header(&window, spec).await {
            break Some(header);
        }
        let elapsed = start.elapsed();
        if elapsed >= hard_deadline {
            break None;
        }
        if interactive && !shown && elapsed >= silent_phase {
            let _ = window.show();
            let _ = window.set_focus();
            shown = true;
        }
        // A user who closes the login window aborts the wait instead of hanging until the deadline.
        if shown && app.get_webview_window(&label).is_none() {
            return Err("登录窗口已关闭".into());
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    };

    let _ = window.close();

    let Some(header) = header else {
        if interactive {
            return Err("登录超时，请重试".into());
        }
        return Ok(false);
    };
    store_cookie_header(state, provider, account_id, &header)?;
    Ok(true)
}

/// Reads the provider's session cookies out of the login window's cookie store and assembles them
/// into a `Cookie:` header. Runs on a blocking thread because the webview cookie query parks until
/// the event loop replies.
async fn read_cookie_header(window: &WebviewWindow, spec: LoginSpec) -> Option<String> {
    let window = window.clone();
    tauri::async_runtime::spawn_blocking(move || collect_cookie_header(&window, spec))
        .await
        .ok()
        .flatten()
}

fn collect_cookie_header(window: &WebviewWindow, spec: LoginSpec) -> Option<String> {
    let mut found: HashMap<String, String> = HashMap::new();
    for raw in spec.cookie_urls {
        let Ok(url) = raw.parse::<tauri::Url>() else {
            continue;
        };
        let Ok(cookies) = window.cookies_for_url(url) else {
            continue;
        };
        for cookie in cookies {
            let name = cookie.name();
            if spec.cookie_names.contains(&name) && !cookie.value().is_empty() {
                found
                    .entry(name.to_owned())
                    .or_insert_with(|| cookie.value().to_owned());
            }
        }
    }
    if found.is_empty() {
        return None;
    }
    // Emit in the spec's declared order so the header is stable across reads.
    let header = spec
        .cookie_names
        .iter()
        .filter_map(|name| found.get(*name).map(|value| format!("{name}={value}")))
        .collect::<Vec<_>>()
        .join("; ");
    Some(header)
}

/// Writes a freshly captured cookie header onto the selected saved account.
fn store_cookie_header(
    state: &AppState,
    provider: ProviderId,
    account_id: Option<&str>,
    header: &str,
) -> Result<(), String> {
    let mut config = state
        .config_store
        .load()
        .map_err(|error| error.to_string())?;
    let settings = config.providers.entry(provider).or_default();
    let selected = auth_account_index(&settings.accounts, account_id)?;
    settings.enabled = true;
    settings.accounts[selected].cookie_header = Some(header.to_owned());
    settings.accounts[selected].enabled = true;
    state
        .config_store
        .save(&config)
        .map_err(|error| error.to_string())
}

/// After a refresh, silently re-reads cookies for any already-connected cookie provider that just
/// errored — this transparently follows cookie rotation while the `WebView2` session is still alive,
/// with no window and no user action. Providers that were never connected are left alone so nothing
/// pops up unprompted. Returns whether any stored header changed.
async fn background_resync(
    app: &tauri::AppHandle,
    state: &AppState,
    states: &[ProviderState],
) -> bool {
    let Ok(config) = state.config_store.load() else {
        return false;
    };
    let mut changed = false;
    for provider_state in states {
        if provider_state.status != ProviderStatus::Error
            || resolve_auth_action(
                provider_state.descriptor.id,
                ProviderAuthActionKind::BrowserLogin,
            ) != Ok(AuthActionHandler::WebView2Login)
        {
            continue;
        }
        let Some(account_target) = resync_account_id(&provider_state.account_id) else {
            continue;
        };
        let accounts = &config.provider(provider_state.descriptor.id).accounts;
        let has_stored_cookie = match account_target {
            ResyncAccountTarget::Named(account_id) => accounts.iter().any(|account| {
                account.id == account_id
                    && ProviderConfig::normalized_secret(&account.cookie_header).is_some()
            }),
        };
        if !has_stored_cookie {
            continue;
        }
        if matches!(
            run_login(
                app,
                state,
                provider_state.descriptor.id,
                match account_target {
                    ResyncAccountTarget::Named(account_id) => Some(account_id),
                },
                false,
            )
            .await,
            Ok(true)
        ) {
            changed = true;
        }
    }
    changed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResyncAccountTarget<'a> {
    Named(&'a str),
}

fn resync_account_id(account_id: &str) -> Option<ResyncAccountTarget<'_>> {
    let account_id = account_id.trim();
    is_safe_managed_account_id(account_id).then_some(ResyncAccountTarget::Named(account_id))
}

type ProviderCredentialStateMap = HashMap<(ProviderId, String), ManagedCredentialState>;

fn credential_states_for_projection(
    config: &AppConfig,
    report: &CredentialMigrationReport,
) -> ProviderCredentialStateMap {
    let mut states = HashMap::new();
    for provider in ProviderId::ALL {
        for account in &config.provider(provider).accounts {
            states.insert(
                (provider, account.id.clone()),
                if account.managed_credentials.is_some() {
                    ManagedCredentialState::Available
                } else {
                    ManagedCredentialState::Missing
                },
            );
        }
    }
    for (provider, account_id, state) in &report.failed {
        states.insert((*provider, account_id.clone()), *state);
    }
    states
}

fn generic_credential_state(
    credential_states: &ProviderCredentialStateMap,
    provider: ProviderId,
    account: &ProviderAccount,
) -> ManagedCredentialState {
    credential_states
        .get(&(provider, account.id.clone()))
        .copied()
        .unwrap_or(ManagedCredentialState::Missing)
}

#[cfg(test)]
fn project_provider_account_pools(
    config: &AppConfig,
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
    _config_dir: Option<&std::path::Path>,
) -> HashMap<ProviderId, ProviderAccountPoolView> {
    let credential_states =
        credential_states_for_projection(config, &CredentialMigrationReport::default());
    project_provider_account_pools_with_states(config, statuses, &credential_states)
}

fn project_provider_account_pools_with_states(
    config: &AppConfig,
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
    credential_states: &ProviderCredentialStateMap,
) -> HashMap<ProviderId, ProviderAccountPoolView> {
    ProviderId::ALL
        .into_iter()
        .map(|provider| {
            let fallback = ProviderAccountStatus {
                provider_id: provider,
                enrollment: Vec::new(),
                activation: provider_accounts::ActivationSupport {
                    kind: ActivationTargetKind::Unsupported,
                    target_description: None,
                    blocked_reason: Some(
                        "Official client credential activation is not supported for this provider."
                            .into(),
                    ),
                },
                active_account_id: None,
                external_identity: None,
                recovery: ProviderRecoveryState::None,
                operation_in_progress: false,
            };
            let status = statuses.get(&provider).unwrap_or(&fallback);
            let switching_supported = status.activation.kind != ActivationTargetKind::Unsupported;
            let active_account_id = projected_active_account_id(status).map(str::to_owned);
            let accounts = config
                .provider(provider)
                .accounts
                .iter()
                .map(|account| {
                    let credential_state =
                        generic_credential_state(credential_states, provider, account);
                    let is_active = active_account_id.as_deref() == Some(account.id.as_str());
                    let can_activate = switching_supported
                        && !is_active
                        && account.enabled
                        && account.identity.as_ref().is_some_and(|identity| {
                            identity.provider == provider && identity.is_activation_eligible()
                        })
                        && credential_state == ManagedCredentialState::Available
                        && status.recovery == ProviderRecoveryState::None
                        && !status.operation_in_progress;
                    provider_accounts::ProviderAccountView {
                        account_id: account.id.clone(),
                        label: account.label.clone(),
                        enabled: account.enabled,
                        identity: account.identity.clone(),
                        managed_credential_state: credential_state,
                        is_active,
                        can_activate,
                        activation_blocked_reason: (!is_active && !can_activate).then(|| {
                            account_activation_blocked_reason(account, status, credential_state)
                        }),
                    }
                })
                .collect();
            (
                provider,
                ProviderAccountPoolView {
                    provider_id: provider,
                    enrollment: status.enrollment.clone(),
                    active_account_id,
                    accounts,
                    activation: status.activation.clone(),
                    external_identity: status.external_identity.clone(),
                    recovery_state: status.recovery,
                    operation_in_progress: status.operation_in_progress,
                    state_unavailable: false,
                },
            )
        })
        .collect()
}

fn projected_active_account_id(status: &ProviderAccountStatus) -> Option<&str> {
    (status.activation.kind != ActivationTargetKind::Unsupported
        && status.recovery == ProviderRecoveryState::None
        && status.external_identity.is_none())
    .then_some(status.active_account_id.as_deref())
    .flatten()
}

fn account_activation_blocked_reason(
    account: &ProviderAccount,
    status: &ProviderAccountStatus,
    credential_state: ManagedCredentialState,
) -> String {
    if status.operation_in_progress {
        "Another account operation is in progress for this provider.".into()
    } else if status.recovery != ProviderRecoveryState::None {
        "Credential recovery is required before switching accounts.".into()
    } else if !account.enabled {
        "Resume monitoring for this account before switching to it.".into()
    } else if account
        .identity
        .as_ref()
        .is_none_or(|identity| !identity.is_activation_eligible())
    {
        "This account does not have a verified official identity.".into()
    } else if credential_state != ManagedCredentialState::Available {
        "This account credential must be re-imported or re-authenticated.".into()
    } else {
        status
            .activation
            .blocked_reason
            .clone()
            .unwrap_or_else(|| "This account cannot be activated right now.".into())
    }
}

fn providers_requiring_reconciliation(
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
) -> Vec<ProviderId> {
    ProviderId::ALL
        .into_iter()
        .filter(|provider| {
            statuses.get(provider).is_some_and(|status| {
                status.activation.kind != ActivationTargetKind::Unsupported
                    && status.recovery == ProviderRecoveryState::None
                    && !status.operation_in_progress
            })
        })
        .collect()
}

async fn provider_account_statuses(
    state: &AppState,
    config: &AppConfig,
) -> HashMap<ProviderId, ProviderAccountStatus> {
    let mut statuses = HashMap::with_capacity(ProviderId::ALL.len());
    for provider in ProviderId::ALL {
        statuses.insert(
            provider,
            state
                .provider_accounts
                .status_with_config(provider, config)
                .await,
        );
    }
    statuses
}

async fn reconcile_provider_accounts(state: &AppState) {
    let Ok(config) = state.config_store.load() else {
        return;
    };
    let statuses = provider_account_statuses(state, &config).await;
    for provider in providers_requiring_reconciliation(&statuses) {
        let _ = state
            .provider_accounts
            .reconcile(provider, &state.config_store)
            .await;
    }
}

async fn build_bootstrap(state: &AppState) -> Result<Bootstrap, String> {
    state
        .codex_profiles
        .migrate_legacy_profiles(&state.config_store);
    reconcile_provider_accounts(state).await;
    let (config, credential_report) = state
        .config_store
        .load_with_migration_report()
        .map_err(|error| error.to_string())?;
    let provider_statuses = provider_account_statuses(state, &config).await;
    let credential_states = credential_states_for_projection(&config, &credential_report);
    let config_dir = state
        .config_store
        .path()
        .parent()
        .map(std::path::Path::to_path_buf);
    let surfaces = project_provider_surfaces(
        state.states.read().await.clone(),
        &config,
        config_dir.as_deref(),
        &provider_statuses,
        &credential_states,
    );
    Ok(Bootstrap {
        descriptors: state.engine.descriptors(),
        config: surfaces.config,
        config_path: state.config_store.path().display().to_string(),
        states: surfaces.cards,
        shortcut_error: state.shortcut_error.read().await.clone(),
        provider_account_pools: surfaces.pools,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishStep {
    ProviderPoolsEvent,
    UsageEvent,
    WarningEventAndToasts,
    TrayPresentation,
}

fn publish_steps() -> [PublishStep; 4] {
    [
        PublishStep::ProviderPoolsEvent,
        PublishStep::UsageEvent,
        PublishStep::WarningEventAndToasts,
        PublishStep::TrayPresentation,
    ]
}

async fn publish_refresh<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    state: &AppState,
    states: Vec<ProviderState>,
) -> Vec<ProviderCard> {
    let publication = match project_current_provider_surfaces(state, states.clone()).await {
        Ok(surfaces) => surfaces.into(),
        Err(_) => unavailable_provider_publication(&states),
    };
    for step in publish_steps() {
        match step {
            PublishStep::ProviderPoolsEvent => {
                let _ = app.emit("provider-account-pools-updated", publication.pools.clone());
            }
            PublishStep::UsageEvent => {
                let _ = app.emit("usage-updated", publication.cards.clone());
            }
            PublishStep::WarningEventAndToasts => emit_warnings(app, state).await,
            PublishStep::TrayPresentation => update_tray_presentation(app, state).await,
        }
    }
    publication.cards
}

async fn refresh_and_publish<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    state: &AppState,
) -> Result<Vec<ProviderCard>, String> {
    let states = refresh(state).await?;
    Ok(publish_refresh(app, state, states).await)
}

async fn refresh(state: &AppState) -> Result<Vec<ProviderState>, String> {
    let _guard = state.refresh_lock.lock().await;
    state
        .codex_profiles
        .migrate_legacy_profiles(&state.config_store);
    reconcile_provider_accounts(state).await;
    let config = state
        .config_store
        .load()
        .map_err(|error| error.to_string())?;
    let config_dir = state
        .config_store
        .path()
        .parent()
        .map(std::path::Path::to_path_buf);
    let mut states = state
        .engine
        .refresh_all(&config, config_dir.as_deref())
        .await;
    merge_service_status(state, &mut states).await;
    *state.states.write().await = states.clone();

    // Best-effort persistence: history and the third-party widget snapshot are side effects of a
    // successful refresh and never change the returned states.
    record_history_and_snapshot(state, &config, &states);

    // Best-effort warning evaluation: it runs after the required usage fetch and never affects the
    // returned states. `warnings-updated` is broadcast separately by the emit sites.
    let now_minute = local_minute_of_day();
    let now = Utc::now();
    let fired = {
        let mut tracker = state.warning_tracker.lock().await;
        let mut fired = evaluate_warnings(&states, &config.notifications, now_minute, &mut tracker);
        if config.notifications.predictive_pace {
            let history = gather_recent_history(state, &states, now);
            fired.extend(evaluate_pace_warnings(
                &states,
                &history,
                &config.notifications,
                now,
                now_minute,
                &mut tracker,
            ));
        }
        fired
    };
    *state.last_warnings.write().await = fired;

    Ok(states)
}

/// Delay until the next background refresh. With adaptive refresh enabled the engine policy shortens
/// the interval near a reset, on stale data, or after an error, and lengthens it when data is stable;
/// with it disabled the fixed configured interval is used.
fn adaptive_delay(state: &AppState, states: &[ProviderState]) -> Duration {
    let Ok(config) = state.config_store.load() else {
        return Duration::from_secs(5 * 60);
    };
    let base = Duration::from_secs(config.refresh_interval_minutes.clamp(1, 60) * 60);
    if !config.adaptive_refresh.enabled {
        return base;
    }
    let decision = next_refresh(RefreshSignals {
        states,
        base_interval: base,
        max_interval: Duration::from_secs(config.adaptive_refresh.max_interval_minutes.max(1) * 60),
        reset_proximity: Duration::from_secs(
            config.adaptive_refresh.reset_proximity_minutes.max(1) * 60,
        ),
        now: Utc::now(),
        stable: true,
    });
    decision.delay
}

/// Upper bound for exponential retry backoff after a whole-refresh failure.
fn adaptive_retry_cap(state: &AppState) -> Duration {
    let minutes = state.config_store.load().map_or(30, |config| {
        config.adaptive_refresh.max_interval_minutes.max(1)
    });
    Duration::from_secs(minutes * 60)
}

/// Read the last 24 hours of recorded history for the providers in `states` (used by predictive-pace
/// evaluation). Best-effort: unreadable providers contribute nothing.
fn gather_recent_history(
    state: &AppState,
    states: &[ProviderState],
    now: DateTime<Utc>,
) -> Vec<HistoryPoint> {
    let Some(base) = state.config_store.path().parent() else {
        return Vec::new();
    };
    let store = HistoryStore::at(base.join("history"));
    let mut providers: Vec<ProviderId> = states
        .iter()
        .map(|provider_state| provider_state.descriptor.id)
        .collect();
    providers.sort_by_key(|provider| provider.as_str());
    providers.dedup();
    let mut points = Vec::new();
    for provider in providers {
        if let Ok(mut queried) = store.query(provider, None, HistoryRange::Hours24, now) {
            points.append(&mut queried);
        }
    }
    points
}

/// Append usage history and rewrite the reduced widget snapshot after a refresh. Both are opt-in and
/// best-effort: a failure is logged and never propagated, and both derive their paths from the config
/// directory (`history\` and `snapshot.json`) unless the snapshot path is overridden.
fn record_history_and_snapshot(state: &AppState, config: &AppConfig, states: &[ProviderState]) {
    let Some(base) = state.config_store.path().parent() else {
        return;
    };
    let now = Utc::now();
    if config.history.enabled {
        let store = HistoryStore::at(base.join("history"));
        if let Err(error) = store.append_states(states, now, config.history.retention_days) {
            eprintln!("history append failed: {error}");
        }
    }
    if config.widget_snapshot.enabled {
        let path = config
            .widget_snapshot
            .path
            .clone()
            .unwrap_or_else(|| base.join("snapshot.json"));
        let snapshot = WidgetSnapshot::from_states(states, now);
        if let Err(error) = WidgetSnapshotWriter::at(path).write(&snapshot) {
            eprintln!("widget snapshot write failed: {error}");
        }
    }
}

/// Copy the latest cached service-incident status onto each provider state by provider id.
async fn merge_service_status(state: &AppState, states: &mut [ProviderState]) {
    let cache = state.service_status.read().await;
    if cache.is_empty() {
        return;
    }
    for provider_state in states.iter_mut() {
        provider_state.service_status = cache.get(&provider_state.descriptor.id).cloned();
    }
}

/// One pass of the independent status poller: fetch each polled provider's incident status and
/// update the cache. A fetch failure keeps any previous value (or records `Unknown` on first sight)
/// so a single flaky request does not clear a known incident. Returns whether the cache changed.
async fn poll_service_status_once(state: &AppState) -> bool {
    let mut changed = false;
    for provider in status_polled_providers() {
        let Some(result) = state.engine.service_status(provider).await else {
            continue;
        };
        if let Ok(status) = result {
            let mut cache = state.service_status.write().await;
            if cache.get(&provider) != Some(&status) {
                cache.insert(provider, status);
                changed = true;
            }
        } else {
            let mut cache = state.service_status.write().await;
            if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(provider) {
                slot.insert(ServiceStatus {
                    indicator: ServiceIndicator::Unknown,
                    description: None,
                    updated_at: None,
                });
                changed = true;
            }
        }
    }
    changed
}

/// Local wall-clock minute of day (0..=1439), used only for quiet-hours suppression.
fn local_minute_of_day() -> u16 {
    let now = Local::now();
    (now.hour() * 60 + now.minute()) as u16
}

/// Broadcast the warnings produced by the most recent [`refresh`], if any. Emitting is best-effort;
/// a delivery failure is ignored just like `usage-updated`.
async fn emit_warnings<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &AppState) {
    let fired = state.last_warnings.read().await.clone();
    let _ = app.emit("warnings-updated", fired.clone());
    if fired.is_empty() {
        return;
    }
    let locale = state
        .config_store
        .load()
        .map_or(LocalePreference::System, |config| config.locale);
    let states = state.states.read().await.clone();
    for warning in &fired {
        notifications::show_warning(app, warning, &states, &locale);
    }
}

/// Refresh when the main panel is revealed and the newest data is older than the configured
/// stale-on-open threshold. Fresh data (or a disabled threshold) opens instantly with no fetch.
async fn refresh_if_stale<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &AppState) {
    let stale_after = state.config_store.load().map_or(60, |config| {
        config.adaptive_refresh.stale_after_seconds.max(1)
    });
    let newest = state
        .states
        .read()
        .await
        .iter()
        .filter_map(|provider_state| {
            provider_state
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.fetched_at)
        })
        .max();
    let is_stale = newest.is_none_or(|fetched_at| {
        Utc::now().signed_duration_since(fetched_at).num_seconds() >= stale_after as i64
    });
    if is_stale {
        let _ = refresh_and_publish(app, state).await;
    }
}

/// Update the tray image and tooltip from the same selected provider/account metric.
async fn update_tray_presentation<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &AppState) {
    let Some(tray) = app.tray_by_id("codexbar") else {
        return;
    };
    let menu_bar = state
        .config_store
        .load()
        .map(|config| config.menu_bar)
        .unwrap_or_default();
    let metric = {
        let states = state.states.read().await;
        select_tray_metric(&states, &menu_bar)
    };
    let tooltip = metric.as_ref().map_or_else(
        || "CodexBar".to_owned(),
        codexbar_engine::IconMetric::tooltip,
    );
    let _ = tray.set_icon(Some(tray_icon::render(&menu_bar, metric.as_ref())));
    let _ = tray.set_tooltip(Some(&tooltip));
}

#[cfg(test)]
fn config_view(config: &AppConfig, config_dir: Option<&std::path::Path>) -> ConfigView {
    let credential_states =
        credential_states_for_projection(config, &CredentialMigrationReport::default());
    config_view_with_profiles(config, config_dir, &credential_states)
}

#[cfg(test)]
fn config_view_with_profiles(
    config: &AppConfig,
    config_dir: Option<&std::path::Path>,
    credential_states: &ProviderCredentialStateMap,
) -> ConfigView {
    config_view_with_provider_statuses(config, config_dir, &HashMap::new(), credential_states)
}

fn config_view_with_provider_statuses(
    config: &AppConfig,
    config_dir: Option<&std::path::Path>,
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
    credential_states: &ProviderCredentialStateMap,
) -> ConfigView {
    ConfigView {
        refresh_interval_minutes: config.refresh_interval_minutes,
        locale: config.locale.clone(),
        menu_bar: MenuBarView {
            display_mode: config.menu_bar.display_mode,
            highest_usage: config.menu_bar.highest_usage,
            show_percentage: config.menu_bar.show_percentage,
        },
        notifications: NotificationsView {
            enabled: config.notifications.enabled,
            thresholds: config.notifications.thresholds.clone(),
            predictive_pace: config.notifications.predictive_pace,
            quiet_start: config.notifications.quiet_start.clone(),
            quiet_end: config.notifications.quiet_end.clone(),
        },
        shortcuts: ShortcutsView::from(&config.shortcuts),
        providers: ProviderId::ALL
            .into_iter()
            .map(|provider| {
                let settings = config.provider(provider);
                (
                    provider,
                    ProviderSettingsView {
                        enabled: settings.enabled,
                        source_mode: settings.source_mode,
                        accounts: settings
                            .accounts
                            .iter()
                            .map(|account| {
                                account_view(
                                    account,
                                    provider,
                                    config_dir,
                                    statuses.get(&provider),
                                    credential_states,
                                )
                            })
                            .collect(),
                    },
                )
            })
            .collect(),
    }
}

fn account_view(
    account: &ProviderAccount,
    provider: ProviderId,
    _config_dir: Option<&std::path::Path>,
    status: Option<&ProviderAccountStatus>,
    credential_states: &ProviderCredentialStateMap,
) -> AccountView {
    let managed_credential_state = generic_credential_state(credential_states, provider, account);
    let has_managed_credential = managed_credential_state == ManagedCredentialState::Available;
    let values = NON_SECRET_SETTING_KEYS
        .iter()
        .filter_map(|key| setting_value(account, *key).map(|value| (*key, value)))
        .collect();
    let configured_secrets = [
        (ProviderSettingKey::ApiKey, &account.api_key),
        (ProviderSettingKey::SecretKey, &account.secret_key),
        (ProviderSettingKey::CookieHeader, &account.cookie_header),
    ]
    .into_iter()
    .filter_map(|(key, value)| ProviderConfig::normalized_secret(value).map(|_| key))
    .collect();
    AccountView {
        id: account.id.clone(),
        label: account.label.clone(),
        enabled: account.enabled,
        values,
        configured_secrets,
        has_managed_credential,
        identity: account.identity.clone(),
        managed_credential_state,
        is_active: status.and_then(projected_active_account_id) == Some(account.id.as_str()),
    }
}

/// Whether an OAuth account (Claude/Codex/Copilot) has a managed credential slot imported on disk.
fn account_has_managed_credential(
    provider: ProviderId,
    account_id: &str,
    config_dir: Option<&std::path::Path>,
) -> bool {
    managed_credential_spec(provider).is_some_and(|spec| {
        !account_id.is_empty()
            && config_dir.is_some_and(|dir| {
                managed_credential_path(dir, spec.provider_key, account_id)
                    .is_some_and(|path| path.exists())
            })
    })
}

/// Whether an account carries a stored secret worth treating as "configured" (mirrors the
/// `configured_secrets` computation in `account_view`).
fn account_has_stored_secret(account: &ProviderAccount) -> bool {
    ProviderConfig::normalized_secret(&account.api_key).is_some()
        || ProviderConfig::normalized_secret(&account.secret_key).is_some()
        || ProviderConfig::normalized_secret(&account.cookie_header).is_some()
}

/// True when a fetch failed only because no credentials were found (every attempt reported
/// `MissingCredentials`). A timeout leaves `fetch_attempts` empty, which is treated as "had
/// credentials, the fetch just failed" so a transient error never hides a configured card.
fn is_missing_credentials_only(attempts: &[ProviderFetchAttempt]) -> bool {
    !attempts.is_empty()
        && attempts
            .iter()
            .all(|attempt| attempt.error_kind == Some(ProviderErrorKind::MissingCredentials))
}

/// Whether a provider card should appear on the usage page: it must be enabled, and either its account
/// carries a stored/managed credential, or it is actively returning data / failing for a reason other
/// than missing credentials.
fn provider_configured(
    state: &ProviderState,
    config: &AppConfig,
    config_dir: Option<&std::path::Path>,
) -> bool {
    let provider = state.descriptor.id;
    let settings = config.provider(provider);
    if !settings.enabled {
        return false;
    }
    let has_stored = settings
        .accounts
        .iter()
        .find(|account| account.id == state.account_id)
        .is_some_and(account_has_stored_secret);
    if has_stored || account_has_managed_credential(provider, &state.account_id, config_dir) {
        return true;
    }
    match state.status {
        ProviderStatus::Ready => true,
        ProviderStatus::Error => !is_missing_credentials_only(&state.fetch_attempts),
        ProviderStatus::Loading | ProviderStatus::Disabled => false,
    }
}

/// Wrap states with their computed `configured` flag for the usage view.
#[cfg(test)]
fn stamp_cards(
    states: Vec<ProviderState>,
    config: &AppConfig,
    config_dir: Option<&std::path::Path>,
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
) -> Vec<ProviderCard> {
    let credential_states =
        credential_states_for_projection(config, &CredentialMigrationReport::default());
    stamp_cards_with_states(states, config, config_dir, statuses, &credential_states)
}

#[cfg(test)]
fn refresh_usage_cards(
    states: &[ProviderState],
    config: &AppConfig,
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
    credential_states: &ProviderCredentialStateMap,
) -> Vec<ProviderCard> {
    stamp_cards_with_states(states.to_vec(), config, None, statuses, credential_states)
}

fn stamp_cards_with_states(
    states: Vec<ProviderState>,
    config: &AppConfig,
    config_dir: Option<&std::path::Path>,
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
    credential_states: &ProviderCredentialStateMap,
) -> Vec<ProviderCard> {
    let pools = project_provider_account_pools_with_states(config, statuses, credential_states);
    states
        .into_iter()
        .map(|state| {
            let account = pools
                .get(&state.descriptor.id)
                .into_iter()
                .flat_map(|pool| &pool.accounts)
                .find(|account| account.account_id == state.account_id);
            let is_active = account.is_some_and(|account| account.is_active);
            let can_activate = account.is_some_and(|account| account.can_activate);
            let activation_blocked_reason =
                account.and_then(|account| account.activation_blocked_reason.clone());
            let managed_available = account.is_some_and(|account| {
                account.managed_credential_state == ManagedCredentialState::Available
            });
            ProviderCard {
                configured: provider_configured(&state, config, config_dir) || managed_available,
                is_active,
                can_activate,
                activation_blocked_reason,
                state,
            }
        })
        .collect()
}

struct ProviderSurfaces {
    config: ConfigView,
    cards: Vec<ProviderCard>,
    pools: HashMap<ProviderId, ProviderAccountPoolView>,
}

struct ProviderPublication {
    cards: Vec<ProviderCard>,
    pools: HashMap<ProviderId, ProviderAccountPoolView>,
}

impl From<ProviderSurfaces> for ProviderPublication {
    fn from(surfaces: ProviderSurfaces) -> Self {
        Self {
            cards: surfaces.cards,
            pools: surfaces.pools,
        }
    }
}

fn project_provider_surfaces(
    states: Vec<ProviderState>,
    config: &AppConfig,
    config_dir: Option<&std::path::Path>,
    statuses: &HashMap<ProviderId, ProviderAccountStatus>,
    credential_states: &ProviderCredentialStateMap,
) -> ProviderSurfaces {
    ProviderSurfaces {
        config: config_view_with_provider_statuses(config, config_dir, statuses, credential_states),
        cards: stamp_cards_with_states(states, config, config_dir, statuses, credential_states),
        pools: project_provider_account_pools_with_states(config, statuses, credential_states),
    }
}

async fn project_current_provider_surfaces(
    state: &AppState,
    states: Vec<ProviderState>,
) -> Result<ProviderSurfaces, String> {
    let (config, report) = state
        .config_store
        .load_with_migration_report()
        .map_err(|error| error.to_string())?;
    let statuses = provider_account_statuses(state, &config).await;
    let credential_states = credential_states_for_projection(&config, &report);
    Ok(project_provider_surfaces(
        states,
        &config,
        state.config_store.path().parent(),
        &statuses,
        &credential_states,
    ))
}

fn unavailable_provider_cards(states: &[ProviderState]) -> Vec<ProviderCard> {
    states
        .iter()
        .cloned()
        .map(|state| ProviderCard {
            state,
            configured: true,
            is_active: false,
            can_activate: false,
            activation_blocked_reason: Some(
                "Provider account state is temporarily unavailable.".into(),
            ),
        })
        .collect()
}

fn unavailable_provider_publication(states: &[ProviderState]) -> ProviderPublication {
    let blocked_reason = "Provider account state is temporarily unavailable.";
    let pools = ProviderId::ALL
        .into_iter()
        .map(|provider| {
            let accounts = states
                .iter()
                .filter(|state| state.descriptor.id == provider)
                .map(|state| provider_accounts::ProviderAccountView {
                    account_id: state.account_id.clone(),
                    label: state.account_label.clone(),
                    enabled: false,
                    identity: None,
                    managed_credential_state: ManagedCredentialState::Missing,
                    is_active: false,
                    can_activate: false,
                    activation_blocked_reason: Some(blocked_reason.into()),
                })
                .collect();
            (
                provider,
                ProviderAccountPoolView {
                    provider_id: provider,
                    enrollment: Vec::new(),
                    active_account_id: None,
                    accounts,
                    activation: provider_accounts::ActivationSupport::unsupported_with_reason(
                        blocked_reason,
                    ),
                    external_identity: None,
                    recovery_state: ProviderRecoveryState::None,
                    operation_in_progress: true,
                    state_unavailable: true,
                },
            )
        })
        .collect();
    ProviderPublication {
        cards: unavailable_provider_cards(states),
        pools,
    }
}

const NON_SECRET_SETTING_KEYS: &[ProviderSettingKey] = &[
    ProviderSettingKey::Browser,
    ProviderSettingKey::BaseUrl,
    ProviderSettingKey::Region,
    ProviderSettingKey::WorkspaceId,
    ProviderSettingKey::OrganizationId,
    ProviderSettingKey::ProjectId,
    ProviderSettingKey::Deployment,
    ProviderSettingKey::EnterpriseHost,
    ProviderSettingKey::UsageScope,
    ProviderSettingKey::AwsProfile,
    ProviderSettingKey::AwsAuthMode,
    ProviderSettingKey::KiloOrganizationIds,
];

fn clean(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub fn run() {
    let engine = Arc::new(Engine::new().expect("HTTP client should initialize"));
    let initial_states = engine
        .descriptors()
        .into_iter()
        .map(ProviderState::loading)
        .collect();
    let config_store = ConfigStore::discover().expect("Windows AppData should be available");
    let initial_menu_bar = config_store
        .load()
        .map(|config| config.menu_bar)
        .unwrap_or_default();
    let provider_adapters = ProviderAdapterRegistry::verified_default_file_adapters()
        .unwrap_or_else(|_| ProviderAdapterRegistry::empty());
    let provider_config_dir = config_store
        .path()
        .parent()
        .expect("config path should have a parent")
        .to_path_buf();
    let provider_accounts = Arc::new(ProviderAccountManager::new(
        provider_config_dir,
        Arc::new(codexbar_engine::auth::dpapi::DpapiCodec),
        provider_adapters.clone(),
    ));
    let state = AppState {
        engine,
        config_store,
        states: Arc::new(RwLock::new(initial_states)),
        refresh_lock: Arc::new(Mutex::new(())),
        warning_tracker: Arc::new(Mutex::new(WarningTracker::new())),
        last_warnings: Arc::new(RwLock::new(Vec::new())),
        service_status: Arc::new(RwLock::new(HashMap::new())),
        shortcut_error: Arc::new(RwLock::new(None)),
        provider_accounts,
        provider_adapters,
        provider_login_runner: Arc::new(provider_accounts::codex::ProcessCodexLoginRunner),
        codex_profiles: Arc::new(CodexProfileManager::default()),
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(shortcuts::plugin())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_process::init())
        .manage(state.clone())
        .manage(shortcuts::ShortcutRegistry::default())
        .invoke_handler(tauri::generate_handler![
            bootstrap,
            begin_provider_account_login,
            cancel_provider_account_login,
            import_current_provider_account,
            activate_provider_account,
            delete_provider_account,
            recover_provider_auth,
            refresh_all,
            save_settings,
            open_dashboard,
            provider_history,
            scan_cost,
            import_cli_credential,
            delete_managed_credential,
            connect_provider,
            browser_login,
            cookie_import,
            cli_import,
            device_oauth,
            oauth_connect,
            get_launch_at_startup,
            set_launch_at_startup
        ])
        .setup(move |app| {
            let shortcut_handle = app.handle().clone();
            let shortcut_state = state.clone();
            tauri::async_runtime::spawn(async move {
                let result = shortcut_state
                    .config_store
                    .load()
                    .map_err(|error| error.to_string())
                    .and_then(|config| {
                        shortcut_handle
                            .state::<shortcuts::ShortcutRegistry>()
                            .replace_config(&shortcut_handle, &config.shortcuts)
                            .map(|_| ())
                    });
                *shortcut_state.shortcut_error.write().await = result.err();
            });

            let open = MenuItem::with_id(app, "open", "Open CodexBar", true, None::<&str>)?;
            let refresh_item = MenuItem::with_id(app, "refresh", "Refresh", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &refresh_item, &quit])?;
            TrayIconBuilder::with_id("codexbar")
                .icon(tray_icon::render(&initial_menu_bar, None))
                .tooltip("CodexBar")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        show_main_window(app);
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let state = app.state::<AppState>();
                            refresh_if_stale(&app, &state).await;
                        });
                    }
                    "refresh" => {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let state = app.state::<AppState>();
                            let _ = refresh_and_publish(&app, &state).await;
                        });
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let visible = window.is_visible().unwrap_or(false);
                            let minimized = window.is_minimized().unwrap_or(false);
                            if visible && !minimized {
                                let _ = window.hide();
                            } else {
                                show_main_window(app);
                                let app = app.clone();
                                tauri::async_runtime::spawn(async move {
                                    let state = app.state::<AppState>();
                                    refresh_if_stale(&app, &state).await;
                                });
                            }
                        }
                    }
                })
                .build(app)?;

            let app_handle = app.handle().clone();
            let background_state = state.clone();
            tauri::async_runtime::spawn(async move {
                // Consecutive whole-refresh failures drive exponential retry backoff; a success resets
                // it. Per-account fetch errors are handled inside `next_refresh` instead.
                let mut consecutive_failures: u32 = 0;
                loop {
                    let delay = if let Ok(states) = refresh(&background_state).await {
                        consecutive_failures = 0;
                        // A cookie provider that just failed may only need its rotated session
                        // cookie re-read from the still-live WebView2 session; do that silently,
                        // then refresh again so the recovery reaches the UI in the same cycle.
                        let published =
                            if background_resync(&app_handle, &background_state, &states).await {
                                refresh(&background_state).await.unwrap_or(states)
                            } else {
                                states
                            };
                        let delay = adaptive_delay(&background_state, &published);
                        publish_refresh(&app_handle, &background_state, published).await;
                        delay
                    } else {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        let cap = adaptive_retry_cap(&background_state);
                        retry_delay(consecutive_failures - 1, cap)
                    };
                    tokio::time::sleep(delay.max(Duration::from_secs(60))).await;
                }
            });
            // Independent service-status poller. It runs on its own interval, and when an incident
            // status changes it re-merges into the last published states and re-emits so an incident
            // badge appears without waiting for the next usage refresh.
            let status_handle = app.handle().clone();
            let status_state = state.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let config = status_state.config_store.load().ok();
                    let enabled = config
                        .as_ref()
                        .is_none_or(|config| config.status_polling.enabled);
                    let interval = config
                        .as_ref()
                        .map_or(10, |config| config.status_polling.interval_minutes);
                    if enabled && poll_service_status_once(&status_state).await {
                        let mut states = status_state.states.read().await.clone();
                        merge_service_status(&status_state, &mut states).await;
                        *status_state.states.write().await = states.clone();
                        let publication =
                            match project_current_provider_surfaces(&status_state, states.clone())
                                .await
                            {
                                Ok(surfaces) => surfaces.into(),
                                Err(_) => unavailable_provider_publication(&states),
                            };
                        let _ =
                            status_handle.emit("provider-account-pools-updated", publication.pools);
                        let _ = status_handle.emit("usage-updated", publication.cards);
                        update_tray_presentation(&status_handle, &status_state).await;
                    }
                    tokio::time::sleep(Duration::from_secs(interval.clamp(1, 1_440) * 60)).await;
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Only the main panel hides-to-tray on close; login windows must close for real so the
            // user (or `run_login`) can dismiss them.
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running CodexBar");
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    fn publication_orders_required_state_before_optional_side_effects() {
        assert_eq!(
            publish_steps(),
            [
                PublishStep::ProviderPoolsEvent,
                PublishStep::UsageEvent,
                PublishStep::WarningEventAndToasts,
                PublishStep::TrayPresentation,
            ]
        );
    }

    #[test]
    fn unavailable_projection_disables_and_republishes_every_provider_pool() {
        let descriptor = Engine::new()
            .unwrap()
            .descriptors()
            .into_iter()
            .find(|descriptor| descriptor.id == ProviderId::Codex)
            .unwrap();
        let states = vec![ProviderState::loading(descriptor).with_account("acc_target", None)];

        let publication = unavailable_provider_publication(&states);

        assert_eq!(publication.cards.len(), 1);
        assert!(!publication.cards[0].is_active);
        assert!(!publication.cards[0].can_activate);
        assert!(publication.cards[0].activation_blocked_reason.is_some());
        for provider in ProviderId::ALL {
            let pool = &publication.pools[&provider];
            assert_eq!(pool.active_account_id, None);
            assert_eq!(pool.activation.kind, ActivationTargetKind::Unsupported);
            assert!(pool.activation.blocked_reason.is_some());
            assert!(pool.external_identity.is_none());
            assert!(pool.operation_in_progress);
            assert!(pool.enrollment.is_empty());
            assert!(pool.state_unavailable);
            assert_eq!(
                serde_json::to_value(pool).unwrap()["stateUnavailable"],
                serde_json::json!(true)
            );
            assert!(pool.accounts.iter().all(|account| {
                !account.is_active
                    && !account.can_activate
                    && account.activation_blocked_reason.is_some()
            }));
        }
        let target = publication.pools[&ProviderId::Codex]
            .accounts
            .iter()
            .find(|account| account.account_id == "acc_target")
            .unwrap();
        assert!(!target.can_activate);
    }
}

#[cfg(test)]
mod configured_tests {
    use super::*;
    use codexbar_engine::{AuthKind, ProviderSnapshot, ProviderStrategyKind};

    fn descriptor(id: ProviderId) -> ProviderDescriptor {
        ProviderDescriptor {
            id,
            display_name: "Test",
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.test",
            credential_hint: "test",
            supports_multiple_accounts: true,
            capabilities: provider_capabilities(id),
        }
    }

    fn attempt(error_kind: Option<ProviderErrorKind>) -> ProviderFetchAttempt {
        ProviderFetchAttempt {
            strategy_id: "strategy".into(),
            kind: ProviderStrategyKind::ApiToken,
            was_available: true,
            error_kind,
        }
    }

    #[test]
    fn stored_credential_configures_even_on_error() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .accounts = vec![ProviderAccount {
            id: "acc_a".into(),
            api_key: Some("key".into()),
            ..Default::default()
        }];
        let state = ProviderState::failed(descriptor(ProviderId::Openrouter), "boom")
            .with_account("acc_a", None)
            .with_fetch_attempts(vec![attempt(Some(ProviderErrorKind::MissingCredentials))]);

        assert!(provider_configured(&state, &config, None));
    }

    #[test]
    fn disabled_provider_is_never_configured() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Openrouter)
            .unwrap()
            .enabled = false;
        let state = ProviderState::disabled(descriptor(ProviderId::Openrouter));

        assert!(!provider_configured(&state, &config, None));
    }

    #[test]
    fn ready_without_stored_credential_is_configured() {
        // Covers implicit credentials (external CLI login / env-var API key): the fetch succeeded.
        let config = AppConfig::default();
        let state = ProviderState::ready(
            descriptor(ProviderId::Openrouter),
            ProviderSnapshot::new(ProviderId::Openrouter, "cli"),
        );

        assert!(provider_configured(&state, &config, None));
    }

    #[test]
    fn missing_credentials_error_is_not_configured() {
        let config = AppConfig::default();
        let state = ProviderState::failed(descriptor(ProviderId::Openrouter), "no creds")
            .with_fetch_attempts(vec![attempt(Some(ProviderErrorKind::MissingCredentials))]);

        assert!(!provider_configured(&state, &config, None));
    }

    #[test]
    fn non_credential_error_stays_configured() {
        // A network blip must not make a configured card disappear.
        let config = AppConfig::default();
        let state = ProviderState::failed(descriptor(ProviderId::Openrouter), "network down")
            .with_fetch_attempts(vec![attempt(Some(ProviderErrorKind::Network))]);

        assert!(provider_configured(&state, &config, None));
    }

    #[test]
    fn error_without_attempts_stays_configured() {
        // A timeout leaves no attempts; treat it as "had credentials, fetch failed".
        let config = AppConfig::default();
        let state = ProviderState::failed(descriptor(ProviderId::Openrouter), "timed out");

        assert!(provider_configured(&state, &config, None));
    }

    #[test]
    fn loading_without_credential_is_not_configured() {
        let config = AppConfig::default();
        let state = ProviderState::loading(descriptor(ProviderId::Openrouter));

        assert!(!provider_configured(&state, &config, None));
    }

    #[test]
    fn managed_credential_configures_a_loading_card() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let slot = managed_credential_path(base, "claude", "acc_a").unwrap();
        std::fs::create_dir_all(slot.parent().unwrap()).unwrap();
        std::fs::write(&slot, b"{}").unwrap();

        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .enabled = true;
        let state =
            ProviderState::loading(descriptor(ProviderId::Claude)).with_account("acc_a", None);

        assert!(provider_configured(&state, &config, Some(base)));
    }

    #[test]
    fn stamp_cards_sets_flag_and_flattens_state() {
        let config = AppConfig::default();
        let states = vec![ProviderState::ready(
            descriptor(ProviderId::Openrouter),
            ProviderSnapshot::new(ProviderId::Openrouter, "cli"),
        )];

        let cards = stamp_cards(states, &config, None, &HashMap::new());

        assert_eq!(cards.len(), 1);
        assert!(cards[0].configured);
        let json = serde_json::to_value(&cards[0]).unwrap();
        assert_eq!(json["configured"], serde_json::json!(true));
        assert!(
            json.get("descriptor").is_some(),
            "state fields must flatten"
        );
        assert!(json.get("status").is_some(), "state fields must flatten");
    }
}

#[cfg(test)]
mod provider_settings_tests {
    use super::*;
    use codexbar_engine::{
        ProviderAuthActionKind, ProviderSettingDescriptor, ProviderSettingKey, ProviderSettingKind,
        ProviderSourceMode,
    };

    const ALL_NON_SECRET_SETTINGS: &[ProviderSettingDescriptor] = &[
        setting(ProviderSettingKey::Browser, ProviderSettingKind::Select),
        setting(ProviderSettingKey::BaseUrl, ProviderSettingKind::Plain),
        setting(ProviderSettingKey::Region, ProviderSettingKind::Plain),
        setting(ProviderSettingKey::WorkspaceId, ProviderSettingKind::Plain),
        setting(
            ProviderSettingKey::OrganizationId,
            ProviderSettingKind::Plain,
        ),
        setting(ProviderSettingKey::ProjectId, ProviderSettingKind::Plain),
        setting(ProviderSettingKey::Deployment, ProviderSettingKind::Plain),
        setting(
            ProviderSettingKey::EnterpriseHost,
            ProviderSettingKind::Plain,
        ),
        setting(ProviderSettingKey::UsageScope, ProviderSettingKind::Plain),
        setting(ProviderSettingKey::AwsProfile, ProviderSettingKind::Plain),
        setting(ProviderSettingKey::AwsAuthMode, ProviderSettingKind::Plain),
        setting(
            ProviderSettingKey::KiloOrganizationIds,
            ProviderSettingKind::MultiValue,
        ),
    ];

    const fn setting(
        key: ProviderSettingKey,
        kind: ProviderSettingKind,
    ) -> ProviderSettingDescriptor {
        ProviderSettingDescriptor {
            key,
            kind,
            required: false,
            choices: None,
        }
    }

    fn text(value: &str) -> ProviderSettingValue {
        ProviderSettingValue::Text(value.to_owned())
    }

    #[test]
    fn config_view_exposes_source_mode_all_values_and_only_secret_presence() {
        let mut config = AppConfig::default();
        let settings = config.providers.get_mut(&ProviderId::Claude).unwrap();
        settings.source_mode = ProviderSourceMode::Web;
        settings.accounts = vec![ProviderAccount {
            id: "acc_fixture".into(),
            label: Some("Fixture".into()),
            api_key: Some("api-fixture-secret".into()),
            secret_key: Some("secondary-fixture-secret".into()),
            cookie_header: Some("session=fixture-secret".into()),
            workspace_id: Some("workspace".into()),
            region: Some("region".into()),
            organization_id: Some("organization".into()),
            project_id: Some("project".into()),
            deployment: Some("deployment".into()),
            enterprise_host: Some("enterprise.example".into()),
            usage_scope: Some("team".into()),
            aws_profile: Some("profile".into()),
            aws_auth_mode: Some("profile".into()),
            kilo_organization_ids: vec!["org-a".into(), "org-b".into()],
            base_url: Some("https://api.example".into()),
            browser: BrowserPreference::Edge,
            ..Default::default()
        }];

        let view = config_view(&config, None);
        let provider = &view.providers[&ProviderId::Claude];
        assert_eq!(provider.source_mode, ProviderSourceMode::Web);
        let account = &provider.accounts[0];
        assert_eq!(account.values.len(), ALL_NON_SECRET_SETTINGS.len());
        assert_eq!(
            account.configured_secrets,
            vec![
                ProviderSettingKey::ApiKey,
                ProviderSettingKey::SecretKey,
                ProviderSettingKey::CookieHeader,
            ]
        );
        let json = serde_json::to_string(&view).unwrap();
        for secret in [
            "api-fixture-secret",
            "secondary-fixture-secret",
            "session=fixture-secret",
        ] {
            assert!(!json.contains(secret));
        }
        assert!(json.contains("enterprise.example"));
        assert!(json.contains("kiloOrganizationIds"));
    }

    #[test]
    fn generic_setting_mapping_round_trips_every_v4_non_secret_field() {
        let mut account = ProviderAccount::default();
        for descriptor in ALL_NON_SECRET_SETTINGS {
            let value = if descriptor.kind == ProviderSettingKind::MultiValue {
                ProviderSettingValue::MultiValue(vec!["org-a".into(), "org-b".into()])
            } else if descriptor.key == ProviderSettingKey::Browser {
                text("edge")
            } else {
                text(&format!(
                    "{}-value",
                    serde_json::to_value(descriptor.key)
                        .unwrap()
                        .as_str()
                        .unwrap()
                ))
            };
            apply_setting_value(&mut account, *descriptor, value.clone()).unwrap();
            assert_eq!(setting_value(&account, descriptor.key), Some(value));
        }
    }

    #[test]
    fn generic_merge_preserves_replaces_and_explicitly_clears_secrets() {
        let existing = ProviderAccount {
            id: "acc_existing".into(),
            api_key: Some("old-api".into()),
            cookie_header: Some("old-cookie".into()),
            browser: BrowserPreference::Chrome,
            ..Default::default()
        };
        let existing_map = HashMap::from([(existing.id.clone(), existing)]);
        let update = AccountUpdate {
            id: Some("acc_existing".into()),
            label: Some("renamed".into()),
            enabled: true,
            values: HashMap::from([(
                ProviderSettingKey::Browser,
                ProviderSettingValue::Text("edge".into()),
            )]),
            secrets: HashMap::from([(ProviderSettingKey::CookieHeader, "new-cookie".into())]),
            clear_secrets: vec![ProviderSettingKey::ApiKey],
        };

        let merged = merge_account(&existing_map, &update, ProviderId::Claude).unwrap();
        assert_eq!(merged.api_key, None);
        assert_eq!(merged.cookie_header.as_deref(), Some("new-cookie"));
        assert_eq!(merged.label.as_deref(), Some("renamed"));
        assert_eq!(merged.browser, BrowserPreference::Edge);
    }

    #[test]
    fn rejected_provider_update_leaves_current_settings_unchanged() {
        let current = ProviderConfig {
            enabled: true,
            source_mode: ProviderSourceMode::Auto,
            accounts: vec![ProviderAccount {
                id: "acc_existing".into(),
                api_key: Some("keep-secret".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let serialized_before = serde_json::to_value(&current).unwrap();
        let unsupported_source = ProviderSettingsUpdate {
            enabled: false,
            source_mode: ProviderSourceMode::Web,
            accounts: vec![],
        };
        assert!(
            merge_provider_settings(ProviderId::Deepgram, &current, &unsupported_source).is_err()
        );
        assert_eq!(serde_json::to_value(&current).unwrap(), serialized_before);

        let wrong_kind = ProviderSettingsUpdate {
            enabled: true,
            source_mode: ProviderSourceMode::Auto,
            accounts: vec![AccountUpdate {
                id: Some("acc_existing".into()),
                label: None,
                enabled: true,
                values: HashMap::from([(
                    ProviderSettingKey::ProjectId,
                    ProviderSettingValue::MultiValue(vec!["wrong".into()]),
                )]),
                secrets: HashMap::new(),
                clear_secrets: vec![],
            }],
        };
        assert!(merge_provider_settings(ProviderId::Deepgram, &current, &wrong_kind).is_err());

        let unsupported_key = ProviderSettingsUpdate {
            enabled: true,
            source_mode: ProviderSourceMode::Auto,
            accounts: vec![AccountUpdate {
                id: Some("acc_existing".into()),
                label: None,
                enabled: true,
                values: HashMap::from([(ProviderSettingKey::Region, text("china"))]),
                secrets: HashMap::new(),
                clear_secrets: vec![],
            }],
        };
        assert!(merge_provider_settings(ProviderId::Deepgram, &current, &unsupported_key).is_err());
        assert_eq!(serde_json::to_value(&current).unwrap(), serialized_before);
    }

    #[test]
    fn browser_and_managed_credential_metadata_is_table_driven() {
        let claude = login_spec(ProviderId::Claude).expect("Claude login metadata");
        assert_eq!(claude.login_url, "https://claude.ai");
        assert_eq!(claude.cookie_domains, &["claude.ai"]);
        assert_eq!(claude.cookie_names, &["sessionKey"]);
        assert_eq!(login_spec(ProviderId::Cursor).unwrap().display, "Cursor");
        assert_eq!(
            login_spec(ProviderId::Opencode).unwrap().display,
            "OpenCode"
        );
        assert_eq!(
            managed_credential_spec(ProviderId::Claude)
                .unwrap()
                .provider_key,
            "claude"
        );
        assert_eq!(
            managed_credential_spec(ProviderId::Codex)
                .unwrap()
                .provider_key,
            "codex"
        );
        assert!(managed_credential_spec(ProviderId::Cursor).is_none());
    }

    #[test]
    fn auth_executor_rejects_unadvertised_and_reports_unavailable_handlers() {
        let unadvertised =
            resolve_auth_action(ProviderId::Deepgram, ProviderAuthActionKind::BrowserLogin)
                .unwrap_err();
        assert!(unadvertised.contains("not advertised"));

        for (action, handler) in [
            (
                ProviderAuthActionKind::BrowserLogin,
                AuthActionHandler::WebView2Login,
            ),
            (
                ProviderAuthActionKind::CookieImport,
                AuthActionHandler::BrowserCookieImport,
            ),
            (
                ProviderAuthActionKind::CliImport,
                AuthActionHandler::ManagedCliImport,
            ),
        ] {
            assert_eq!(
                resolve_auth_action(ProviderId::Claude, action).unwrap(),
                handler
            );
        }

        assert_eq!(
            resolve_auth_action(ProviderId::Copilot, ProviderAuthActionKind::DeviceOAuth).unwrap(),
            AuthActionHandler::CopilotDeviceOAuth
        );

        for provider in ProviderId::ALL {
            for action in provider_capabilities(provider).auth_actions {
                assert!(
                    resolve_auth_action(provider, *action).is_ok(),
                    "{provider} advertises {action:?} without an executable handler"
                );
            }
        }
    }

    #[test]
    fn compatibility_connect_selects_an_advertised_action() {
        assert_eq!(
            preferred_connect_action(ProviderId::Copilot),
            Some(ProviderAuthActionKind::DeviceOAuth)
        );
        assert_eq!(
            preferred_connect_action(ProviderId::Claude),
            Some(ProviderAuthActionKind::BrowserLogin)
        );
        assert_eq!(
            preferred_connect_action(ProviderId::Codex),
            Some(ProviderAuthActionKind::CliImport)
        );
        assert_eq!(
            preferred_connect_action(ProviderId::Cursor),
            Some(ProviderAuthActionKind::BrowserLogin)
        );
        assert_eq!(preferred_connect_action(ProviderId::Deepgram), None);
    }

    #[test]
    fn compatibility_cli_import_uses_the_active_or_first_saved_account() {
        let mut config = AppConfig::default();
        let mut codex = config.provider(ProviderId::Codex);
        codex.accounts = vec![
            ProviderAccount {
                id: "acc_first".into(),
                ..Default::default()
            },
            ProviderAccount {
                id: "acc_active".into(),
                ..Default::default()
            },
        ];
        codex.active_account_id = Some("acc_active".into());
        config.providers.insert(ProviderId::Codex, codex);
        assert_eq!(
            compatibility_account_id(&config, ProviderId::Codex).as_deref(),
            Some("acc_active")
        );

        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .active_account_id = Some("acc_missing".into());
        assert_eq!(
            compatibility_account_id(&config, ProviderId::Codex).as_deref(),
            Some("acc_first")
        );
        assert_eq!(
            compatibility_account_id(&config, ProviderId::Deepgram),
            None
        );
    }
    #[test]
    fn auth_account_selection_requires_an_explicit_saved_safe_account() {
        let descriptor = Engine::new()
            .unwrap()
            .descriptors()
            .into_iter()
            .find(|descriptor| !descriptor.supports_multiple_accounts)
            .expect("provider with legacy flag disabled");
        assert!(!descriptor.supports_multiple_accounts);
        let accounts = vec![
            ProviderAccount {
                id: "acc_one".into(),
                ..Default::default()
            },
            ProviderAccount {
                id: "acc_two".into(),
                ..Default::default()
            },
        ];
        assert!(auth_account_index(&accounts, None).is_err());
        assert!(auth_account_index(&accounts, Some("  ")).is_err());
        assert_eq!(auth_account_index(&accounts, Some("acc_two")).unwrap(), 1);
        assert!(auth_account_index(&accounts, Some("acc_missing")).is_err());
        assert!(auth_account_index(&accounts, Some("../unsafe")).is_err());
    }

    #[test]
    fn background_resync_requires_a_named_safe_account() {
        assert_eq!(resync_account_id(""), None);
        assert_eq!(resync_account_id("  "), None);
        assert_eq!(resync_account_id("../unsafe"), None);
        assert_eq!(
            resync_account_id("acc_two"),
            Some(ResyncAccountTarget::Named("acc_two"))
        );
    }

    #[test]
    fn provider_merge_rejects_unknown_duplicate_and_unsafe_explicit_ids_without_mutation() {
        let current = ProviderConfig {
            accounts: vec![ProviderAccount {
                id: "acc_existing".into(),
                api_key: Some("keep-secret".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let before = serde_json::to_value(&current).unwrap();
        let account = |id: Option<&str>| AccountUpdate {
            id: id.map(str::to_owned),
            label: None,
            enabled: true,
            values: HashMap::new(),
            secrets: HashMap::new(),
            clear_secrets: vec![],
        };
        for accounts in [
            vec![account(Some("acc_other_provider"))],
            vec![account(Some("../escape"))],
            vec![account(Some("acc_existing")), account(Some("acc_existing"))],
        ] {
            let update = ProviderSettingsUpdate {
                enabled: true,
                source_mode: ProviderSourceMode::Auto,
                accounts,
            };
            assert!(merge_provider_settings(ProviderId::Openrouter, &current, &update).is_err());
            assert_eq!(serde_json::to_value(&current).unwrap(), before);
        }
        let new_account = ProviderSettingsUpdate {
            enabled: true,
            source_mode: ProviderSourceMode::Auto,
            accounts: vec![account(Some("  "))],
        };
        assert!(merge_provider_settings(ProviderId::Openrouter, &current, &new_account).is_ok());
    }

    #[test]
    fn replacement_secret_wins_over_stale_clear_marker() {
        let existing = HashMap::from([(
            "acc_existing".into(),
            ProviderAccount {
                id: "acc_existing".into(),
                api_key: Some("old".into()),
                ..Default::default()
            },
        )]);
        let update = AccountUpdate {
            id: Some("acc_existing".into()),
            label: None,
            enabled: true,
            values: HashMap::new(),
            secrets: HashMap::from([(ProviderSettingKey::ApiKey, "replacement".into())]),
            clear_secrets: vec![ProviderSettingKey::ApiKey],
        };
        let merged = merge_account(&existing, &update, ProviderId::Openrouter).unwrap();
        assert_eq!(merged.api_key.as_deref(), Some("replacement"));
    }

    #[test]
    fn active_codex_profile_cannot_be_paused_or_removed_by_settings_save() {
        let current = ProviderConfig {
            active_account_id: Some("acc_active".into()),
            accounts: vec![ProviderAccount {
                id: "acc_active".into(),
                label: Some("Active".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let update_account = |enabled| AccountUpdate {
            id: Some("acc_active".into()),
            label: Some("Active".into()),
            enabled,
            values: HashMap::new(),
            secrets: HashMap::new(),
            clear_secrets: Vec::new(),
        };
        for update in [
            ProviderSettingsUpdate {
                enabled: true,
                source_mode: ProviderSourceMode::Auto,
                accounts: vec![update_account(false)],
            },
            ProviderSettingsUpdate {
                enabled: true,
                source_mode: ProviderSourceMode::Auto,
                accounts: Vec::new(),
            },
            ProviderSettingsUpdate {
                enabled: false,
                source_mode: ProviderSourceMode::Auto,
                accounts: vec![update_account(true)],
            },
        ] {
            assert!(merge_provider_settings(ProviderId::Codex, &current, &update).is_err());
        }
    }

    #[test]
    fn codex_profiles_must_be_created_and_deleted_through_lifecycle_commands() {
        let current = ProviderConfig {
            accounts: vec![ProviderAccount {
                id: "acc_existing".into(),
                label: Some("Existing".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let blank = AccountUpdate {
            id: None,
            label: Some("Blank".into()),
            enabled: true,
            values: HashMap::new(),
            secrets: HashMap::new(),
            clear_secrets: Vec::new(),
        };
        for accounts in [Vec::new(), vec![blank]] {
            let update = ProviderSettingsUpdate {
                enabled: true,
                source_mode: ProviderSourceMode::Auto,
                accounts,
            };
            assert!(merge_provider_settings(ProviderId::Codex, &current, &update).is_err());
        }
    }

    #[test]
    fn managed_auth_requires_a_safe_existing_provider_account() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts = vec![ProviderAccount {
            id: "acc_claude".into(),
            ..Default::default()
        }];
        assert_eq!(
            require_managed_account(&config, ProviderId::Claude, "acc_claude").unwrap(),
            "acc_claude"
        );
        assert!(require_managed_account(&config, ProviderId::Claude, "acc_missing").is_err());
        assert!(require_managed_account(&config, ProviderId::Codex, "acc_claude").is_err());
        assert!(require_managed_account(&config, ProviderId::Claude, "../escape").is_err());
        assert_eq!(
            resolve_auth_action(ProviderId::Claude, ProviderAuthActionKind::CliImport).unwrap(),
            AuthActionHandler::ManagedCliImport
        );
    }

    #[test]
    fn requested_cookie_import_replaces_on_success_and_preserves_on_failure() {
        let mut account = ProviderAccount {
            cookie_header: Some("old=session".into()),
            browser: BrowserPreference::Edge,
            ..Default::default()
        };
        let mut called = 0;
        replace_cookie_from_import(&mut account, |browser| {
            called += 1;
            assert_eq!(browser, BrowserPreference::Edge);
            Ok("new=session".to_owned())
        })
        .unwrap();
        assert_eq!(called, 1);
        assert_eq!(account.cookie_header.as_deref(), Some("new=session"));

        let error = replace_cookie_from_import(&mut account, |_| Err("import failed".to_owned()));
        assert!(error.is_err());
        assert_eq!(account.cookie_header.as_deref(), Some("new=session"));
    }
}
