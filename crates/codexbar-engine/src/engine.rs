use crate::{
    config::{AppConfig, ProviderAccount, ProviderConfig},
    model::{ProviderId, ProviderSourceMode, ProviderState},
    provider::{FetchContext, Provider, ProviderFetchOutcome, run_provider_fetch_pipeline},
    providers,
};
use futures::future::join_all;
use reqwest::Client;
use std::{sync::Arc, time::Duration};

pub struct Engine {
    client: Client,
    providers: Vec<Arc<dyn Provider>>,
}

impl Engine {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent("CodexBar-Windows/0.1")
            .build()?;
        Ok(Self {
            client,
            providers: providers::all_providers(),
        })
    }

    pub fn descriptors(&self) -> Vec<crate::model::ProviderDescriptor> {
        self.providers
            .iter()
            .map(|provider| provider.descriptor())
            .collect()
    }

    pub async fn refresh_all(
        &self,
        config: &AppConfig,
        config_dir: Option<&std::path::Path>,
    ) -> Vec<ProviderState> {
        let context = FetchContext {
            client: &self.client,
            config,
            config_dir,
        };
        // One slow account must not stall the whole refresh: each fetch gets a soft timeout from
        // config, after which that account's card shows a timeout error while every other account's
        // result is unaffected.
        let timeout = Duration::from_secs(config.adaptive_refresh.provider_timeout_seconds.max(1));
        // Each provider yields one state per account; providers run concurrently and so do their
        // accounts. `join_all` preserves order, so cards stay grouped by provider then account.
        let per_provider = self.providers.iter().map(|provider| {
            let descriptor = provider.descriptor();
            let settings = config.provider(descriptor.id);
            let context = &context;
            async move {
                if !settings.enabled {
                    return vec![ProviderState::disabled(descriptor)];
                }
                let source_mode = settings.source_mode;
                let accounts = resolve_accounts(settings);
                join_all(accounts.into_iter().map(|account| {
                    let descriptor = descriptor.clone();
                    async move {
                        fetch_with_timeout(
                            provider.as_ref(),
                            context,
                            &account,
                            source_mode,
                            timeout,
                            descriptor,
                        )
                        .await
                        .with_account(account.id.clone(), account.display_label())
                    }
                }))
                .await
            }
        });
        join_all(per_provider).await.into_iter().flatten().collect()
    }

    pub fn provider_enabled(config: &AppConfig, provider: ProviderId) -> bool {
        config.provider(provider).enabled
    }

    /// Poll one provider's service-incident status using the engine's shared HTTP client.
    /// Returns `None` when the provider has no status source; otherwise the fetch result (an error
    /// is left for the caller to fold into `Unknown` or the previous value to avoid flapping).
    pub async fn service_status(
        &self,
        provider: ProviderId,
    ) -> Option<Result<crate::status::ServiceStatus, crate::status::StatusError>> {
        let source = crate::status::status_source(provider)?;
        Some(crate::status::fetch_service_status(&self.client, source).await)
    }
}

/// Fetch one account with a soft timeout. A timeout produces a per-account error state rather than
/// stalling the refresh; `provider` is borrowed so the same trait object serves every account.
async fn fetch_with_timeout(
    provider: &dyn Provider,
    context: &FetchContext<'_>,
    account: &ProviderAccount,
    source_mode: ProviderSourceMode,
    timeout: Duration,
    descriptor: crate::model::ProviderDescriptor,
) -> ProviderState {
    let Ok(ProviderFetchOutcome { result, attempts }) = tokio::time::timeout(
        timeout,
        run_provider_fetch_pipeline(provider, context, account, source_mode),
    )
    .await
    else {
        let message = format!(
            "{} timed out after {}s",
            descriptor.display_name,
            timeout.as_secs()
        );
        return ProviderState::failed(descriptor, message);
    };

    match result {
        Ok(snapshot) => ProviderState::ready(descriptor, snapshot).with_fetch_attempts(attempts),
        Err(error) => {
            ProviderState::failed(descriptor, error.to_string()).with_fetch_attempts(attempts)
        }
    }
}

/// Enabled accounts for a provider. When none are configured we still return a single blank
/// account so providers that read local credentials (CLI OAuth, browser cookies) or an env-var API
/// key keep working with zero explicit configuration — and unconfigured API-key providers surface a
/// "missing credentials" card exactly as before.
fn resolve_accounts(settings: ProviderConfig) -> Vec<ProviderAccount> {
    let accounts: Vec<ProviderAccount> = settings
        .accounts
        .into_iter()
        .filter(|account| account.enabled)
        .collect();
    if accounts.is_empty() {
        vec![ProviderAccount::default()]
    } else {
        accounts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthKind, ProviderDescriptor, ProviderErrorKind, ProviderId, ProviderSnapshot,
        ProviderStatus, ProviderStrategyDescriptor, ProviderStrategyKind,
    };
    use crate::provider::ProviderError;
    use async_trait::async_trait;
    use std::time::Duration;

    struct SleepyProvider {
        delay: Duration,
    }

    struct SourceModeProvider;

    struct ManagedSlotProbeProvider;

    fn test_descriptor() -> ProviderDescriptor {
        ProviderDescriptor {
            id: ProviderId::Openrouter,
            display_name: "Sleepy",
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.com",
            credential_hint: "",
            supports_multiple_accounts: true,
            capabilities: crate::model::provider_capabilities(ProviderId::Openrouter),
        }
    }

    #[async_trait]
    impl Provider for SleepyProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            test_descriptor()
        }

        async fn fetch(
            &self,
            _context: &FetchContext<'_>,
            _account: &ProviderAccount,
        ) -> Result<ProviderSnapshot, ProviderError> {
            tokio::time::sleep(self.delay).await;
            Ok(ProviderSnapshot::new(ProviderId::Openrouter, "test"))
        }
    }

    #[async_trait]
    impl Provider for SourceModeProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            test_descriptor()
        }

        async fn fetch(
            &self,
            _context: &FetchContext<'_>,
            _account: &ProviderAccount,
        ) -> Result<ProviderSnapshot, ProviderError> {
            unreachable!("strategy fetch should be used")
        }

        fn strategies(&self, source_mode: ProviderSourceMode) -> Vec<ProviderStrategyDescriptor> {
            let (id, kind) = match source_mode {
                ProviderSourceMode::Web => ("observed-web", ProviderStrategyKind::Web),
                _ => ("observed-other", ProviderStrategyKind::ApiToken),
            };
            vec![ProviderStrategyDescriptor {
                id,
                kind,
                source_mode,
            }]
        }

        async fn fetch_strategy(
            &self,
            strategy: &ProviderStrategyDescriptor,
            _context: &FetchContext<'_>,
            _account: &ProviderAccount,
        ) -> Result<ProviderSnapshot, ProviderError> {
            Ok(ProviderSnapshot::new(ProviderId::Openrouter, strategy.id))
        }
    }

    #[async_trait]
    impl Provider for ManagedSlotProbeProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            test_descriptor()
        }

        async fn fetch(
            &self,
            context: &FetchContext<'_>,
            account: &ProviderAccount,
        ) -> Result<ProviderSnapshot, ProviderError> {
            let slot = crate::auth::credentials::resolve_managed_slot(
                context.config_dir,
                "claude",
                &account.id,
            )?;
            if slot.is_none() {
                return Err(ProviderError::MissingCredentials(
                    "global credential fallback seam was reached".into(),
                ));
            }
            Ok(ProviderSnapshot::new(ProviderId::Openrouter, "managed"))
        }
    }

    /// A single-thread runtime with timers, built without pulling in tokio's `macros` feature.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    #[test]
    fn a_slow_account_times_out_without_a_snapshot() {
        runtime().block_on(async {
            let provider = SleepyProvider {
                delay: Duration::from_millis(200),
            };
            let client = Client::new();
            let config = AppConfig::default();
            let context = FetchContext {
                client: &client,
                config: &config,
                config_dir: None,
            };
            let account = ProviderAccount::default();

            let state = fetch_with_timeout(
                &provider,
                &context,
                &account,
                ProviderSourceMode::Auto,
                Duration::from_millis(20),
                test_descriptor(),
            )
            .await;

            assert_eq!(state.status, ProviderStatus::Error);
            assert!(
                state
                    .error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("timed out")
            );
            assert!(state.snapshot.is_none());
            assert!(state.fetch_attempts.is_empty());
        });
    }

    #[test]
    fn a_fast_account_returns_its_snapshot() {
        runtime().block_on(async {
            let provider = SleepyProvider {
                delay: Duration::from_millis(1),
            };
            let client = Client::new();
            let config = AppConfig::default();
            let context = FetchContext {
                client: &client,
                config: &config,
                config_dir: None,
            };
            let account = ProviderAccount::default();

            let state = fetch_with_timeout(
                &provider,
                &context,
                &account,
                ProviderSourceMode::Auto,
                Duration::from_secs(5),
                test_descriptor(),
            )
            .await;

            assert_eq!(state.status, ProviderStatus::Ready);
            assert!(state.snapshot.is_some());
            assert_eq!(state.fetch_attempts.len(), 1);
            assert_eq!(state.fetch_attempts[0].strategy_id, "legacy-api");
        });
    }

    #[test]
    fn refresh_uses_the_provider_configured_source_mode() {
        runtime().block_on(async {
            let engine = Engine {
                client: Client::new(),
                providers: vec![Arc::new(SourceModeProvider)],
            };
            let mut config = AppConfig::default();
            let settings = config.providers.get_mut(&ProviderId::Openrouter).unwrap();
            settings.source_mode = ProviderSourceMode::Web;

            let states = engine.refresh_all(&config, None).await;

            assert_eq!(states.len(), 1);
            assert_eq!(states[0].status, ProviderStatus::Ready);
            assert_eq!(
                states[0]
                    .snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.source.as_str()),
                Some("observed-web")
            );
            assert_eq!(states[0].fetch_attempts[0].strategy_id, "observed-web");
        });
    }

    #[test]
    fn malformed_account_id_fails_before_global_credential_fallback_without_config_dir() {
        runtime().block_on(async {
            let engine = Engine {
                client: Client::new(),
                providers: vec![Arc::new(ManagedSlotProbeProvider)],
            };
            let mut config = AppConfig::default();
            let settings = config.providers.get_mut(&ProviderId::Openrouter).unwrap();
            settings.accounts = vec![ProviderAccount {
                id: "../escape".into(),
                ..ProviderAccount::default()
            }];

            let states = engine.refresh_all(&config, None).await;

            assert_eq!(states.len(), 1);
            assert_eq!(states[0].status, ProviderStatus::Error);
            assert_eq!(states[0].fetch_attempts.len(), 1);
            assert_eq!(
                states[0].fetch_attempts[0].error_kind,
                Some(ProviderErrorKind::Credential)
            );
            assert!(
                !states[0]
                    .error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("global credential fallback seam")
            );
        });
    }
}
