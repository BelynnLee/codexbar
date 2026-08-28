use async_trait::async_trait;
use codexbar_engine::{
    AppConfig, AuthKind, FetchContext, Provider, ProviderAccount, ProviderDescriptor,
    ProviderError, ProviderFetchAttempt, ProviderId, ProviderSnapshot, ProviderSourceMode,
    ProviderStrategyDescriptor, ProviderStrategyKind, run_provider_fetch_pipeline,
};
use reqwest::Client;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct AvailabilityFallbackProvider {
    availability_checks: Arc<AtomicUsize>,
    fetches: Arc<AtomicUsize>,
}

struct PolicyFallbackProvider {
    allow_fallback: bool,
    fetches: Arc<AtomicUsize>,
}

fn descriptor() -> ProviderDescriptor {
    ProviderDescriptor {
        id: ProviderId::Openrouter,
        display_name: "Strategy fixture",
        auth_kind: AuthKind::ApiKey,
        color: "#000000",
        dashboard_url: "https://example.test",
        credential_hint: "",
        supports_multiple_accounts: false,
        capabilities: codexbar_engine::provider_capabilities(ProviderId::Openrouter),
    }
}

fn api_strategy() -> ProviderStrategyDescriptor {
    ProviderStrategyDescriptor {
        id: "api",
        kind: ProviderStrategyKind::ApiToken,
        source_mode: ProviderSourceMode::Api,
    }
}

fn web_strategy() -> ProviderStrategyDescriptor {
    ProviderStrategyDescriptor {
        id: "web",
        kind: ProviderStrategyKind::Web,
        source_mode: ProviderSourceMode::Web,
    }
}

#[async_trait]
impl Provider for AvailabilityFallbackProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor()
    }

    async fn fetch(
        &self,
        _context: &FetchContext<'_>,
        _account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        unreachable!("the pipeline should call fetch_strategy")
    }

    fn strategies(&self, _source_mode: ProviderSourceMode) -> Vec<ProviderStrategyDescriptor> {
        vec![api_strategy(), web_strategy()]
    }

    fn is_strategy_available(
        &self,
        strategy: &ProviderStrategyDescriptor,
        _context: &FetchContext<'_>,
        _account: &ProviderAccount,
    ) -> bool {
        self.availability_checks.fetch_add(1, Ordering::SeqCst);
        strategy.id != "api"
    }

    async fn fetch_strategy(
        &self,
        strategy: &ProviderStrategyDescriptor,
        _context: &FetchContext<'_>,
        _account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderSnapshot::new(ProviderId::Openrouter, strategy.id))
    }
}

#[async_trait]
impl Provider for PolicyFallbackProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor()
    }

    async fn fetch(
        &self,
        _context: &FetchContext<'_>,
        _account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        unreachable!("the pipeline should call fetch_strategy")
    }

    fn strategies(&self, _source_mode: ProviderSourceMode) -> Vec<ProviderStrategyDescriptor> {
        vec![api_strategy(), web_strategy()]
    }

    async fn fetch_strategy(
        &self,
        strategy: &ProviderStrategyDescriptor,
        _context: &FetchContext<'_>,
        _account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if strategy.id == "api" {
            Err(ProviderError::Unauthorized(
                "expired bearer super-secret".to_owned(),
            ))
        } else {
            Ok(ProviderSnapshot::new(ProviderId::Openrouter, strategy.id))
        }
    }

    fn should_fallback(
        &self,
        strategy: &ProviderStrategyDescriptor,
        _error: &ProviderError,
    ) -> bool {
        self.allow_fallback && strategy.id == "api"
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn auto_skips_an_unavailable_strategy_and_preserves_ordered_attempts() {
    runtime().block_on(async {
        let availability_checks = Arc::new(AtomicUsize::new(0));
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = AvailabilityFallbackProvider {
            availability_checks: Arc::clone(&availability_checks),
            fetches: Arc::clone(&fetches),
        };
        let client = Client::new();
        let config = AppConfig::default();
        let context = FetchContext {
            client: &client,
            config: &config,
            config_dir: None,
        };

        let outcome = run_provider_fetch_pipeline(
            &provider,
            &context,
            &ProviderAccount::default(),
            ProviderSourceMode::Auto,
        )
        .await;

        let snapshot = outcome.result.expect("second strategy should succeed");
        assert_eq!(snapshot.source, "web");
        assert_eq!(availability_checks.load(Ordering::SeqCst), 2);
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.attempts[0].strategy_id, "api");
        assert!(!outcome.attempts[0].was_available);
        assert_eq!(outcome.attempts[0].error_kind, None);
        assert_eq!(outcome.attempts[1].strategy_id, "web");
        assert!(outcome.attempts[1].was_available);
        assert_eq!(outcome.attempts[1].error_kind, None);
    });
}

#[test]
fn auto_falls_back_after_failure_only_when_provider_policy_allows_it() {
    runtime().block_on(async {
        let client = Client::new();
        let config = AppConfig::default();
        let context = FetchContext {
            client: &client,
            config: &config,
            config_dir: None,
        };
        let account = ProviderAccount::default();

        let denied_fetches = Arc::new(AtomicUsize::new(0));
        let denied = PolicyFallbackProvider {
            allow_fallback: false,
            fetches: Arc::clone(&denied_fetches),
        };
        let denied_outcome =
            run_provider_fetch_pipeline(&denied, &context, &account, ProviderSourceMode::Auto)
                .await;
        assert!(matches!(
            denied_outcome.result,
            Err(ProviderError::Unauthorized(_))
        ));
        assert_eq!(denied_fetches.load(Ordering::SeqCst), 1);
        assert_eq!(denied_outcome.attempts.len(), 1);

        let allowed_fetches = Arc::new(AtomicUsize::new(0));
        let allowed = PolicyFallbackProvider {
            allow_fallback: true,
            fetches: Arc::clone(&allowed_fetches),
        };
        let allowed_outcome =
            run_provider_fetch_pipeline(&allowed, &context, &account, ProviderSourceMode::Auto)
                .await;
        assert_eq!(
            allowed_outcome
                .result
                .expect("policy should permit the Web fallback")
                .source,
            "web"
        );
        assert_eq!(allowed_fetches.load(Ordering::SeqCst), 2);
        assert_eq!(allowed_outcome.attempts.len(), 2);
        assert_eq!(
            allowed_outcome.attempts[0].error_kind,
            Some(codexbar_engine::ProviderErrorKind::Unauthorized)
        );
    });
}

#[test]
fn explicit_api_mode_never_executes_a_web_strategy() {
    runtime().block_on(async {
        let fetches = Arc::new(AtomicUsize::new(0));
        let provider = PolicyFallbackProvider {
            allow_fallback: true,
            fetches: Arc::clone(&fetches),
        };
        let client = Client::new();
        let config = AppConfig::default();
        let context = FetchContext {
            client: &client,
            config: &config,
            config_dir: None,
        };

        let outcome = run_provider_fetch_pipeline(
            &provider,
            &context,
            &ProviderAccount::default(),
            ProviderSourceMode::Api,
        )
        .await;

        assert!(matches!(
            outcome.result,
            Err(ProviderError::Unauthorized(_))
        ));
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.attempts.len(), 1);
        assert_eq!(outcome.attempts[0].strategy_id, "api");
    });
}

#[test]
fn serialized_attempt_contains_only_a_categorical_error() {
    let secret = "bearer super-secret-value";
    let error = ProviderError::Unauthorized(secret.to_owned());
    let attempt = ProviderFetchAttempt {
        strategy_id: "api".to_owned(),
        kind: ProviderStrategyKind::ApiToken,
        was_available: true,
        error_kind: Some((&error).into()),
    };

    let json = serde_json::to_string(&attempt).expect("attempt should serialize");

    assert!(json.contains("\"errorKind\":\"unauthorized\""));
    assert!(json.contains("\"wasAvailable\":true"));
    assert!(!json.contains(secret));
    assert!(!json.contains("error_kind"));
}
