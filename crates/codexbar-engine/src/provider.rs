use crate::{
    config::{AppConfig, ProviderAccount},
    model::{
        AuthKind, ProviderDescriptor, ProviderErrorKind, ProviderFetchAttempt, ProviderSnapshot,
        ProviderSourceMode, ProviderStrategyDescriptor, ProviderStrategyKind,
    },
};
use async_trait::async_trait;
use reqwest::Client;
use std::path::Path;
use thiserror::Error;

#[derive(Clone)]
pub struct FetchContext<'a> {
    pub client: &'a Client,
    pub config: &'a AppConfig,
    /// Resolved config directory (parent of `config.json`). Used to locate per-account managed
    /// credential slots under `accounts/<provider>/<accountId>.json`. `None` disables managed slots
    /// (the provider then uses the default CLI credential path).
    pub config_dir: Option<&'a Path>,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("{0}")]
    MissingCredentials(String),
    #[error("Authentication expired: {0}")]
    Unauthorized(String),
    #[error("{provider} returned HTTP {status}")]
    Http { provider: &'static str, status: u16 },
    #[error("{provider} returned an unsupported response: {message}")]
    Parse {
        provider: &'static str,
        message: String,
    },
    #[error("{0}")]
    Platform(String),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Local credential error: {0}")]
    Credential(String),
}

impl ProviderError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::MissingCredentials(_) => ProviderErrorKind::MissingCredentials,
            Self::Unauthorized(_) => ProviderErrorKind::Unauthorized,
            Self::Http { .. } => ProviderErrorKind::Http,
            Self::Parse { .. } => ProviderErrorKind::Parse,
            Self::Platform(_) => ProviderErrorKind::Platform,
            Self::Network(_) => ProviderErrorKind::Network,
            Self::Credential(_) => ProviderErrorKind::Credential,
        }
    }
}

impl From<&ProviderError> for ProviderErrorKind {
    fn from(error: &ProviderError) -> Self {
        error.kind()
    }
}

#[derive(Debug)]
pub struct ProviderFetchOutcome {
    pub result: Result<ProviderSnapshot, ProviderError>,
    pub attempts: Vec<ProviderFetchAttempt>,
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    /// Fetch usage for a single account. The engine calls this once per configured account.
    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError>;

    fn strategies(&self, source_mode: ProviderSourceMode) -> Vec<ProviderStrategyDescriptor> {
        let strategy = match self.descriptor().auth_kind {
            AuthKind::ApiKey => ProviderStrategyDescriptor {
                id: "legacy-api",
                kind: ProviderStrategyKind::ApiToken,
                source_mode: ProviderSourceMode::Api,
            },
            AuthKind::DeviceOAuth => ProviderStrategyDescriptor {
                id: "legacy-oauth",
                kind: ProviderStrategyKind::Oauth,
                source_mode: ProviderSourceMode::Oauth,
            },
            AuthKind::BrowserCookie => ProviderStrategyDescriptor {
                id: "legacy-web",
                kind: ProviderStrategyKind::Web,
                source_mode: ProviderSourceMode::Web,
            },
            AuthKind::CliOAuth => ProviderStrategyDescriptor {
                id: "legacy-cli",
                kind: ProviderStrategyKind::Cli,
                source_mode: ProviderSourceMode::Cli,
            },
        };

        if matches!(source_mode, ProviderSourceMode::Auto) || source_mode == strategy.source_mode {
            vec![strategy]
        } else {
            Vec::new()
        }
    }

    fn is_strategy_available(
        &self,
        _strategy: &ProviderStrategyDescriptor,
        _context: &FetchContext<'_>,
        _account: &ProviderAccount,
    ) -> bool {
        true
    }

    fn should_record_unavailable_strategy(
        &self,
        _strategy: &ProviderStrategyDescriptor,
        _source_mode: ProviderSourceMode,
    ) -> bool {
        true
    }

    async fn fetch_strategy(
        &self,
        _strategy: &ProviderStrategyDescriptor,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        self.fetch(context, account).await
    }

    fn should_fallback(
        &self,
        _strategy: &ProviderStrategyDescriptor,
        _error: &ProviderError,
    ) -> bool {
        false
    }
}

pub async fn run_provider_fetch_pipeline(
    provider: &dyn Provider,
    context: &FetchContext<'_>,
    account: &ProviderAccount,
    source_mode: ProviderSourceMode,
) -> ProviderFetchOutcome {
    let strategies = provider.strategies(source_mode);
    let mut attempts = Vec::with_capacity(strategies.len());
    let mut last_error = None;

    for strategy in strategies {
        if !matches!(source_mode, ProviderSourceMode::Auto) && strategy.source_mode != source_mode {
            continue;
        }
        let was_available = provider.is_strategy_available(&strategy, context, account);
        if !was_available && matches!(source_mode, ProviderSourceMode::Auto) {
            if provider.should_record_unavailable_strategy(&strategy, source_mode) {
                attempts.push(ProviderFetchAttempt {
                    strategy_id: strategy.id.to_owned(),
                    kind: strategy.kind,
                    was_available: false,
                    error_kind: None,
                });
            }
            continue;
        }

        match provider.fetch_strategy(&strategy, context, account).await {
            Ok(snapshot) => {
                attempts.push(ProviderFetchAttempt {
                    strategy_id: strategy.id.to_owned(),
                    kind: strategy.kind,
                    was_available,
                    error_kind: None,
                });
                return ProviderFetchOutcome {
                    result: Ok(snapshot),
                    attempts,
                };
            }
            Err(error) => {
                let should_fallback = provider.should_fallback(&strategy, &error);
                attempts.push(ProviderFetchAttempt {
                    strategy_id: strategy.id.to_owned(),
                    kind: strategy.kind,
                    was_available,
                    error_kind: Some(error.kind()),
                });
                if should_fallback {
                    last_error = Some(error);
                    continue;
                }
                return ProviderFetchOutcome {
                    result: Err(error),
                    attempts,
                };
            }
        }
    }

    let result = last_error.map_or_else(
        || {
            Err(ProviderError::Platform(format!(
                "No available strategy for {}",
                provider.descriptor().id
            )))
        },
        Err,
    );
    ProviderFetchOutcome { result, attempts }
}
