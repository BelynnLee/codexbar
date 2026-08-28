use crate::{
    accounts::ProviderCredentialVault,
    auth::{
        chromium,
        credentials::{ClaudeCredentials, is_safe_managed_account_id},
        dpapi::{DpapiCodec, SecretCodec},
    },
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot,
        ProviderSourceMode, ProviderStrategyDescriptor, ProviderStrategyKind, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, Days, SecondsFormat, Utc};
use regex::Regex;
use reqwest::StatusCode;
use serde_json::Value;
use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::process::Command;

const ADMIN_API_BASE_URL: &str = "https://api.anthropic.com";
const WEB_BASE_URL: &str = "https://claude.ai";
const OAUTH_USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
const OAUTH_REFRESH_URL: &str = "https://platform.claude.com/v1/oauth/token";
const CLAUDE_SUBSCRIPTION_QUOTA_UNAVAILABLE: &str =
    "Claude CLI /usage returned a subscription notice without session quota data.";
static DPAPI_CODEC: DpapiCodec = DpapiCodec;

const ADMIN_STRATEGY: ProviderStrategyDescriptor = ProviderStrategyDescriptor {
    id: "claude.admin-api",
    kind: ProviderStrategyKind::ApiToken,
    source_mode: ProviderSourceMode::Api,
};
const OAUTH_STRATEGY: ProviderStrategyDescriptor = ProviderStrategyDescriptor {
    id: "claude.oauth",
    kind: ProviderStrategyKind::Oauth,
    source_mode: ProviderSourceMode::Oauth,
};
const CLI_STRATEGY: ProviderStrategyDescriptor = ProviderStrategyDescriptor {
    id: "claude.cli",
    kind: ProviderStrategyKind::Cli,
    source_mode: ProviderSourceMode::Cli,
};
const WEB_STRATEGY: ProviderStrategyDescriptor = ProviderStrategyDescriptor {
    id: "claude.web",
    kind: ProviderStrategyKind::Web,
    source_mode: ProviderSourceMode::Web,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeCliInvocation {
    program: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    environment: HashMap<String, String>,
}

#[async_trait]
trait ClaudeCliRunner: Send + Sync {
    fn resolve_binary(&self) -> Option<PathBuf>;
    async fn run(&self, invocation: ClaudeCliInvocation) -> Result<String, ProviderError>;
}

#[derive(Default)]
struct ProcessClaudeCliRunner;

#[async_trait]
impl ClaudeCliRunner for ProcessClaudeCliRunner {
    fn resolve_binary(&self) -> Option<PathBuf> {
        resolve_claude_binary(&env::vars_os().collect())
    }

    async fn run(&self, invocation: ClaudeCliInvocation) -> Result<String, ProviderError> {
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.arguments)
            .env_clear()
            .envs(&invocation.environment)
            .kill_on_drop(true);
        let output = tokio::time::timeout(invocation.timeout, command.output())
            .await
            .map_err(|_| ProviderError::Platform("Claude CLI /usage timed out".into()))?
            .map_err(|error| {
                ProviderError::Platform(format!("Could not run Claude CLI: {error}"))
            })?;
        validate_cli_process_output(output.status.success(), &output.stdout, &output.stderr)
    }
}

pub struct ClaudeProvider {
    admin_api_base_url: String,
    web_base_url: String,
    oauth_usage_url: String,
    oauth_refresh_url: String,
    cli_runner: Arc<dyn ClaudeCliRunner>,
    credential_codec: Arc<dyn SecretCodec>,
    allow_default_oauth_credentials: bool,
    browser_import_enabled: bool,
}

impl Default for ClaudeProvider {
    fn default() -> Self {
        Self {
            admin_api_base_url: ADMIN_API_BASE_URL.into(),
            web_base_url: WEB_BASE_URL.into(),
            oauth_usage_url: OAUTH_USAGE_URL.into(),
            oauth_refresh_url: OAUTH_REFRESH_URL.into(),
            cli_runner: Arc::new(ProcessClaudeCliRunner),
            credential_codec: Arc::new(DpapiCodec),
            allow_default_oauth_credentials: true,
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Claude,
    display_name: "Claude",
    auth_kind: AuthKind::CliOAuth,
    color: "#d97757",
    dashboard_url: "https://claude.ai/settings/usage",
    credential_hint: "Uses %USERPROFILE%\\.claude\\.credentials.json and refreshes OAuth when required.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Claude),
};

#[async_trait]
impl Provider for ClaudeProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        self.fetch_oauth(context, account).await
    }

    fn strategies(&self, source_mode: ProviderSourceMode) -> Vec<ProviderStrategyDescriptor> {
        match source_mode {
            ProviderSourceMode::Auto => {
                vec![ADMIN_STRATEGY, OAUTH_STRATEGY, CLI_STRATEGY, WEB_STRATEGY]
            }
            ProviderSourceMode::Api => vec![ADMIN_STRATEGY],
            ProviderSourceMode::Oauth => vec![OAUTH_STRATEGY],
            ProviderSourceMode::Cli => vec![CLI_STRATEGY],
            ProviderSourceMode::Web => vec![WEB_STRATEGY],
        }
    }

    fn is_strategy_available(
        &self,
        strategy: &ProviderStrategyDescriptor,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> bool {
        match strategy.id {
            "claude.admin-api" => resolve_admin_api_key(account, &env::vars().collect()).is_some(),
            "claude.oauth" => oauth_credentials_available(
                context.config_dir,
                account,
                self.allow_default_oauth_credentials,
            ),
            "claude.cli" => {
                account.id.trim().is_empty() && self.cli_runner.resolve_binary().is_some()
            }
            "claude.web" => {
                ProviderConfig::normalized_secret(&account.cookie_header).is_some()
                    || (account.id.trim().is_empty() && self.browser_import_enabled)
            }
            _ => false,
        }
    }

    fn should_record_unavailable_strategy(
        &self,
        strategy: &ProviderStrategyDescriptor,
        source_mode: ProviderSourceMode,
    ) -> bool {
        !(source_mode == ProviderSourceMode::Auto && strategy.id == "claude.admin-api")
    }

    async fn fetch_strategy(
        &self,
        strategy: &ProviderStrategyDescriptor,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        match strategy.id {
            "claude.admin-api" => self.fetch_admin_api(context, account).await,
            "claude.oauth" => self.fetch_oauth(context, account).await,
            "claude.cli" if account.id.trim().is_empty() => self.fetch_cli().await,
            "claude.cli" => Err(ProviderError::MissingCredentials(
                "Named Claude accounts use only their encrypted account credential Vault.".into(),
            )),
            "claude.web" => self.fetch_web(context, account).await,
            _ => Err(ProviderError::Platform(format!(
                "Unsupported Claude strategy: {}",
                strategy.id
            ))),
        }
    }

    fn should_fallback(
        &self,
        strategy: &ProviderStrategyDescriptor,
        error: &ProviderError,
    ) -> bool {
        match strategy.id {
            "claude.oauth" => true,
            "claude.cli" => !matches!(
                error,
                ProviderError::Parse { message, .. }
                    if message.contains(CLAUDE_SUBSCRIPTION_QUOTA_UNAVAILABLE)
            ),
            _ => false,
        }
    }
}

impl ClaudeProvider {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_test_endpoints(
        admin_api_base_url: String,
        web_base_url: String,
        oauth_usage_url: String,
        oauth_refresh_url: String,
        cli_runner: Arc<dyn ClaudeCliRunner>,
        credential_codec: Arc<dyn SecretCodec>,
        allow_default_oauth_credentials: bool,
        browser_import_enabled: bool,
    ) -> Self {
        Self {
            admin_api_base_url,
            web_base_url,
            oauth_usage_url,
            oauth_refresh_url,
            cli_runner,
            credential_codec,
            allow_default_oauth_credentials,
            browser_import_enabled,
        }
    }

    async fn fetch_oauth(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let mut source = ClaudeCredentialSource::load(
            context,
            account,
            &self.oauth_refresh_url,
            self.credential_codec.as_ref(),
        )
        .await?;
        let mut credentials = source.credentials().clone();
        let mut response =
            request_usage(context, &self.oauth_usage_url, &credentials.access_token).await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            credentials = source
                .force_refresh(
                    context.client,
                    &self.oauth_refresh_url,
                    self.credential_codec.as_ref(),
                )
                .await?;
            response =
                request_usage(context, &self.oauth_usage_url, &credentials.access_token).await?;
        }
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(ProviderError::Unauthorized(
                "Claude OAuth token was rejected. Run `claude login`.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Claude",
                status: response.status().as_u16(),
            });
        }
        let payload = parse_json_response(response, "OAuth usage").await?;
        map_usage(&payload, &credentials)
    }

    async fn fetch_admin_api(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let key = resolve_admin_api_key(account, &env::vars().collect()).ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Claude Admin API key is missing. Configure apiKey or ANTHROPIC_ADMIN_KEY.".into(),
            )
        })?;
        let (starting_at, ending_at) = admin_daily_range(Utc::now());
        let costs = fetch_admin_report(
            context,
            &format!(
                "{}/v1/organizations/cost_report",
                self.admin_api_base_url.trim_end_matches('/')
            ),
            &key,
            &starting_at,
            &ending_at,
            "description",
        )
        .await?;
        let messages = fetch_admin_report(
            context,
            &format!(
                "{}/v1/organizations/usage_report/messages",
                self.admin_api_base_url.trim_end_matches('/')
            ),
            &key,
            &starting_at,
            &ending_at,
            "model",
        )
        .await?;
        map_admin_usage(&costs, &messages)
    }

    async fn fetch_web(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let initial_session_key = match ProviderConfig::normalized_secret(&account.cookie_header) {
            Some(header) => extract_session_key(header)?,
            None if account.id.trim().is_empty() && self.browser_import_enabled => {
                let imported =
                    chromium::find_cookie_header(account.browser, &["claude.ai"], &["sessionKey"])
                        .map_err(|error| ProviderError::MissingCredentials(error.to_string()))?;
                extract_session_key(&imported.value)?
            }
            None => {
                return Err(ProviderError::MissingCredentials(
                    "Claude Web sessionKey is missing".into(),
                ));
            }
        };
        let mut session_key = initial_session_key;
        let organizations_url = format!(
            "{}/api/organizations",
            self.web_base_url.trim_end_matches('/')
        );
        let response = web_get(context, &organizations_url, &session_key).await?;
        update_session_key(&response, &mut session_key);
        check_status(response.status(), "Claude Web")?;
        let organizations = parse_json_response(response, "Web organizations").await?;
        let organization = select_organization(&organizations, account.organization_id.as_deref())?;
        let org_id = organization
            .get("uuid")
            .and_then(Value::as_str)
            .expect("validated organization uuid");
        let org_name = organization
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let usage_url = format!(
            "{}/api/organizations/{org_id}/usage",
            self.web_base_url.trim_end_matches('/')
        );
        let response = web_get(context, &usage_url, &session_key).await?;
        update_session_key(&response, &mut session_key);
        check_status(response.status(), "Claude Web")?;
        let usage = parse_json_response(response, "Web usage").await?;
        let mut snapshot = map_web_usage(&usage)?;
        snapshot.account_label = org_name;

        let account_url = format!("{}/api/account", self.web_base_url.trim_end_matches('/'));
        if let Ok(response) = web_get(context, &account_url, &session_key).await {
            update_session_key(&response, &mut session_key);
            if response.status().is_success()
                && let Ok(identity) = parse_json_response(response, "Web account").await
            {
                if let Some(email) = identity
                    .get("email_address")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    snapshot.account_label = Some(email.to_owned());
                }
            }
        }
        Ok(snapshot)
    }

    async fn fetch_cli(&self) -> Result<ProviderSnapshot, ProviderError> {
        let program = self.cli_runner.resolve_binary().ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Claude CLI is not installed or CLAUDE_CLI_PATH is invalid".into(),
            )
        })?;
        let invocation = ClaudeCliInvocation {
            program,
            arguments: vec!["/usage".into()],
            timeout: Duration::from_secs(20),
            environment: claude_cli_environment(env::vars().collect()),
        };
        let output = self.cli_runner.run(invocation).await?;
        map_cli_usage(&output)
    }
}

enum ClaudeCredentialSource {
    Default(ClaudeCredentials),
    Vault {
        config_dir: PathBuf,
        account_id: String,
        identity: crate::ProviderAccountIdentity,
        bundle: crate::ProviderCredentialBundle,
        artifact: Vec<u8>,
        credentials: Box<ClaudeCredentials>,
    },
}

impl ClaudeCredentialSource {
    async fn load(
        context: &FetchContext<'_>,
        account: &ProviderAccount,
        refresh_url: &str,
        codec: &dyn SecretCodec,
    ) -> Result<Self, ProviderError> {
        if account.id.trim().is_empty() {
            return Ok(Self::Default(
                ClaudeCredentials::load_and_refresh_with_url(context.client, refresh_url).await?,
            ));
        }
        let config_dir = context.config_dir.ok_or_else(|| {
            ProviderError::MissingCredentials(
                "The selected Claude account has no encrypted credential. Import it and retry."
                    .into(),
            )
        })?;
        let mut source = Self::load_named(config_dir, &account.id, codec)?;
        if source.credentials().needs_refresh() {
            let refreshed = source
                .credentials()
                .force_refresh_and_save_with_url(context.client, refresh_url)
                .await?;
            let updated = refreshed.updated_credentials_json(source.artifact()?)?;
            source.persist_refreshed(refreshed, updated, codec)?;
        }
        Ok(source)
    }

    fn load_named(
        config_dir: &Path,
        account_id: &str,
        codec: &dyn SecretCodec,
    ) -> Result<Self, ProviderError> {
        if !is_safe_managed_account_id(account_id) {
            return Err(ProviderError::Credential(
                "Managed credential account id or provider was rejected".into(),
            ));
        }
        let loaded = ProviderCredentialVault::new(config_dir, codec)
            .load(ProviderId::Claude, account_id)
            .map_err(|_| {
                ProviderError::MissingCredentials(
                    "The selected Claude account has no usable encrypted credential. Import it and retry."
                        .into(),
                )
            })?;
        if loaded.credentials.artifact_format.as_deref() != Some("claude-credentials-json") {
            return Err(ProviderError::Credential(
                "The selected Claude account credential artifact is invalid".into(),
            ));
        }
        let artifact = loaded.credentials.artifact.clone().ok_or_else(|| {
            ProviderError::Credential(
                "The selected Claude account credential artifact is invalid".into(),
            )
        })?;
        let credentials = ClaudeCredentials::parse(&artifact, None)?;
        Ok(Self::Vault {
            config_dir: config_dir.to_path_buf(),
            account_id: account_id.to_owned(),
            identity: loaded.identity,
            bundle: loaded.credentials,
            artifact,
            credentials: Box::new(credentials),
        })
    }

    fn credentials(&self) -> &ClaudeCredentials {
        match self {
            Self::Default(credentials) => credentials,
            Self::Vault { credentials, .. } => credentials.as_ref(),
        }
    }

    fn artifact(&self) -> Result<&[u8], ProviderError> {
        match self {
            Self::Vault { artifact, .. } => Ok(artifact),
            Self::Default(_) => Err(ProviderError::Credential(
                "The default Claude credential is not a managed artifact".into(),
            )),
        }
    }

    fn persist_refreshed(
        &mut self,
        credentials: ClaudeCredentials,
        artifact: Vec<u8>,
        codec: &dyn SecretCodec,
    ) -> Result<(), ProviderError> {
        let Self::Vault {
            config_dir,
            account_id,
            identity,
            bundle,
            artifact: current_artifact,
            credentials: current_credentials,
        } = self
        else {
            return Err(ProviderError::Credential(
                "The default Claude credential cannot be written to an account Vault".into(),
            ));
        };
        let mut updated_bundle = bundle.clone();
        updated_bundle.artifact_format = Some("claude-credentials-json".into());
        updated_bundle.artifact = Some(artifact.clone());
        ProviderCredentialVault::new(config_dir, codec)
            .save(ProviderId::Claude, account_id, identity, &updated_bundle)
            .map_err(|_| {
                ProviderError::Credential(
                    "The selected Claude account Vault could not be updated".into(),
                )
            })?;
        *bundle = updated_bundle;
        *current_artifact = artifact;
        **current_credentials = credentials;
        Ok(())
    }

    async fn force_refresh(
        &mut self,
        client: &reqwest::Client,
        refresh_url: &str,
        codec: &dyn SecretCodec,
    ) -> Result<ClaudeCredentials, ProviderError> {
        match self {
            Self::Default(credentials) => {
                let refreshed = credentials
                    .force_refresh_and_save_with_url(client, refresh_url)
                    .await?;
                *credentials = refreshed.clone();
                Ok(refreshed)
            }
            Self::Vault { .. } => {
                let refreshed = self
                    .credentials()
                    .force_refresh_and_save_with_url(client, refresh_url)
                    .await?;
                let updated = refreshed.updated_credentials_json(self.artifact()?)?;
                self.persist_refreshed(refreshed.clone(), updated, codec)?;
                Ok(refreshed)
            }
        }
    }
}

async fn request_usage(
    context: &FetchContext<'_>,
    endpoint: &str,
    access_token: &str,
) -> Result<reqwest::Response, ProviderError> {
    Ok(context
        .client
        .get(endpoint)
        .bearer_auth(access_token)
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("User-Agent", "claude-code/2.1.0")
        .send()
        .await?)
}

fn oauth_credentials_available(
    config_dir: Option<&Path>,
    account: &ProviderAccount,
    allow_default: bool,
) -> bool {
    if !account.id.trim().is_empty() {
        if !is_safe_managed_account_id(&account.id) {
            return true;
        }
        return config_dir.is_some_and(|config_dir| {
            ProviderCredentialVault::new(config_dir, &DPAPI_CODEC)
                .path(ProviderId::Claude, &account.id)
                .is_ok_and(|path| path.is_file())
        });
    }
    allow_default
        && (env::var("CODEXBAR_CLAUDE_OAUTH_TOKEN").is_ok_and(|value| !value.trim().is_empty())
            || ClaudeCredentials::default_path().is_ok_and(|path| path.is_file()))
}

fn resolve_admin_api_key(
    account: &ProviderAccount,
    environment: &HashMap<String, String>,
) -> Option<String> {
    let configured = ProviderConfig::normalized_secret(&account.api_key).map(ToOwned::to_owned);
    if !account.id.trim().is_empty() {
        return configured;
    }
    configured
        .or_else(|| clean_map_value(environment, "ANTHROPIC_ADMIN_KEY"))
        .or_else(|| clean_map_value(environment, "ANTHROPIC_ADMIN_API_KEY"))
}

fn clean_map_value(environment: &HashMap<String, String>, key: &str) -> Option<String> {
    environment
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn admin_daily_range(now: DateTime<Utc>) -> (String, String) {
    let today = now.date_naive();
    let start = today.checked_sub_days(Days::new(30)).unwrap_or(today);
    let end = today.checked_add_days(Days::new(1)).unwrap_or(today);
    let start =
        DateTime::<Utc>::from_naive_utc_and_offset(start.and_hms_opt(0, 0, 0).unwrap(), Utc);
    let end = DateTime::<Utc>::from_naive_utc_and_offset(end.and_hms_opt(0, 0, 0).unwrap(), Utc);
    (
        start.to_rfc3339_opts(SecondsFormat::Secs, true),
        end.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

async fn fetch_admin_report(
    context: &FetchContext<'_>,
    endpoint: &str,
    api_key: &str,
    starting_at: &str,
    ending_at: &str,
    group_by: &str,
) -> Result<Value, ProviderError> {
    let response = context
        .client
        .get(endpoint)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("Accept", "application/json")
        .query(&[
            ("starting_at", starting_at),
            ("ending_at", ending_at),
            ("bucket_width", "1d"),
            ("limit", "31"),
            ("group_by[]", group_by),
        ])
        .send()
        .await?;
    check_status(response.status(), "Claude")?;
    parse_json_response(response, "Admin API report").await
}

fn map_admin_usage(costs: &Value, messages: &Value) -> Result<ProviderSnapshot, ProviderError> {
    let cost_buckets =
        costs
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderError::Parse {
                provider: "Claude",
                message: "Admin cost report omitted data".into(),
            })?;
    let message_buckets = messages
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| ProviderError::Parse {
            provider: "Claude",
            message: "Admin usage report omitted data".into(),
        })?;
    let mut spend = 0.0;
    let mut cost_items: HashMap<String, f64> = HashMap::new();
    for result in report_results(cost_buckets)? {
        validate_result_object(result, "cost")?;
        validate_optional_string(result, "currency", "cost")?;
        validate_optional_string(result, "description", "cost")?;
        validate_optional_string(result, "cost_type", "cost")?;
        let amount = result
            .get("amount")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite())
            .ok_or_else(|| ProviderError::Parse {
                provider: "Claude",
                message: "Admin cost result has an invalid amount".into(),
            })?
            / 100.0;
        spend += amount;
        let description =
            string_at(result, &["description", "cost_type"]).unwrap_or_else(|| "Claude API".into());
        *cost_items.entry(description).or_default() += amount;
    }
    let mut input = 0_u64;
    let mut cache_creation = 0_u64;
    let mut cache_read = 0_u64;
    let mut output = 0_u64;
    let mut models: HashMap<String, u64> = HashMap::new();
    for result in report_results(message_buckets)? {
        validate_result_object(result, "usage")?;
        validate_optional_string(result, "model", "usage")?;
        let uncached = optional_integer_at(result, "uncached_input_tokens")?.unwrap_or(0);
        let creation = match result.get("cache_creation") {
            None | Some(Value::Null) => 0,
            Some(cache) if cache.is_object() => {
                optional_integer_at(cache, "ephemeral_1h_input_tokens")?.unwrap_or(0)
                    + optional_integer_at(cache, "ephemeral_5m_input_tokens")?.unwrap_or(0)
            }
            Some(_) => {
                return Err(ProviderError::Parse {
                    provider: "Claude",
                    message: "Admin usage result has invalid cache_creation".into(),
                });
            }
        };
        let read = optional_integer_at(result, "cache_read_input_tokens")?.unwrap_or(0);
        let generated = optional_integer_at(result, "output_tokens")?.unwrap_or(0);
        let total = uncached + creation + read + generated;
        input += uncached;
        cache_creation += creation;
        cache_read += read;
        output += generated;
        let model = string_at(result, &["model"]).unwrap_or_else(|| "Claude API".into());
        *models.entry(model).or_default() += total;
    }
    let total = input + cache_creation + cache_read + output;
    let mut snapshot = ProviderSnapshot::new(ProviderId::Claude, "admin-api");
    snapshot.plan = Some("Admin API".into());
    snapshot.financials = Some(FinancialSnapshot {
        balance: None,
        spend: Some(spend),
        currency: Some("USD".into()),
    });
    snapshot
        .summary
        .push(SummaryItem::new("30-day spend", format!("${spend:.2} USD")));
    snapshot
        .summary
        .push(SummaryItem::new("30-day tokens", total.to_string()));
    snapshot.summary.push(SummaryItem::new(
        "Token details",
        format!(
            "input {input}, cache creation {cache_creation}, cache read {cache_read}, output {output}"
        ),
    ));
    if let Some((model, tokens)) = models.into_iter().max_by_key(|(_, tokens)| *tokens) {
        snapshot.summary.push(SummaryItem::new(
            "Top model",
            format!("{model}: {tokens} tokens"),
        ));
    }
    if let Some((description, amount)) = cost_items
        .into_iter()
        .max_by(|left, right| left.1.total_cmp(&right.1))
    {
        snapshot.summary.push(SummaryItem::new(
            "Top cost item",
            format!("{description}: ${amount:.2}"),
        ));
    }
    Ok(snapshot)
}

fn report_results(buckets: &[Value]) -> Result<Vec<&Value>, ProviderError> {
    let mut results = Vec::new();
    for bucket in buckets {
        let start = bucket
            .get("starting_at")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .ok_or_else(|| ProviderError::Parse {
                provider: "Claude",
                message: "Admin report bucket has invalid starting_at".into(),
            })?;
        let end = bucket
            .get("ending_at")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .ok_or_else(|| ProviderError::Parse {
                provider: "Claude",
                message: "Admin report bucket has invalid ending_at".into(),
            })?;
        if end <= start {
            return Err(ProviderError::Parse {
                provider: "Claude",
                message: "Admin report bucket ending_at must follow starting_at".into(),
            });
        }
        let bucket_results = bucket
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderError::Parse {
                provider: "Claude",
                message: "Admin report bucket omitted results".into(),
            })?;
        results.extend(bucket_results);
    }
    Ok(results)
}

fn validate_result_object(value: &Value, report: &str) -> Result<(), ProviderError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(ProviderError::Parse {
            provider: "Claude",
            message: format!("Admin {report} result was not an object"),
        })
    }
}

fn validate_optional_string(value: &Value, key: &str, report: &str) -> Result<(), ProviderError> {
    match value.get(key) {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        Some(_) => Err(ProviderError::Parse {
            provider: "Claude",
            message: format!("Admin {report} result has invalid {key}"),
        }),
    }
}

fn optional_integer_at(value: &Value, key: &str) -> Result<Option<u64>, ProviderError> {
    let Some(value) = value.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| ProviderError::Parse {
            provider: "Claude",
            message: format!("Admin usage result has invalid {key}"),
        })
}

fn extract_session_key(cookie_header: &str) -> Result<String, ProviderError> {
    let value = cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        name.trim()
            .eq("sessionKey")
            .then_some(value.trim().to_owned())
    });
    match value {
        Some(value)
            if value.starts_with("sk-ant-")
                && value.len() > "sk-ant-".len()
                && !value.chars().any(char::is_whitespace) =>
        {
            Ok(value)
        }
        Some(_) => Err(ProviderError::Credential(
            "Claude sessionKey has an invalid format".into(),
        )),
        None => Err(ProviderError::MissingCredentials(
            "Claude Cookie header does not contain sessionKey".into(),
        )),
    }
}

async fn web_get(
    context: &FetchContext<'_>,
    url: &str,
    session_key: &str,
) -> Result<reqwest::Response, ProviderError> {
    Ok(context
        .client
        .get(url)
        .header("Cookie", format!("sessionKey={session_key}"))
        .header("Accept", "application/json")
        .send()
        .await?)
}

fn update_session_key(response: &reqwest::Response, session_key: &mut String) {
    for header in response.headers().get_all(reqwest::header::SET_COOKIE) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        if let Ok(renewed) = extract_session_key(header) {
            *session_key = renewed;
        }
    }
}

fn select_organization<'a>(
    payload: &'a Value,
    configured_id: Option<&str>,
) -> Result<&'a Value, ProviderError> {
    let organizations = payload.as_array().ok_or_else(|| ProviderError::Parse {
        provider: "Claude",
        message: "Web organizations response was not an array".into(),
    })?;
    if organizations
        .iter()
        .any(|organization| organization.get("uuid").and_then(Value::as_str).is_none())
    {
        return Err(ProviderError::Parse {
            provider: "Claude",
            message: "Web organization omitted uuid".into(),
        });
    }
    if let Some(configured_id) = configured_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return organizations
            .iter()
            .find(|organization| {
                organization.get("uuid").and_then(Value::as_str) == Some(configured_id)
            })
            .ok_or_else(|| ProviderError::Parse {
                provider: "Claude",
                message: "Configured Claude organization is unavailable for this session".into(),
            });
    }
    organizations
        .iter()
        .find(|organization| has_capability(organization, "chat"))
        .or_else(|| {
            organizations
                .iter()
                .find(|organization| !is_api_only(organization))
        })
        .or_else(|| organizations.first())
        .ok_or_else(|| ProviderError::Parse {
            provider: "Claude",
            message: "No Claude organization was returned".into(),
        })
}

fn has_capability(organization: &Value, expected: &str) -> bool {
    organization
        .get("capabilities")
        .and_then(Value::as_array)
        .is_some_and(|capabilities| {
            capabilities.iter().any(|capability| {
                capability
                    .as_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case(expected))
            })
        })
}

fn is_api_only(organization: &Value) -> bool {
    let capabilities = organization.get("capabilities").and_then(Value::as_array);
    capabilities.is_some_and(|values| {
        values.len() == 1
            && values[0]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case("api"))
    })
}

fn map_web_usage(payload: &Value) -> Result<ProviderSnapshot, ProviderError> {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Claude, "web");
    if payload.get("five_hour").is_some_and(Value::is_null) {
        snapshot
            .windows
            .push(UsageWindow::new("five_hour", "Session", 0.0).with_window_minutes(5 * 60));
    }
    append_standard_windows(&mut snapshot, payload);
    append_extra_usage(&mut snapshot, payload);
    if snapshot.windows.is_empty() && snapshot.summary.is_empty() {
        return Err(ProviderError::Parse {
            provider: "Claude",
            message: "no recognized Web quota windows".into(),
        });
    }
    Ok(snapshot)
}

fn check_status(status: StatusCode, provider: &'static str) -> Result<(), ProviderError> {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        Err(ProviderError::Unauthorized(format!(
            "{provider} authentication was rejected"
        )))
    } else if !status.is_success() {
        Err(ProviderError::Http {
            provider,
            status: status.as_u16(),
        })
    } else {
        Ok(())
    }
}

async fn parse_json_response(
    response: reqwest::Response,
    label: &str,
) -> Result<Value, ProviderError> {
    let bytes = response.bytes().await?;
    serde_json::from_slice(&bytes).map_err(|_| ProviderError::Parse {
        provider: "Claude",
        message: format!("{label} response was malformed"),
    })
}

fn map_usage(
    payload: &Value,
    credentials: &ClaudeCredentials,
) -> Result<ProviderSnapshot, ProviderError> {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Claude, "oauth");
    snapshot.plan = credentials
        .subscription_type
        .clone()
        .or_else(|| credentials.rate_limit_tier.clone());
    append_standard_windows(&mut snapshot, payload);
    append_extra_usage(&mut snapshot, payload);
    if snapshot.windows.is_empty() && snapshot.summary.is_empty() {
        return Err(ProviderError::Parse {
            provider: "Claude",
            message: "no recognized quota windows".into(),
        });
    }
    Ok(snapshot)
}

fn append_standard_windows(snapshot: &mut ProviderSnapshot, payload: &Value) {
    for (key, title, minutes) in [
        ("five_hour", "Session", 5 * 60),
        ("seven_day", "Weekly", 7 * 24 * 60),
    ] {
        if let Some(window) = payload
            .get(key)
            .and_then(|value| map_window(key, title, minutes, value))
        {
            snapshot.windows.push(window);
        }
    }
    if let Some(window) = payload
        .get("seven_day_sonnet")
        .and_then(|value| map_window("seven_day_sonnet", "Sonnet", 7 * 24 * 60, value))
    {
        snapshot.windows.push(window);
    }
    for (key, title) in [
        ("seven_day_oauth_apps", "OAuth apps"),
        ("seven_day_routines", "Routines"),
    ] {
        if let Some(window) = payload
            .get(key)
            .and_then(|value| map_window(key, title, 7 * 24 * 60, value))
        {
            snapshot.windows.push(window);
        }
    }
    if let Some(limits) = payload.get("limits").and_then(Value::as_array) {
        for (index, limit) in limits.iter().enumerate() {
            let title = limit
                .pointer("/scope/model/display_name")
                .and_then(Value::as_str)
                .or_else(|| limit.get("name").and_then(Value::as_str))
                .unwrap_or("Additional limit");
            if let Some(window) = map_window(&format!("limit-{index}"), title, 7 * 24 * 60, limit) {
                snapshot.windows.push(window);
            }
        }
    }
}

fn append_extra_usage(snapshot: &mut ProviderSnapshot, payload: &Value) {
    if let Some(extra) = payload
        .get("extra_usage")
        .filter(|value| bool_at(value, &["is_enabled", "isEnabled", "enabled"]).unwrap_or(false))
    {
        let used = number_at(extra, &["used_credits", "usedCredits"]);
        let limit = number_at(
            extra,
            &["monthly_limit", "monthlyLimit", "monthly_credit_limit"],
        );
        if let (Some(used), Some(limit)) = (used, limit) {
            let currency = string_at(extra, &["currency"]).unwrap_or_else(|| "USD".into());
            snapshot.summary.push(SummaryItem::new(
                "Extra usage",
                format_currency_pair(used / 100.0, limit / 100.0, &currency),
            ));
        }
    }
}

fn resolve_claude_binary(
    environment: &HashMap<std::ffi::OsString, std::ffi::OsString>,
) -> Option<PathBuf> {
    if let Some(path) = os_environment_value(environment, "CLAUDE_CLI_PATH")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
    {
        return Some(path);
    }
    let path = os_environment_value(environment, "PATH")?;
    let extensions = os_environment_value(environment, "PATHEXT")
        .and_then(|value| value.to_str())
        .map_or_else(
            || vec![".COM", ".EXE", ".BAT", ".CMD"],
            |value| {
                value
                    .split(';')
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>()
            },
        );
    for directory in env::split_paths(path) {
        let direct = directory.join("claude");
        if direct.is_file() {
            return Some(direct);
        }
        for extension in &extensions {
            let candidate = directory.join(format!("claude{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn os_environment_value<'a>(
    environment: &'a HashMap<std::ffi::OsString, std::ffi::OsString>,
    key: &str,
) -> Option<&'a std::ffi::OsString> {
    environment.iter().find_map(|(candidate, value)| {
        candidate
            .to_string_lossy()
            .eq_ignore_ascii_case(key)
            .then_some(value)
    })
}

fn claude_cli_environment(mut environment: HashMap<String, String>) -> HashMap<String, String> {
    let scrubbed_keys = [
        "CODEXBAR_CLAUDE_OAUTH_TOKEN",
        "CODEXBAR_CLAUDE_OAUTH_SCOPES",
        "ANTHROPIC_ADMIN_KEY",
        "ANTHROPIC_ADMIN_API_KEY",
        "DISABLE_AUTOUPDATER",
    ];
    environment.retain(|key, _| {
        !scrubbed_keys
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
    });
    environment.insert("DISABLE_AUTOUPDATER".into(), "1".into());
    environment
}

fn validate_cli_process_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, ProviderError> {
    if !success {
        return Err(ProviderError::Platform(
            "Claude CLI /usage exited unsuccessfully".into(),
        ));
    }
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(stderr));
    Ok(text)
}

fn map_cli_usage(output: &str) -> Result<ProviderSnapshot, ProviderError> {
    let ansi = Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").expect("valid ANSI regex");
    let clean = ansi.replace_all(output, "");
    let trimmed = clean.trim();
    let normalized = trimmed.to_ascii_lowercase();
    let compact = normalized
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let parse_error = |message: &str| ProviderError::Parse {
        provider: "Claude",
        message: message.into(),
    };
    if trimmed.is_empty() {
        return Err(parse_error("Claude CLI /usage returned no output"));
    }
    if compact.contains("currentlyusingyoursubscription")
        && compact.contains("claudecodeusage")
        && !compact.contains("currentsession")
        && !compact.contains("currentweek")
    {
        return Err(parse_error(CLAUDE_SUBSCRIPTION_QUOTA_UNAVAILABLE));
    }
    if compact.contains("loadingusagedata") {
        return Err(parse_error("Claude CLI /usage is still loading"));
    }
    if normalized.contains("please run /login")
        || normalized.contains("not logged in")
        || normalized.contains("authentication_error")
    {
        return Err(parse_error("Claude CLI is not logged in"));
    }

    let lines = trimmed.lines().map(str::trim).collect::<Vec<_>>();
    let mut snapshot = ProviderSnapshot::new(ProviderId::Claude, "cli");
    let definitions = [
        ("Current session", "session", "Session", 5 * 60),
        ("Current week (all models)", "weekly", "Weekly", 7 * 24 * 60),
        (
            "Current week (Sonnet only)",
            "sonnet",
            "Sonnet",
            7 * 24 * 60,
        ),
        ("Current week (Sonnet)", "sonnet", "Sonnet", 7 * 24 * 60),
    ];
    for (label, id, title, minutes) in definitions {
        if snapshot.windows.iter().any(|window| window.id == id) {
            continue;
        }
        if let Some(index) = lines.iter().position(|line| {
            line.to_ascii_lowercase()
                .contains(&label.to_ascii_lowercase())
        }) && let Some(window) = cli_window(&lines, index, id, title, minutes)
        {
            snapshot.windows.push(window);
        }
    }
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with("current week (")
            || lower.contains("all models")
            || lower.contains("sonnet")
            || lower.contains("opus")
        {
            continue;
        }
        let title = line
            .trim_start_matches(|character: char| character.is_whitespace())
            .strip_prefix("Current week (")
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or("Additional")
            .trim();
        if let Some(window) = cli_window(
            &lines,
            index,
            &format!("weekly-{}", slug(title)),
            title,
            7 * 24 * 60,
        ) {
            snapshot.windows.push(window);
        }
    }
    if snapshot.windows.is_empty() {
        return Err(parse_error(
            "Claude CLI /usage had no recognized quota windows",
        ));
    }
    if !snapshot.windows.iter().any(|window| window.id == "session") {
        return Err(parse_error("Claude CLI /usage omitted the current session"));
    }
    Ok(snapshot)
}

fn cli_window(
    lines: &[&str],
    label_index: usize,
    id: &str,
    title: &str,
    minutes: u32,
) -> Option<UsageWindow> {
    let next_label = lines
        .iter()
        .enumerate()
        .skip(label_index + 1)
        .find(|(_, line)| {
            let lower = line.to_ascii_lowercase();
            lower.starts_with("current session") || lower.starts_with("current week")
        })
        .map_or(lines.len(), |(index, _)| index);
    let end = (label_index + 12).min(next_label).min(lines.len());
    let candidates = &lines[label_index..end];
    let used = candidates.iter().find_map(|line| parse_cli_percent(line))?;
    let reset_line = candidates
        .iter()
        .find(|line| line.to_ascii_lowercase().contains("reset"))
        .map(|line| line.trim().to_owned());
    let reset = reset_line.as_deref().and_then(parse_reset_from_line);
    let mut window = UsageWindow::new(id, title, used)
        .with_window_minutes(minutes)
        .with_reset(reset);
    if reset.is_none()
        && let Some(detail) = reset_line
    {
        window = window.with_detail(detail);
    }
    Some(window)
}

fn parse_cli_percent(line: &str) -> Option<f64> {
    let regex = Regex::new(
        r"(?i)([0-9]{1,3}(?:\.[0-9]+)?)\s*%\s*(used|spent|consumed|left|remaining|available)",
    )
    .expect("valid percent regex");
    let captures = regex.captures(line)?;
    let value = captures
        .get(1)?
        .as_str()
        .parse::<f64>()
        .ok()?
        .clamp(0.0, 100.0);
    let qualifier = captures.get(2)?.as_str().to_ascii_lowercase();
    Some(
        if matches!(qualifier.as_str(), "left" | "remaining" | "available") {
            100.0 - value
        } else {
            value
        },
    )
}

fn parse_reset_from_line(line: &str) -> Option<DateTime<Utc>> {
    let regex = Regex::new(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[^\s]+)").expect("valid reset regex");
    let raw = regex.captures(line)?.get(1)?.as_str();
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn map_window(id: &str, title: &str, minutes: u32, value: &Value) -> Option<UsageWindow> {
    let utilization = number_at(
        value,
        &["utilization", "percent", "used_percent", "usedPercent"],
    )?;
    let reset = string_at(value, &["resets_at", "resetsAt"]).and_then(parse_date);
    Some(
        UsageWindow::new(id, title, utilization)
            .with_window_minutes(minutes)
            .with_reset(reset),
    )
}

fn parse_date(value: String) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn string_at(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn number_at(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        value.get(key).and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
    })
}

fn bool_at(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| value.get(key).and_then(Value::as_bool))
}

fn format_currency_pair(used: f64, limit: f64, currency: &str) -> String {
    let symbol = match currency.to_ascii_uppercase().as_str() {
        "USD" => "$",
        "CNY" => "¥",
        "EUR" => "€",
        _ => "",
    };
    format!("{symbol}{used:.2} / {symbol}{limit:.2} {currency}")
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProviderAccountIdentity, ProviderCredentialBundle,
        accounts::ProviderCredentialVault,
        auth::dpapi::{SecretCodec, SecretError},
        config::AppConfig,
        model::{ProviderErrorKind, ProviderSourceMode, ProviderStrategyKind},
        provider::run_provider_fetch_pipeline,
    };
    use async_trait::async_trait;
    use std::{
        collections::HashMap,
        io::{Read, Write},
        net::TcpListener,
        path::{Path, PathBuf},
        sync::{Arc, Mutex, mpsc},
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

    fn claude_identity(label: &str) -> ProviderAccountIdentity {
        ProviderAccountIdentity::new(ProviderId::Claude, [], None, Some(label.into()))
    }

    fn claude_bundle(marker: &str) -> ProviderCredentialBundle {
        ProviderCredentialBundle {
            artifact_format: Some("claude-credentials-json".into()),
            artifact: Some(
                serde_json::to_vec(&serde_json::json!({
                    "claudeAiOauth": {
                        "accessToken": format!("access-{marker}"),
                        "refreshToken": "refresh",
                        "expiresAt": 4070908800000_i64,
                    },
                    "marker": marker,
                }))
                .unwrap(),
            ),
            ..Default::default()
        }
    }

    #[derive(Clone)]
    struct MockResponse {
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: &'static str,
    }

    struct MockServer {
        base_url: String,
        requests: mpsc::Receiver<String>,
    }

    fn serve(responses: Vec<MockResponse>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("mock address");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept mock request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut chunk).expect("read mock request");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                sender
                    .send(String::from_utf8(request).expect("UTF-8 HTTP request"))
                    .expect("capture request");
                let reason = if response.status == 200 {
                    "OK"
                } else {
                    "Error"
                };
                let headers =
                    response
                        .headers
                        .iter()
                        .fold(String::new(), |mut headers, (name, value)| {
                            std::fmt::Write::write_fmt(
                                &mut headers,
                                format_args!("{name}: {value}\r\n"),
                            )
                            .expect("write mock header");
                            headers
                        });
                let wire = format!(
                    "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.body
                );
                stream.write_all(wire.as_bytes()).expect("write response");
            }
        });
        MockServer {
            base_url: format!("http://{address}"),
            requests: receiver,
        }
    }

    fn ok(body: &'static str) -> MockResponse {
        MockResponse {
            status: 200,
            headers: Vec::new(),
            body,
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn context<'a>(
        client: &'a reqwest::Client,
        config: &'a AppConfig,
        config_dir: Option<&'a Path>,
    ) -> FetchContext<'a> {
        FetchContext {
            client,
            config,
            config_dir,
        }
    }

    fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            candidate.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }

    struct FakeCliRunner {
        binary: Option<PathBuf>,
        output: Mutex<Option<Result<String, ProviderError>>>,
        invocations: Mutex<Vec<ClaudeCliInvocation>>,
    }

    impl Default for FakeCliRunner {
        fn default() -> Self {
            Self {
                binary: None,
                output: Mutex::new(Some(Ok(String::new()))),
                invocations: Mutex::new(Vec::new()),
            }
        }
    }

    impl FakeCliRunner {
        fn successful(output: &str) -> Arc<Self> {
            Arc::new(Self {
                binary: Some(PathBuf::from(r"C:\fixture\claude.exe")),
                output: Mutex::new(Some(Ok(output.to_owned()))),
                invocations: Mutex::new(Vec::new()),
            })
        }

        fn failing(error: ProviderError) -> Arc<Self> {
            Arc::new(Self {
                binary: Some(PathBuf::from(r"C:\fixture\claude.exe")),
                output: Mutex::new(Some(Err(error))),
                invocations: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl ClaudeCliRunner for FakeCliRunner {
        fn resolve_binary(&self) -> Option<PathBuf> {
            self.binary.clone()
        }

        async fn run(&self, invocation: ClaudeCliInvocation) -> Result<String, ProviderError> {
            self.invocations.lock().unwrap().push(invocation);
            self.output
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(ProviderError::Platform("fake CLI output exhausted".into())))
        }
    }

    fn test_provider(
        api_base_url: String,
        web_base_url: String,
        oauth_usage_url: String,
        oauth_refresh_url: String,
        cli_runner: Arc<dyn ClaudeCliRunner>,
    ) -> ClaudeProvider {
        ClaudeProvider::with_test_endpoints(
            api_base_url,
            web_base_url,
            oauth_usage_url,
            oauth_refresh_url,
            cli_runner,
            Arc::new(XorCodec),
            false,
            false,
        )
    }

    #[test]
    fn maps_oauth_windows_and_extra_usage() {
        let payload = serde_json::json!({
            "five_hour": { "utilization": 42.5, "resets_at": "2026-07-13T12:00:00Z" },
            "seven_day": { "utilization": 18 },
            "extra_usage": { "is_enabled": true, "used_credits": 1250, "monthly_limit": 5000, "currency": "USD" }
        });
        let credentials = ClaudeCredentials::parse(
            br#"{"claudeAiOauth":{"accessToken":"test","expiresAt":4102444800000,"subscriptionType":"pro"}}"#,
            Some(PathBuf::from("credentials.json")),
        )
        .expect("credentials");
        let snapshot = map_usage(&payload, &credentials).expect("usage");
        assert_eq!(snapshot.windows[0].used_percent, 42.5);
        assert_eq!(snapshot.plan.as_deref(), Some("pro"));
        assert_eq!(snapshot.summary[0].value, "$12.50 / $50.00 USD");
    }

    #[test]
    fn exposes_admin_oauth_cli_web_strategies_and_filters_explicit_modes() {
        let provider = ClaudeProvider::default();
        let auto = provider.strategies(ProviderSourceMode::Auto);
        assert_eq!(
            auto.iter().map(|strategy| strategy.id).collect::<Vec<_>>(),
            vec![
                "claude.admin-api",
                "claude.oauth",
                "claude.cli",
                "claude.web"
            ]
        );
        assert_eq!(auto[0].kind, ProviderStrategyKind::ApiToken);
        assert_eq!(auto[1].kind, ProviderStrategyKind::Oauth);
        assert_eq!(auto[2].kind, ProviderStrategyKind::Cli);
        assert_eq!(auto[3].kind, ProviderStrategyKind::Web);
        for (mode, id) in [
            (ProviderSourceMode::Api, "claude.admin-api"),
            (ProviderSourceMode::Oauth, "claude.oauth"),
            (ProviderSourceMode::Cli, "claude.cli"),
            (ProviderSourceMode::Web, "claude.web"),
        ] {
            assert_eq!(
                provider
                    .strategies(mode)
                    .iter()
                    .map(|strategy| strategy.id)
                    .collect::<Vec<_>>(),
                vec![id]
            );
        }
    }

    #[test]
    fn named_account_never_uses_global_admin_cli_or_browser_credentials() {
        let provider = ClaudeProvider::with_test_endpoints(
            "http://127.0.0.1:1".into(),
            "http://127.0.0.1:1".into(),
            "http://127.0.0.1:1".into(),
            "http://127.0.0.1:1".into(),
            Arc::new(FakeCliRunner {
                binary: Some(PathBuf::from("C:/bin/claude.exe")),
                ..Default::default()
            }),
            Arc::new(XorCodec),
            false,
            true,
        );
        let client = reqwest::Client::new();
        let config = AppConfig::default();
        let named = ProviderAccount {
            id: "acc_named".into(),
            ..Default::default()
        };
        let environment = HashMap::from([("ANTHROPIC_ADMIN_KEY".into(), "global-key".into())]);
        assert!(resolve_admin_api_key(&named, &environment).is_none());

        let strategies = provider.strategies(ProviderSourceMode::Auto);
        assert!(!provider.is_strategy_available(
            &strategies[2],
            &context(&client, &config, None),
            &named,
        ));
        assert!(!provider.is_strategy_available(
            &strategies[3],
            &context(&client, &config, None),
            &named,
        ));

        let explicitly_scoped = ProviderAccount {
            id: "acc_named".into(),
            api_key: Some("account-admin-key".into()),
            cookie_header: Some("sessionKey=account-session".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_admin_api_key(&explicitly_scoped, &environment).as_deref(),
            Some("account-admin-key")
        );
        assert!(provider.is_strategy_available(
            &strategies[3],
            &context(&client, &config, None),
            &explicitly_scoped,
        ));
    }

    #[test]
    fn admin_key_precedence_is_account_then_primary_then_legacy_environment() {
        let environment = HashMap::from([
            ("ANTHROPIC_ADMIN_KEY".to_owned(), "primary".to_owned()),
            ("ANTHROPIC_ADMIN_API_KEY".to_owned(), "legacy".to_owned()),
        ]);
        let account = ProviderAccount {
            api_key: Some("account".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_admin_api_key(&account, &environment).as_deref(),
            Some("account")
        );
        assert_eq!(
            resolve_admin_api_key(&ProviderAccount::default(), &environment).as_deref(),
            Some("primary")
        );
        assert_eq!(
            resolve_admin_api_key(
                &ProviderAccount::default(),
                &HashMap::from([("ANTHROPIC_ADMIN_API_KEY".to_owned(), "legacy".to_owned())]),
            )
            .as_deref(),
            Some("legacy")
        );
        assert_eq!(
            resolve_admin_api_key(
                &ProviderAccount::default(),
                &HashMap::from([("anthropic_admin_key".to_owned(), "mixed".to_owned())]),
            )
            .as_deref(),
            Some("mixed")
        );
    }

    #[test]
    fn windows_cli_resolution_and_scrubbing_are_case_insensitive() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("claude.EXE");
        std::fs::write(&binary, b"fixture").unwrap();
        let environment = HashMap::from([
            (
                std::ffi::OsString::from("Path"),
                env::join_paths([directory.path()]).unwrap(),
            ),
            (
                std::ffi::OsString::from("Pathext"),
                std::ffi::OsString::from(".EXE"),
            ),
        ]);
        assert_eq!(resolve_claude_binary(&environment), Some(binary));

        let scrubbed = claude_cli_environment(HashMap::from([
            ("Anthropic_Admin_Key".to_owned(), "secret-a".to_owned()),
            (
                "codexbar_claude_oauth_token".to_owned(),
                "secret-b".to_owned(),
            ),
            ("Disable_Autoupdater".to_owned(), "0".to_owned()),
        ]));
        assert!(!scrubbed.keys().any(|key| {
            key.eq_ignore_ascii_case("ANTHROPIC_ADMIN_KEY")
                || key.eq_ignore_ascii_case("CODEXBAR_CLAUDE_OAUTH_TOKEN")
        }));
        assert_eq!(
            scrubbed.get("DISABLE_AUTOUPDATER").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            scrubbed
                .keys()
                .filter(|key| key.eq_ignore_ascii_case("DISABLE_AUTOUPDATER"))
                .count(),
            1
        );
    }

    #[test]
    fn admin_api_sends_official_headers_range_and_maps_cost_and_tokens() {
        runtime().block_on(async {
            let server = serve(vec![
                ok(r#"{"data":[{"starting_at":"2026-07-01T00:00:00Z","ending_at":"2026-07-02T00:00:00Z","results":[{"amount":"250","description":"Claude API"}]}],"has_more":false}"#),
                ok(r#"{"data":[{"starting_at":"2026-07-01T00:00:00Z","ending_at":"2026-07-02T00:00:00Z","results":[{"uncached_input_tokens":10,"cache_creation":{"ephemeral_1h_input_tokens":3,"ephemeral_5m_input_tokens":2},"cache_read_input_tokens":4,"output_tokens":6,"model":"claude-fixture"}]}],"has_more":false}"#),
            ]);
            let runner = Arc::new(FakeCliRunner::default());
            let provider = test_provider(
                server.base_url.clone(),
                "http://127.0.0.1:1".into(),
                "http://127.0.0.1:1/oauth".into(),
                "http://127.0.0.1:1/refresh".into(),
                runner,
            );
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let account = ProviderAccount {
                api_key: Some("admin-fixture".into()),
                ..Default::default()
            };
            let strategy = provider.strategies(ProviderSourceMode::Api)[0];
            let snapshot = provider
                .fetch_strategy(&strategy, &context(&client, &config, None), &account)
                .await
                .expect("admin usage");

            assert_eq!(snapshot.source, "admin-api");
            assert_eq!(snapshot.financials.as_ref().and_then(|item| item.spend), Some(2.5));
            assert!(snapshot.summary.iter().any(|item| item.value.contains("25")));
            assert!(snapshot.summary.iter().any(|item| item.value.contains("claude-fixture")));
            for expected_path in ["/v1/organizations/cost_report", "/v1/organizations/usage_report/messages"] {
                let request = server.requests.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(request.starts_with(&format!("GET {expected_path}?")));
                assert_eq!(header(&request, "x-api-key"), Some("admin-fixture"));
                assert_eq!(header(&request, "anthropic-version"), Some("2023-06-01"));
                assert!(request.contains("bucket_width=1d"));
                assert!(request.contains("limit=31"));
                assert!(request.contains("starting_at="));
                assert!(request.contains("ending_at="));
            }
        });
    }

    #[test]
    fn admin_api_classifies_auth_http_and_parse_failures_without_fallback() {
        runtime().block_on(async {
            for (status, body, expected) in [
                (
                    401,
                    r#"{"error":"unauthorized"}"#,
                    ProviderErrorKind::Unauthorized,
                ),
                (
                    403,
                    r#"{"error":"forbidden"}"#,
                    ProviderErrorKind::Unauthorized,
                ),
                (500, r#"{"error":"server"}"#, ProviderErrorKind::Http),
                (200, "not-json", ProviderErrorKind::Parse),
            ] {
                let server = serve(vec![MockResponse {
                    status,
                    headers: Vec::new(),
                    body,
                }]);
                let provider = test_provider(
                    server.base_url,
                    "http://127.0.0.1:1".into(),
                    "http://127.0.0.1:1/oauth".into(),
                    "http://127.0.0.1:1/refresh".into(),
                    Arc::new(FakeCliRunner::default()),
                );
                let client = reqwest::Client::new();
                let config = AppConfig::default();
                let account = ProviderAccount {
                    api_key: Some("fixture".into()),
                    ..Default::default()
                };
                let outcome = run_provider_fetch_pipeline(
                    &provider,
                    &context(&client, &config, None),
                    &account,
                    ProviderSourceMode::Auto,
                )
                .await;
                assert_eq!(outcome.attempts.len(), 1);
                assert_eq!(outcome.attempts[0].strategy_id, "claude.admin-api");
                assert_eq!(outcome.attempts[0].error_kind, Some(expected));
                assert!(outcome.result.is_err());
            }
        });
    }

    #[test]
    fn web_selects_chat_org_uses_renewed_session_and_maps_optional_fields() {
        runtime().block_on(async {
            let server = serve(vec![
                MockResponse {
                    status: 200,
                    headers: vec![("Set-Cookie", "sessionKey=sk-ant-renewed; Path=/; Secure")],
                    body: r#"[{"uuid":"api-org","name":"API","capabilities":["api"]},{"uuid":"chat-org","name":"Chat Team","capabilities":["chat"]}]"#,
                },
                ok(r#"{"five_hour":{"utilization":12,"resets_at":"2026-07-20T12:00:00Z"},"seven_day":{"utilization":34,"resets_at":"2026-07-24T12:00:00Z"},"seven_day_sonnet":{"utilization":56},"seven_day_opus":{"utilization":99},"seven_day_routines":{"utilization":7},"limits":[{"percent":8,"resets_at":"2026-07-24T12:00:00Z","scope":{"model":{"display_name":"Haiku"}}}],"extra_usage":{"is_enabled":true,"used_credits":1250,"monthly_limit":5000,"currency":"USD"}}"#),
                MockResponse { status: 500, headers: Vec::new(), body: r#"{"error":"optional"}"# },
            ]);
            let provider = test_provider(
                "http://127.0.0.1:1".into(),
                server.base_url.clone(),
                "http://127.0.0.1:1/oauth".into(),
                "http://127.0.0.1:1/refresh".into(),
                Arc::new(FakeCliRunner::default()),
            );
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let account = ProviderAccount {
                cookie_header: Some("other=drop-me; sessionKey=sk-ant-manual; another=drop".into()),
                ..Default::default()
            };
            let strategy = provider.strategies(ProviderSourceMode::Web)[0];
            let snapshot = provider
                .fetch_strategy(&strategy, &context(&client, &config, None), &account)
                .await
                .expect("web usage");
            assert_eq!(snapshot.source, "web");
            assert_eq!(snapshot.account_label.as_deref(), Some("Chat Team"));
            assert_eq!(snapshot.windows.iter().map(|window| window.used_percent).collect::<Vec<_>>(), vec![12.0, 34.0, 56.0, 7.0, 8.0]);
            assert_eq!(snapshot.summary[0].value, "$12.50 / $50.00 USD");

            let organizations = server.requests.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(organizations.starts_with("GET /api/organizations HTTP/1.1"));
            assert_eq!(header(&organizations, "Cookie"), Some("sessionKey=sk-ant-manual"));
            let usage = server.requests.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(usage.starts_with("GET /api/organizations/chat-org/usage HTTP/1.1"));
            assert_eq!(header(&usage, "Cookie"), Some("sessionKey=sk-ant-renewed"));
            let account_request = server.requests.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(header(&account_request, "Cookie"), Some("sessionKey=sk-ant-renewed"));
        });
    }

    #[test]
    fn web_honors_configured_org_and_rejects_malformed_cookie_and_payloads() {
        assert!(matches!(
            extract_session_key("sessionKey=not-a-claude-session"),
            Err(ProviderError::Credential(_))
        ));
        runtime().block_on(async {
            let server = serve(vec![ok(r#"[{"uuid":"one","capabilities":["chat"]}]"#)]);
            let provider = test_provider(
                "http://127.0.0.1:1".into(),
                server.base_url,
                "http://127.0.0.1:1/oauth".into(),
                "http://127.0.0.1:1/refresh".into(),
                Arc::new(FakeCliRunner::default()),
            );
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let account = ProviderAccount {
                cookie_header: Some("sessionKey=sk-ant-valid".into()),
                organization_id: Some("missing".into()),
                ..Default::default()
            };
            let strategy = provider.strategies(ProviderSourceMode::Web)[0];
            assert!(matches!(
                provider
                    .fetch_strategy(&strategy, &context(&client, &config, None), &account)
                    .await,
                Err(ProviderError::Parse {
                    provider: "Claude",
                    ..
                })
            ));
        });
    }

    #[test]
    fn cli_parser_handles_ansi_used_left_resets_and_scoped_weekly_panels() {
        let snapshot = map_cli_usage(
            "\u{1b}[2JCurrent session\n25% used\nResets at 2026-07-20T12:00:00Z\nCurrent week (all models)\n70% left\nResets at 2026-07-24T12:00:00Z\nCurrent week (Sonnet only)\n10% used\nCurrent week (Haiku)\n80% remaining\n",
        )
        .expect("CLI usage");
        assert_eq!(snapshot.source, "cli");
        assert_eq!(
            snapshot
                .windows
                .iter()
                .map(|window| window.used_percent)
                .collect::<Vec<_>>(),
            vec![25.0, 30.0, 10.0, 20.0]
        );
        assert_eq!(
            snapshot.windows[0].resets_at.unwrap().to_rfc3339(),
            "2026-07-20T12:00:00+00:00"
        );
    }

    #[test]
    fn cli_parser_rejects_empty_loading_login_subscription_and_malformed_output() {
        for output in [
            "",
            "Loading usage data...",
            "Please run /login",
            "You are currently using your subscription to power your Claude Code usage",
            "Current session without a percentage",
        ] {
            assert!(matches!(
                map_cli_usage(output),
                Err(ProviderError::Parse {
                    provider: "Claude",
                    ..
                })
            ));
        }
    }

    #[test]
    fn cli_parser_does_not_borrow_a_percentage_from_the_next_panel() {
        assert!(matches!(
            map_cli_usage("Current session\nReset in 2h\nCurrent week (all models)\n70% left\n"),
            Err(ProviderError::Parse {
                provider: "Claude",
                ..
            })
        ));
    }

    #[test]
    fn cli_parser_retains_human_reset_text_when_it_is_not_rfc3339() {
        let snapshot = map_cli_usage(
            "Current session\n25% used\nResets 3pm Friday\nCurrent week (all models)\n70% left\n",
        )
        .expect("CLI usage");
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("Resets 3pm Friday")
        );
    }

    #[test]
    fn nonzero_cli_process_exit_is_categorical_and_never_exposes_output() {
        let error = validate_cli_process_output(false, b"secret stdout", b"secret stderr")
            .expect_err("nonzero exit");
        assert!(matches!(error, ProviderError::Platform(_)));
        let message = error.to_string();
        assert!(!message.contains("secret stdout"));
        assert!(!message.contains("secret stderr"));
    }

    #[test]
    fn admin_success_with_malformed_result_fields_is_parse_error() {
        let costs = serde_json::json!({
            "data": [{
                "starting_at": "2026-07-01T00:00:00Z",
                "ending_at": "2026-07-02T00:00:00Z",
                "results": [{"amount": {"unexpected": true}, "description": "bad"}]
            }]
        });
        let messages = serde_json::json!({"data": []});
        assert!(matches!(
            map_admin_usage(&costs, &messages),
            Err(ProviderError::Parse {
                provider: "Claude",
                ..
            })
        ));
    }

    #[test]
    fn admin_buckets_require_valid_start_and_end_timestamps() {
        let valid_bucket = serde_json::json!({
            "starting_at": "2026-07-01T00:00:00Z",
            "ending_at": "2026-07-02T00:00:00Z",
            "results": []
        });
        for malformed in [
            serde_json::json!({"ending_at": "2026-07-02T00:00:00Z", "results": []}),
            serde_json::json!({"starting_at": "not-a-date", "ending_at": "2026-07-02T00:00:00Z", "results": []}),
            serde_json::json!({"starting_at": "2026-07-01T00:00:00Z", "results": []}),
            serde_json::json!({"starting_at": "2026-07-01T00:00:00Z", "ending_at": 123, "results": []}),
        ] {
            for (cost_bucket, message_bucket) in [
                (malformed.clone(), valid_bucket.clone()),
                (valid_bucket.clone(), malformed.clone()),
            ] {
                assert!(matches!(
                    map_admin_usage(
                        &serde_json::json!({"data": [cost_bucket]}),
                        &serde_json::json!({"data": [message_bucket]}),
                    ),
                    Err(ProviderError::Parse {
                        provider: "Claude",
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn admin_results_follow_the_swift_typed_contract() {
        let valid_messages = serde_json::json!({
            "data": [{
                "starting_at": "2026-07-01T00:00:00Z",
                "ending_at": "2026-07-02T00:00:00Z",
                "results": []
            }]
        });
        let invalid_costs = serde_json::json!({
            "data": [{
                "starting_at": "2026-07-01T00:00:00Z",
                "ending_at": "2026-07-02T00:00:00Z",
                "results": [{"amount": 250, "description": "Claude API"}]
            }]
        });
        assert!(matches!(
            map_admin_usage(&invalid_costs, &valid_messages),
            Err(ProviderError::Parse {
                provider: "Claude",
                ..
            })
        ));

        let valid_costs = serde_json::json!({
            "data": [{
                "starting_at": "2026-07-01T00:00:00Z",
                "ending_at": "2026-07-02T00:00:00Z",
                "results": [{"amount": "250", "description": "Claude API"}]
            }]
        });
        let invalid_messages = serde_json::json!({
            "data": [{
                "starting_at": "2026-07-01T00:00:00Z",
                "ending_at": "2026-07-02T00:00:00Z",
                "results": [{"uncached_input_tokens": "10", "model": 123}]
            }]
        });
        assert!(matches!(
            map_admin_usage(&valid_costs, &invalid_messages),
            Err(ProviderError::Parse {
                provider: "Claude",
                ..
            })
        ));
    }

    #[test]
    fn web_null_five_hour_is_a_valid_zero_percent_session_window() {
        let snapshot = map_web_usage(&serde_json::json!({"five_hour": null}))
            .expect("enterprise Web quota without a five-hour limit");
        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
        assert_eq!(snapshot.windows[0].window_minutes, Some(300));
    }

    #[test]
    fn retired_opus_tertiary_limit_is_ignored() {
        let web = map_web_usage(&serde_json::json!({
            "five_hour": {"utilization": 5},
            "seven_day_opus": {"utilization": 99}
        }))
        .expect("web usage");
        assert_eq!(
            web.windows
                .iter()
                .map(|window| window.id.as_str())
                .collect::<Vec<_>>(),
            vec!["five_hour"]
        );

        let cli = map_cli_usage(concat!(
            "Current session\n5% used\n",
            "Current week (Opus)\n99% used\n"
        ))
        .expect("CLI usage");
        assert_eq!(cli.windows.len(), 1);
        assert_eq!(cli.windows[0].id, "session");
    }

    #[test]
    fn cli_runner_receives_direct_usage_timeout_and_scrubbed_environment() {
        runtime().block_on(async {
            let runner = FakeCliRunner::successful("Current session\n5% used\n");
            let provider = test_provider(
                "http://127.0.0.1:1".into(),
                "http://127.0.0.1:1".into(),
                "http://127.0.0.1:1/oauth".into(),
                "http://127.0.0.1:1/refresh".into(),
                runner.clone(),
            );
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let strategy = provider.strategies(ProviderSourceMode::Cli)[0];
            let snapshot = provider
                .fetch_strategy(
                    &strategy,
                    &context(&client, &config, None),
                    &ProviderAccount::default(),
                )
                .await
                .expect("CLI usage");
            assert_eq!(snapshot.windows[0].used_percent, 5.0);
            let invocations = runner.invocations.lock().unwrap();
            let invocation = &invocations[0];
            assert_eq!(invocation.program, PathBuf::from(r"C:\fixture\claude.exe"));
            assert_eq!(invocation.arguments, vec!["/usage"]);
            assert_eq!(invocation.timeout, Duration::from_secs(20));
            assert_eq!(
                invocation
                    .environment
                    .get("DISABLE_AUTOUPDATER")
                    .map(String::as_str),
                Some("1")
            );
            for key in [
                "CODEXBAR_CLAUDE_OAUTH_TOKEN",
                "CODEXBAR_CLAUDE_OAUTH_SCOPES",
                "ANTHROPIC_ADMIN_KEY",
                "ANTHROPIC_ADMIN_API_KEY",
            ] {
                assert!(!invocation.environment.contains_key(key));
            }
        });
    }

    #[test]
    fn auto_falls_from_cli_to_web_but_subscription_notice_is_terminal() {
        runtime().block_on(async {
            let web = serve(vec![
                ok(r#"[{"uuid":"chat","name":"Chat","capabilities":["chat"]}]"#),
                ok(r#"{"five_hour":{"utilization":1}}"#),
                ok(r"{}"),
            ]);
            let provider = test_provider(
                "http://127.0.0.1:1".into(),
                web.base_url,
                "http://127.0.0.1:1/oauth".into(),
                "http://127.0.0.1:1/refresh".into(),
                FakeCliRunner::failing(ProviderError::Parse {
                    provider: "Claude",
                    message: "ordinary CLI parse failure".into(),
                }),
            );
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let account = ProviderAccount {
                cookie_header: Some("sessionKey=sk-ant-web".into()),
                ..Default::default()
            };
            let outcome = run_provider_fetch_pipeline(
                &provider,
                &context(&client, &config, None),
                &account,
                ProviderSourceMode::Auto,
            )
            .await;
            assert_eq!(outcome.result.unwrap().source, "web");
            assert_eq!(
                outcome
                    .attempts
                    .iter()
                    .map(|attempt| attempt.strategy_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["claude.oauth", "claude.cli", "claude.web"]
            );

            let explicit_api = run_provider_fetch_pipeline(
                &provider,
                &context(&client, &config, None),
                &account,
                ProviderSourceMode::Api,
            )
            .await;
            assert!(matches!(
                explicit_api.result,
                Err(ProviderError::MissingCredentials(_))
            ));
            assert_eq!(explicit_api.attempts.len(), 1);
            assert_eq!(explicit_api.attempts[0].strategy_id, "claude.admin-api");
            assert!(!explicit_api.attempts[0].was_available);
            assert_eq!(
                explicit_api.attempts[0].error_kind,
                Some(ProviderErrorKind::MissingCredentials)
            );

            let terminal = ClaudeProvider::default();
            let cli = terminal.strategies(ProviderSourceMode::Cli)[0];
            assert!(!terminal.should_fallback(
                &cli,
                &ProviderError::Parse {
                    provider: "Claude",
                    message: CLAUDE_SUBSCRIPTION_QUOTA_UNAVAILABLE.into(),
                }
            ));
            assert!(terminal.should_fallback(
                &cli,
                &ProviderError::Parse {
                    provider: "Claude",
                    message: "ordinary CLI parse failure".into(),
                }
            ));
            let oauth = terminal.strategies(ProviderSourceMode::Oauth)[0];
            assert!(
                terminal.should_fallback(&oauth, &ProviderError::Unauthorized("expired".into()))
            );
        });
    }

    #[test]
    fn oauth_refreshes_expired_selected_account_without_touching_sibling() {
        runtime().block_on(async {
            let server = serve(vec![
                ok(r#"{"access_token":"fresh-a","refresh_token":"refresh-a2","expires_in":3600}"#),
                ok(r#"{"five_hour":{"utilization":9}}"#),
            ]);
            let directory = tempfile::tempdir().unwrap();
            let vault = ProviderCredentialVault::new(directory.path(), &XorCodec);
            let selected_bundle = ProviderCredentialBundle {
                artifact_format: Some("claude-credentials-json".into()),
                artifact: Some(br#"{"claudeAiOauth":{"accessToken":"stale-a","refreshToken":"refresh-a","expiresAt":0}}"#.to_vec()),
                ..Default::default()
            };
            let sibling_bundle = claude_bundle("sibling");
            vault.save(ProviderId::Claude, "acc_a", &claude_identity("a"), &selected_bundle).unwrap();
            vault.save(ProviderId::Claude, "acc_b", &claude_identity("b"), &sibling_bundle).unwrap();
            let sibling_before = vault.load(ProviderId::Claude, "acc_b").unwrap().credentials;
            let provider = test_provider(
                "http://127.0.0.1:1".into(),
                "http://127.0.0.1:1".into(),
                format!("{}/usage", server.base_url),
                format!("{}/refresh", server.base_url),
                Arc::new(FakeCliRunner::default()),
            );
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let account = ProviderAccount { id: "acc_a".into(), ..Default::default() };
            let strategy = provider.strategies(ProviderSourceMode::Oauth)[0];
            let snapshot = provider.fetch_strategy(&strategy, &context(&client, &config, Some(directory.path())), &account).await.expect("OAuth usage");
            assert_eq!(snapshot.source, "oauth");
            let selected_after = String::from_utf8(
                vault.load(ProviderId::Claude, "acc_a").unwrap().credentials.artifact.unwrap(),
            ).unwrap();
            assert!(selected_after.contains("fresh-a"));
            assert!(!selected_after.contains("stale-a"));
            assert_eq!(
                vault.load(ProviderId::Claude, "acc_b").unwrap().credentials,
                sibling_before
            );
        });
    }

    #[test]
    fn oauth_401_forces_one_refresh_and_one_retry() {
        runtime().block_on(async {
            let server = serve(vec![
                MockResponse { status: 401, headers: Vec::new(), body: r#"{"error":"expired"}"# },
                ok(r#"{"access_token":"after-401","expires_in":3600}"#),
                ok(r#"{"five_hour":{"utilization":11}}"#),
            ]);
            let directory = tempfile::tempdir().unwrap();
            let vault = ProviderCredentialVault::new(directory.path(), &XorCodec);
            let selected_bundle = ProviderCredentialBundle {
                artifact_format: Some("claude-credentials-json".into()),
                artifact: Some(br#"{"claudeAiOauth":{"accessToken":"current","refreshToken":"refresh","expiresAt":4102444800000}}"#.to_vec()),
                ..Default::default()
            };
            vault.save(ProviderId::Claude, "acc_a", &claude_identity("a"), &selected_bundle).unwrap();
            let provider = test_provider(
                "http://127.0.0.1:1".into(),
                "http://127.0.0.1:1".into(),
                format!("{}/usage", server.base_url),
                format!("{}/refresh", server.base_url),
                Arc::new(FakeCliRunner::default()),
            );
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let account = ProviderAccount { id: "acc_a".into(), ..Default::default() };
            let strategy = provider.strategies(ProviderSourceMode::Oauth)[0];
            let snapshot = provider.fetch_strategy(&strategy, &context(&client, &config, Some(directory.path())), &account).await.expect("retried OAuth usage");
            assert_eq!(snapshot.windows[0].used_percent, 11.0);
            assert!(
                String::from_utf8(
                    vault.load(ProviderId::Claude, "acc_a").unwrap().credentials.artifact.unwrap()
                )
                .unwrap()
                .contains("after-401")
            );
            assert!(server.requests.recv_timeout(Duration::from_secs(5)).unwrap().starts_with("GET /usage"));
            assert!(server.requests.recv_timeout(Duration::from_secs(5)).unwrap().starts_with("POST /refresh"));
            assert!(server.requests.recv_timeout(Duration::from_secs(5)).unwrap().starts_with("GET /usage"));
            assert!(server.requests.recv_timeout(Duration::from_millis(100)).is_err());
        });
    }

    #[test]
    fn named_account_loads_only_its_generic_encrypted_vault_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        vault
            .save(
                ProviderId::Claude,
                "acc_named",
                &claude_identity("named"),
                &claude_bundle("named-vault"),
            )
            .unwrap();

        let source =
            ClaudeCredentialSource::load_named(temporary.path(), "acc_named", &XorCodec).unwrap();

        assert_eq!(source.credentials().access_token, "access-named-vault");
        assert_eq!(
            source.artifact().unwrap(),
            claude_bundle("named-vault").artifact.unwrap()
        );
        assert!(matches!(
            ClaudeCredentialSource::load_named(temporary.path(), "acc_missing", &XorCodec),
            Err(ProviderError::MissingCredentials(_))
        ));
    }

    #[test]
    fn named_refresh_writes_back_only_the_same_generic_vault_bundle() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        vault
            .save(
                ProviderId::Claude,
                "acc_first",
                &claude_identity("first"),
                &claude_bundle("before"),
            )
            .unwrap();
        vault
            .save(
                ProviderId::Claude,
                "acc_second",
                &claude_identity("second"),
                &claude_bundle("sibling"),
            )
            .unwrap();
        let sibling_before = vault
            .load(ProviderId::Claude, "acc_second")
            .unwrap()
            .credentials;
        let mut source =
            ClaudeCredentialSource::load_named(temporary.path(), "acc_first", &XorCodec).unwrap();

        let refreshed_artifact = claude_bundle("after").artifact.unwrap();
        let refreshed = ClaudeCredentials::parse(&refreshed_artifact, None).unwrap();
        source
            .persist_refreshed(refreshed, refreshed_artifact, &XorCodec)
            .unwrap();

        assert_eq!(
            vault
                .load(ProviderId::Claude, "acc_first")
                .unwrap()
                .credentials
                .artifact,
            claude_bundle("after").artifact
        );
        assert_eq!(
            vault
                .load(ProviderId::Claude, "acc_second")
                .unwrap()
                .credentials,
            sibling_before
        );
    }
}
