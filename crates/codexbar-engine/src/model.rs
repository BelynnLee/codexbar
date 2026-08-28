use crate::status::ServiceStatus;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Claude,
    Codex,
    Copilot,
    Cursor,
    Opencode,
    Opencodezen,
    Openrouter,
    Deepseek,
    Moonshot,
    Venice,
    Poe,
    Groq,
    Elevenlabs,
    Deepgram,
    Kimik2,
    Crossmodel,
    Clawrouter,
    Crof,
    Codebuff,
    Llmproxy,
    Openai,
    Chutes,
    Synthetic,
    Azureopenai,
    Litellm,
    Sub2api,
    Zai,
    Minimax,
    Wayfinder,
    Kilo,
    Perplexity,
    Kimi,
    Manus,
    Abacus,
    Amp,
    Commandcode,
    Stepfun,
    T3chat,
    Qoder,
    Mimo,
    Augment,
}

impl ProviderId {
    pub const ALL: [Self; 41] = [
        Self::Claude,
        Self::Codex,
        Self::Copilot,
        Self::Cursor,
        Self::Opencode,
        Self::Opencodezen,
        Self::Openrouter,
        Self::Deepseek,
        Self::Moonshot,
        Self::Venice,
        Self::Poe,
        Self::Groq,
        Self::Elevenlabs,
        Self::Deepgram,
        Self::Kimik2,
        Self::Crossmodel,
        Self::Clawrouter,
        Self::Crof,
        Self::Codebuff,
        Self::Llmproxy,
        Self::Openai,
        Self::Chutes,
        Self::Synthetic,
        Self::Azureopenai,
        Self::Litellm,
        Self::Sub2api,
        Self::Zai,
        Self::Minimax,
        Self::Wayfinder,
        Self::Kilo,
        Self::Perplexity,
        Self::Kimi,
        Self::Manus,
        Self::Abacus,
        Self::Amp,
        Self::Commandcode,
        Self::Stepfun,
        Self::T3chat,
        Self::Qoder,
        Self::Mimo,
        Self::Augment,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Cursor => "cursor",
            Self::Opencode => "opencode",
            Self::Opencodezen => "opencodezen",
            Self::Openrouter => "openrouter",
            Self::Deepseek => "deepseek",
            Self::Moonshot => "moonshot",
            Self::Venice => "venice",
            Self::Poe => "poe",
            Self::Groq => "groq",
            Self::Elevenlabs => "elevenlabs",
            Self::Deepgram => "deepgram",
            Self::Kimik2 => "kimik2",
            Self::Crossmodel => "crossmodel",
            Self::Clawrouter => "clawrouter",
            Self::Crof => "crof",
            Self::Codebuff => "codebuff",
            Self::Llmproxy => "llmproxy",
            Self::Openai => "openai",
            Self::Chutes => "chutes",
            Self::Synthetic => "synthetic",
            Self::Azureopenai => "azureopenai",
            Self::Litellm => "litellm",
            Self::Sub2api => "sub2api",
            Self::Zai => "zai",
            Self::Minimax => "minimax",
            Self::Wayfinder => "wayfinder",
            Self::Kilo => "kilo",
            Self::Perplexity => "perplexity",
            Self::Kimi => "kimi",
            Self::Manus => "manus",
            Self::Abacus => "abacus",
            Self::Amp => "amp",
            Self::Commandcode => "commandcode",
            Self::Stepfun => "stepfun",
            Self::T3chat => "t3chat",
            Self::Qoder => "qoder",
            Self::Mimo => "mimo",
            Self::Augment => "augment",
        }
    }

    /// Whether a fresh config enables this provider. Experimental multi-source Claude and long-tail
    /// providers ship disabled so a new install is not flooded with credential errors, while
    /// existing configs preserve their stored enablement.
    pub const fn default_enabled(self) -> bool {
        matches!(
            self,
            Self::Codex
                | Self::Cursor
                | Self::Opencode
                | Self::Opencodezen
                | Self::Openrouter
                | Self::Deepseek
                | Self::Moonshot
                | Self::Venice
                | Self::Poe
        )
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    #[serde(rename = "cli_oauth")]
    CliOAuth,
    BrowserCookie,
    ApiKey,
    DeviceOAuth,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderSourceMode {
    #[default]
    Auto,
    Api,
    Web,
    Cli,
    Oauth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderStrategyKind {
    ApiToken,
    Web,
    Cli,
    Oauth,
    LocalProbe,
    WebDashboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderMaturity {
    Experimental,
    Stable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderSettingKey {
    ApiKey,
    SecretKey,
    CookieHeader,
    Browser,
    BaseUrl,
    Region,
    WorkspaceId,
    OrganizationId,
    ProjectId,
    Deployment,
    EnterpriseHost,
    UsageScope,
    AwsProfile,
    AwsAuthMode,
    KiloOrganizationIds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderSettingKind {
    Plain,
    Secret,
    Select,
    MultiValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSettingDescriptor {
    pub key: ProviderSettingKey,
    pub kind: ProviderSettingKind,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choices: Option<&'static [&'static str]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAuthActionKind {
    BrowserLogin,
    CookieImport,
    CliImport,
    DeviceOAuth,
    #[serde(rename = "oauthConnect")]
    OAuthConnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCapabilityDescriptor {
    pub maturity: ProviderMaturity,
    pub source_modes: &'static [ProviderSourceMode],
    pub settings: &'static [ProviderSettingDescriptor],
    pub auth_actions: &'static [ProviderAuthActionKind],
}

const AUTO_API: &[ProviderSourceMode] = &[ProviderSourceMode::Auto, ProviderSourceMode::Api];
const AUTO_WEB: &[ProviderSourceMode] = &[ProviderSourceMode::Auto, ProviderSourceMode::Web];
const CLAUDE_SOURCES: &[ProviderSourceMode] = &[
    ProviderSourceMode::Auto,
    ProviderSourceMode::Api,
    ProviderSourceMode::Web,
    ProviderSourceMode::Cli,
    ProviderSourceMode::Oauth,
];
const CODEX_SOURCES: &[ProviderSourceMode] = &[ProviderSourceMode::Auto, ProviderSourceMode::Oauth];
const CURSOR_SOURCES: &[ProviderSourceMode] = &[
    ProviderSourceMode::Auto,
    ProviderSourceMode::Cli,
    ProviderSourceMode::Web,
];
const AUTO_OAUTH: &[ProviderSourceMode] = &[ProviderSourceMode::Auto, ProviderSourceMode::Oauth];

const API_KEY: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::ApiKey,
    kind: ProviderSettingKind::Secret,
    required: true,
    choices: None,
};
const OPTIONAL_API_KEY: ProviderSettingDescriptor = ProviderSettingDescriptor {
    required: false,
    ..API_KEY
};
const COOKIE_HEADER: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::CookieHeader,
    kind: ProviderSettingKind::Secret,
    required: false,
    choices: None,
};
const BROWSER: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::Browser,
    kind: ProviderSettingKind::Select,
    required: false,
    choices: Some(&["auto", "chrome", "edge"]),
};
const BASE_URL: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::BaseUrl,
    kind: ProviderSettingKind::Plain,
    required: false,
    choices: None,
};
const REQUIRED_BASE_URL: ProviderSettingDescriptor = ProviderSettingDescriptor {
    required: true,
    ..BASE_URL
};
const WORKSPACE_ID: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::WorkspaceId,
    kind: ProviderSettingKind::Plain,
    required: false,
    choices: None,
};
const PROJECT_ID: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::ProjectId,
    kind: ProviderSettingKind::Plain,
    required: false,
    choices: None,
};
const ORGANIZATION_ID: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::OrganizationId,
    kind: ProviderSettingKind::Plain,
    required: false,
    choices: None,
};
const MOONSHOT_REGION: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::Region,
    kind: ProviderSettingKind::Select,
    required: false,
    choices: Some(&["international", "china"]),
};
const DEPLOYMENT: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::Deployment,
    kind: ProviderSettingKind::Plain,
    required: true,
    choices: None,
};
const ZAI_REGION: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::Region,
    kind: ProviderSettingKind::Select,
    required: false,
    choices: Some(&["global", "bigmodel-cn"]),
};
const MINIMAX_REGION: ProviderSettingDescriptor = ProviderSettingDescriptor {
    key: ProviderSettingKey::Region,
    kind: ProviderSettingKind::Select,
    required: false,
    choices: Some(&["global", "cn"]),
};

const NO_SETTINGS: &[ProviderSettingDescriptor] = &[];
const API_KEY_SETTINGS: &[ProviderSettingDescriptor] = &[API_KEY];
const API_KEY_BASE_URL_SETTINGS: &[ProviderSettingDescriptor] = &[API_KEY, BASE_URL];
const API_KEY_REQUIRED_BASE_URL_SETTINGS: &[ProviderSettingDescriptor] =
    &[API_KEY, REQUIRED_BASE_URL];
const AZURE_OPENAI_SETTINGS: &[ProviderSettingDescriptor] =
    &[API_KEY, REQUIRED_BASE_URL, DEPLOYMENT];
const ZAI_SETTINGS: &[ProviderSettingDescriptor] =
    &[API_KEY, ZAI_REGION, ORGANIZATION_ID, PROJECT_ID];
const MINIMAX_SETTINGS: &[ProviderSettingDescriptor] = &[API_KEY, MINIMAX_REGION];
const KILO_SETTINGS: &[ProviderSettingDescriptor] = &[API_KEY, ORGANIZATION_ID];
const WAYFINDER_SETTINGS: &[ProviderSettingDescriptor] = &[BASE_URL];
const CLAUDE_SETTINGS: &[ProviderSettingDescriptor] =
    &[OPTIONAL_API_KEY, COOKIE_HEADER, BROWSER, ORGANIZATION_ID];
const WEB_SETTINGS: &[ProviderSettingDescriptor] = &[COOKIE_HEADER, BROWSER];
const OPENCODE_SETTINGS: &[ProviderSettingDescriptor] = &[COOKIE_HEADER, BROWSER, WORKSPACE_ID];
const MOONSHOT_SETTINGS: &[ProviderSettingDescriptor] = &[API_KEY, MOONSHOT_REGION];
const DEEPGRAM_SETTINGS: &[ProviderSettingDescriptor] = &[API_KEY, PROJECT_ID];

const NO_AUTH_ACTIONS: &[ProviderAuthActionKind] = &[];
const CLAUDE_AUTH_ACTIONS: &[ProviderAuthActionKind] = &[
    ProviderAuthActionKind::BrowserLogin,
    ProviderAuthActionKind::CookieImport,
    ProviderAuthActionKind::CliImport,
];
const CODEX_AUTH_ACTIONS: &[ProviderAuthActionKind] = &[ProviderAuthActionKind::CliImport];
const CURSOR_AUTH_ACTIONS: &[ProviderAuthActionKind] = &[
    ProviderAuthActionKind::BrowserLogin,
    ProviderAuthActionKind::CookieImport,
];
const WEB_AUTH_ACTIONS: &[ProviderAuthActionKind] = &[
    ProviderAuthActionKind::BrowserLogin,
    ProviderAuthActionKind::CookieImport,
];
const DEVICE_AUTH_ACTIONS: &[ProviderAuthActionKind] = &[ProviderAuthActionKind::DeviceOAuth];

const fn capabilities(
    source_modes: &'static [ProviderSourceMode],
    settings: &'static [ProviderSettingDescriptor],
    auth_actions: &'static [ProviderAuthActionKind],
) -> ProviderCapabilityDescriptor {
    ProviderCapabilityDescriptor {
        maturity: ProviderMaturity::Experimental,
        source_modes,
        settings,
        auth_actions,
    }
}

/// Executable Windows capabilities; tests align source modes and auth actions with runtime handlers.
pub const fn provider_capabilities(id: ProviderId) -> ProviderCapabilityDescriptor {
    match id {
        ProviderId::Claude => capabilities(CLAUDE_SOURCES, CLAUDE_SETTINGS, CLAUDE_AUTH_ACTIONS),
        ProviderId::Codex => capabilities(CODEX_SOURCES, NO_SETTINGS, CODEX_AUTH_ACTIONS),
        ProviderId::Copilot => capabilities(AUTO_OAUTH, API_KEY_SETTINGS, DEVICE_AUTH_ACTIONS),
        ProviderId::Cursor => capabilities(CURSOR_SOURCES, WEB_SETTINGS, CURSOR_AUTH_ACTIONS),
        ProviderId::Opencode => capabilities(AUTO_WEB, OPENCODE_SETTINGS, WEB_AUTH_ACTIONS),
        ProviderId::Moonshot => capabilities(AUTO_API, MOONSHOT_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Deepgram => capabilities(AUTO_API, DEEPGRAM_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Chutes => capabilities(AUTO_API, API_KEY_BASE_URL_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Llmproxy | ProviderId::Litellm | ProviderId::Sub2api => capabilities(
            AUTO_API,
            API_KEY_REQUIRED_BASE_URL_SETTINGS,
            NO_AUTH_ACTIONS,
        ),
        ProviderId::Azureopenai => capabilities(AUTO_API, AZURE_OPENAI_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Zai => capabilities(AUTO_API, ZAI_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Minimax => capabilities(AUTO_API, MINIMAX_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Kilo => capabilities(AUTO_API, KILO_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Wayfinder => capabilities(AUTO_API, WAYFINDER_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Perplexity
        | ProviderId::Kimi
        | ProviderId::Manus
        | ProviderId::Abacus
        | ProviderId::Commandcode
        | ProviderId::Stepfun
        | ProviderId::T3chat
        | ProviderId::Qoder
        | ProviderId::Mimo
        | ProviderId::Augment => capabilities(AUTO_WEB, WEB_SETTINGS, NO_AUTH_ACTIONS),
        ProviderId::Opencodezen
        | ProviderId::Openrouter
        | ProviderId::Deepseek
        | ProviderId::Venice
        | ProviderId::Poe
        | ProviderId::Groq
        | ProviderId::Elevenlabs
        | ProviderId::Kimik2
        | ProviderId::Crossmodel
        | ProviderId::Clawrouter
        | ProviderId::Crof
        | ProviderId::Codebuff
        | ProviderId::Openai
        | ProviderId::Synthetic
        | ProviderId::Amp => capabilities(AUTO_API, API_KEY_SETTINGS, NO_AUTH_ACTIONS),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderErrorKind {
    MissingCredentials,
    Unauthorized,
    Http,
    Parse,
    Platform,
    Network,
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderStrategyDescriptor {
    pub id: &'static str,
    pub kind: ProviderStrategyKind,
    pub source_mode: ProviderSourceMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderFetchAttempt {
    pub strategy_id: String,
    pub kind: ProviderStrategyKind,
    pub was_available: bool,
    pub error_kind: Option<ProviderErrorKind>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDescriptor {
    pub id: ProviderId,
    pub display_name: &'static str,
    pub auth_kind: AuthKind,
    pub color: &'static str,
    pub dashboard_url: &'static str,
    pub credential_hint: &'static str,
    /// When true the settings UI lets the user attach several credentials (each rendered as its own
    /// usage card). API-key providers set this; cookie/OAuth providers stay single-account.
    pub supports_multiple_accounts: bool,
    pub capabilities: ProviderCapabilityDescriptor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageWindow {
    pub id: String,
    pub title: String,
    pub used_percent: f64,
    pub window_minutes: Option<u32>,
    pub resets_at: Option<DateTime<Utc>>,
    pub detail: Option<String>,
}

impl UsageWindow {
    pub fn new(id: impl Into<String>, title: impl Into<String>, used_percent: f64) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            used_percent: used_percent.clamp(0.0, 100.0),
            window_minutes: None,
            resets_at: None,
            detail: None,
        }
    }

    pub const fn with_window_minutes(mut self, minutes: u32) -> Self {
        self.window_minutes = Some(minutes);
        self
    }

    pub fn with_reset(mut self, resets_at: Option<DateTime<Utc>>) -> Self {
        self.resets_at = resets_at;
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryItem {
    pub label: String,
    pub value: String,
}

impl SummaryItem {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinancialSnapshot {
    pub balance: Option<f64>,
    pub spend: Option<f64>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSnapshot {
    pub provider: ProviderId,
    pub source: String,
    pub windows: Vec<UsageWindow>,
    pub summary: Vec<SummaryItem>,
    pub account_label: Option<String>,
    pub plan: Option<String>,
    pub fetched_at: DateTime<Utc>,
    #[serde(default)]
    pub financials: Option<FinancialSnapshot>,
}

impl ProviderSnapshot {
    pub fn new(provider: ProviderId, source: impl Into<String>) -> Self {
        Self {
            provider,
            source: source.into(),
            windows: Vec::new(),
            summary: Vec::new(),
            account_label: None,
            plan: None,
            fetched_at: Utc::now(),
            financials: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderStatus {
    Ready,
    Error,
    Disabled,
    Loading,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderState {
    pub descriptor: ProviderDescriptor,
    /// Identifies which account produced this state. Empty for single-account/implicit accounts.
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub account_label: Option<String>,
    pub status: ProviderStatus,
    pub snapshot: Option<ProviderSnapshot>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fetch_attempts: Vec<ProviderFetchAttempt>,
    /// Independent service-incident status for the provider, merged in after the usage fetch. Absent
    /// until the status poller has a result; providers without a status source stay `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_status: Option<ServiceStatus>,
}

impl ProviderState {
    pub fn loading(descriptor: ProviderDescriptor) -> Self {
        Self {
            descriptor,
            account_id: String::new(),
            account_label: None,
            status: ProviderStatus::Loading,
            snapshot: None,
            error: None,
            fetch_attempts: Vec::new(),
            service_status: None,
        }
    }

    pub fn disabled(descriptor: ProviderDescriptor) -> Self {
        Self {
            descriptor,
            account_id: String::new(),
            account_label: None,
            status: ProviderStatus::Disabled,
            snapshot: None,
            error: None,
            fetch_attempts: Vec::new(),
            service_status: None,
        }
    }

    pub fn ready(descriptor: ProviderDescriptor, snapshot: ProviderSnapshot) -> Self {
        Self {
            descriptor,
            account_id: String::new(),
            account_label: None,
            status: ProviderStatus::Ready,
            snapshot: Some(snapshot),
            error: None,
            fetch_attempts: Vec::new(),
            service_status: None,
        }
    }

    pub fn failed(descriptor: ProviderDescriptor, error: impl Into<String>) -> Self {
        Self {
            descriptor,
            account_id: String::new(),
            account_label: None,
            status: ProviderStatus::Error,
            snapshot: None,
            error: Some(error.into()),
            fetch_attempts: Vec::new(),
            service_status: None,
        }
    }

    /// Tag a state with the account it belongs to (chained after the status constructors).
    pub fn with_account(mut self, id: impl Into<String>, label: Option<String>) -> Self {
        self.account_id = id.into();
        self.account_label = label;
        self
    }

    pub fn with_fetch_attempts(mut self, attempts: Vec<ProviderFetchAttempt>) -> Self {
        self.fetch_attempts = attempts;
        self
    }

    /// Attach the provider's independent service-incident status (chained after construction).
    pub fn with_service_status(mut self, service_status: Option<ServiceStatus>) -> Self {
        self.service_status = service_status;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_capability_exposes_organization_selection() {
        let capabilities = provider_capabilities(ProviderId::Claude);
        assert!(
            capabilities
                .settings
                .iter()
                .any(|setting| setting.key == ProviderSettingKey::OrganizationId)
        );
    }

    #[test]
    fn experimental_claude_is_disabled_in_a_fresh_windows_config() {
        assert!(!ProviderId::Claude.default_enabled());
    }

    #[test]
    fn snapshot_without_financials_remains_compatible() {
        let snapshot: ProviderSnapshot = serde_json::from_value(serde_json::json!({
            "provider": "openrouter",
            "source": "fixture",
            "windows": [],
            "summary": [],
            "accountLabel": null,
            "plan": null,
            "fetchedAt": "2026-07-15T10:00:00Z"
        }))
        .expect("snapshot");

        assert_eq!(snapshot.financials, None);
    }

    #[test]
    fn copilot_is_a_stable_provider_id() {
        assert_eq!(ProviderId::Copilot.as_str(), "copilot");
        assert!(ProviderId::ALL.contains(&ProviderId::Copilot));
        assert_eq!(
            serde_json::to_string(&ProviderId::Copilot).unwrap(),
            "\"copilot\""
        );
    }

    #[test]
    fn provider_state_omits_empty_fetch_attempts_from_json() {
        let descriptor = ProviderDescriptor {
            id: ProviderId::Openrouter,
            display_name: "OpenRouter",
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.test",
            credential_hint: "",
            supports_multiple_accounts: false,
            capabilities: provider_capabilities(ProviderId::Openrouter),
        };

        let json = serde_json::to_value(ProviderState::loading(descriptor)).expect("state");

        assert!(json.get("fetchAttempts").is_none());
    }
}
