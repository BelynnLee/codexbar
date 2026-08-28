use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, ProviderSourceMode,
        ProviderStrategyDescriptor, ProviderStrategyKind, SummaryItem, UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use rusqlite::{Connection, OpenFlags, OptionalExtension, types::ValueRef};
use serde::Deserialize;
use std::{
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct CursorProvider {
    base_url: String,
    state_db_path: Option<PathBuf>,
    browser_import_enabled: bool,
}

impl Default for CursorProvider {
    fn default() -> Self {
        Self {
            base_url: "https://cursor.com".into(),
            state_db_path: None,
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Cursor,
    display_name: "Cursor",
    auth_kind: AuthKind::BrowserCookie,
    color: "#00bfa5",
    dashboard_url: "https://cursor.com/dashboard?tab=usage",
    credential_hint: "Imports cursor.com cookies from Chrome/Edge with DPAPI, or accepts a manual Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Cursor),
};

const COOKIE_NAMES: &[&str] = &[
    "WorkosCursorSessionToken",
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
    "wos-session",
    "__Secure-wos-session",
    "authjs.session-token",
    "__Secure-authjs.session-token",
];

const WEB_STRATEGY: ProviderStrategyDescriptor = ProviderStrategyDescriptor {
    id: "cursor.web",
    kind: ProviderStrategyKind::Web,
    source_mode: ProviderSourceMode::Web,
};
const LOCAL_STRATEGY: ProviderStrategyDescriptor = ProviderStrategyDescriptor {
    id: "cursor.local",
    kind: ProviderStrategyKind::LocalProbe,
    source_mode: ProviderSourceMode::Cli,
};

#[async_trait]
impl Provider for CursorProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        self.fetch_web(context, account).await
    }

    fn strategies(&self, source_mode: ProviderSourceMode) -> Vec<ProviderStrategyDescriptor> {
        match source_mode {
            ProviderSourceMode::Auto => vec![WEB_STRATEGY, LOCAL_STRATEGY],
            ProviderSourceMode::Web => vec![WEB_STRATEGY],
            ProviderSourceMode::Cli => vec![LOCAL_STRATEGY],
            ProviderSourceMode::Api | ProviderSourceMode::Oauth => Vec::new(),
        }
    }

    fn is_strategy_available(
        &self,
        strategy: &ProviderStrategyDescriptor,
        _context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> bool {
        match strategy.id {
            "cursor.web" => {
                ProviderConfig::normalized_secret(&account.cookie_header).is_some()
                    || self.browser_import_enabled
            }
            "cursor.local" => self.local_state_db_path().is_some(),
            _ => false,
        }
    }

    async fn fetch_strategy(
        &self,
        strategy: &ProviderStrategyDescriptor,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        match strategy.id {
            "cursor.web" => self.fetch_web(context, account).await,
            "cursor.local" => self.fetch_local(context).await,
            _ => Err(ProviderError::Platform(format!(
                "Unsupported Cursor strategy: {}",
                strategy.id
            ))),
        }
    }

    fn should_fallback(
        &self,
        strategy: &ProviderStrategyDescriptor,
        error: &ProviderError,
    ) -> bool {
        strategy.id == "cursor.web"
            && matches!(
                error,
                ProviderError::MissingCredentials(_) | ProviderError::Platform(_)
            )
    }
}

impl CursorProvider {
    async fn fetch_web(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let cookie = resolve_cookie(account)?;
        self.fetch_with_cookie(context, &cookie, "web").await
    }

    async fn fetch_local(
        &self,
        context: &FetchContext<'_>,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let path = self.local_state_db_path().ok_or_else(|| {
            ProviderError::MissingCredentials(
                "APPDATA is unavailable; Cursor local credentials cannot be located.".into(),
            )
        })?;
        let session =
            load_cursor_local_session(&path, Utc::now().timestamp())?.ok_or_else(|| {
                ProviderError::MissingCredentials(
                    "Cursor local access token was not found in state.vscdb.".into(),
                )
            })?;
        self.fetch_with_cookie(context, &session.cookie_header(), "local")
            .await
    }

    async fn fetch_with_cookie(
        &self,
        context: &FetchContext<'_>,
        cookie: &str,
        source: &str,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let usage_response = context
            .client
            .get(self.endpoint("/api/usage-summary"))
            .header("Accept", "application/json")
            .header("Cookie", cookie)
            .send()
            .await?;
        if matches!(
            usage_response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(ProviderError::Unauthorized(
                "Cursor session cookie expired. Sign in to cursor.com or replace the manual Cookie header.".into(),
            ));
        }
        if !usage_response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Cursor",
                status: usage_response.status().as_u16(),
            });
        }
        let usage: CursorUsageSummary =
            usage_response
                .json()
                .await
                .map_err(|error| ProviderError::Parse {
                    provider: "Cursor",
                    message: error.to_string(),
                })?;

        // Identity is optional and deliberately awaited after the required usage call so a failure cannot cancel it.
        let user = match context
            .client
            .get(self.endpoint("/api/auth/me"))
            .header("Accept", "application/json")
            .header("Cookie", cookie)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                response.json::<CursorUser>().await.ok()
            }
            _ => None,
        };
        let request_usage =
            if let Some(user_id) = user.as_ref().and_then(|user| user.sub.as_deref()) {
                match context
                    .client
                    .get(self.endpoint("/api/usage"))
                    .query(&[("user", user_id)])
                    .header("Accept", "application/json")
                    .header("Cookie", cookie)
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => {
                        response.json::<LegacyUsage>().await.ok()
                    }
                    _ => None,
                }
            } else {
                None
            };
        map_usage(usage, user, request_usage, source.into())
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base_url.trim_end_matches('/'))
    }

    fn local_state_db_path(&self) -> Option<PathBuf> {
        self.state_db_path
            .clone()
            .or_else(|| cursor_state_db_path_from_appdata(env::var_os("APPDATA").as_deref()))
    }
}

fn resolve_cookie(account: &ProviderAccount) -> Result<String, ProviderError> {
    if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
        let header = if value.contains('=') {
            value.to_owned()
        } else {
            format!("WorkosCursorSessionToken={value}")
        };
        return Ok(header);
    }
    let imported = chromium::find_cookie_header(
        account.browser,
        &[
            "cursor.com",
            "www.cursor.com",
            "cursor.sh",
            "authenticator.cursor.sh",
        ],
        COOKIE_NAMES,
    )?;
    Ok(imported.value)
}

fn cursor_state_db_path_from_appdata(appdata: Option<&OsStr>) -> Option<PathBuf> {
    let appdata = appdata.filter(|value| !value.is_empty())?;
    Some(
        PathBuf::from(appdata)
            .join("Cursor")
            .join("User")
            .join("globalStorage")
            .join("state.vscdb"),
    )
}

#[derive(Debug, PartialEq, Eq)]
struct CursorLocalSession {
    access_token: String,
    user_id: String,
}

impl CursorLocalSession {
    fn cookie_header(&self) -> String {
        format!(
            "WorkosCursorSessionToken={}%3A%3A{}",
            self.user_id, self.access_token
        )
    }
}

#[derive(Deserialize)]
struct CursorJwtPayload {
    sub: Option<String>,
    exp: Option<f64>,
}

fn load_cursor_local_session(
    path: &Path,
    now_timestamp: i64,
) -> Result<Option<CursorLocalSession>, ProviderError> {
    if !path.is_file() {
        return Ok(None);
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| ProviderError::Credential(format!("Cannot read Cursor state DB: {error}")))?;
    connection
        .busy_timeout(Duration::from_millis(250))
        .map_err(|error| {
            ProviderError::Credential(format!("Cannot configure Cursor state DB: {error}"))
        })?;
    let token = connection
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?1 LIMIT 1",
            ["cursorAuth/accessToken"],
            |row| match row.get_ref(0)? {
                ValueRef::Text(value) | ValueRef::Blob(value) => Ok(value.to_vec()),
                _ => Err(rusqlite::Error::InvalidColumnType(
                    0,
                    "value".into(),
                    row.get_ref(0)?.data_type(),
                )),
            },
        )
        .optional()
        .map_err(|error| {
            ProviderError::Credential(format!("Cannot query Cursor state DB: {error}"))
        })?;
    let Some(token) = token else {
        return Ok(None);
    };
    let token = String::from_utf8(token).map_err(|_| ProviderError::Parse {
        provider: "Cursor",
        message: "Cursor local access token is not UTF-8".into(),
    })?;
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    parse_cursor_local_session(token, now_timestamp).map(Some)
}

fn parse_cursor_local_session(
    access_token: &str,
    now_timestamp: i64,
) -> Result<CursorLocalSession, ProviderError> {
    let payload = access_token
        .split('.')
        .nth(1)
        .ok_or_else(|| cursor_token_parse_error("Cursor local access token is not a JWT"))?;
    let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| {
        cursor_token_parse_error("Cursor local access token has an invalid payload")
    })?;
    let payload: CursorJwtPayload = serde_json::from_slice(&payload).map_err(|_| {
        cursor_token_parse_error("Cursor local access token has an invalid payload")
    })?;
    let subject = payload.sub.ok_or_else(|| {
        cursor_token_parse_error("Cursor local access token is missing a subject")
    })?;
    let user_id = subject
        .split('|')
        .rfind(|component| !component.is_empty())
        .filter(|component| {
            component.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
        })
        .ok_or_else(|| {
            cursor_token_parse_error("Cursor local access token has an unsafe user ID")
        })?;
    let expires_at = payload
        .exp
        .filter(|value| value.is_finite())
        .ok_or_else(|| {
            cursor_token_parse_error("Cursor local access token is missing an expiration")
        })?;
    if expires_at <= now_timestamp as f64 + 60.0 {
        return Err(cursor_token_parse_error(
            "Cursor local access token is expired or expires too soon",
        ));
    }
    Ok(CursorLocalSession {
        access_token: access_token.into(),
        user_id: user_id.into(),
    })
}

fn cursor_token_parse_error(message: &str) -> ProviderError {
    ProviderError::Parse {
        provider: "Cursor",
        message: message.into(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorUsageSummary {
    billing_cycle_start: Option<String>,
    billing_cycle_end: Option<String>,
    membership_type: Option<String>,
    individual_usage: Option<IndividualUsage>,
    team_usage: Option<TeamUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndividualUsage {
    plan: Option<PlanUsage>,
    on_demand: Option<MoneyUsage>,
    overall: Option<MoneyUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanUsage {
    used: Option<i64>,
    limit: Option<i64>,
    total_percent_used: Option<f64>,
    auto_percent_used: Option<f64>,
    api_percent_used: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct MoneyUsage {
    used: Option<i64>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamUsage {
    on_demand: Option<MoneyUsage>,
    pooled: Option<MoneyUsage>,
}

#[derive(Debug, Deserialize)]
struct CursorUser {
    email: Option<String>,
    name: Option<String>,
    sub: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyUsage {
    #[serde(rename = "gpt-4")]
    gpt4: Option<LegacyModelUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyModelUsage {
    num_requests: Option<u64>,
    num_requests_total: Option<u64>,
    max_request_usage: Option<u64>,
}

fn map_usage(
    usage: CursorUsageSummary,
    user: Option<CursorUser>,
    request_usage: Option<LegacyUsage>,
    source: String,
) -> Result<ProviderSnapshot, ProviderError> {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Cursor, source);
    snapshot.plan = usage.membership_type;
    snapshot.account_label = user
        .as_ref()
        .and_then(|user| user.email.clone().or_else(|| user.name.clone()));
    let plan = usage
        .individual_usage
        .as_ref()
        .and_then(|usage| usage.plan.as_ref());
    let plan_used = plan.and_then(|plan| plan.used).unwrap_or_default() as f64;
    let plan_limit = plan.and_then(|plan| plan.limit).unwrap_or_default() as f64;
    let overall = usage
        .individual_usage
        .as_ref()
        .and_then(|usage| usage.overall.as_ref());
    let pooled = usage
        .team_usage
        .as_ref()
        .and_then(|usage| usage.pooled.as_ref());
    let percent = plan
        .and_then(|plan| plan.total_percent_used)
        .or_else(|| {
            let auto = plan.and_then(|plan| plan.auto_percent_used);
            let api = plan.and_then(|plan| plan.api_percent_used);
            match (auto, api) {
                (Some(auto), Some(api)) => Some(f64::midpoint(auto, api)),
                (Some(value), None) | (None, Some(value)) => Some(value),
                (None, None) => None,
            }
        })
        .or_else(|| ratio(plan_used, plan_limit))
        .or_else(|| money_ratio(overall))
        .or_else(|| money_ratio(pooled))
        .unwrap_or(0.0);
    let start = usage.billing_cycle_start.as_deref().and_then(parse_date);
    let end = usage.billing_cycle_end.as_deref().and_then(parse_date);
    let minutes = start
        .as_ref()
        .zip(end.as_ref())
        .and_then(|(start, end)| u32::try_from((*end - *start).num_minutes().max(0)).ok());
    let mut total = UsageWindow::new("total", "Total", percent).with_reset(end);
    if let Some(minutes) = minutes {
        total = total.with_window_minutes(minutes);
    }
    snapshot.windows.push(total);
    if let Some(percent) = plan.and_then(|plan| plan.auto_percent_used) {
        snapshot
            .windows
            .push(UsageWindow::new("auto", "Auto", percent).with_reset(end));
    }
    if let Some(percent) = plan.and_then(|plan| plan.api_percent_used) {
        snapshot
            .windows
            .push(UsageWindow::new("api", "API", percent).with_reset(end));
    }

    let (used, limit) = if plan_used > 0.0 || plan_limit > 0.0 {
        (plan_used, plan_limit)
    } else if let Some(overall) = overall {
        (
            overall.used.unwrap_or_default() as f64,
            overall.limit.unwrap_or_default() as f64,
        )
    } else if let Some(pooled) = pooled {
        (
            pooled.used.unwrap_or_default() as f64,
            pooled.limit.unwrap_or_default() as f64,
        )
    } else {
        (0.0, 0.0)
    };
    if used > 0.0 || limit > 0.0 {
        snapshot.summary.push(SummaryItem::new(
            "Included usage",
            format!("${:.2} / ${:.2}", used / 100.0, limit / 100.0),
        ));
    }
    if let Some(on_demand) = usage
        .individual_usage
        .as_ref()
        .and_then(|usage| usage.on_demand.as_ref())
    {
        add_money_summary(&mut snapshot, "On-demand", on_demand);
    }
    if let Some(on_demand) = usage
        .team_usage
        .as_ref()
        .and_then(|usage| usage.on_demand.as_ref())
    {
        add_money_summary(&mut snapshot, "Team on-demand", on_demand);
    }
    if let Some(requests) = request_usage.and_then(|usage| usage.gpt4) {
        let used = requests
            .num_requests_total
            .or(requests.num_requests)
            .unwrap_or_default();
        if let Some(limit) = requests.max_request_usage.filter(|limit| *limit > 0) {
            snapshot.windows.push(
                UsageWindow::new("requests", "Requests", (used as f64 / limit as f64) * 100.0)
                    .with_detail(format!("{used} / {limit}")),
            );
        }
    }
    Ok(snapshot)
}

fn add_money_summary(snapshot: &mut ProviderSnapshot, label: &str, usage: &MoneyUsage) {
    if let Some(used) = usage.used {
        let value = usage.limit.map_or_else(
            || format!("${:.2}", used as f64 / 100.0),
            |limit| format!("${:.2} / ${:.2}", used as f64 / 100.0, limit as f64 / 100.0),
        );
        snapshot.summary.push(SummaryItem::new(label, value));
    }
}

fn ratio(used: f64, limit: f64) -> Option<f64> {
    (limit > 0.0).then_some((used / limit) * 100.0)
}

fn money_ratio(usage: Option<&MoneyUsage>) -> Option<f64> {
    let usage = usage?;
    ratio(usage.used? as f64, usage.limit? as f64)
}

fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AppConfig,
        model::{ProviderErrorKind, ProviderSourceMode, ProviderStrategyKind},
        provider::run_provider_fetch_pipeline,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rusqlite::{Connection, params};
    use std::{
        ffi::OsStr,
        io::{Read, Write},
        net::TcpListener,
        path::{Path, PathBuf},
        sync::mpsc,
        thread,
        time::Duration,
    };
    use tempfile::TempDir;

    struct MockServer {
        base_url: String,
        requests: mpsc::Receiver<String>,
    }

    fn serve(responses: Vec<(u16, &'static str)>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("mock address");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().expect("accept mock request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 2048];
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
                let reason = if status == 200 { "OK" } else { "Error" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write mock response");
            }
        });
        MockServer {
            base_url: format!("http://{address}"),
            requests: receiver,
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn request_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            candidate.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }

    fn jwt(subject: &str, expires_at: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "sub": subject,
                "exp": expires_at,
            }))
            .expect("JWT payload"),
        );
        format!("{header}.{payload}.fixture")
    }

    fn cursor_db(value: Option<(&str, bool)>) -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temp Cursor directory");
        let path = directory.path().join("state.vscdb");
        let connection = Connection::open(&path).expect("create Cursor DB");
        connection
            .execute(
                "CREATE TABLE ItemTable(key TEXT PRIMARY KEY, value BLOB)",
                [],
            )
            .expect("create ItemTable");
        if let Some((token, blob)) = value {
            if blob {
                connection
                    .execute(
                        "INSERT INTO ItemTable(key, value) VALUES(?1, ?2)",
                        params!["cursorAuth/accessToken", token.as_bytes()],
                    )
                    .expect("insert blob token");
            } else {
                connection
                    .execute(
                        "INSERT INTO ItemTable(key, value) VALUES(?1, ?2)",
                        params!["cursorAuth/accessToken", token],
                    )
                    .expect("insert text token");
            }
        }
        drop(connection);
        (directory, path)
    }

    fn test_provider(base_url: String, state_db_path: &Path) -> CursorProvider {
        CursorProvider {
            base_url,
            state_db_path: Some(state_db_path.to_owned()),
            browser_import_enabled: false,
        }
    }

    fn context<'a>(client: &'a reqwest::Client, config: &'a AppConfig) -> FetchContext<'a> {
        FetchContext {
            client,
            config,
            config_dir: None,
        }
    }

    #[test]
    fn cursor_exposes_web_then_local_strategies_with_explicit_filtering() {
        let provider = CursorProvider::default();

        let auto = provider.strategies(ProviderSourceMode::Auto);
        assert_eq!(
            auto.iter().map(|strategy| strategy.id).collect::<Vec<_>>(),
            vec!["cursor.web", "cursor.local"]
        );
        assert_eq!(auto[0].kind, ProviderStrategyKind::Web);
        assert_eq!(auto[0].source_mode, ProviderSourceMode::Web);
        assert_eq!(auto[1].kind, ProviderStrategyKind::LocalProbe);
        assert_eq!(auto[1].source_mode, ProviderSourceMode::Cli);

        assert_eq!(
            provider
                .strategies(ProviderSourceMode::Web)
                .iter()
                .map(|strategy| strategy.id)
                .collect::<Vec<_>>(),
            vec!["cursor.web"]
        );
        assert_eq!(
            provider
                .strategies(ProviderSourceMode::Cli)
                .iter()
                .map(|strategy| strategy.id)
                .collect::<Vec<_>>(),
            vec!["cursor.local"]
        );
        assert!(provider.strategies(ProviderSourceMode::Api).is_empty());
        assert!(provider.strategies(ProviderSourceMode::Oauth).is_empty());
    }

    #[test]
    fn cursor_state_db_path_uses_the_supplied_appdata_directory() {
        let appdata = OsStr::new(r"C:\Users\Fixture\AppData\Roaming");
        assert_eq!(
            cursor_state_db_path_from_appdata(Some(appdata)),
            Some(
                PathBuf::from(appdata)
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("state.vscdb")
            )
        );
        assert_eq!(cursor_state_db_path_from_appdata(None), None);
    }

    #[test]
    fn local_auth_reads_text_and_blob_tokens_from_temporary_sqlite() {
        let token = jwt("auth0|user_test", 4_000_000_000);
        for blob in [false, true] {
            let (_directory, path) = cursor_db(Some((&token, blob)));
            let session = load_cursor_local_session(&path, 2_000_000_000)
                .expect("read local session")
                .expect("session");
            assert_eq!(session.access_token, token);
            assert_eq!(session.user_id, "user_test");
            assert_eq!(
                session.cookie_header(),
                format!("WorkosCursorSessionToken=user_test%3A%3A{token}")
            );
        }
    }

    #[test]
    fn local_auth_distinguishes_missing_and_invalid_credentials() {
        let (_directory, missing_row) = cursor_db(None);
        assert!(
            load_cursor_local_session(&missing_row, 2_000_000_000)
                .expect("missing row is not a DB error")
                .is_none()
        );
        let missing_file = missing_row.with_file_name("missing.vscdb");
        assert!(
            load_cursor_local_session(&missing_file, 2_000_000_000)
                .expect("missing file is unavailable")
                .is_none()
        );

        for token in [
            "not-a-jwt".to_owned(),
            jwt("auth0|unsafe:user", 4_000_000_000),
            jwt("auth0|user_test", 2_000_000_060),
        ] {
            let (_directory, path) = cursor_db(Some((&token, false)));
            assert!(matches!(
                load_cursor_local_session(&path, 2_000_000_000),
                Err(ProviderError::Parse {
                    provider: "Cursor",
                    ..
                })
            ));
        }
    }

    #[test]
    fn auto_skips_unavailable_web_and_uses_local_session_with_distinct_attempts() {
        runtime().block_on(async {
            let token = jwt("auth0|user_test", 4_000_000_000);
            let (_directory, path) = cursor_db(Some((&token, false)));
            let server = serve(vec![
                (
                    200,
                    r#"{"membershipType":"pro","individualUsage":{"plan":{"used":388,"limit":2000,"totalPercentUsed":19.4}}}"#,
                ),
                (200, r#"{"email":"local@example.com","name":"Local"}"#),
            ]);
            let provider = test_provider(server.base_url, &path);
            let client = reqwest::Client::new();
            let config = AppConfig::default();
            let outcome = run_provider_fetch_pipeline(
                &provider,
                &context(&client, &config),
                &ProviderAccount::default(),
                ProviderSourceMode::Auto,
            )
            .await;

            let snapshot = outcome.result.expect("local fallback usage");
            assert_eq!(snapshot.source, "local");
            assert_eq!(snapshot.account_label.as_deref(), Some("local@example.com"));
            assert_eq!(
                outcome
                    .attempts
                    .iter()
                    .map(|attempt| (&*attempt.strategy_id, attempt.was_available))
                    .collect::<Vec<_>>(),
                vec![("cursor.web", false), ("cursor.local", true)]
            );
            let usage_request = server
                .requests
                .recv_timeout(Duration::from_secs(5))
                .expect("usage request");
            assert!(usage_request.starts_with("GET /api/usage-summary HTTP/1.1\r\n"));
            assert_eq!(
                request_header(&usage_request, "Cookie"),
                Some(format!("WorkosCursorSessionToken=user_test%3A%3A{token}").as_str())
            );
        });
    }

    #[test]
    fn web_auth_and_response_errors_never_fall_back_to_local() {
        runtime().block_on(async {
            let token = jwt("auth0|user_test", 4_000_000_000);
            let (_directory, path) = cursor_db(Some((&token, false)));
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
                (200, "not-json", ProviderErrorKind::Parse),
                (500, r#"{"error":"server"}"#, ProviderErrorKind::Http),
            ] {
                let server = serve(vec![(status, body)]);
                let provider = test_provider(server.base_url, &path);
                let client = reqwest::Client::new();
                let config = AppConfig::default();
                let account = ProviderAccount {
                    cookie_header: Some("WorkosCursorSessionToken=web-session".into()),
                    ..Default::default()
                };
                let outcome = run_provider_fetch_pipeline(
                    &provider,
                    &context(&client, &config),
                    &account,
                    ProviderSourceMode::Auto,
                )
                .await;

                assert!(outcome.result.is_err());
                assert_eq!(outcome.attempts.len(), 1);
                assert_eq!(outcome.attempts[0].strategy_id, "cursor.web");
                assert_eq!(outcome.attempts[0].error_kind, Some(expected));
                let request = server
                    .requests
                    .recv_timeout(Duration::from_secs(5))
                    .expect("single Web request");
                assert_eq!(
                    request_header(&request, "Cookie"),
                    Some("WorkosCursorSessionToken=web-session")
                );
            }
        });
    }

    #[test]
    fn cursor_fallback_policy_allows_only_missing_web_credentials() {
        let provider = CursorProvider::default();
        let strategy = provider.strategies(ProviderSourceMode::Web)[0];
        assert!(provider.should_fallback(
            &strategy,
            &ProviderError::MissingCredentials("missing web cookie".into())
        ));
        assert!(provider.should_fallback(
            &strategy,
            &ProviderError::Platform("browser roots are unavailable".into())
        ));
        for error in [
            ProviderError::Unauthorized("expired".into()),
            ProviderError::Parse {
                provider: "Cursor",
                message: "bad body".into(),
            },
            ProviderError::Http {
                provider: "Cursor",
                status: 500,
            },
            ProviderError::Credential("bad local token".into()),
        ] {
            assert!(!provider.should_fallback(&strategy, &error));
        }
    }

    #[test]
    fn cursor_percent_fields_are_already_percentage_units() {
        let usage: CursorUsageSummary = serde_json::from_value(serde_json::json!({
            "billingCycleStart": "2026-03-18T20:45:42.000Z",
            "billingCycleEnd": "2026-04-18T20:45:42.000Z",
            "membershipType": "pro",
            "individualUsage": {
                "plan": {
                    "used": 86,
                    "limit": 19500,
                    "autoPercentUsed": 0.36,
                    "apiPercentUsed": 0.7111111111111111
                }
            }
        }))
        .expect("Cursor payload");
        let snapshot = map_usage(usage, None, None, "test".into()).expect("usage");
        assert!((snapshot.windows[0].used_percent - 0.535_555_555_555_555_6).abs() < 1e-10);
        assert_eq!(snapshot.windows[1].used_percent, 0.36);
        assert_eq!(snapshot.windows[0].window_minutes, Some(44_640));
    }
}
