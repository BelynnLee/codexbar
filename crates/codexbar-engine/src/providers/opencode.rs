use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::sync::LazyLock;
use url::Url;

static WORKSPACE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"wrk_[A-Za-z0-9]+").expect("workspace regex"));
static WORKSPACE_RESPONSE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"id\s*:\s*\"(wrk_[^\"]+)\""#).expect("workspace response regex"));

pub struct OpenCodeProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Opencode,
    display_name: "OpenCode",
    auth_kind: AuthKind::BrowserCookie,
    color: "#f2b84b",
    dashboard_url: "https://opencode.ai",
    credential_hint: "Imports opencode.ai auth cookies from Chrome/Edge, or accepts a manual Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Opencode),
};

const WORKSPACES_SERVER_ID: &str =
    "def39973159c7f0483d8793a822b8dbb10d067e12c65455fcb4608459ba0234f";
const SUBSCRIPTION_SERVER_ID: &str =
    "7abeebee372f304e050aaaf92be863f4a86490e382f8c79db68fd94040d691b4";
const COOKIE_NAMES: &[&str] = &["auth", "__Host-auth"];

#[async_trait]
impl Provider for OpenCodeProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let (cookie, source) = resolve_cookie(account)?;
        let workspace = match ProviderConfig::normalized_secret(&account.workspace_id)
            .and_then(normalize_workspace_id)
        {
            Some(workspace) => workspace,
            None => fetch_workspace_id(context, &cookie).await?,
        };
        let referer = format!("https://opencode.ai/workspace/{workspace}/billing");
        let args = vec![Value::String(workspace)];
        let text = server_request(
            context,
            SUBSCRIPTION_SERVER_ID,
            Some(args.clone()),
            Method::GET,
            &cookie,
            &referer,
        )
        .await?;
        let now = Utc::now();
        let parsed = if let Ok(parsed) = parse_subscription(&text, now) {
            parsed
        } else {
            let fallback = server_request(
                context,
                SUBSCRIPTION_SERVER_ID,
                Some(args),
                Method::POST,
                &cookie,
                &referer,
            )
            .await?;
            parse_subscription(&fallback, now)?
        };
        let mut snapshot = ProviderSnapshot::new(ProviderId::Opencode, source);
        snapshot.windows.push(
            UsageWindow::new("rolling", "Rolling", parsed.rolling_percent)
                .with_reset(Some(parsed.rolling_reset))
                .with_detail(format!("Resets in {} min", parsed.rolling_seconds / 60)),
        );
        snapshot.windows.push(
            UsageWindow::new("weekly", "Weekly", parsed.weekly_percent)
                .with_window_minutes(7 * 24 * 60)
                .with_reset(Some(parsed.weekly_reset))
                .with_detail(format!("Resets in {} h", parsed.weekly_seconds / 3600)),
        );
        if let Some(renews_at) = parsed.renews_at {
            snapshot
                .summary
                .push(SummaryItem::new("Renews", renews_at.to_rfc3339()));
        }
        Ok(snapshot)
    }
}

async fn fetch_workspace_id(
    context: &FetchContext<'_>,
    cookie: &str,
) -> Result<String, ProviderError> {
    let text = server_request(
        context,
        WORKSPACES_SERVER_ID,
        None,
        Method::GET,
        cookie,
        "https://opencode.ai",
    )
    .await?;
    if let Some(workspace) = parse_workspace_ids(&text).into_iter().next() {
        return Ok(workspace);
    }
    let fallback = server_request(
        context,
        WORKSPACES_SERVER_ID,
        Some(Vec::new()),
        Method::POST,
        cookie,
        "https://opencode.ai",
    )
    .await?;
    parse_workspace_ids(&fallback)
        .into_iter()
        .next()
        .ok_or_else(|| ProviderError::Parse {
            provider: "OpenCode",
            message: "workspace id was not present in GET or POST response".into(),
        })
}

fn resolve_cookie(account: &ProviderAccount) -> Result<(String, String), ProviderError> {
    if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
        let header = normalize_auth_cookie_header(value).ok_or_else(|| {
            ProviderError::MissingCredentials(
                "OpenCode manual Cookie header must contain auth or __Host-auth.".into(),
            )
        })?;
        return Ok((header, "manual cookie".into()));
    }
    let imported = chromium::find_cookie_header(
        account.browser,
        &["opencode.ai", "app.opencode.ai"],
        COOKIE_NAMES,
    )?;
    Ok((imported.value, imported.source))
}

async fn server_request(
    context: &FetchContext<'_>,
    server_id: &str,
    args: Option<Vec<Value>>,
    method: Method,
    cookie: &str,
    referer: &str,
) -> Result<String, ProviderError> {
    let mut url = Url::parse("https://opencode.ai/_server").expect("static OpenCode URL");
    if method == Method::GET {
        let mut query = url.query_pairs_mut();
        query.append_pair("id", server_id);
        if let Some(args) = &args {
            let encoded = serde_json::to_string(args).map_err(|error| ProviderError::Parse {
                provider: "OpenCode",
                message: error.to_string(),
            })?;
            query.append_pair("args", &encoded);
        }
    }
    let mut request = context
        .client
        .request(method.clone(), url)
        .header("Cookie", cookie)
        .header("X-Server-Id", server_id)
        .header(
            "X-Server-Instance",
            format!("server-fn:{}", Utc::now().timestamp_micros()),
        )
        .header("Origin", "https://opencode.ai")
        .header("Referer", referer)
        .header(
            "Accept",
            "text/javascript, application/json;q=0.9, */*;q=0.8",
        );
    if method != Method::GET {
        request = request.json(&args.unwrap_or_default());
    }
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) || looks_signed_out(&text)
    {
        return Err(ProviderError::Unauthorized(
            "OpenCode session cookie expired. Sign in to opencode.ai or replace the manual Cookie header.".into(),
        ));
    }
    if !status.is_success() {
        return Err(ProviderError::Http {
            provider: "OpenCode",
            status: status.as_u16(),
        });
    }
    Ok(text)
}

fn normalize_auth_cookie_header(header: &str) -> Option<String> {
    let selected = header
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            COOKIE_NAMES
                .contains(&name.trim())
                .then(|| format!("{}={}", name.trim(), value.trim()))
        })
        .collect::<Vec<_>>();
    (!selected.is_empty()).then(|| selected.join("; "))
}

fn normalize_workspace_id(value: &str) -> Option<String> {
    WORKSPACE_ID_RE
        .find(value)
        .map(|match_| match_.as_str().to_owned())
}

fn parse_workspace_ids(text: &str) -> Vec<String> {
    let mut results = WORKSPACE_RESPONSE_RE
        .captures_iter(text)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_owned()))
        .collect::<Vec<_>>();
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        collect_workspace_ids(&value, &mut results);
    }
    results.dedup();
    results
}

fn collect_workspace_ids(value: &Value, results: &mut Vec<String>) {
    match value {
        Value::String(value) if value.starts_with("wrk_") => results.push(value.clone()),
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_workspace_ids(value, results)),
        Value::Object(values) => values
            .values()
            .for_each(|value| collect_workspace_ids(value, results)),
        _ => {}
    }
}

#[derive(Debug, PartialEq)]
struct SubscriptionUsage {
    rolling_percent: f64,
    weekly_percent: f64,
    rolling_seconds: u64,
    weekly_seconds: u64,
    rolling_reset: DateTime<Utc>,
    weekly_reset: DateTime<Utc>,
    renews_at: Option<DateTime<Utc>>,
}

fn parse_subscription(text: &str, now: DateTime<Utc>) -> Result<SubscriptionUsage, ProviderError> {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if let Some(parsed) = parse_subscription_json(&value, now, None, 0) {
            return Ok(parsed);
        }
    }
    let rolling = parse_script_window(text, "rollingUsage", now);
    let weekly = parse_script_window(text, "weeklyUsage", now);
    if let (
        Some((rolling_percent, rolling_seconds, rolling_reset)),
        Some((weekly_percent, weekly_seconds, weekly_reset)),
    ) = (rolling, weekly)
    {
        return Ok(SubscriptionUsage {
            rolling_percent,
            weekly_percent,
            rolling_seconds,
            weekly_seconds,
            rolling_reset,
            weekly_reset,
            renews_at: None,
        });
    }
    Err(ProviderError::Parse {
        provider: "OpenCode",
        message: "rolling and weekly usage fields were not present".into(),
    })
}

fn parse_subscription_json(
    value: &Value,
    now: DateTime<Utc>,
    inherited_renewal: Option<DateTime<Utc>>,
    depth: usize,
) -> Option<SubscriptionUsage> {
    if depth > 8 {
        return None;
    }
    let object = value.as_object()?;
    let renews_at = find_value(object, &["renewAt", "renew_at"])
        .and_then(parse_date_value)
        .or(inherited_renewal);
    let pairs = [
        (
            [
                "rollingUsage",
                "rolling",
                "rolling_usage",
                "rollingWindow",
                "rolling_window",
            ],
            [
                "weeklyUsage",
                "weekly",
                "weekly_usage",
                "weeklyWindow",
                "weekly_window",
            ],
        ),
        (
            [
                "primaryWindow",
                "primary",
                "primary_window",
                "session",
                "sessionWindow",
            ],
            [
                "secondaryWindow",
                "secondary",
                "secondary_window",
                "week",
                "weeklyWindow",
            ],
        ),
    ];
    for (rolling_keys, weekly_keys) in pairs {
        let rolling = find_value(object, &rolling_keys).and_then(Value::as_object);
        let weekly = find_value(object, &weekly_keys).and_then(Value::as_object);
        if let (Some(rolling), Some(weekly)) = (rolling, weekly) {
            if let (Some(rolling), Some(weekly)) = (
                parse_json_window(rolling, now),
                parse_json_window(weekly, now),
            ) {
                return Some(SubscriptionUsage {
                    rolling_percent: rolling.0,
                    weekly_percent: weekly.0,
                    rolling_seconds: rolling.1,
                    weekly_seconds: weekly.1,
                    rolling_reset: rolling.2,
                    weekly_reset: weekly.2,
                    renews_at,
                });
            }
        }
    }
    object
        .values()
        .find_map(|value| parse_subscription_json(value, now, renews_at, depth + 1))
}

fn parse_json_window(
    object: &serde_json::Map<String, Value>,
    now: DateTime<Utc>,
) -> Option<(f64, u64, DateTime<Utc>)> {
    let percent = find_value(
        object,
        &[
            "usagePercent",
            "usedPercent",
            "percentUsed",
            "percent",
            "usage_percent",
            "used_percent",
            "utilization",
            "utilizationPercent",
            "utilization_percent",
            "usage",
        ],
    )
    .and_then(number_value)
    .map(normalize_percent)
    .or_else(|| {
        let used = find_value(object, &["used", "usageUsed", "consumed"]).and_then(number_value)?;
        let limit =
            find_value(object, &["limit", "total", "maximum", "max"]).and_then(number_value)?;
        (limit > 0.0).then_some((used / limit) * 100.0)
    })?;
    let seconds = find_value(
        object,
        &[
            "resetInSec",
            "resetInSeconds",
            "resetSeconds",
            "reset_sec",
            "reset_in_sec",
            "resetsInSec",
            "resetsInSeconds",
            "resetIn",
            "resetSec",
        ],
    )
    .and_then(number_value)
    .filter(|value| value.is_finite() && *value >= 0.0 && *value <= u64::MAX as f64)
    .map(|value| value as u64);
    let reset_at = find_value(
        object,
        &[
            "resetAt",
            "resetsAt",
            "reset_at",
            "resets_at",
            "nextReset",
            "next_reset",
            "renewAt",
            "renew_at",
        ],
    )
    .and_then(parse_date_value);
    // Prefer an absolute reset timestamp when the response carries one: it is stable across refreshes,
    // so the threshold/pace dedup key stays put instead of drifting a few seconds every poll (which
    // would re-fire the Toast). Fall back to `now + seconds` only when no absolute reset is available;
    // when both are present the explicit seconds still drive the "resets in" label.
    let (seconds, reset) = match (reset_at, seconds) {
        (Some(reset), Some(seconds)) => (seconds, reset),
        (Some(reset), None) => ((reset - now).num_seconds().max(0) as u64, reset),
        (None, Some(seconds)) => (
            seconds,
            now + Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX)),
        ),
        (None, None) => (0, now),
    };
    Some((percent, seconds, reset))
}

fn parse_script_window(
    text: &str,
    name: &str,
    now: DateTime<Utc>,
) -> Option<(f64, u64, DateTime<Utc>)> {
    let escaped = regex::escape(name);
    let percent_regex = Regex::new(&format!(
        r"(?s){escaped}.{{0,500}}?usagePercent\s*:\s*([0-9]+(?:\.[0-9]+)?)"
    ))
    .ok()?;
    let reset_regex = Regex::new(&format!(
        r"(?s){escaped}.{{0,500}}?resetInSec\s*:\s*([0-9]+)"
    ))
    .ok()?;
    let percent = percent_regex
        .captures(text)?
        .get(1)?
        .as_str()
        .parse()
        .ok()?;
    let seconds = reset_regex
        .captures(text)?
        .get(1)?
        .as_str()
        .parse::<u64>()
        .ok()?;
    Some((
        percent,
        seconds,
        now + Duration::seconds(i64::try_from(seconds).ok()?),
    ))
}

fn find_value<'a>(object: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn number_value(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str()?.trim().parse().ok())
        .filter(|value| value.is_finite())
}

fn normalize_percent(value: f64) -> f64 {
    if value > 0.0 && value < 1.0 {
        value * 100.0
    } else {
        value
    }
}

fn parse_date_value(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(text) = value.as_str() {
        if let Ok(date) = DateTime::parse_from_rfc3339(text) {
            return Some(date.with_timezone(&Utc));
        }
        if let Ok(number) = text.parse::<f64>() {
            return parse_numeric_date(number);
        }
    }
    value.as_f64().and_then(parse_numeric_date)
}

fn parse_numeric_date(value: f64) -> Option<DateTime<Utc>> {
    if !value.is_finite() || value < 0.0 || value > i64::MAX as f64 {
        return None;
    }
    let value = value as i64;
    if value > 10_000_000_000 {
        DateTime::from_timestamp_millis(value)
    } else {
        DateTime::from_timestamp(value, 0)
    }
}

fn looks_signed_out(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    [
        "sign in",
        "auth/authorize",
        "not associated with an account",
        "actor of type \"public\"",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_manual_cookie_header() {
        assert_eq!(
            normalize_auth_cookie_header(
                "provider=google; auth=session123; theme=dark; __Host-auth=host456"
            ),
            Some("auth=session123; __Host-auth=host456".into())
        );
    }

    #[test]
    fn parses_workspace_ids_from_script() {
        let text = r#"value={id:"wrk_01K6AR1ZET89H8NB691FQ2C2VB",name:"Default"}"#;
        assert_eq!(
            parse_workspace_ids(text),
            ["wrk_01K6AR1ZET89H8NB691FQ2C2VB"]
        );
    }

    #[test]
    fn parses_json_fractional_percent_and_reset_at() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let payload = serde_json::json!({
            "usage": {
                "rollingUsage": { "usagePercent": 0.25, "resetAt": "2023-11-14T23:13:20Z" },
                "weeklyUsage": { "usagePercent": 75, "resetInSec": 7200 }
            }
        });
        let parsed = parse_subscription(&payload.to_string(), now).expect("subscription");
        assert_eq!(parsed.rolling_percent, 25.0);
        assert_eq!(parsed.weekly_percent, 75.0);
        assert_eq!(parsed.rolling_seconds, 3600);
    }

    #[test]
    fn json_prefers_absolute_reset_over_relative_seconds() {
        // With both an absolute reset and a relative "seconds remaining", the absolute timestamp must
        // win so the warning dedup key stays stable across refreshes; the explicit seconds still feed
        // the "resets in" label.
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let payload = serde_json::json!({
            "usage": {
                // resetAt is now + 3600s; resetInSec deliberately disagrees so the winner is visible.
                "rollingUsage": { "usagePercent": 50, "resetAt": "2023-11-14T23:13:20Z", "resetInSec": 60 },
                "weeklyUsage": { "usagePercent": 75, "resetInSec": 7200 }
            }
        });
        let parsed = parse_subscription(&payload.to_string(), now).expect("subscription");
        assert_eq!(
            parsed.rolling_reset,
            DateTime::from_timestamp(1_700_003_600, 0).unwrap(),
            "absolute resetAt must win over now + resetInSec"
        );
        assert_eq!(
            parsed.rolling_seconds, 60,
            "explicit seconds still drive the label"
        );
    }

    #[test]
    fn parses_script_subscription() {
        let now = DateTime::from_timestamp(0, 0).unwrap();
        let text = "$R={rollingUsage:{resetInSec:5944,usagePercent:17},weeklyUsage:{resetInSec:278201,usagePercent:75}}";
        let parsed = parse_subscription(text, now).expect("subscription");
        assert_eq!(parsed.rolling_percent, 17.0);
        assert_eq!(parsed.weekly_seconds, 278_201);
    }
}
