use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::env;

pub struct KimiProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for KimiProvider {
    fn default() -> Self {
        Self {
            base_url: "https://www.kimi.com".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Kimi,
    display_name: "Kimi",
    auth_kind: AuthKind::BrowserCookie,
    color: "#101010",
    dashboard_url: "https://www.kimi.com/code/console",
    credential_hint: "Imports the kimi.com kimi-auth cookie from Chrome/Edge with DPAPI, or accepts \
a manual Cookie header / KIMI_AUTH_TOKEN.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Kimi),
};

const USAGE_PATH: &str = "/apiv2/kimi.gateway.billing.v1.BillingService/GetUsages";
const SUBSCRIPTION_PATH: &str =
    "/apiv2/kimi.gateway.membership.v2.MembershipService/GetSubscriptionStats";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";
const RATE_WINDOW_MINUTES: u32 = 5 * 60;
const WEEK_MINUTES: u32 = 7 * 24 * 60;

#[async_trait]
impl Provider for KimiProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let token = self.resolve_token(account)?;
        let coding = self.fetch_usage(context, &token).await?;
        // Subscription stats enrich the card but must never fail the required usage fetch.
        let subscription = self
            .fetch_subscription(context, &token)
            .await
            .ok()
            .flatten();
        Ok(map_usage(&coding, subscription.as_ref(), Utc::now()))
    }
}

impl KimiProvider {
    async fn fetch_usage(
        &self,
        context: &FetchContext<'_>,
        token: &str,
    ) -> Result<CodingUsage, ProviderError> {
        let url = format!("{}{USAGE_PATH}", self.base_url.trim_end_matches('/'));
        let response = post(
            context,
            &url,
            token,
            &json!({ "scope": ["FEATURE_CODING"] }),
        )
        .send()
        .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Kimi session token expired. Sign in to kimi.com or replace the manual token."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Kimi",
                status: response.status().as_u16(),
            });
        }
        let payload: UsagesResponse =
            response
                .json()
                .await
                .map_err(|error| ProviderError::Parse {
                    provider: "Kimi",
                    message: error.to_string(),
                })?;
        payload
            .usages
            .into_iter()
            .find(|usage| usage.scope == "FEATURE_CODING")
            .map(|usage| CodingUsage {
                weekly: usage.detail,
                rate_limit: usage
                    .limits
                    .into_iter()
                    .flatten()
                    .next()
                    .map(|limit| limit.detail),
            })
            .ok_or(ProviderError::Parse {
                provider: "Kimi",
                message: "FEATURE_CODING scope not found in response".into(),
            })
    }

    async fn fetch_subscription(
        &self,
        context: &FetchContext<'_>,
        token: &str,
    ) -> Result<Option<SubscriptionStats>, ProviderError> {
        let url = format!("{}{SUBSCRIPTION_PATH}", self.base_url.trim_end_matches('/'));
        let response = post(context, &url, token, &json!({})).send().await?;
        if !response.status().is_success() {
            return Ok(None);
        }
        Ok(response.json::<SubscriptionStats>().await.ok())
    }

    fn resolve_token(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(raw) = ProviderConfig::normalized_secret(&account.cookie_header) {
            if let Some(token) = extract_token(raw) {
                return Ok(token);
            }
        }
        if let Some(token) =
            env_token("KIMI_AUTH_TOKEN").or_else(|| env_token("KIMI_MANUAL_COOKIE"))
        {
            return Ok(token);
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a kimi.com Cookie header or set KIMI_AUTH_TOKEN.".into(),
            ));
        }
        let imported = chromium::find_cookie_header(
            account.browser,
            &["kimi.com", "www.kimi.com"],
            &["kimi-auth"],
        )?;
        extract_token(&imported.value).ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Imported kimi.com cookies had no kimi-auth token.".into(),
            )
        })
    }
}

fn post(
    context: &FetchContext<'_>,
    url: &str,
    token: &str,
    body: &Value,
) -> reqwest::RequestBuilder {
    context
        .client
        .post(url)
        .bearer_auth(token)
        .header("Cookie", format!("kimi-auth={token}"))
        .header("Accept", "*/*")
        .header("Origin", "https://www.kimi.com")
        .header("Referer", "https://www.kimi.com/code/console")
        .header("User-Agent", USER_AGENT)
        .header("connect-protocol-version", "1")
        .header("x-msh-platform", "web")
        .json(body)
}

fn env_token(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .and_then(|value| extract_token(value.trim()))
}

/// Accepts a `kimi-auth=<token>` cookie/header fragment or a bare JWT.
fn extract_token(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if let Some(index) = raw.find("kimi-auth=") {
        let rest = &raw[index + "kimi-auth=".len()..];
        let token = rest
            .split([';', ' ', '\t', '\r', '\n', '\'', '"'])
            .next()
            .unwrap_or("")
            .trim();
        if !token.is_empty() {
            return Some(token.to_owned());
        }
    }
    if raw.starts_with("eyJ") && raw.split('.').count() == 3 {
        return Some(raw.to_owned());
    }
    None
}

struct CodingUsage {
    weekly: UsageDetail,
    rate_limit: Option<UsageDetail>,
}

fn map_usage(
    coding: &CodingUsage,
    subscription: Option<&SubscriptionStats>,
    _now: DateTime<Utc>,
) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Kimi, "web");

    let weekly = &coding.weekly;
    let (weekly_used, weekly_limit) = used_and_limit(weekly);
    let weekly_percent = ratio_percent(weekly_used, weekly_limit);
    snapshot.windows.push(
        UsageWindow::new("weekly", "Weekly", weekly_percent)
            .with_reset(parse_date(weekly.reset_time.as_deref()))
            .with_detail(format!("{weekly_used}/{weekly_limit} requests")),
    );

    if let Some(rate) = &coding.rate_limit {
        let (used, limit) = used_and_limit(rate);
        if limit > 0 {
            snapshot.windows.push(
                UsageWindow::new("rate", "Rate (5h)", ratio_percent(used, limit))
                    .with_window_minutes(RATE_WINDOW_MINUTES)
                    .with_reset(parse_date(rate.reset_time.as_deref()))
                    .with_detail(format!("{used}/{limit} per 5 hours")),
            );
        }
    }

    if let Some(subscription) = subscription {
        if let Some(window) = subscription.monthly_window() {
            snapshot.windows.push(window);
        }
        if let Some(window) = subscription.code_weekly_window() {
            snapshot.windows.push(window);
        }
    }
    snapshot
}

fn used_and_limit(detail: &UsageDetail) -> (i64, i64) {
    let limit = detail.limit.as_ref().and_then(scalar_int).unwrap_or(0);
    let remaining = detail.remaining.as_ref().and_then(scalar_int);
    let used = detail
        .used
        .as_ref()
        .and_then(scalar_int)
        .unwrap_or_else(|| remaining.map_or(0, |remaining| (limit - remaining).max(0)));
    (used, limit)
}

fn ratio_percent(used: i64, limit: i64) -> f64 {
    if limit > 0 {
        (used as f64 / limit as f64 * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    }
}

fn parse_date(raw: Option<&str>) -> Option<DateTime<Utc>> {
    let raw = raw?.trim();
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

/// Kimi encodes numeric usage counters as strings or numbers depending on the field.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Scalar {
    Text(String),
    Int(i64),
    Float(f64),
}

fn scalar_int(scalar: &Scalar) -> Option<i64> {
    match scalar {
        Scalar::Text(text) => text.trim().parse().ok(),
        Scalar::Int(value) => Some(*value),
        Scalar::Float(value) => Some(*value as i64),
    }
}

#[derive(Debug, Deserialize)]
struct UsagesResponse {
    #[serde(default)]
    usages: Vec<Usage>,
}

#[derive(Debug, Deserialize)]
struct Usage {
    #[serde(default)]
    scope: String,
    detail: UsageDetail,
    #[serde(default)]
    limits: Option<Vec<RateLimit>>,
}

#[derive(Debug, Deserialize)]
struct RateLimit {
    detail: UsageDetail,
}

#[derive(Debug, Deserialize)]
struct UsageDetail {
    #[serde(default)]
    limit: Option<Scalar>,
    #[serde(default)]
    used: Option<Scalar>,
    #[serde(default)]
    remaining: Option<Scalar>,
    #[serde(
        default,
        alias = "resetTime",
        alias = "resetAt",
        alias = "reset_time",
        alias = "reset_at"
    )]
    reset_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionStats {
    #[serde(default)]
    subscription_balance: Option<SubscriptionBalance>,
    #[serde(default)]
    ratelimit_code7d: Option<SubscriptionRateLimit>,
}

impl SubscriptionStats {
    fn monthly_window(&self) -> Option<UsageWindow> {
        let balance = self.subscription_balance.as_ref()?;
        // The subscription pool is shared across features, so `amountUsedRatio` is the real remaining.
        if !matches!(balance.feature.as_deref(), None | Some("FEATURE_OMNI")) {
            return None;
        }
        if !matches!(balance.type_field.as_deref(), None | Some("SUBSCRIPTION")) {
            return None;
        }
        let ratio = balance
            .amount_used_ratio
            .filter(|value| value.is_finite())?;
        Some(
            UsageWindow::new("monthly", "Monthly", (ratio * 100.0).clamp(0.0, 100.0))
                .with_reset(parse_date(balance.expire_time.as_deref())),
        )
    }

    fn code_weekly_window(&self) -> Option<UsageWindow> {
        let limit = self.ratelimit_code7d.as_ref()?;
        if limit.enabled == Some(false) {
            return None;
        }
        let ratio = limit.ratio.filter(|value| value.is_finite())?;
        Some(
            UsageWindow::new("code7d", "Code 7-day", (ratio * 100.0).clamp(0.0, 100.0))
                .with_window_minutes(WEEK_MINUTES)
                .with_reset(parse_date(limit.reset_time.as_deref())),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionBalance {
    #[serde(default)]
    feature: Option<String>,
    #[serde(default, rename = "type")]
    type_field: Option<String>,
    #[serde(default)]
    amount_used_ratio: Option<f64>,
    #[serde(default)]
    expire_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionRateLimit {
    #[serde(default)]
    ratio: Option<f64>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    reset_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0).unwrap()
    }

    #[test]
    fn extracts_token_from_cookie_fragment_and_bare_jwt() {
        assert_eq!(
            extract_token("kimi-auth=eyJabc.def.ghi; other=1").as_deref(),
            Some("eyJabc.def.ghi")
        );
        assert_eq!(extract_token("eyJa.bc.de").as_deref(), Some("eyJa.bc.de"));
        assert_eq!(
            extract_token("Cookie: kimi-auth=tok123").as_deref(),
            Some("tok123")
        );
        assert_eq!(extract_token("no-token-here"), None);
    }

    #[test]
    fn maps_weekly_and_rate_windows_from_string_counters() {
        let payload: UsagesResponse = serde_json::from_value(json!({
            "usages": [{
                "scope": "FEATURE_CODING",
                "detail": { "limit": "1000", "used": "250", "resetTime": "2026-08-01T00:00:00Z" },
                "limits": [{ "detail": { "limit": 40, "remaining": 10 } }]
            }]
        }))
        .unwrap();
        let coding = payload
            .usages
            .into_iter()
            .find(|u| u.scope == "FEATURE_CODING")
            .map(|u| CodingUsage {
                weekly: u.detail,
                rate_limit: u.limits.into_iter().flatten().next().map(|l| l.detail),
            })
            .unwrap();
        let snapshot = map_usage(&coding, None, now());
        assert_eq!(snapshot.windows[0].id, "weekly");
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("250/1000 requests")
        );
        // rate limit: 40 limit, 10 remaining → 30 used → 75%.
        let rate = snapshot.windows.iter().find(|w| w.id == "rate").unwrap();
        assert_eq!(rate.used_percent, 75.0);
        assert_eq!(rate.window_minutes, Some(300));
    }

    #[test]
    fn adds_subscription_monthly_and_code_windows() {
        let subscription: SubscriptionStats = serde_json::from_value(json!({
            "subscriptionBalance": {
                "feature": "FEATURE_OMNI", "type": "SUBSCRIPTION",
                "amountUsedRatio": 0.4, "expireTime": "2026-08-15T00:00:00Z"
            },
            "ratelimitCode7d": { "ratio": 0.2, "enabled": true }
        }))
        .unwrap();
        let coding = CodingUsage {
            weekly: serde_json::from_value(json!({ "limit": "100", "used": "10" })).unwrap(),
            rate_limit: None,
        };
        let snapshot = map_usage(&coding, Some(&subscription), now());
        let monthly = snapshot.windows.iter().find(|w| w.id == "monthly").unwrap();
        assert_eq!(monthly.used_percent, 40.0);
        let code = snapshot.windows.iter().find(|w| w.id == "code7d").unwrap();
        assert_eq!(code.used_percent, 20.0);
        assert_eq!(code.window_minutes, Some(WEEK_MINUTES));
    }

    #[test]
    fn derives_used_from_remaining_when_used_absent() {
        let detail: UsageDetail =
            serde_json::from_value(json!({ "limit": 500, "remaining": 200 })).unwrap();
        assert_eq!(used_and_limit(&detail), (300, 500));
    }

    #[test]
    fn code_window_hidden_when_disabled() {
        let subscription: SubscriptionStats = serde_json::from_value(json!({
            "ratelimitCode7d": { "ratio": 0.9, "enabled": false }
        }))
        .unwrap();
        assert!(subscription.code_weekly_window().is_none());
    }
}
