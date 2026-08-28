use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::env;

pub struct Sub2ApiProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Sub2api,
    display_name: "sub2api",
    auth_kind: AuthKind::ApiKey,
    color: "#5b57ff",
    dashboard_url: "",
    credential_hint: "Set an API key + base URL in Settings, or SUB2API_API_KEY / SUB2API_BASE_URL.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Sub2api),
};

const DAY_MINUTES: u32 = 24 * 60;
const WEEK_MINUTES: u32 = 7 * 24 * 60;
const MONTH_MINUTES: u32 = 30 * 24 * 60;

#[async_trait]
impl Provider for Sub2ApiProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let base_url = resolve_base_url(account)?;
        let url = format!("{}?days=30", usage_url(&base_url));

        let response = context
            .client
            .get(&url)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "sub2api rejected the API key.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "sub2api",
                status: response.status().as_u16(),
            });
        }
        let payload: UsageResponse = response.json().await?;
        if !payload.is_valid.unwrap_or(true) {
            return Err(ProviderError::Unauthorized(
                "sub2api rejected the API key.".into(),
            ));
        }
        Ok(map_usage(payload))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("SUB2API_API_KEY"))
        .ok_or_else(|| ProviderError::MissingCredentials("Missing sub2api API key.".into()))
}

fn resolve_base_url(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.base_url)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("SUB2API_BASE_URL"))
        .ok_or_else(|| {
            ProviderError::MissingCredentials(
                "sub2api needs a base URL (set it in Settings or SUB2API_BASE_URL).".into(),
            )
        })
}

fn env_var(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Normalizes the configured base to the `/v1/usage` endpoint, tolerating a base that already ends
/// in `/v1` or the full `/v1/usage` path.
fn usage_url(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.ends_with("/v1/usage") {
        trimmed.to_owned()
    } else if trimmed.ends_with("/v1") {
        format!("{trimmed}/usage")
    } else {
        format!("{trimmed}/v1/usage")
    }
}

fn map_usage(payload: UsageResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Sub2api, "api key");
    let unit = payload
        .unit
        .clone()
        .or_else(|| payload.quota.as_ref().and_then(|q| q.unit.clone()))
        .unwrap_or_else(|| "USD".to_owned());

    if let Some(subscription) = &payload.subscription {
        push_cost_window(
            &mut snapshot,
            "daily",
            "Daily limit",
            subscription.daily_usage_usd.unwrap_or(0.0),
            subscription.daily_limit_usd,
            DAY_MINUTES,
        );
        push_cost_window(
            &mut snapshot,
            "weekly",
            "7 day limit",
            subscription.weekly_usage_usd.unwrap_or(0.0),
            subscription.weekly_limit_usd,
            WEEK_MINUTES,
        );
        push_cost_window(
            &mut snapshot,
            "monthly",
            "Monthly limit",
            subscription.monthly_usage_usd.unwrap_or(0.0),
            subscription.monthly_limit_usd,
            MONTH_MINUTES,
        );
    } else if let Some(quota) = &payload.quota {
        if quota.limit > 0.0 {
            let used_percent = (quota.used / quota.limit * 100.0).clamp(0.0, 100.0);
            snapshot.windows.push(
                UsageWindow::new("quota", "Quota", used_percent).with_detail(amount_pair(
                    quota.used,
                    quota.limit,
                    quota.unit.as_deref().unwrap_or(&unit),
                )),
            );
        }
    }

    for rate_limit in payload.rate_limits.iter().flatten() {
        if rate_limit.limit <= 0.0 {
            continue;
        }
        let used_percent = (rate_limit.used / rate_limit.limit * 100.0).clamp(0.0, 100.0);
        let mut window = UsageWindow::new(
            rate_limit.window.clone(),
            rate_limit_title(&rate_limit.window),
            used_percent,
        )
        .with_reset(parse_date(rate_limit.reset_at.as_deref()))
        .with_detail(amount_pair(rate_limit.used, rate_limit.limit, &unit));
        if let Some(minutes) = window_minutes(&rate_limit.window) {
            window = window.with_window_minutes(minutes);
        }
        snapshot.windows.push(window);
    }

    if let Some(usage) = &payload.usage {
        if let Some(today) = &usage.today {
            add_usage_summary(&mut snapshot, "Today", today);
        } else if let Some(total) = &usage.total {
            add_usage_summary(&mut snapshot, "Total", total);
        }
    }

    if let Some(balance) = payload.balance {
        snapshot
            .summary
            .push(SummaryItem::new("Balance", amount(balance, &unit)));
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(balance),
            spend: None,
            currency: currency_code(&unit),
        });
    }

    snapshot.plan = payload
        .plan_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    snapshot
}

fn push_cost_window(
    snapshot: &mut ProviderSnapshot,
    id: &str,
    title: &str,
    usage: f64,
    limit: Option<f64>,
    window_minutes: u32,
) {
    let Some(limit) = limit.filter(|value| *value > 0.0) else {
        return;
    };
    let used_percent = (usage / limit * 100.0).clamp(0.0, 100.0);
    snapshot.windows.push(
        UsageWindow::new(id, title, used_percent)
            .with_window_minutes(window_minutes)
            .with_detail(amount_pair(usage, limit, "USD")),
    );
}

fn add_usage_summary(snapshot: &mut ProviderSnapshot, prefix: &str, totals: &Totals) {
    let requests = totals.requests.unwrap_or(0);
    let tokens = totals.total_tokens.unwrap_or(0);
    let cost = totals.actual_cost.unwrap_or(0.0);
    if requests > 0 {
        snapshot.summary.push(SummaryItem::new(
            format!("{prefix} requests"),
            requests.to_string(),
        ));
    }
    if tokens > 0 {
        snapshot.summary.push(SummaryItem::new(
            format!("{prefix} tokens"),
            tokens.to_string(),
        ));
    }
    if cost > 0.0 {
        snapshot.summary.push(SummaryItem::new(
            format!("{prefix} cost"),
            format!("${cost:.2}"),
        ));
    }
}

fn amount(value: f64, unit: &str) -> String {
    if unit.eq_ignore_ascii_case("USD") {
        format!("${value:.2}")
    } else {
        format!("{value:.2} {unit}")
    }
}

fn amount_pair(used: f64, limit: f64, unit: &str) -> String {
    format!("{} / {}", amount(used, unit), amount(limit, unit))
}

fn currency_code(unit: &str) -> Option<String> {
    unit.eq_ignore_ascii_case("USD")
        .then(|| "USD".to_owned())
        .or_else(|| (!unit.trim().is_empty()).then(|| unit.to_owned()))
}

fn rate_limit_title(window: &str) -> String {
    match window.to_ascii_lowercase().as_str() {
        "5h" => "5 hour limit".to_owned(),
        "1d" => "Daily limit".to_owned(),
        "7d" => "7 day limit".to_owned(),
        other => format!("{other} limit"),
    }
}

fn window_minutes(window: &str) -> Option<u32> {
    match window.to_ascii_lowercase().as_str() {
        "5h" => Some(5 * 60),
        "1d" => Some(DAY_MINUTES),
        "7d" => Some(WEEK_MINUTES),
        _ => None,
    }
}

fn parse_date(raw: Option<&str>) -> Option<DateTime<Utc>> {
    let raw = raw?.trim();
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

#[derive(Debug, Deserialize)]
struct UsageResponse {
    #[serde(default, rename = "isValid")]
    is_valid: Option<bool>,
    #[serde(default, rename = "planName")]
    plan_name: Option<String>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    balance: Option<f64>,
    #[serde(default)]
    quota: Option<Quota>,
    #[serde(default)]
    rate_limits: Option<Vec<RateLimit>>,
    #[serde(default)]
    subscription: Option<Subscription>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Quota {
    #[serde(default)]
    limit: f64,
    #[serde(default)]
    used: f64,
    #[serde(default)]
    unit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RateLimit {
    window: String,
    #[serde(default)]
    limit: f64,
    #[serde(default)]
    used: f64,
    #[serde(default)]
    reset_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Subscription {
    #[serde(default)]
    daily_usage_usd: Option<f64>,
    #[serde(default)]
    weekly_usage_usd: Option<f64>,
    #[serde(default)]
    monthly_usage_usd: Option<f64>,
    #[serde(default)]
    daily_limit_usd: Option<f64>,
    #[serde(default)]
    weekly_limit_usd: Option<f64>,
    #[serde(default)]
    monthly_limit_usd: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Usage {
    #[serde(default)]
    today: Option<Totals>,
    #[serde(default)]
    total: Option<Totals>,
}

#[derive(Debug, Deserialize)]
struct Totals {
    #[serde(default)]
    requests: Option<i64>,
    #[serde(default)]
    total_tokens: Option<i64>,
    #[serde(default)]
    actual_cost: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_usage_url() {
        assert_eq!(usage_url("https://x.test"), "https://x.test/v1/usage");
        assert_eq!(usage_url("https://x.test/v1"), "https://x.test/v1/usage");
        assert_eq!(
            usage_url("https://x.test/v1/usage/"),
            "https://x.test/v1/usage"
        );
    }

    #[test]
    fn maps_subscription_windows() {
        let payload: UsageResponse = serde_json::from_value(json!({
            "isValid": true,
            "planName": "Pro",
            "subscription": {
                "daily_usage_usd": 2.0, "daily_limit_usd": 10.0,
                "weekly_usage_usd": 20.0, "weekly_limit_usd": 40.0,
                "monthly_usage_usd": 50.0, "monthly_limit_usd": 200.0
            }
        }))
        .unwrap();
        let snapshot = map_usage(payload);
        assert_eq!(snapshot.windows.len(), 3);
        assert_eq!(snapshot.windows[0].id, "daily");
        assert_eq!(snapshot.windows[0].used_percent, 20.0);
        assert_eq!(snapshot.windows[2].used_percent, 25.0);
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
    }

    #[test]
    fn maps_quota_and_rate_limits() {
        let payload: UsageResponse = serde_json::from_value(json!({
            "quota": { "limit": 100.0, "used": 40.0, "unit": "credits" },
            "rate_limits": [
                { "window": "5h", "limit": 50.0, "used": 25.0, "reset_at": "2026-08-01T00:00:00Z" }
            ],
            "balance": 12.5
        }))
        .unwrap();
        let snapshot = map_usage(payload);
        assert_eq!(snapshot.windows[0].id, "quota");
        assert_eq!(snapshot.windows[0].used_percent, 40.0);
        let rate = snapshot.windows.iter().find(|w| w.id == "5h").unwrap();
        assert_eq!(rate.used_percent, 50.0);
        assert_eq!(rate.window_minutes, Some(300));
        assert_eq!(snapshot.financials.unwrap().balance, Some(12.5));
    }

    #[test]
    fn adds_usage_totals_summary() {
        let payload: UsageResponse = serde_json::from_value(json!({
            "usage": { "today": { "requests": 12, "total_tokens": 3400, "actual_cost": 0.42 } }
        }))
        .unwrap();
        let snapshot = map_usage(payload);
        assert!(
            snapshot
                .summary
                .iter()
                .any(|i| i.label == "Today requests" && i.value == "12")
        );
        assert!(
            snapshot
                .summary
                .iter()
                .any(|i| i.label == "Today cost" && i.value == "$0.42")
        );
    }

    #[test]
    fn skips_windows_without_positive_limits() {
        let payload: UsageResponse = serde_json::from_value(json!({
            "subscription": { "daily_usage_usd": 5.0, "daily_limit_usd": 0.0 }
        }))
        .unwrap();
        assert!(map_usage(payload).windows.is_empty());
    }
}
