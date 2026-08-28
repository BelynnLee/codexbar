use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;
use std::env;

pub struct ChutesProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Chutes,
    display_name: "Chutes",
    auth_kind: AuthKind::ApiKey,
    color: "#3184ff",
    dashboard_url: "https://chutes.ai",
    credential_hint: "Set an API key in Settings or CHUTES_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Chutes),
};

const DEFAULT_BASE_URL: &str = "https://api.chutes.ai";
const USAGE_PATH: &str = "/users/me/subscription_usage";
const ROLLING_WINDOW_MINUTES: u32 = 4 * 60;
const MONTHLY_WINDOW_MINUTES: u32 = 30 * 24 * 60;

#[async_trait]
impl Provider for ChutesProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let url = format!("{}{USAGE_PATH}", base_url(account));
        let response = context
            .client
            .get(&url)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Chutes API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Chutes",
                status: response.status().as_u16(),
            });
        }
        let body: Value = response.json().await?;
        Ok(map_usage(&body))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("CHUTES_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Chutes API key.".into()))
}

/// Chutes has a public default endpoint; the account `base_url` (or `CHUTES_API_URL`) only overrides
/// it for self-hosted/proxied deployments. Trailing slashes are trimmed so path joins stay clean.
fn base_url(account: &ProviderAccount) -> String {
    ProviderConfig::normalized_secret(&account.base_url)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("CHUTES_API_URL")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .map_or_else(
            || DEFAULT_BASE_URL.to_owned(),
            |value| value.trim_end_matches('/').to_owned(),
        )
}

fn map_usage(body: &Value) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Chutes, "api key");
    let root = object(body, &["data", "result"]).unwrap_or(body);

    let rolling = object(
        root,
        &[
            "rolling",
            "rolling_window",
            "rollingWindow",
            "rolling_4h",
            "four_hour",
            "fourHour",
            "window_4h",
        ],
    );
    if let Some(window) = quota_window(rolling, "session", "4-hour quota", ROLLING_WINDOW_MINUTES) {
        snapshot.windows.push(window);
    }

    let monthly = object(
        root,
        &[
            "monthly",
            "monthly_usage",
            "monthlyUsage",
            "subscription_usage",
            "subscriptionUsage",
            "billing_period",
            "billingPeriod",
        ],
    );
    if let Some(window) = quota_window(monthly, "monthly", "Monthly quota", MONTHLY_WINDOW_MINUTES)
    {
        snapshot.windows.push(window);
    }

    // No labelled window matched: treat the root object itself as a single quota so an account with a
    // flat `{used, limit}` payload still renders a bar instead of an empty card.
    if snapshot.windows.is_empty() {
        if let Some(window) = quota_window(Some(root), "usage", "Usage", MONTHLY_WINDOW_MINUTES) {
            snapshot.windows.push(window);
        }
    }

    snapshot.plan = string(
        root,
        &[
            "plan_name",
            "planName",
            "plan",
            "tier",
            "subscription_plan",
            "subscription_tier",
        ],
    )
    .or_else(|| string(body, &["plan_name", "planName", "plan", "tier"]));
    snapshot
}

/// Build a window from a quota payload, preferring an explicit percent then deriving one from
/// used/limit/remaining. Returns `None` when no percentage can be established.
fn quota_window(
    payload: Option<&Value>,
    id: &str,
    title: &str,
    window_minutes: u32,
) -> Option<UsageWindow> {
    let payload = payload?;

    let mut used_percent = normalized_percent(number(
        payload,
        &[
            "percent_used",
            "percentUsed",
            "usage_percent",
            "usagePercent",
            "used_percent",
            "usedPercent",
            "utilization",
        ],
    ));
    if used_percent.is_none() {
        if let Some(remaining_percent) = normalized_percent(number(
            payload,
            &["percent_remaining", "percentRemaining", "remaining_percent"],
        )) {
            used_percent = Some(100.0 - remaining_percent);
        }
    }

    let limit = number(
        payload,
        &[
            "limit",
            "quota",
            "cap",
            "max",
            "total",
            "monthly_limit",
            "monthlyLimit",
        ],
    );
    let used = number(
        payload,
        &[
            "used",
            "usage",
            "consumed",
            "current",
            "requests",
            "tokens",
            "monthly_usage",
        ],
    );
    let remaining = number(payload, &["remaining", "available", "balance", "left"]);
    let (limit, used) = resolve_used_limit(limit, used, remaining);
    if used_percent.is_none() {
        if let (Some(limit), Some(used)) = (limit, used) {
            if limit > 0.0 {
                used_percent = Some(used / limit * 100.0);
            }
        }
    }

    let used_percent = used_percent?.clamp(0.0, 100.0);
    let resets_at = date(
        payload
            .get("reset_at")
            .or_else(|| payload.get("resetAt"))
            .or_else(|| payload.get("resets_at"))
            .or_else(|| payload.get("resetsAt"))
            .or_else(|| payload.get("renews_at"))
            .or_else(|| payload.get("renewsAt"))
            .or_else(|| payload.get("current_period_end"))
            .or_else(|| payload.get("currentPeriodEnd"))
            .or_else(|| payload.get("period_end"))
            .or_else(|| payload.get("expires_at")),
    );

    let mut window = UsageWindow::new(id, title, used_percent)
        .with_window_minutes(window_minutes)
        .with_reset(resets_at);
    if let (Some(limit), Some(used)) = (limit, used) {
        window = window.with_detail(format!("{} / {}", compact(used), compact(limit)));
    }
    Some(window)
}

fn resolve_used_limit(
    mut limit: Option<f64>,
    mut used: Option<f64>,
    remaining: Option<f64>,
) -> (Option<f64>, Option<f64>) {
    if limit.is_none() {
        if let (Some(used), Some(remaining)) = (used, remaining) {
            limit = Some(used + remaining);
        }
    }
    if used.is_none() {
        if let (Some(limit), Some(remaining)) = (limit, remaining) {
            used = Some((limit - remaining).max(0.0));
        }
    }
    (limit, used)
}

fn normalized_percent(value: Option<f64>) -> Option<f64> {
    let value = value?;
    if !value.is_finite() {
        return None;
    }
    let percent = if value.abs() <= 1.0 {
        value * 100.0
    } else {
        value
    };
    Some(percent.clamp(0.0, 100.0))
}

/// First key whose value is a JSON object.
fn object<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .filter_map(|key| value.get(key))
        .find(|candidate| candidate.is_object())
}

fn number(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| match value.get(key) {
        Some(Value::Number(number)) => number.as_f64().filter(|value| value.is_finite()),
        Some(Value::String(text)) => text.trim().replace(',', "").parse().ok(),
        _ => None,
    })
}

fn string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn date(value: Option<&Value>) -> Option<DateTime<Utc>> {
    match value? {
        Value::String(text) => DateTime::parse_from_rfc3339(text.trim())
            .ok()
            .map(|value| value.with_timezone(&Utc)),
        Value::Number(number) => {
            let raw = number.as_f64()?;
            let seconds = if raw >= 1_000_000_000_000.0 {
                raw / 1000.0
            } else {
                raw
            };
            Utc.timestamp_opt(seconds as i64, 0).single()
        }
        _ => None,
    }
}

fn compact(value: f64) -> String {
    if value.fract() == 0.0 {
        let integer = value as i64;
        let digits = integer.unsigned_abs().to_string();
        let mut grouped = String::new();
        for (index, ch) in digits.chars().enumerate() {
            if index > 0 && (digits.len() - index) % 3 == 0 {
                grouped.push(',');
            }
            grouped.push(ch);
        }
        if integer < 0 {
            format!("-{grouped}")
        } else {
            grouped
        }
    } else {
        format!("{value:.2}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_rolling_and_monthly_windows() {
        let body = json!({
            "rolling": { "used": 30, "limit": 100, "reset_at": "2026-08-01T00:00:00Z" },
            "monthly": { "used": 250, "limit": 1000, "current_period_end": "2026-08-15T00:00:00Z" },
            "plan": "Pro"
        });
        let snapshot = map_usage(&body);
        assert_eq!(snapshot.windows.len(), 2);
        assert_eq!(snapshot.windows[0].id, "session");
        assert_eq!(snapshot.windows[0].used_percent, 30.0);
        assert_eq!(
            snapshot.windows[0].window_minutes,
            Some(ROLLING_WINDOW_MINUTES)
        );
        assert_eq!(snapshot.windows[1].id, "monthly");
        assert_eq!(snapshot.windows[1].used_percent, 25.0);
        assert_eq!(snapshot.windows[1].detail.as_deref(), Some("250 / 1,000"));
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
    }

    #[test]
    fn derives_percent_from_remaining_and_reads_data_root() {
        let body = json!({
            "data": {
                "monthly": { "remaining": 40, "limit": 100 }
            }
        });
        let snapshot = map_usage(&body);
        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.windows[0].id, "monthly");
        // 40 remaining of 100 → 60 used.
        assert_eq!(snapshot.windows[0].used_percent, 60.0);
    }

    #[test]
    fn flat_payload_falls_back_to_single_usage_window() {
        let body = json!({ "used": 75, "limit": 100 });
        let snapshot = map_usage(&body);
        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.windows[0].id, "usage");
        assert_eq!(snapshot.windows[0].used_percent, 75.0);
    }

    #[test]
    fn empty_payload_yields_no_windows() {
        let snapshot = map_usage(&json!({ "plan": "Free" }));
        assert!(snapshot.windows.is_empty());
        assert_eq!(snapshot.plan.as_deref(), Some("Free"));
    }
}
