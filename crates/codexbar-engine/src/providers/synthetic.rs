use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;
use std::env;

pub struct SyntheticProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Synthetic,
    display_name: "Synthetic",
    auth_kind: AuthKind::ApiKey,
    color: "#141414",
    dashboard_url: "https://synthetic.new",
    credential_hint: "Set an API key in Settings or SYNTHETIC_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Synthetic),
};

const QUOTAS_URL: &str = "https://api.synthetic.new/v2/quotas";

#[async_trait]
impl Provider for SyntheticProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let response = context
            .client
            .get(QUOTAS_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Synthetic API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Synthetic",
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
            env::var("SYNTHETIC_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Synthetic API key.".into()))
}

/// The three known Synthetic lanes, kept in slot order so a missing lane never promotes the next one
/// into the wrong label: rolling 5-hour → weekly tokens → search hourly.
fn map_usage(body: &Value) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Synthetic, "api key");
    let data = body.get("data").filter(|value| value.is_object());
    let root = data.unwrap_or(body);

    if let Some(window) = quota_window(
        root.get("rollingFiveHourLimit"),
        "session",
        "Five-hour quota",
        5 * 60,
    ) {
        snapshot.windows.push(window);
    }
    let weekly = root.get("weeklyTokenLimit");
    if let Some(window) = quota_window(weekly, "weekly", "Weekly tokens", 7 * 24 * 60) {
        snapshot.windows.push(window);
    }
    let search_hourly = root.get("search").and_then(|search| search.get("hourly"));
    if let Some(window) = quota_window(search_hourly, "search", "Search hourly", 60) {
        snapshot.windows.push(window);
    }

    // Weekly credits, when the plan reports them, become the balance shown on the card.
    if let Some(weekly) = weekly {
        let limit = number(weekly, &["maxCredits", "max_credits"]);
        let remaining = number(weekly, &["remainingCredits", "remaining_credits"]);
        if let Some(remaining) = remaining {
            snapshot.financials = Some(FinancialSnapshot {
                balance: Some(remaining),
                spend: match (limit, remaining) {
                    (Some(limit), remaining) => Some((limit - remaining).max(0.0)),
                    _ => None,
                },
                currency: Some("USD".into()),
            });
        }
    }

    snapshot.plan = string(root, &["plan", "planName", "plan_name", "tier"])
        .or_else(|| string(body, &["plan", "planName", "plan_name", "tier"]));
    snapshot
}

/// Build a window from a quota payload, preferring an explicit percent, then deriving one from
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
            "percentUsed",
            "usedPercent",
            "usagePercent",
            "used_percent",
            "percent",
        ],
    ));
    if used_percent.is_none() {
        if let Some(remaining_percent) = normalized_percent(number(
            payload,
            &["percentRemaining", "remainingPercent", "remaining_percent"],
        )) {
            used_percent = Some(100.0 - remaining_percent);
        }
    }

    let limit = number(payload, &["limit", "quota", "max", "total", "capacity"]);
    let used = number(
        payload,
        &["used", "usage", "consumed", "requests", "tokens"],
    );
    let remaining = number(payload, &["remaining", "left", "available", "balance"]);
    if used_percent.is_none() {
        let (limit, used) = resolve_used_limit(limit, used, remaining);
        if let (Some(limit), Some(used)) = (limit, used) {
            if limit > 0.0 {
                used_percent = Some(used / limit * 100.0);
            }
        }
    }

    let used_percent = used_percent?.clamp(0.0, 100.0);
    let resets_at = date(
        payload
            .get("resetsAt")
            .or_else(|| payload.get("resets_at"))
            .or_else(|| payload.get("resetAt"))
            .or_else(|| payload.get("reset_at"))
            .or_else(|| payload.get("renewsAt"))
            .or_else(|| payload.get("expiresAt")),
    );

    let mut window = UsageWindow::new(id, title, used_percent).with_window_minutes(window_minutes);
    window = window.with_reset(resets_at);
    let (limit, used) = resolve_used_limit(limit, used, remaining);
    if let (Some(limit), Some(used)) = (limit, used) {
        window = window.with_detail(format!("{} / {}", compact(used), compact(limit)));
    }
    Some(window)
}

/// Fill in whichever of used/limit is derivable from the other two (limit = used + remaining, etc.).
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

/// Synthetic reports percentages either as a 0–1 fraction or a 0–100 value; fold both into 0–100.
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

/// Accept ISO-8601 strings and epoch numbers (seconds or milliseconds).
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
    fn maps_three_slotted_windows_in_order() {
        let body = json!({
            "rollingFiveHourLimit": { "used": 30, "limit": 100, "resetsAt": "2026-08-01T00:00:00Z" },
            "weeklyTokenLimit": { "used": 2_000_000, "limit": 10_000_000 },
            "search": { "hourly": { "used": 5, "limit": 20 } },
            "plan": "Pro"
        });
        let snapshot = map_usage(&body);
        assert_eq!(snapshot.windows.len(), 3);
        assert_eq!(snapshot.windows[0].id, "session");
        assert_eq!(snapshot.windows[0].used_percent, 30.0);
        assert_eq!(snapshot.windows[0].detail.as_deref(), Some("30 / 100"));
        assert_eq!(snapshot.windows[1].id, "weekly");
        assert_eq!(snapshot.windows[1].used_percent, 20.0);
        assert_eq!(snapshot.windows[2].id, "search");
        assert_eq!(snapshot.windows[2].used_percent, 25.0);
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
    }

    #[test]
    fn missing_search_lane_leaves_two_windows_and_reads_data_root() {
        let body = json!({
            "data": {
                "rollingFiveHourLimit": { "percentUsed": 0.5 },
                "weeklyTokenLimit": { "remaining": 40, "limit": 100 }
            }
        });
        let snapshot = map_usage(&body);
        assert_eq!(snapshot.windows.len(), 2);
        assert_eq!(snapshot.windows[0].used_percent, 50.0);
        // 40 remaining of 100 → 60 used.
        assert_eq!(snapshot.windows[1].used_percent, 60.0);
    }

    #[test]
    fn weekly_credits_become_the_balance() {
        let body = json!({
            "weeklyTokenLimit": { "percentUsed": 10, "maxCredits": 100, "remainingCredits": 82.5 }
        });
        let snapshot = map_usage(&body);
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(financials.balance, Some(82.5));
        assert_eq!(financials.spend, Some(17.5));
    }

    #[test]
    fn absent_quota_data_yields_no_windows() {
        let snapshot = map_usage(&json!({ "plan": "Free" }));
        assert!(snapshot.windows.is_empty());
        assert_eq!(snapshot.plan.as_deref(), Some("Free"));
    }
}
