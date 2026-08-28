use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};
use std::env;

pub struct CodebuffProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Codebuff,
    display_name: "Codebuff",
    auth_kind: AuthKind::ApiKey,
    color: "#44ff00",
    dashboard_url: "https://www.codebuff.com/usage",
    credential_hint: "Set an API key in Settings or CODEBUFF_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Codebuff),
};

const USAGE_URL: &str = "https://www.codebuff.com/api/v1/usage";
const SUBSCRIPTION_URL: &str = "https://www.codebuff.com/api/user/subscription";

#[async_trait]
impl Provider for CodebuffProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let usage_response = context
            .client
            .post(USAGE_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .json(&json!({ "fingerprintId": "codexbar-usage" }))
            .send()
            .await?;
        if matches!(usage_response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Codebuff API key is invalid.".into(),
            ));
        }
        if !usage_response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Codebuff",
                status: usage_response.status().as_u16(),
            });
        }
        let usage: Value = usage_response.json().await?;

        // Subscription details (weekly limit, tier, email) are best-effort.
        let subscription = context
            .client
            .get(SUBSCRIPTION_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()
            .filter(|response| response.status().is_success());
        let subscription = match subscription {
            Some(response) => response.json::<Value>().await.ok(),
            None => None,
        };

        Ok(map_usage(&usage, subscription.as_ref()))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("CODEBUFF_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Codebuff API key.".into()))
}

fn number(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| match value.get(key) {
        Some(Value::Number(n)) => n.as_f64().filter(|v| v.is_finite()),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    })
}

fn string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
    })
}

/// Codebuff timestamps arrive as ISO-8601 strings or epoch (seconds / milliseconds) numbers.
fn date(value: Option<&Value>) -> Option<DateTime<Utc>> {
    match value? {
        Value::String(text) => DateTime::parse_from_rfc3339(text.trim())
            .ok()
            .map(|dt| dt.with_timezone(&Utc)),
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

fn map_usage(usage: &Value, subscription: Option<&Value>) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Codebuff, "api key");

    let total = number(usage, &["quota", "limit", "creditsTotal"]);
    let remaining = number(
        usage,
        &["remainingBalance", "remaining", "creditsRemaining"],
    );
    let used = number(usage, &["creditsUsed", "used"]);
    let reset = date(
        usage
            .get("next_quota_reset")
            .or_else(|| usage.get("nextQuotaReset")),
    );

    // Credits window.
    let credits_used = match (used, total, remaining) {
        (Some(used), _, _) => Some(used),
        (None, Some(total), Some(remaining)) => Some((total - remaining).max(0.0)),
        _ => None,
    };
    match (total, credits_used) {
        (Some(total), Some(used)) if total > 0.0 => {
            let percent = (used / total * 100.0).clamp(0.0, 100.0);
            snapshot.windows.push(
                UsageWindow::new("credits", "Credits", percent)
                    .with_reset(reset)
                    .with_detail(format!("{} / {} credits", compact(used), compact(total))),
            );
        }
        _ if remaining.is_some() || credits_used.is_some() => {
            // Unknown cap but a balance exists: mark exhausted-unknown rather than a healthy bar.
            snapshot
                .windows
                .push(UsageWindow::new("credits", "Credits", 100.0).with_reset(reset));
        }
        _ => {}
    }

    if let Some(remaining) = remaining {
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(remaining),
            spend: credits_used,
            currency: None,
        });
        snapshot
            .summary
            .push(SummaryItem::new("Credits remaining", compact(remaining)));
    }

    // Subscription: weekly window + identity.
    if let Some(subscription) = subscription {
        let rate_limit = subscription.get("rateLimit");
        let weekly_limit = rate_limit.and_then(|rl| number(rl, &["weeklyLimit"]));
        let weekly_used = rate_limit
            .and_then(|rl| number(rl, &["weeklyUsed"]))
            .unwrap_or(0.0);
        if let Some(limit) = weekly_limit {
            if limit > 0.0 {
                let percent = (weekly_used.max(0.0) / limit * 100.0).clamp(0.0, 100.0);
                let weekly_reset = date(rate_limit.and_then(|rl| rl.get("weeklyResetsAt")));
                snapshot.windows.push(
                    UsageWindow::new("weekly", "Weekly", percent)
                        .with_reset(weekly_reset)
                        .with_detail(format!("{} / {}", compact(weekly_used), compact(limit))),
                );
            }
        }
        snapshot.plan = string(subscription, &["displayName", "tier"]).or_else(|| {
            subscription
                .get("subscription")
                .and_then(|s| string(s, &["displayName", "tier"]))
        });
        snapshot.account_label = string(subscription, &["email"])
            .or_else(|| subscription.get("user").and_then(|u| string(u, &["email"])));
    }
    snapshot
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

    #[test]
    fn computes_credit_percentage_from_quota_and_remaining() {
        let usage = json!({ "quota": 1000, "remainingBalance": 750, "next_quota_reset": "2026-08-01T00:00:00Z" });
        let snapshot = map_usage(&usage, None);
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("250 / 1,000 credits")
        );
        assert_eq!(snapshot.financials.as_ref().unwrap().balance, Some(750.0));
    }

    #[test]
    fn unknown_cap_with_balance_marks_exhausted_unknown() {
        let usage = json!({ "remaining": 40 });
        let snapshot = map_usage(&usage, None);
        assert_eq!(snapshot.windows[0].used_percent, 100.0);
    }

    #[test]
    fn adds_weekly_window_and_identity_from_subscription() {
        let usage = json!({ "quota": 100, "remainingBalance": 60 });
        let subscription = json!({
            "displayName": "Pro",
            "email": "dev@example.com",
            "rateLimit": { "weeklyUsed": 30, "weeklyLimit": 100 }
        });
        let snapshot = map_usage(&usage, Some(&subscription));
        let weekly = snapshot
            .windows
            .iter()
            .find(|w| w.id == "weekly")
            .expect("weekly");
        assert_eq!(weekly.used_percent, 30.0);
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
        assert_eq!(snapshot.account_label.as_deref(), Some("dev@example.com"));
    }
}
