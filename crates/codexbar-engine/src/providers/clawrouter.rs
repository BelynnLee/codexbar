use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use std::env;

pub struct ClawRouterProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Clawrouter,
    display_name: "ClawRouter",
    auth_kind: AuthKind::ApiKey,
    color: "#596ef6",
    dashboard_url: "https://clawrouter.openclaw.ai/dashboard/access",
    credential_hint: "Set an API key in Settings or CLAWROUTER_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Clawrouter),
};

const USAGE_URL: &str = "https://clawrouter.openclaw.ai/v1/usage";

#[async_trait]
impl Provider for ClawRouterProvider {
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
            .get(USAGE_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "ClawRouter API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "ClawRouter",
                status: response.status().as_u16(),
            });
        }
        let payload: UsageResponse = response.json().await?;
        Ok(map_usage(payload))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("CLAWROUTER_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing ClawRouter API key.".into()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageResponse {
    budget: Budget,
    usage: Usage,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Budget {
    #[serde(default)]
    configured: bool,
    #[serde(default)]
    window_key: Option<String>,
    #[serde(default)]
    limit_micros: Option<i64>,
    #[serde(default)]
    spent_micros: Option<i64>,
    #[serde(default)]
    remaining_micros: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Usage {
    summary: Summary,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    #[serde(default)]
    request_count: i64,
    #[serde(default)]
    total_tokens: i64,
    #[serde(default)]
    actual_cost_micros: i64,
}

fn dollars(micros: i64) -> f64 {
    micros as f64 / 1_000_000.0
}

fn map_usage(payload: UsageResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Clawrouter, "api key");
    let limit = payload.budget.limit_micros.map(dollars);
    let spent = payload.budget.spent_micros.map(dollars);
    let remaining = payload.budget.remaining_micros.map(dollars);
    let resets_at = payload
        .budget
        .window_key
        .as_deref()
        .and_then(next_monthly_reset);

    snapshot.plan = Some(if payload.budget.configured {
        "Managed monthly budget".into()
    } else {
        "Unmetered".into()
    });

    if let (Some(spent), Some(limit)) = (spent, limit) {
        if limit > 0.0 {
            let used_percent = (spent / limit * 100.0).clamp(0.0, 100.0);
            snapshot.windows.push(
                UsageWindow::new("budget", "Monthly budget", used_percent)
                    .with_reset(resets_at)
                    .with_detail(format!("${spent:.2} / ${limit:.2}")),
            );
        }
    }

    snapshot.financials = Some(FinancialSnapshot {
        balance: remaining,
        spend: spent,
        currency: Some("USD".into()),
    });
    if let Some(remaining) = remaining {
        snapshot
            .summary
            .push(SummaryItem::new("Remaining", format!("${remaining:.2}")));
    }
    let summary = &payload.usage.summary;
    snapshot.summary.push(SummaryItem::new(
        "Requests",
        summary.request_count.to_string(),
    ));
    if summary.total_tokens > 0 {
        snapshot
            .summary
            .push(SummaryItem::new("Tokens", summary.total_tokens.to_string()));
    }
    if summary.actual_cost_micros > 0 {
        snapshot.summary.push(SummaryItem::new(
            "Spend",
            format!("${:.2}", dollars(summary.actual_cost_micros)),
        ));
    }
    snapshot
}

/// The budget window key ends in a `YYYY-MM` suffix; the budget resets at 00:00 UTC on the first
/// day of the following month.
fn next_monthly_reset(window_key: &str) -> Option<chrono::DateTime<Utc>> {
    let suffix = window_key.rsplit('/').next()?;
    let mut parts = suffix.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    Utc.with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
        .single()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> ProviderSnapshot {
        map_usage(serde_json::from_value(json).expect("usage"))
    }

    #[test]
    fn computes_budget_percentage_and_financials() {
        let snapshot = parse(serde_json::json!({
            "budget": {
                "configured": true,
                "windowKey": "budget/2026-07",
                "limitMicros": 100_000_000i64,
                "spentMicros": 25_000_000i64,
                "remainingMicros": 75_000_000i64
            },
            "usage": { "summary": { "requestCount": 12, "totalTokens": 3400, "actualCostMicros": 25_000_000i64 } }
        }));
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("$25.00 / $100.00")
        );
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(financials.balance, Some(75.0));
        assert_eq!(snapshot.plan.as_deref(), Some("Managed monthly budget"));
    }

    #[test]
    fn unmetered_budget_has_no_window() {
        let snapshot = parse(serde_json::json!({
            "budget": { "configured": false },
            "usage": { "summary": { "requestCount": 3 } }
        }));
        assert!(snapshot.windows.is_empty());
        assert_eq!(snapshot.plan.as_deref(), Some("Unmetered"));
    }

    #[test]
    fn parses_next_monthly_reset() {
        let reset = next_monthly_reset("budget/2026-07").expect("reset");
        assert_eq!(reset.to_rfc3339(), "2026-08-01T00:00:00+00:00");
        let december = next_monthly_reset("x/2026-12").expect("reset");
        assert_eq!(december.to_rfc3339(), "2027-01-01T00:00:00+00:00");
    }
}
