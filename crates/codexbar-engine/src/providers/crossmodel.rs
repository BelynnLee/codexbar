use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::env;

pub struct CrossModelProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Crossmodel,
    display_name: "CrossModel",
    auth_kind: AuthKind::ApiKey,
    color: "#7c3aed",
    dashboard_url: "https://crossmodel.ai/console/usage",
    credential_hint: "Set an API key in Settings or CROSSMODEL_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Crossmodel),
};

const BASE_URL: &str = "https://api.crossmodel.ai/v1";

#[async_trait]
impl Provider for CrossModelProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let credits = fetch_credits(context, &api_key).await?;
        // Usage windows are best-effort: a slow or failing /usage call must not block the balance.
        let usage = fetch_usage(context, &api_key).await.ok().flatten();
        Ok(map_usage(credits, usage))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("CROSSMODEL_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing CrossModel API key.".into()))
}

async fn fetch_credits(
    context: &FetchContext<'_>,
    api_key: &str,
) -> Result<CreditsResponse, ProviderError> {
    let response = context
        .client
        .get(format!("{BASE_URL}/credits"))
        .bearer_auth(api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
    if matches!(response.status().as_u16(), 401 | 403) {
        return Err(ProviderError::Unauthorized(
            "CrossModel API key is invalid.".into(),
        ));
    }
    if !response.status().is_success() {
        return Err(ProviderError::Http {
            provider: "CrossModel",
            status: response.status().as_u16(),
        });
    }
    Ok(response.json().await?)
}

async fn fetch_usage(
    context: &FetchContext<'_>,
    api_key: &str,
) -> Result<Option<UsageResponse>, ProviderError> {
    let response = context
        .client
        .get(format!("{BASE_URL}/usage"))
        .bearer_auth(api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
    if !response.status().is_success() {
        return Ok(None);
    }
    Ok(response.json().await.ok())
}

#[derive(Debug, Deserialize)]
struct CreditsResponse {
    #[serde(default)]
    currency: String,
    #[serde(default)]
    balance_micro: i64,
    #[serde(default)]
    uncollected_micro: i64,
}

#[derive(Debug, Deserialize)]
struct UsageResponse {
    #[serde(default)]
    currency: String,
    daily: UsageWindowDto,
    weekly: UsageWindowDto,
    monthly: UsageWindowDto,
}

#[derive(Debug, Deserialize)]
struct UsageWindowDto {
    #[serde(default)]
    cost_micro: i64,
    #[serde(default)]
    total_tokens: i64,
    #[serde(default)]
    request_count: i64,
}

fn major_units(micro: i64) -> f64 {
    micro as f64 / 1_000_000.0
}

fn map_usage(credits: CreditsResponse, usage: Option<UsageResponse>) -> ProviderSnapshot {
    let currency = credits.currency.trim().to_uppercase();
    let balance = major_units(credits.balance_micro);
    let uncollected = major_units(credits.uncollected_micro);

    let mut snapshot = ProviderSnapshot::new(ProviderId::Crossmodel, "api key");
    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(balance),
        spend: None,
        currency: if currency.is_empty() {
            None
        } else {
            Some(currency.clone())
        },
    });
    snapshot.summary.push(SummaryItem::new(
        "Balance",
        format_money(balance, &currency),
    ));
    if uncollected > 0.0 {
        snapshot.summary.push(SummaryItem::new(
            "Uncollected",
            format_money(uncollected, &currency),
        ));
    }

    // Only trust usage windows whose currency matches the wallet's.
    if let Some(usage) = usage.filter(|u| u.currency.trim().to_uppercase() == currency) {
        for (label, window) in [
            ("Today", &usage.daily),
            ("This week", &usage.weekly),
            ("This month", &usage.monthly),
        ] {
            let spend = major_units(window.cost_micro);
            if spend > 0.0 || window.request_count > 0 {
                snapshot.summary.push(SummaryItem::new(
                    label,
                    format!(
                        "{} · {} req · {} tok",
                        format_money(spend, &currency),
                        window.request_count,
                        window.total_tokens
                    ),
                ));
            }
        }
    }
    snapshot
}

fn format_money(value: f64, currency: &str) -> String {
    match currency {
        "USD" | "" => format!("${value:.2}"),
        other => format!("{value:.2} {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credits(json: serde_json::Value) -> CreditsResponse {
        serde_json::from_value(json).expect("credits")
    }

    #[test]
    fn converts_micro_units_to_balance() {
        let snapshot = map_usage(
            credits(serde_json::json!({
                "currency": "usd",
                "balance_micro": 12_500_000i64,
                "uncollected_micro": 250_000i64
            })),
            None,
        );
        assert_eq!(snapshot.summary[0].value, "$12.50");
        assert_eq!(snapshot.summary[1].value, "$0.25");
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(financials.balance, Some(12.5));
        assert_eq!(financials.currency.as_deref(), Some("USD"));
    }

    #[test]
    fn appends_matching_currency_usage_windows() {
        let usage: UsageResponse = serde_json::from_value(serde_json::json!({
            "currency": "USD",
            "daily": { "cost_micro": 1_000_000i64, "total_tokens": 500, "request_count": 3 },
            "weekly": { "cost_micro": 0, "total_tokens": 0, "request_count": 0 },
            "monthly": { "cost_micro": 5_000_000i64, "total_tokens": 9000, "request_count": 40 }
        }))
        .expect("usage");
        let snapshot = map_usage(
            credits(serde_json::json!({ "currency": "USD", "balance_micro": 0 })),
            Some(usage),
        );
        assert!(snapshot.summary.iter().any(|item| item.label == "Today"));
        assert!(
            snapshot
                .summary
                .iter()
                .any(|item| item.label == "This month")
        );
        assert!(
            snapshot
                .summary
                .iter()
                .all(|item| item.label != "This week")
        );
    }

    #[test]
    fn drops_usage_with_mismatched_currency() {
        let usage: UsageResponse = serde_json::from_value(serde_json::json!({
            "currency": "EUR",
            "daily": { "cost_micro": 1_000_000i64, "request_count": 3 },
            "weekly": { "cost_micro": 0 },
            "monthly": { "cost_micro": 0 }
        }))
        .expect("usage");
        let snapshot = map_usage(
            credits(serde_json::json!({ "currency": "USD", "balance_micro": 0 })),
            Some(usage),
        );
        assert!(snapshot.summary.iter().all(|item| item.label != "Today"));
    }
}
