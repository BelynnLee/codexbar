use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::env;

pub struct OpenRouterProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Openrouter,
    display_name: "OpenRouter",
    auth_kind: AuthKind::ApiKey,
    color: "#6d5dfc",
    dashboard_url: "https://openrouter.ai/settings/credits",
    credential_hint: "Set an API key in Settings or OPENROUTER_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Openrouter),
};

#[async_trait]
impl Provider for OpenRouterProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let credits_response = context
            .client
            .get("https://openrouter.ai/api/v1/credits")
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .header("X-Title", "CodexBar Windows")
            .send()
            .await?;
        if matches!(credits_response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "OpenRouter API key is invalid.".into(),
            ));
        }
        if !credits_response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "OpenRouter",
                status: credits_response.status().as_u16(),
            });
        }
        let credits: CreditsResponse = credits_response.json().await?;

        // Key quota is optional enrichment. Credits remain usable if this endpoint is absent or slow.
        let key_data = match context
            .client
            .get("https://openrouter.ai/api/v1/key")
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => response
                .json::<KeyResponse>()
                .await
                .ok()
                .map(|response| response.data),
            _ => None,
        };
        Ok(map_usage(credits.data, key_data))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("OPENROUTER_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing OpenRouter API key.".into()))
}

#[derive(Debug, Deserialize)]
struct CreditsResponse {
    data: Credits,
}

#[derive(Debug, Deserialize)]
struct Credits {
    total_credits: f64,
    total_usage: f64,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    data: KeyData,
}

#[derive(Debug, Deserialize)]
struct KeyData {
    limit: Option<f64>,
    usage: Option<f64>,
    usage_daily: Option<f64>,
    usage_weekly: Option<f64>,
    usage_monthly: Option<f64>,
    rate_limit: Option<RateLimit>,
}

#[derive(Debug, Deserialize)]
struct RateLimit {
    requests: u64,
    interval: String,
}

fn map_usage(credits: Credits, key: Option<KeyData>) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Openrouter, "api key");
    let balance = (credits.total_credits - credits.total_usage).max(0.0);
    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(balance),
        spend: Some(credits.total_usage),
        currency: Some("USD".into()),
    });
    snapshot.summary.extend([
        SummaryItem::new("Balance", format!("${balance:.2}")),
        SummaryItem::new("Lifetime usage", format!("${:.2}", credits.total_usage)),
    ]);
    if let Some(key) = key {
        if let (Some(limit), Some(usage)) = (key.limit, key.usage) {
            if limit > 0.0 && usage >= 0.0 {
                snapshot.windows.push(
                    UsageWindow::new("key-quota", "Key quota", (usage / limit) * 100.0)
                        .with_detail(format!("${usage:.2} / ${limit:.2}")),
                );
            }
        }
        for (label, value) in [
            ("Today", key.usage_daily),
            ("This week", key.usage_weekly),
            ("This month", key.usage_monthly),
        ] {
            if let Some(value) = value {
                snapshot
                    .summary
                    .push(SummaryItem::new(label, format!("${value:.2}")));
            }
        }
        if let Some(rate) = key.rate_limit {
            snapshot.summary.push(SummaryItem::new(
                "Rate limit",
                format!("{} requests / {}", rate.requests, rate.interval),
            ));
        }
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_quota_drives_primary_window() {
        let snapshot = map_usage(
            Credits {
                total_credits: 50.0,
                total_usage: 45.389_559_632_5,
            },
            Some(KeyData {
                limit: Some(20.0),
                usage: Some(5.0),
                usage_daily: None,
                usage_weekly: None,
                usage_monthly: None,
                rate_limit: None,
            }),
        );
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
        assert_eq!(snapshot.summary[0].value, "$4.61");
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(
            format!("${:.2}", financials.balance.expect("balance")),
            snapshot.summary[0].value
        );
        assert_eq!(
            format!("${:.2}", financials.spend.expect("spend")),
            snapshot.summary[1].value
        );
        assert_eq!(financials.currency.as_deref(), Some("USD"));
    }
}
