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
use std::{collections::BTreeMap, env};

pub struct LLMProxyProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Llmproxy,
    display_name: "LLM Proxy",
    auth_kind: AuthKind::ApiKey,
    color: "#24b47e",
    dashboard_url: "",
    credential_hint: "Set an API key + base URL in Settings, or LLM_PROXY_API_KEY / LLM_PROXY_BASE_URL.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Llmproxy),
};

#[async_trait]
impl Provider for LLMProxyProvider {
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
        let url = quota_stats_url(&base_url);
        let response = context
            .client
            .get(url)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "LLM Proxy API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "LLM Proxy",
                status: response.status().as_u16(),
            });
        }
        let payload: QuotaStatsResponse = response.json().await?;
        Ok(map_usage(payload))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("LLM_PROXY_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing LLM Proxy API key.".into()))
}

fn resolve_base_url(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.base_url)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("LLM_PROXY_BASE_URL")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| {
            ProviderError::MissingCredentials(
                "LLM Proxy needs a base URL (set it in Settings or LLM_PROXY_BASE_URL).".into(),
            )
        })
}

/// `{base}` → `{base}/v1/quota-stats`, unless `{base}` already ends in `/v1`.
fn quota_stats_url(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.rsplit('/').next() == Some("v1") {
        format!("{trimmed}/quota-stats")
    } else {
        format!("{trimmed}/v1/quota-stats")
    }
}

#[derive(Debug, Deserialize)]
struct QuotaStatsResponse {
    #[serde(default)]
    providers: BTreeMap<String, ProviderStats>,
    #[serde(default)]
    summary: Option<Summary>,
}

#[derive(Debug, Deserialize)]
struct ProviderStats {
    #[serde(default)]
    credential_count: Option<i64>,
    #[serde(default)]
    active_count: Option<i64>,
    #[serde(default)]
    exhausted_count: Option<i64>,
    #[serde(default)]
    total_requests: Option<i64>,
    #[serde(default)]
    tokens: Option<Tokens>,
    #[serde(default, rename = "approx_cost")]
    approximate_cost: Option<f64>,
    #[serde(default)]
    quota_groups: Option<Vec<QuotaGroup>>,
}

#[derive(Debug, Deserialize)]
struct Tokens {
    #[serde(default)]
    input_cached: Option<i64>,
    #[serde(default)]
    input_uncached: Option<i64>,
    #[serde(default)]
    output: Option<i64>,
}

impl Tokens {
    fn total(&self) -> i64 {
        self.input_cached.unwrap_or(0) + self.input_uncached.unwrap_or(0) + self.output.unwrap_or(0)
    }
}

#[derive(Debug, Deserialize)]
struct QuotaGroup {
    #[serde(default)]
    remaining_percent: Option<f64>,
    #[serde(default)]
    reset_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Summary {
    #[serde(default)]
    total_requests: Option<i64>,
    #[serde(default)]
    total_tokens: Option<i64>,
    #[serde(default, rename = "approx_cost")]
    approximate_cost: Option<f64>,
}

fn map_usage(payload: QuotaStatsResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Llmproxy, "quota-stats");

    let provider_count = payload.providers.len();
    let sum = |pick: fn(&ProviderStats) -> Option<i64>| {
        payload.providers.values().filter_map(pick).sum::<i64>()
    };
    let credentials = sum(|s| s.credential_count);
    let active = sum(|s| s.active_count);
    let exhausted = sum(|s| s.exhausted_count);

    let min_remaining = payload
        .providers
        .values()
        .flat_map(|s| s.quota_groups.iter().flatten())
        .filter_map(|group| group.remaining_percent)
        .min_by(f64::total_cmp);
    let earliest_reset = payload
        .providers
        .values()
        .flat_map(|s| s.quota_groups.iter().flatten())
        .filter_map(|group| group.reset_time.as_deref().and_then(parse_reset))
        .min();

    if let Some(remaining) = min_remaining {
        let used_percent = (100.0 - remaining).clamp(0.0, 100.0);
        snapshot.windows.push(
            UsageWindow::new("quota", "Tightest quota", used_percent)
                .with_reset(earliest_reset)
                .with_detail(format!("{remaining:.0}% remaining")),
        );
    }

    let total_requests = payload
        .summary
        .as_ref()
        .and_then(|s| s.total_requests)
        .unwrap_or_else(|| sum(|s| s.total_requests));
    let total_tokens = payload
        .summary
        .as_ref()
        .and_then(|s| s.total_tokens)
        .unwrap_or_else(|| {
            payload
                .providers
                .values()
                .filter_map(|s| s.tokens.as_ref().map(Tokens::total))
                .sum()
        });
    let approx_cost = payload
        .summary
        .as_ref()
        .and_then(|s| s.approximate_cost)
        .or_else(|| {
            let total: f64 = payload
                .providers
                .values()
                .filter_map(|s| s.approximate_cost)
                .sum();
            (total > 0.0).then_some(total)
        });

    snapshot
        .summary
        .push(SummaryItem::new("Providers", provider_count.to_string()));
    if credentials > 0 {
        snapshot.summary.push(SummaryItem::new(
            "Credentials",
            format!("{active} active / {credentials} ({exhausted} exhausted)"),
        ));
    }
    if total_requests > 0 {
        snapshot
            .summary
            .push(SummaryItem::new("Requests", total_requests.to_string()));
    }
    if total_tokens > 0 {
        snapshot
            .summary
            .push(SummaryItem::new("Tokens", total_tokens.to_string()));
    }
    if let Some(cost) = approx_cost {
        snapshot
            .summary
            .push(SummaryItem::new("Est. cost", format!("${cost:.2}")));
        snapshot.financials = Some(FinancialSnapshot {
            balance: None,
            spend: Some(cost),
            currency: Some("USD".into()),
        });
    }
    snapshot
}

fn parse_reset(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_quota_stats_url() {
        assert_eq!(
            quota_stats_url("https://proxy.example.com"),
            "https://proxy.example.com/v1/quota-stats"
        );
        assert_eq!(
            quota_stats_url("https://proxy.example.com/v1/"),
            "https://proxy.example.com/v1/quota-stats"
        );
    }

    #[test]
    fn aggregates_providers_and_picks_tightest_quota() {
        let payload: QuotaStatsResponse = serde_json::from_value(serde_json::json!({
            "providers": {
                "openai": {
                    "credential_count": 2, "active_count": 1, "exhausted_count": 1,
                    "total_requests": 10, "approx_cost": 1.5,
                    "tokens": { "input_uncached": 100, "output": 50 },
                    "quota_groups": [{ "remaining_percent": 80.0, "reset_time": "2026-08-01T00:00:00Z" }]
                },
                "anthropic": {
                    "credential_count": 1, "active_count": 1, "exhausted_count": 0,
                    "total_requests": 5, "approx_cost": 0.5,
                    "quota_groups": [{ "remaining_percent": 20.0, "reset_time": "2026-07-20T00:00:00Z" }]
                }
            }
        }))
        .expect("payload");
        let snapshot = map_usage(payload);
        // Tightest quota = 20% remaining → 80% used.
        assert_eq!(snapshot.windows[0].used_percent, 80.0);
        assert_eq!(snapshot.summary[0].value, "2"); // providers
        assert!(
            snapshot
                .summary
                .iter()
                .any(|i| i.value == "2 active / 3 (1 exhausted)")
        );
        assert_eq!(snapshot.financials.as_ref().unwrap().spend, Some(2.0));
    }

    #[test]
    fn prefers_summary_totals_when_present() {
        let payload: QuotaStatsResponse = serde_json::from_value(serde_json::json!({
            "providers": { "x": { "total_requests": 1 } },
            "summary": { "total_requests": 999, "total_tokens": 5000, "approx_cost": 9.0 }
        }))
        .expect("payload");
        let snapshot = map_usage(payload);
        assert!(
            snapshot
                .summary
                .iter()
                .any(|i| i.label == "Requests" && i.value == "999")
        );
        assert!(
            snapshot
                .summary
                .iter()
                .any(|i| i.label == "Tokens" && i.value == "5000")
        );
    }
}
