use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::env;

pub struct GroqProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Groq,
    display_name: "Groq",
    auth_kind: AuthKind::ApiKey,
    color: "#f56844",
    dashboard_url: "https://console.groq.com/dashboard/metrics",
    credential_hint: "Set an API key in Settings or GROQ_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Groq),
};

/// Groq Cloud exposes usage as Prometheus rate metrics (5-minute rate windows). The base URL is
/// `https://api.groq.com/v1`; each query hits `/metrics/prometheus/api/v1/query`. Tokens are read
/// from `GROQ_API_KEY`.
const BASE_URL: &str = "https://api.groq.com/v1/metrics/prometheus/api/v1/query";

const REQUESTS_QUERY: &str = "sum(model_project_id_status_code:requests:rate5m)";
const INPUT_TOKENS_QUERY: &str = "sum(model_project_id:tokens_in:rate5m)";
const OUTPUT_TOKENS_QUERY: &str = "sum(model_project_id:tokens_out:rate5m)";
const CACHE_HITS_QUERY: &str = "sum(model_project_id:prompt_cache_hits:rate5m)";

#[async_trait]
impl Provider for GroqProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let requests = query_scalar(context, &api_key, REQUESTS_QUERY).await?;
        let input_tokens = query_scalar(context, &api_key, INPUT_TOKENS_QUERY).await?;
        let output_tokens = query_scalar(context, &api_key, OUTPUT_TOKENS_QUERY).await?;
        let cache_hits = query_scalar(context, &api_key, CACHE_HITS_QUERY).await?;
        Ok(map_usage(requests, input_tokens, output_tokens, cache_hits))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("GROQ_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Groq API key.".into()))
}

async fn query_scalar(
    context: &FetchContext<'_>,
    api_key: &str,
    query: &str,
) -> Result<f64, ProviderError> {
    let response = context
        .client
        .get(BASE_URL)
        .query(&[("query", query)])
        .bearer_auth(api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
    if matches!(response.status().as_u16(), 401 | 403) {
        return Err(ProviderError::Unauthorized(
            "Groq metrics access denied.".into(),
        ));
    }
    if !response.status().is_success() {
        return Err(ProviderError::Http {
            provider: "Groq",
            status: response.status().as_u16(),
        });
    }
    let payload: PrometheusResponse = response.json().await?;
    parse_scalar(payload)
}

#[derive(Debug, Deserialize)]
struct PrometheusResponse {
    status: String,
    #[serde(default)]
    data: Option<PrometheusData>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrometheusData {
    #[serde(default)]
    result: Vec<PrometheusSeries>,
}

#[derive(Debug, Deserialize)]
struct PrometheusSeries {
    #[serde(default)]
    value: Option<Vec<PrometheusValue>>,
}

/// Prometheus instant-vector values arrive as `[<unix_ts>, "<number>"]` — a float timestamp
/// followed by the sample rendered as a string.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PrometheusValue {
    Number(f64),
    Text(String),
}

impl PrometheusValue {
    fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            Self::Text(text) => text.parse().ok(),
        }
    }
}

fn parse_scalar(payload: PrometheusResponse) -> Result<f64, ProviderError> {
    if payload.status != "success" {
        return Err(ProviderError::Parse {
            provider: "Groq",
            message: payload.error.unwrap_or_else(|| "query failed".into()),
        });
    }
    let total = payload.data.map_or(0.0, |data| {
        data.result
            .iter()
            .filter_map(|series| series.value.as_ref()?.last()?.as_f64())
            .sum::<f64>()
    });
    Ok(total)
}

fn map_usage(
    requests_per_second: f64,
    input_tokens_per_second: f64,
    output_tokens_per_second: f64,
    cache_hits_per_second: f64,
) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Groq, "metrics");
    let requests_per_minute = requests_per_second * 60.0;
    let tokens_per_minute = (input_tokens_per_second + output_tokens_per_second) * 60.0;
    snapshot.windows.push(
        UsageWindow::new("requests", "Requests", 0.0)
            .with_window_minutes(5)
            .with_detail(format!("{} req/min", format_rate(requests_per_minute))),
    );
    snapshot.windows.push(
        UsageWindow::new("tokens", "Tokens", 0.0)
            .with_window_minutes(5)
            .with_detail(format!("{} tok/min", format_rate(tokens_per_minute))),
    );
    snapshot.summary.push(SummaryItem::new(
        "Requests",
        format!("{} req/min", format_rate(requests_per_minute)),
    ));
    snapshot.summary.push(SummaryItem::new(
        "Tokens",
        format!("{} tok/min", format_rate(tokens_per_minute)),
    ));
    if cache_hits_per_second > 0.0 {
        snapshot.summary.push(SummaryItem::new(
            "Cache hits",
            format!("{} cache/min", format_rate(cache_hits_per_second * 60.0)),
        ));
    }
    snapshot
}

fn format_rate(value: f64) -> String {
    if value >= 100.0 {
        format!("{value:.0}")
    } else if value >= 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.2}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(json: serde_json::Value) -> f64 {
        parse_scalar(serde_json::from_value(json).expect("payload")).expect("scalar")
    }

    #[test]
    fn sums_string_and_number_prometheus_samples() {
        let value = scalar(serde_json::json!({
            "status": "success",
            "data": { "result": [
                { "value": [1_700_000_000.0, "1.5"] },
                { "value": [1_700_000_000.0, 2.5] }
            ] }
        }));
        assert_eq!(value, 4.0);
    }

    #[test]
    fn empty_result_is_zero() {
        let value = scalar(serde_json::json!({
            "status": "success",
            "data": { "result": [] }
        }));
        assert_eq!(value, 0.0);
    }

    #[test]
    fn error_status_is_a_parse_error() {
        let payload: PrometheusResponse = serde_json::from_value(serde_json::json!({
            "status": "error",
            "error": "bad query"
        }))
        .expect("payload");
        assert!(matches!(
            parse_scalar(payload),
            Err(ProviderError::Parse {
                provider: "Groq",
                ..
            })
        ));
    }

    #[test]
    fn renders_per_minute_rates() {
        let snapshot = map_usage(2.0, 100.0, 50.0, 1.0);
        assert_eq!(snapshot.summary[0].value, "120 req/min");
        assert_eq!(snapshot.summary[1].value, "9000 tok/min");
        assert_eq!(snapshot.summary[2].value, "60.0 cache/min");
    }

    #[test]
    fn hides_cache_line_when_zero() {
        let snapshot = map_usage(1.0, 1.0, 1.0, 0.0);
        assert!(
            snapshot
                .summary
                .iter()
                .all(|item| item.label != "Cache hits")
        );
    }
}
