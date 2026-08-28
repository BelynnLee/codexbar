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

pub struct CrofProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Crof,
    display_name: "Crof",
    auth_kind: AuthKind::ApiKey,
    color: "#2eab94",
    dashboard_url: "https://crof.ai/dashboard",
    credential_hint: "Set an API key in Settings or CROF_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Crof),
};

const USAGE_URL: &str = "https://crof.ai/usage_api/";

#[async_trait]
impl Provider for CrofProvider {
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
                "Crof API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Crof",
                status: response.status().as_u16(),
            });
        }
        let usage: UsageResponse = response.json().await?;
        Ok(map_usage(usage))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            ["CROF_API_KEY", "CROFAI_API_KEY"]
                .into_iter()
                .filter_map(|key| env::var(key).ok())
                .map(|value| value.trim().to_owned())
                .find(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Crof API key.".into()))
}

#[derive(Debug, Deserialize)]
struct UsageResponse {
    #[serde(default)]
    credits: f64,
    #[serde(default, rename = "requests_plan")]
    requests_plan: f64,
    #[serde(default, rename = "usable_requests")]
    usable_requests: f64,
}

fn map_usage(usage: UsageResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Crof, "api key");

    let used_percent = if usage.requests_plan > 0.0 {
        let usable = usage.usable_requests.clamp(0.0, usage.requests_plan);
        let remaining_percent = (usable / usage.requests_plan * 100.0)
            .floor()
            .clamp(0.0, 100.0);
        100.0 - remaining_percent
    } else {
        100.0
    };
    snapshot.windows.push(
        UsageWindow::new("requests", "Requests", used_percent)
            .with_window_minutes(24 * 60)
            .with_detail(format!(
                "{} requests left",
                format_number(usage.usable_requests)
            )),
    );

    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(usage.credits),
        spend: None,
        currency: Some("USD".into()),
    });
    snapshot.summary.push(SummaryItem::new(
        "Requests left",
        format_number(usage.usable_requests),
    ));
    snapshot.summary.push(SummaryItem::new(
        "Credits",
        format!("${:.2}", usage.credits.max(0.0)),
    ));
    snapshot
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 {
        (value.max(0.0) as i64).to_string()
    } else {
        format!("{:.1}", value.max(0.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> ProviderSnapshot {
        map_usage(serde_json::from_value(json).expect("usage"))
    }

    #[test]
    fn computes_used_percent_from_usable_requests() {
        let snapshot = parse(serde_json::json!({
            "credits": 4.25,
            "requests_plan": 1000.0,
            "usable_requests": 250.0
        }));
        // 25% remaining → 75% used.
        assert_eq!(snapshot.windows[0].used_percent, 75.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("250 requests left")
        );
        assert_eq!(snapshot.summary[1].value, "$4.25");
        assert_eq!(snapshot.financials.as_ref().unwrap().balance, Some(4.25));
    }

    #[test]
    fn zero_plan_reports_fully_used() {
        let snapshot = parse(serde_json::json!({
            "credits": 0.0,
            "requests_plan": 0.0,
            "usable_requests": 0.0
        }));
        assert_eq!(snapshot.windows[0].used_percent, 100.0);
    }
}
