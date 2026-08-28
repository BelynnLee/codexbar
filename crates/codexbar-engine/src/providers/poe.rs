use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::env;

pub struct PoeProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Poe,
    display_name: "Poe",
    auth_kind: AuthKind::ApiKey,
    color: "#5d2de6",
    dashboard_url: "https://poe.com/api_key",
    credential_hint: "Set an API token in Settings or POE_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Poe),
};

const BALANCE_URL: &str = "https://api.poe.com/usage/current_balance";

#[async_trait]
impl Provider for PoeProvider {
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
            .get(BALANCE_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Invalid or expired Poe API token.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Poe",
                status: response.status().as_u16(),
            });
        }
        let balance: BalanceResponse = response.json().await?;
        Ok(map_usage(balance))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("POE_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Poe API token.".into()))
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    #[serde(default)]
    current_point_balance: Option<f64>,
}

fn map_usage(balance: BalanceResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Poe, "api key");
    match balance.current_point_balance {
        Some(points) => {
            snapshot
                .summary
                .push(SummaryItem::new("Point balance", format_points(points)));
        }
        None => {
            snapshot
                .summary
                .push(SummaryItem::new("Point balance", "No balance returned"));
        }
    }
    snapshot
}

fn format_points(points: f64) -> String {
    // Poe compute points are whole numbers in practice; render them without noise.
    if points.fract() == 0.0 {
        format!("{} points", points as i64)
    } else {
        format!("{points:.2} points")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_integer_point_balance() {
        let balance: BalanceResponse =
            serde_json::from_value(serde_json::json!({ "current_point_balance": 125000.0 }))
                .expect("balance");
        let snapshot = map_usage(balance);
        assert_eq!(snapshot.summary[0].value, "125000 points");
    }

    #[test]
    fn handles_missing_balance_gracefully() {
        let balance: BalanceResponse =
            serde_json::from_value(serde_json::json!({})).expect("balance");
        let snapshot = map_usage(balance);
        assert_eq!(snapshot.summary[0].value, "No balance returned");
    }
}
