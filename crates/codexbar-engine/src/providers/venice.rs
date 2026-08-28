use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::{Deserialize, Deserializer};
use std::env;

pub struct VeniceProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Venice,
    display_name: "Venice",
    auth_kind: AuthKind::ApiKey,
    color: "#ff3d2e",
    dashboard_url: "https://venice.ai/settings/api",
    credential_hint: "Set an API key in Settings or VENICE_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Venice),
};

const BALANCE_URL: &str = "https://api.venice.ai/api/v1/billing/balance";

#[async_trait]
impl Provider for VeniceProvider {
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
                "Venice API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Venice",
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
            env::var("VENICE_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Venice API key.".into()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BalanceResponse {
    can_consume: bool,
    #[serde(default)]
    consumption_currency: Option<String>,
    balances: Balances,
    #[serde(default, deserialize_with = "flexible_double")]
    diem_epoch_allocation: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Balances {
    #[serde(default, deserialize_with = "flexible_double")]
    diem: Option<f64>,
    #[serde(default, deserialize_with = "flexible_double")]
    usd: Option<f64>,
}

/// Venice returns balances as either JSON numbers or numeric strings. Accept both,
/// treating an empty/absent value as `None` (matching the macOS decoder).
fn flexible_double<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<f64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flexible {
        Number(f64),
        Text(String),
        Null,
    }
    match Option::<Flexible>::deserialize(deserializer)? {
        Some(Flexible::Number(value)) => Ok(Some(value)),
        Some(Flexible::Text(text)) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                trimmed
                    .parse::<f64>()
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
        Some(Flexible::Null) | None => Ok(None),
    }
}

fn map_usage(balance: BalanceResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Venice, "api key");
    let active_currency = balance
        .consumption_currency
        .as_deref()
        .map(str::to_ascii_uppercase);
    let (used_percent, detail) = describe_balance(
        balance.can_consume,
        active_currency.as_deref(),
        balance.balances.diem,
        balance.balances.usd,
        balance.diem_epoch_allocation,
    );
    snapshot
        .windows
        .push(UsageWindow::new("balance", "Balance", used_percent).with_detail(detail));

    if let Some(usd) = balance.balances.usd.filter(|value| *value > 0.0) {
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(usd),
            spend: None,
            currency: Some("USD".into()),
        });
        snapshot
            .summary
            .push(SummaryItem::new("USD balance", format!("${usd:.2}")));
    }
    if let Some(diem) = balance.balances.diem.filter(|value| *value > 0.0) {
        snapshot
            .summary
            .push(SummaryItem::new("DIEM balance", format!("{diem:.2}")));
    }
    snapshot
}

fn describe_balance(
    can_consume: bool,
    active_currency: Option<&str>,
    diem: Option<f64>,
    usd: Option<f64>,
    diem_allocation: Option<f64>,
) -> (f64, String) {
    if !can_consume {
        return (100.0, "Balance unavailable for API calls".into());
    }
    if active_currency == Some("USD") {
        if let Some(usd) = usd.filter(|value| *value > 0.0) {
            return (0.0, format!("${usd:.2} USD remaining"));
        }
    }
    if active_currency != Some("USD") {
        if let (Some(diem), Some(allocation)) = (diem, diem_allocation) {
            if allocation > 0.0 {
                let used = ((allocation - diem) / allocation * 100.0).clamp(0.0, 100.0);
                return (
                    used,
                    format!("DIEM {diem:.2} / {allocation:.2} epoch allocation"),
                );
            }
        }
    }
    if let Some(diem) = diem.filter(|value| *value > 0.0) {
        return (0.0, format!("DIEM {diem:.2} remaining"));
    }
    if let Some(usd) = usd.filter(|value| *value > 0.0) {
        return (0.0, format!("${usd:.2} USD remaining"));
    }
    (100.0, "No Venice API balance available".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diem_allocation_drives_used_percent() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "canConsume": true,
            "consumptionCurrency": "DIEM",
            "balances": { "diem": "30", "usd": null },
            "diemEpochAllocation": "100"
        }))
        .expect("balance");
        let snapshot = map_usage(balance);
        assert_eq!(snapshot.windows[0].used_percent, 70.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("DIEM 30.00 / 100.00 epoch allocation")
        );
    }

    #[test]
    fn usd_currency_reports_zero_used_and_financials() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "canConsume": true,
            "consumptionCurrency": "USD",
            "balances": { "diem": null, "usd": 8.4 },
            "diemEpochAllocation": null
        }))
        .expect("balance");
        let snapshot = map_usage(balance);
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("$8.40 USD remaining")
        );
        assert_eq!(
            snapshot.financials.as_ref().and_then(|f| f.balance),
            Some(8.4)
        );
    }

    #[test]
    fn cannot_consume_is_fully_used() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "canConsume": false,
            "consumptionCurrency": "USD",
            "balances": { "diem": null, "usd": 0 },
            "diemEpochAllocation": null
        }))
        .expect("balance");
        let snapshot = map_usage(balance);
        assert_eq!(snapshot.windows[0].used_percent, 100.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("Balance unavailable for API calls")
        );
    }
}
