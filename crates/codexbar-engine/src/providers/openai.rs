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
use serde::Deserialize;
use std::env;

pub struct OpenAIProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Openai,
    display_name: "OpenAI",
    auth_kind: AuthKind::ApiKey,
    color: "#0f8285",
    dashboard_url: "https://platform.openai.com/usage",
    credential_hint: "Set an API key in Settings or OPENAI_API_KEY. Credit balance needs a legacy/admin billing key.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Openai),
};

// Legacy billing endpoint. Project keys (`sk-proj-…`) and service-account keys get 401/403 here; it
// needs a legacy user key or an organization Admin key with billing access. Mirrors the macOS build.
const CREDIT_GRANTS_URL: &str = "https://api.openai.com/v1/dashboard/billing/credit_grants";

#[async_trait]
impl Provider for OpenAIProvider {
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
            .get(CREDIT_GRANTS_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        match response.status().as_u16() {
            401 => {
                return Err(ProviderError::Unauthorized(
                    "OpenAI rejected this key for billing access. Use a legacy user key or an \
                     organization Admin key; project keys do not expose credit grants."
                        .into(),
                ));
            }
            403 => {
                return Err(ProviderError::Unauthorized(
                    "OpenAI billing endpoint returned 403. Use a legacy key with billing access; \
                     project keys may not expose credit grants."
                        .into(),
                ));
            }
            status if !(200..300).contains(&status) => {
                return Err(ProviderError::Http {
                    provider: "OpenAI",
                    status,
                });
            }
            _ => {}
        }
        let grants: CreditGrants = response.json().await?;
        Ok(map_usage(grants, Utc::now()))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            ["OPENAI_ADMIN_KEY", "OPENAI_API_KEY"]
                .into_iter()
                .filter_map(|key| env::var(key).ok())
                .map(|value| value.trim().to_owned())
                .find(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing OpenAI API key.".into()))
}

#[derive(Debug, Deserialize)]
struct CreditGrants {
    #[serde(default)]
    total_granted: f64,
    #[serde(default)]
    total_used: f64,
    #[serde(default)]
    total_available: f64,
    #[serde(default)]
    grants: Option<GrantList>,
}

#[derive(Debug, Deserialize)]
struct GrantList {
    #[serde(default)]
    data: Vec<Grant>,
}

#[derive(Debug, Deserialize)]
struct Grant {
    #[serde(default)]
    expires_at: Option<f64>,
}

fn map_usage(grants: CreditGrants, now: DateTime<Utc>) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Openai, "billing api");

    let used_percent = if grants.total_granted > 0.0 {
        (grants.total_used / grants.total_granted * 100.0).clamp(0.0, 100.0)
    } else if grants.total_available > 0.0 {
        0.0
    } else {
        100.0
    };

    let next_expiry = grants
        .grants
        .as_ref()
        .map(|list| list.data.as_slice())
        .unwrap_or_default()
        .iter()
        .filter_map(|grant| grant.expires_at)
        .filter(|seconds| *seconds > now.timestamp() as f64)
        .min_by(f64::total_cmp)
        .and_then(|seconds| Utc.timestamp_opt(seconds as i64, 0).single());

    snapshot.windows.push(
        UsageWindow::new("credits", "API credits", used_percent)
            .with_reset(next_expiry)
            .with_detail(format!("${:.2} available", grants.total_available.max(0.0))),
    );

    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(grants.total_available),
        spend: Some(grants.total_used.max(0.0)),
        currency: Some("USD".into()),
    });
    snapshot.summary.push(SummaryItem::new(
        "Available",
        format!("${:.2}", grants.total_available.max(0.0)),
    ));
    snapshot.summary.push(SummaryItem::new(
        "Granted",
        format!("${:.2}", grants.total_granted.max(0.0)),
    ));
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: serde_json::Value, now: DateTime<Utc>) -> ProviderSnapshot {
        map_usage(serde_json::from_value(value).expect("grants"), now)
    }

    #[test]
    fn computes_used_percent_and_balance() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let snapshot = parse(
            json!({ "total_granted": 100.0, "total_used": 25.0, "total_available": 75.0 }),
            now,
        );
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("$75.00 available")
        );
        assert_eq!(snapshot.financials.as_ref().unwrap().balance, Some(75.0));
    }

    #[test]
    fn zero_grant_with_available_reads_healthy_but_exhausted_reads_full() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let healthy = parse(
            json!({ "total_granted": 0.0, "total_available": 10.0 }),
            now,
        );
        assert_eq!(healthy.windows[0].used_percent, 0.0);
        let exhausted = parse(json!({ "total_granted": 0.0, "total_available": 0.0 }), now);
        assert_eq!(exhausted.windows[0].used_percent, 100.0);
    }

    #[test]
    fn picks_the_nearest_future_grant_expiry_as_reset() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let snapshot = parse(
            json!({
                "total_granted": 100.0,
                "total_used": 10.0,
                "total_available": 90.0,
                "grants": { "data": [
                    { "expires_at": 1_600_000_000 },
                    { "expires_at": 1_800_000_000 },
                    { "expires_at": 1_750_000_000 }
                ] }
            }),
            now,
        );
        let reset = snapshot.windows[0].resets_at.expect("reset");
        assert_eq!(reset.timestamp(), 1_750_000_000);
    }
}
