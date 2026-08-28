use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde_json::Value;
use std::env;

pub struct KimiK2Provider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Kimik2,
    display_name: "Kimi K2 (unofficial)",
    auth_kind: AuthKind::ApiKey,
    color: "#4c00ff",
    dashboard_url: "https://kimrel.com/my-credits",
    credential_hint: "Set an API key in Settings or KIMI_K2_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Kimik2),
};

const CREDITS_URL: &str = "https://kimi-k2.ai/api/user/credits";

/// Candidate JSON paths for consumed / remaining credits. The upstream API is unofficial and has
/// shipped several key spellings, so both macOS and this port probe a list of aliases.
const CONSUMED_KEYS: &[&str] = &[
    "total_credits_consumed",
    "totalCreditsConsumed",
    "total_credits_used",
    "totalCreditsUsed",
    "credits_consumed",
    "creditsConsumed",
    "consumedCredits",
    "usedCredits",
    "total",
    "consumed",
];
const REMAINING_KEYS: &[&str] = &[
    "credits_remaining",
    "creditsRemaining",
    "remaining_credits",
    "remainingCredits",
    "available_credits",
    "availableCredits",
    "credits_left",
    "creditsLeft",
    "remaining",
];

#[async_trait]
impl Provider for KimiK2Provider {
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
            .get(CREDITS_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if response.status().as_u16() == 401 {
            return Err(ProviderError::Unauthorized(
                "Kimi K2 API key is invalid or expired.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Kimi K2",
                status: response.status().as_u16(),
            });
        }
        let body: Value = response.json().await?;
        map_usage(&body)
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            ["KIMI_K2_API_KEY", "KIMI_API_KEY"]
                .into_iter()
                .filter_map(|key| env::var(key).ok())
                .map(|value| value.trim().to_owned())
                .find(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Kimi K2 API key.".into()))
}

/// Search the root object plus common nesting containers (`data`, `result`, `usage`, `credits`)
/// for the first key in `keys` that holds a finite number.
fn lookup_number(body: &Value, keys: &[&str]) -> Option<f64> {
    let mut contexts: Vec<&Value> = vec![body];
    for container in ["data", "result", "usage", "credits"] {
        if let Some(value) = body.get(container) {
            contexts.push(value);
            for nested in ["usage", "credits"] {
                if let Some(inner) = value.get(nested) {
                    contexts.push(inner);
                }
            }
        }
    }
    for context in contexts {
        for key in keys {
            if let Some(number) = context.get(key).and_then(coerce_number) {
                return Some(number);
            }
        }
    }
    None
}

fn coerce_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64().filter(|n| n.is_finite()),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn map_usage(body: &Value) -> Result<ProviderSnapshot, ProviderError> {
    let consumed = lookup_number(body, CONSUMED_KEYS);
    let remaining = lookup_number(body, REMAINING_KEYS).map(|value| value.max(0.0));
    if consumed.is_none() && remaining.is_none() {
        return Err(ProviderError::Parse {
            provider: "Kimi K2",
            message: "no credit fields present in response".into(),
        });
    }

    let mut snapshot = ProviderSnapshot::new(ProviderId::Kimik2, "api key");
    if let Some(remaining) = remaining {
        snapshot.summary.push(SummaryItem::new(
            "Credits remaining",
            format_credits(remaining),
        ));
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(remaining),
            spend: consumed,
            currency: None,
        });
    }
    if let Some(consumed) = consumed {
        snapshot
            .summary
            .push(SummaryItem::new("Credits used", format_credits(consumed)));
    }
    Ok(snapshot)
}

fn format_credits(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{} credits", value as i64)
    } else {
        format!("{value:.2} credits")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_snake_case_credit_fields() {
        let body = serde_json::json!({
            "credits_remaining": 1200,
            "total_credits_consumed": 800
        });
        let snapshot = map_usage(&body).expect("usage");
        assert_eq!(snapshot.summary[0].value, "1200 credits");
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(financials.balance, Some(1200.0));
        assert_eq!(financials.spend, Some(800.0));
    }

    #[test]
    fn reads_nested_data_usage_object() {
        let body = serde_json::json!({
            "data": { "usage": { "remaining": "45.5", "consumed": 10 } }
        });
        let snapshot = map_usage(&body).expect("usage");
        assert_eq!(snapshot.summary[0].value, "45.50 credits");
    }

    #[test]
    fn missing_credit_fields_is_a_parse_error() {
        let body = serde_json::json!({ "unrelated": true });
        assert!(matches!(
            map_usage(&body),
            Err(ProviderError::Parse {
                provider: "Kimi K2",
                ..
            })
        ));
    }
}
