use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::env;

pub struct OpenCodeZenProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Opencodezen,
    display_name: "OpenCode Zen",
    auth_kind: AuthKind::ApiKey,
    color: "#e88c3a",
    dashboard_url: "https://opencode.ai/zen",
    // Zen's API key only reaches the inference endpoints (/responses, /messages, /chat/completions,
    // /models). There is no credit/usage/billing endpoint, so we report key validity + model access
    // instead of a dollar balance. Confirmed against the Zen docs and by probing the live API.
    credential_hint: "Set an API key in Settings or OPENCODE_ZEN_API_KEY. Zen exposes model access only — no balance API.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Opencodezen),
};

const MODELS_URL: &str = "https://opencode.ai/zen/v1/models";

#[async_trait]
impl Provider for OpenCodeZenProvider {
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
            .get(MODELS_URL)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .header("X-Title", "CodexBar Windows")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "OpenCode Zen API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "OpenCode Zen",
                status: response.status().as_u16(),
            });
        }
        let models: ModelsResponse = response.json().await?;
        Ok(map_usage(models))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("OPENCODE_ZEN_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing OpenCode Zen API key.".into()))
}

#[derive(Debug, Deserialize)]
struct ModelsResponse {
    #[serde(default)]
    data: Vec<ModelEntry>,
}

#[derive(Debug, Deserialize)]
struct ModelEntry {
    id: String,
}

fn map_usage(models: ModelsResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Opencodezen, "api key");
    snapshot.summary.push(SummaryItem::new("API key", "Valid"));
    snapshot
        .summary
        .push(SummaryItem::new("Models", models.data.len().to_string()));
    let sample: Vec<String> = models
        .data
        .iter()
        .take(4)
        .map(|entry| entry.id.clone())
        .collect();
    if !sample.is_empty() {
        snapshot
            .summary
            .push(SummaryItem::new("Available", sample.join(", ")));
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_models_into_summary() {
        let models: ModelsResponse = serde_json::from_value(serde_json::json!({
            "object": "list",
            "data": [
                { "id": "claude-opus-4-8", "object": "model", "owned_by": "opencode" },
                { "id": "claude-sonnet-5", "object": "model", "owned_by": "opencode" }
            ]
        }))
        .expect("models payload");
        let snapshot = map_usage(models);
        assert_eq!(snapshot.summary[0].value, "Valid");
        assert_eq!(snapshot.summary[1].value, "2");
        assert_eq!(
            snapshot.summary[2].value,
            "claude-opus-4-8, claude-sonnet-5"
        );
    }

    #[test]
    fn missing_key_is_reported() {
        let error = resolve_api_key(&ProviderAccount::default()).unwrap_err();
        assert!(matches!(error, ProviderError::MissingCredentials(_)));
    }
}
