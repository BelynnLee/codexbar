use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::env;

pub struct AzureOpenAIProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Azureopenai,
    display_name: "Azure OpenAI",
    auth_kind: AuthKind::ApiKey,
    color: "#0a7bbb",
    dashboard_url: "https://portal.azure.com",
    credential_hint: "Set an API key, endpoint (base URL), and deployment in Settings, or \
AZURE_OPENAI_API_KEY / AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_DEPLOYMENT_NAME.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Azureopenai),
};

const DEFAULT_API_VERSION: &str = "2024-10-21";

#[async_trait]
impl Provider for AzureOpenAIProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let endpoint = resolve_endpoint(account)?;
        let deployment = resolve_deployment(account)?;
        let api_version = resolve_api_version();
        let url = chat_completions_url(&endpoint, &deployment, &api_version);

        let response = context
            .client
            .post(&url)
            .header("api-key", &api_key)
            .header("Accept", "application/json")
            .json(&validation_body(&deployment, &api_version))
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Azure OpenAI API key was rejected.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Azure OpenAI",
                status: response.status().as_u16(),
            });
        }
        let body: ChatCompletionResponse = response.json().await?;
        Ok(map_usage(&endpoint, &deployment, body.model.as_deref()))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("AZURE_OPENAI_API_KEY"))
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Azure OpenAI API key.".into()))
}

fn resolve_endpoint(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.base_url)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("AZURE_OPENAI_ENDPOINT"))
        .map(|value| value.trim_end_matches('/').to_owned())
        .ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Azure OpenAI needs an endpoint (set the base URL in Settings or \
AZURE_OPENAI_ENDPOINT)."
                    .into(),
            )
        })
}

fn resolve_deployment(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.deployment)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("AZURE_OPENAI_DEPLOYMENT_NAME"))
        .ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Azure OpenAI needs a deployment name (set it in Settings or \
AZURE_OPENAI_DEPLOYMENT_NAME)."
                    .into(),
            )
        })
}

fn resolve_api_version() -> String {
    env_var("AZURE_OPENAI_API_VERSION").unwrap_or_else(|| DEFAULT_API_VERSION.to_owned())
}

fn env_var(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// `{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={version}`, avoiding a
/// duplicated `openai` segment when the configured endpoint already ends in one.
fn chat_completions_url(endpoint: &str, deployment: &str, api_version: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    let root = if trimmed
        .rsplit('/')
        .next()
        .is_some_and(|segment| segment.eq_ignore_ascii_case("openai"))
    {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/openai")
    };
    format!("{root}/deployments/{deployment}/chat/completions?api-version={api_version}")
}

fn validation_body(deployment: &str, api_version: &str) -> serde_json::Value {
    if api_version.trim().eq_ignore_ascii_case("v1") {
        json!({
            "messages": [{ "role": "user", "content": "ping" }],
            "model": deployment,
            "max_completion_tokens": 1,
        })
    } else {
        json!({
            "messages": [{ "role": "user", "content": "ping" }],
            "max_tokens": 1,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    #[serde(default)]
    model: Option<String>,
}

fn map_usage(endpoint: &str, deployment: &str, model: Option<&str>) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Azureopenai, "api key");
    let host = endpoint_host(endpoint);
    let model = model.map(str::trim).filter(|value| !value.is_empty());

    let detail = model.map_or_else(
        || format!("Deployment: {deployment}"),
        |model| format!("Deployment: {deployment} · Model: {model}"),
    );
    // Azure OpenAI has no usage/quota endpoint; a successful validation call proves the deployment is
    // reachable. Faithful to macOS, the card shows a 0% window carrying the deployment/model detail.
    snapshot
        .windows
        .push(UsageWindow::new("deployment", "Deployment", 0.0).with_detail(detail));

    snapshot
        .summary
        .push(SummaryItem::new("Endpoint", host.clone()));
    snapshot
        .summary
        .push(SummaryItem::new("Deployment", deployment.to_owned()));
    if let Some(model) = model {
        snapshot
            .summary
            .push(SummaryItem::new("Model", model.to_owned()));
    }
    snapshot.plan = Some(host);
    snapshot
}

/// Best-effort host extraction for display; falls back to the raw endpoint on a parse failure.
fn endpoint_host(endpoint: &str) -> String {
    url::Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| endpoint.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_deployment_chat_completions_url() {
        assert_eq!(
            chat_completions_url("https://res.openai.azure.com/", "gpt4o", "2024-10-21"),
            "https://res.openai.azure.com/openai/deployments/gpt4o/chat/completions?api-version=2024-10-21"
        );
    }

    #[test]
    fn does_not_duplicate_existing_openai_segment() {
        assert_eq!(
            chat_completions_url("https://res.openai.azure.com/openai", "gpt4o", "2024-10-21"),
            "https://res.openai.azure.com/openai/deployments/gpt4o/chat/completions?api-version=2024-10-21"
        );
    }

    #[test]
    fn validation_body_switches_shape_for_v1() {
        assert_eq!(validation_body("dep", "2024-10-21")["max_tokens"], json!(1));
        let v1 = validation_body("dep", "v1");
        assert_eq!(v1["model"], json!("dep"));
        assert_eq!(v1["max_completion_tokens"], json!(1));
    }

    #[test]
    fn maps_deployment_and_model_into_detail_and_summary() {
        let snapshot = map_usage("https://res.openai.azure.com", "gpt4o", Some("gpt-4o-2024"));
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("Deployment: gpt4o · Model: gpt-4o-2024")
        );
        assert_eq!(snapshot.summary[0].value, "res.openai.azure.com");
        assert!(
            snapshot
                .summary
                .iter()
                .any(|item| item.label == "Model" && item.value == "gpt-4o-2024")
        );
    }

    #[test]
    fn omits_model_summary_when_absent() {
        let snapshot = map_usage("https://res.openai.azure.com", "gpt4o", None);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("Deployment: gpt4o")
        );
        assert!(snapshot.summary.iter().all(|item| item.label != "Model"));
    }
}
