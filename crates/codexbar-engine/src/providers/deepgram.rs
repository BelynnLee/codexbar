use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::env;

pub struct DeepgramProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Deepgram,
    display_name: "Deepgram",
    auth_kind: AuthKind::ApiKey,
    color: "#6467f2",
    dashboard_url: "https://console.deepgram.com/",
    credential_hint: "Set an API key in Settings or DEEPGRAM_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Deepgram),
};

const BASE_URL: &str = "https://api.deepgram.com/v1";

#[async_trait]
impl Provider for DeepgramProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let project_id = resolve_project_id(account);

        let projects = match project_id {
            Some(id) => vec![DeepgramProject {
                project_id: id,
                name: None,
            }],
            None => list_projects(context, &api_key).await?,
        };
        if projects.is_empty() {
            return Err(ProviderError::Parse {
                provider: "Deepgram",
                message: "no projects were returned for this API key".into(),
            });
        }

        let mut snapshots = Vec::with_capacity(projects.len());
        for project in &projects {
            snapshots.push(fetch_project_usage(context, &api_key, project).await?);
        }
        Ok(map_usage(&snapshots))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("DEEPGRAM_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Deepgram API key.".into()))
}

fn resolve_project_id(account: &ProviderAccount) -> Option<String> {
    ProviderConfig::normalized_secret(&account.project_id)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("DEEPGRAM_PROJECT_ID")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
}

async fn list_projects(
    context: &FetchContext<'_>,
    api_key: &str,
) -> Result<Vec<DeepgramProject>, ProviderError> {
    let response = context
        .client
        .get(format!("{BASE_URL}/projects"))
        .header("Authorization", format!("Token {api_key}"))
        .header("Accept", "application/json")
        .send()
        .await?;
    check_status(&response)?;
    let payload: ProjectsResponse = response.json().await?;
    Ok(payload.projects)
}

async fn fetch_project_usage(
    context: &FetchContext<'_>,
    api_key: &str,
    project: &DeepgramProject,
) -> Result<ProjectUsage, ProviderError> {
    let url = format!("{BASE_URL}/projects/{}/usage/breakdown", project.project_id);
    let response = context
        .client
        .get(url)
        .header("Authorization", format!("Token {api_key}"))
        .header("Accept", "application/json")
        .send()
        .await?;
    check_status(&response)?;
    let usage: UsageResponse = response.json().await?;
    Ok(ProjectUsage::from_response(project, usage))
}

fn check_status(response: &reqwest::Response) -> Result<(), ProviderError> {
    match response.status().as_u16() {
        200..=299 => Ok(()),
        401 => Err(ProviderError::Unauthorized(
            "Deepgram API key is invalid or expired.".into(),
        )),
        403 => Err(ProviderError::Unauthorized(
            "Deepgram rejected access to the Management API.".into(),
        )),
        status => Err(ProviderError::Http {
            provider: "Deepgram",
            status,
        }),
    }
}

#[derive(Debug, Deserialize)]
struct ProjectsResponse {
    #[serde(default)]
    projects: Vec<DeepgramProject>,
}

#[derive(Debug, Deserialize)]
struct DeepgramProject {
    #[serde(rename = "project_id")]
    project_id: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsageResponse {
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    results: Vec<UsageResult>,
}

#[derive(Debug, Deserialize)]
struct UsageResult {
    #[serde(default)]
    hours: Option<f64>,
    #[serde(default)]
    total_hours: Option<f64>,
    #[serde(default)]
    tokens_in: Option<i64>,
    #[serde(default)]
    tokens_out: Option<i64>,
    #[serde(default)]
    tts_characters: Option<i64>,
    #[serde(default)]
    requests: Option<i64>,
}

#[derive(Debug, Clone)]
struct ProjectUsage {
    project_name: Option<String>,
    start: Option<String>,
    end: Option<String>,
    hours: f64,
    total_hours: f64,
    tokens: i64,
    tts_characters: i64,
    requests: i64,
}

impl ProjectUsage {
    fn from_response(project: &DeepgramProject, usage: UsageResponse) -> Self {
        let sum_f64 = |pick: fn(&UsageResult) -> Option<f64>| {
            usage.results.iter().filter_map(pick).sum::<f64>()
        };
        let sum_i64 = |pick: fn(&UsageResult) -> Option<i64>| {
            usage.results.iter().filter_map(pick).sum::<i64>()
        };
        Self {
            project_name: project.name.clone(),
            start: usage.start,
            end: usage.end,
            hours: sum_f64(|r| r.hours),
            total_hours: sum_f64(|r| r.total_hours),
            tokens: sum_i64(|r| r.tokens_in) + sum_i64(|r| r.tokens_out),
            tts_characters: sum_i64(|r| r.tts_characters),
            requests: sum_i64(|r| r.requests),
        }
    }
}

fn map_usage(snapshots: &[ProjectUsage]) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Deepgram, "api");
    let requests: i64 = snapshots.iter().map(|s| s.requests).sum();
    let hours: f64 = snapshots.iter().map(|s| s.hours).sum();
    let total_hours: f64 = snapshots.iter().map(|s| s.total_hours).sum();
    let tokens: i64 = snapshots.iter().map(|s| s.tokens).sum();
    let tts_characters: i64 = snapshots.iter().map(|s| s.tts_characters).sum();

    snapshot.account_label = Some(if snapshots.len() > 1 {
        format!("{} projects", snapshots.len())
    } else {
        match snapshots.first().and_then(|s| s.project_name.as_deref()) {
            Some(name) if !name.trim().is_empty() => format!("Project: {name}"),
            _ => "Deepgram".into(),
        }
    });

    snapshot
        .summary
        .push(SummaryItem::new("Requests", format_integer(requests)));

    let mut usage_parts = Vec::new();
    if hours > 0.0 {
        usage_parts.push(format!("{} audio hours", format_decimal(hours)));
    }
    if total_hours > 0.0 {
        usage_parts.push(format!("{} billable hours", format_decimal(total_hours)));
    }
    if !usage_parts.is_empty() {
        snapshot
            .summary
            .push(SummaryItem::new("Usage", usage_parts.join(" · ")));
    }
    if tokens > 0 {
        snapshot
            .summary
            .push(SummaryItem::new("Tokens", format_integer(tokens)));
    }
    if tts_characters > 0 {
        snapshot.summary.push(SummaryItem::new(
            "TTS chars",
            format_integer(tts_characters),
        ));
    }
    if let (Some(start), Some(end)) = (
        snapshots.iter().filter_map(|s| s.start.clone()).min(),
        snapshots.iter().filter_map(|s| s.end.clone()).max(),
    ) {
        snapshot
            .summary
            .push(SummaryItem::new("Period", format!("{start} to {end}")));
    }
    snapshot
}

fn format_integer(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut grouped = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    if value < 0 {
        format!("-{grouped}")
    } else {
        grouped
    }
}

fn format_decimal(value: f64) -> String {
    if value.fract() == 0.0 {
        format_integer(value as i64)
    } else {
        format!("{value:.1}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(json: serde_json::Value) -> UsageResponse {
        serde_json::from_value(json).expect("usage")
    }

    #[test]
    fn aggregates_results_within_a_project() {
        let project = DeepgramProject {
            project_id: "p1".into(),
            name: Some("Main".into()),
        };
        let response = usage(serde_json::json!({
            "start": "2026-07-01",
            "end": "2026-07-31",
            "results": [
                { "hours": 1.5, "requests": 10, "tokens_in": 100, "tokens_out": 50 },
                { "hours": 0.5, "requests": 5, "total_hours": 2.0 }
            ]
        }));
        let snapshot = map_usage(&[ProjectUsage::from_response(&project, response)]);
        assert_eq!(snapshot.summary[0].value, "15");
        assert_eq!(snapshot.account_label.as_deref(), Some("Project: Main"));
    }

    #[test]
    fn labels_multiple_projects() {
        let mk = |id: &str| {
            ProjectUsage::from_response(
                &DeepgramProject {
                    project_id: id.into(),
                    name: None,
                },
                usage(serde_json::json!({ "results": [{ "requests": 3 }] })),
            )
        };
        let snapshot = map_usage(&[mk("a"), mk("b")]);
        assert_eq!(snapshot.account_label.as_deref(), Some("2 projects"));
        assert_eq!(snapshot.summary[0].value, "6");
    }

    #[test]
    fn formats_thousands_separators() {
        assert_eq!(format_integer(1_234_567), "1,234,567");
        assert_eq!(format_integer(-42), "-42");
    }
}
