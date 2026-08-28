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
use std::env;

pub struct LiteLLMProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Litellm,
    display_name: "LiteLLM",
    auth_kind: AuthKind::ApiKey,
    color: "#00b8a3",
    dashboard_url: "",
    credential_hint: "Set an API key + base URL in Settings, or LITELLM_API_KEY / LITELLM_BASE_URL.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Litellm),
};

#[async_trait]
impl Provider for LiteLLMProvider {
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
        let management = management_base_url(&base_url);

        let key_info: KeyInfoResponse =
            get_json(context, &format!("{management}/key/info"), &api_key).await?;
        let key = key_info.info;
        let user_id = non_empty(key.user_id.as_deref());
        let team_id = non_empty(key.team_id.as_deref());

        if let Some(user_id) = user_id {
            let url = format!("{management}/user/info?user_id={}", encode(&user_id));
            let user_info: UserInfoResponse = get_json(context, &url, &api_key).await?;
            Ok(map_user_usage(&key, &user_info))
        } else if let Some(team_id) = team_id {
            let url = format!("{management}/team/info?team_id={}", encode(&team_id));
            let team_info: TeamInfoResponse = get_json(context, &url, &api_key).await?;
            Ok(map_team_usage(&key, &team_info.team_info))
        } else {
            Err(ProviderError::Parse {
                provider: "LiteLLM",
                message: "key info did not include a user_id or team_id".into(),
            })
        }
    }
}

async fn get_json<T: for<'de> Deserialize<'de>>(
    context: &FetchContext<'_>,
    url: &str,
    api_key: &str,
) -> Result<T, ProviderError> {
    let response = context
        .client
        .get(url)
        .bearer_auth(api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
    if matches!(response.status().as_u16(), 401 | 403) {
        return Err(ProviderError::Unauthorized(
            "LiteLLM API key is invalid.".into(),
        ));
    }
    if !response.status().is_success() {
        return Err(ProviderError::Http {
            provider: "LiteLLM",
            status: response.status().as_u16(),
        });
    }
    response.json::<T>().await.map_err(Into::into)
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("LITELLM_API_KEY"))
        .ok_or_else(|| ProviderError::MissingCredentials("Missing LiteLLM API key.".into()))
}

fn resolve_base_url(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.base_url)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("LITELLM_BASE_URL"))
        .ok_or_else(|| {
            ProviderError::MissingCredentials(
                "LiteLLM needs a base URL (set it in Settings or LITELLM_BASE_URL).".into(),
            )
        })
}

fn env_var(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Management endpoints live at the base host, so a trailing `/v1` (the chat-completions prefix) is
/// dropped: `https://proxy/v1` → `https://proxy`.
fn management_base_url(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    trimmed
        .strip_suffix("/v1")
        .map_or_else(|| trimmed.to_owned(), ToOwned::to_owned)
}

fn map_user_usage(key: &KeyInfo, response: &UserInfoResponse) -> ProviderSnapshot {
    let info = &response.user_info;
    let mut snapshot = ProviderSnapshot::new(ProviderId::Litellm, "api key");

    let personal_spend = info.spend.unwrap_or(0.0);
    if let Some(window) = budget_window(
        "personal",
        "Personal budget",
        personal_spend,
        info.max_budget,
        parse_date(info.budget_reset_at.as_deref()),
    ) {
        snapshot.windows.push(window);
    }

    let team = response
        .teams
        .as_ref()
        .and_then(|teams| preferred_team(teams, key.team_id.as_deref()));
    if let Some(team) = team {
        let team_spend = team.spend.unwrap_or(0.0);
        if let Some(window) = budget_window(
            "team",
            "Team budget",
            team_spend,
            team.max_budget,
            parse_date(team.budget_reset_at.as_deref()),
        ) {
            snapshot.windows.push(window);
        }
        snapshot.plan = non_empty(team.team_alias.as_deref());
    }

    if let Some(email) = first_non_empty(&[
        info.user_email.as_deref(),
        info.user_alias.as_deref(),
        info.metadata
            .as_ref()
            .and_then(|meta| meta.preferred_username.as_deref()),
    ]) {
        snapshot.summary.push(SummaryItem::new("Account", email));
    }
    snapshot.financials = Some(FinancialSnapshot {
        balance: None,
        spend: Some(personal_spend),
        currency: Some("USD".into()),
    });
    snapshot
}

fn map_team_usage(_key: &KeyInfo, team: &TeamInfo) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Litellm, "api key");
    let team_spend = team.spend.unwrap_or(0.0);
    if let Some(window) = budget_window(
        "team",
        "Team budget",
        team_spend,
        team.max_budget,
        parse_date(team.budget_reset_at.as_deref()),
    ) {
        snapshot.windows.push(window);
    }
    snapshot.plan = non_empty(team.team_alias.as_deref());
    snapshot.financials = Some(FinancialSnapshot {
        balance: None,
        spend: Some(team_spend),
        currency: Some("USD".into()),
    });
    snapshot
}

fn budget_window(
    id: &str,
    title: &str,
    spend: f64,
    budget: Option<f64>,
    resets_at: Option<DateTime<Utc>>,
) -> Option<UsageWindow> {
    let budget = budget.filter(|value| *value > 0.0)?;
    let used_percent = (spend / budget * 100.0).clamp(0.0, 100.0);
    Some(
        UsageWindow::new(id, title, used_percent)
            .with_reset(resets_at)
            .with_detail(format!("${spend:.2} / ${budget:.2}")),
    )
}

fn preferred_team<'a>(teams: &'a [Team], key_team_id: Option<&str>) -> Option<&'a Team> {
    let key_team_id = non_empty(key_team_id)?;
    teams.iter().find(|team| team.team_id == key_team_id)
}

fn parse_date(raw: Option<&str>) -> Option<DateTime<Utc>> {
    let raw = raw?.trim();
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn first_non_empty(values: &[Option<&str>]) -> Option<String> {
    values.iter().find_map(|value| non_empty(*value))
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[derive(Debug, Deserialize)]
struct KeyInfoResponse {
    info: KeyInfo,
}

#[derive(Debug, Deserialize)]
struct KeyInfo {
    #[serde(default, rename = "key_name")]
    _key_name: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserInfoResponse {
    #[serde(default)]
    user_info: UserInfo,
    #[serde(default)]
    teams: Option<Vec<Team>>,
}

#[derive(Debug, Default, Deserialize)]
struct UserInfo {
    #[serde(default)]
    user_alias: Option<String>,
    #[serde(default)]
    max_budget: Option<f64>,
    #[serde(default)]
    spend: Option<f64>,
    #[serde(default)]
    user_email: Option<String>,
    #[serde(default)]
    budget_reset_at: Option<String>,
    #[serde(default)]
    metadata: Option<Metadata>,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    #[serde(default)]
    preferred_username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Team {
    #[serde(default)]
    team_alias: Option<String>,
    #[serde(default)]
    team_id: String,
    #[serde(default)]
    max_budget: Option<f64>,
    #[serde(default)]
    spend: Option<f64>,
    #[serde(default)]
    budget_reset_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TeamInfoResponse {
    team_info: TeamInfo,
}

#[derive(Debug, Deserialize)]
struct TeamInfo {
    #[serde(default)]
    team_alias: Option<String>,
    #[serde(default)]
    max_budget: Option<f64>,
    #[serde(default)]
    spend: Option<f64>,
    #[serde(default)]
    budget_reset_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strips_v1_suffix_for_management_base() {
        assert_eq!(
            management_base_url("https://proxy.example.com/v1"),
            "https://proxy.example.com"
        );
        assert_eq!(
            management_base_url("https://proxy.example.com/"),
            "https://proxy.example.com"
        );
    }

    #[test]
    fn maps_personal_budget_window_and_spend() {
        let key: KeyInfo = serde_json::from_value(json!({
            "user_id": "u_1", "team_id": null
        }))
        .unwrap();
        let response: UserInfoResponse = serde_json::from_value(json!({
            "user_info": {
                "spend": 25.0, "max_budget": 100.0, "user_email": "dev@example.test",
                "budget_reset_at": "2026-08-01T00:00:00Z"
            },
            "teams": []
        }))
        .unwrap();
        let snapshot = map_user_usage(&key, &response);
        assert_eq!(snapshot.windows[0].id, "personal");
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("$25.00 / $100.00")
        );
        assert_eq!(snapshot.summary[0].value, "dev@example.test");
        assert_eq!(snapshot.financials.unwrap().spend, Some(25.0));
    }

    #[test]
    fn adds_team_window_for_the_key_team() {
        let key: KeyInfo =
            serde_json::from_value(json!({ "user_id": "u_1", "team_id": "t_9" })).unwrap();
        let response: UserInfoResponse = serde_json::from_value(json!({
            "user_info": { "spend": 0.0, "max_budget": 0.0 },
            "teams": [
                { "team_id": "t_1", "spend": 5.0, "max_budget": 10.0 },
                { "team_id": "t_9", "team_alias": "Platform", "spend": 30.0, "max_budget": 60.0 }
            ]
        }))
        .unwrap();
        let snapshot = map_user_usage(&key, &response);
        let team = snapshot.windows.iter().find(|w| w.id == "team").unwrap();
        assert_eq!(team.used_percent, 50.0);
        assert_eq!(snapshot.plan.as_deref(), Some("Platform"));
    }

    #[test]
    fn maps_team_only_key() {
        let key: KeyInfo = serde_json::from_value(json!({ "team_id": "t_9" })).unwrap();
        let team: TeamInfo = serde_json::from_value(json!({
            "team_alias": "Ops", "spend": 45.0, "max_budget": 90.0
        }))
        .unwrap();
        let snapshot = map_team_usage(&key, &team);
        assert_eq!(snapshot.windows[0].used_percent, 50.0);
        assert_eq!(snapshot.plan.as_deref(), Some("Ops"));
        assert_eq!(snapshot.financials.unwrap().spend, Some(45.0));
    }

    #[test]
    fn omits_window_without_a_positive_budget() {
        assert!(budget_window("personal", "Personal budget", 10.0, None, None).is_none());
        assert!(budget_window("personal", "Personal budget", 10.0, Some(0.0), None).is_none());
    }
}
