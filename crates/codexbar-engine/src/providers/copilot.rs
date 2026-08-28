use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::{collections::HashMap, env};

pub struct CopilotProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Copilot,
    display_name: "Copilot",
    auth_kind: AuthKind::DeviceOAuth,
    color: "#a855f7",
    dashboard_url: "https://github.com/settings/copilot",
    credential_hint: "Connect a GitHub account with device authorization.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Copilot),
};

const USAGE_URL: &str = "https://api.github.com/copilot_internal/user";

#[async_trait]
impl Provider for CopilotProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let token = resolve_token(account)?;
        let response = context
            .client
            .get(USAGE_URL)
            .header(AUTHORIZATION, format!("token {token}"))
            .header("Accept", "application/json")
            .header("Editor-Version", "vscode/1.96.2")
            .header("Editor-Plugin-Version", "copilot-chat/0.26.7")
            .header("X-Github-Api-Version", "2025-04-01")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "GitHub authorization is invalid or Copilot is unavailable for this account."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Copilot",
                status: response.status().as_u16(),
            });
        }
        let bytes = response.bytes().await?;
        parse_usage(&bytes, Utc::now())
    }
}

fn resolve_token(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("COPILOT_API_TOKEN")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Connect Copilot with GitHub.".into()))
}

#[derive(Debug, Default, Deserialize)]
struct CopilotUsageResponse {
    #[serde(default)]
    copilot_plan: String,
    #[serde(default)]
    quota_reset_date: Option<String>,
    #[serde(default)]
    quota_snapshots: Option<QuotaSnapshots>,
    #[serde(default)]
    monthly_quotas: Option<QuotaCounts>,
    #[serde(default)]
    limited_user_quotas: Option<QuotaCounts>,
    #[serde(default)]
    token_based_billing: bool,
}

#[derive(Debug, Default, Deserialize)]
struct QuotaSnapshots {
    #[serde(default)]
    premium_interactions: Option<QuotaSnapshot>,
    #[serde(default)]
    chat: Option<QuotaSnapshot>,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct QuotaSnapshot {
    #[serde(default, deserialize_with = "deserialize_optional_number")]
    entitlement: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_optional_number")]
    remaining: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_optional_number")]
    percent_remaining: Option<f64>,
    #[serde(default)]
    unlimited: bool,
}

impl QuotaSnapshot {
    fn is_placeholder(&self) -> bool {
        !self.unlimited && self.entitlement == Some(0.0) && self.remaining == Some(0.0)
    }

    fn used_percent(&self) -> Option<f64> {
        if self.unlimited {
            return Some(0.0);
        }
        if self.is_placeholder() {
            return None;
        }
        let remaining = self.percent_remaining.or_else(|| {
            let entitlement = self.entitlement?;
            (entitlement > 0.0).then(|| self.remaining.unwrap_or_default() / entitlement * 100.0)
        })?;
        Some((100.0 - remaining).max(0.0))
    }

    fn usable(self) -> Option<Self> {
        self.used_percent().is_some().then_some(self)
    }
}

#[derive(Debug, Default, Deserialize)]
struct QuotaCounts {
    #[serde(default, deserialize_with = "deserialize_optional_number")]
    chat: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_optional_number")]
    completions: Option<f64>,
}

fn deserialize_optional_number<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_f64()
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("number is outside the supported range")),
        Some(Value::String(value)) => value
            .parse::<f64>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(_) => Err(serde::de::Error::custom(
            "expected a number or numeric string",
        )),
    }
}

fn parse_usage(bytes: &[u8], now: DateTime<Utc>) -> Result<ProviderSnapshot, ProviderError> {
    let response: CopilotUsageResponse =
        serde_json::from_slice(bytes).map_err(|error| ProviderError::Parse {
            provider: "Copilot",
            message: error.to_string(),
        })?;
    let (premium, chat) = normalized_quotas(&response);
    let reset = response.quota_reset_date.as_deref().and_then(parse_reset);

    let mut snapshot = ProviderSnapshot::new(ProviderId::Copilot, "github device oauth");
    snapshot.fetched_at = now;
    snapshot.plan = Some(capitalize_plan(&response.copilot_plan));
    if let Some(window) = quota_window("premium", "Premium", premium.as_ref(), reset) {
        snapshot.windows.push(window);
    }
    if let Some(window) = quota_window("chat", "Chat", chat.as_ref(), reset) {
        snapshot.windows.push(window);
    }
    if snapshot.windows.is_empty() && !response.token_based_billing {
        return Err(ProviderError::Parse {
            provider: "Copilot",
            message: "response contained no usable quota windows".into(),
        });
    }
    Ok(snapshot)
}

fn normalized_quotas(
    response: &CopilotUsageResponse,
) -> (Option<QuotaSnapshot>, Option<QuotaSnapshot>) {
    let mut premium = response
        .quota_snapshots
        .as_ref()
        .and_then(|snapshots| snapshots.premium_interactions.clone())
        .and_then(QuotaSnapshot::usable);
    let mut chat = response
        .quota_snapshots
        .as_ref()
        .and_then(|snapshots| snapshots.chat.clone())
        .and_then(QuotaSnapshot::usable);

    if let Some(snapshots) = response.quota_snapshots.as_ref() {
        let mut first = None;
        for (name, value) in &snapshots.other {
            let Ok(candidate) = serde_json::from_value::<QuotaSnapshot>(value.clone()) else {
                continue;
            };
            let Some(candidate) = candidate.usable() else {
                continue;
            };
            first.get_or_insert_with(|| candidate.clone());
            let name = name.to_ascii_lowercase();
            if chat.is_none() && name.contains("chat") {
                chat = Some(candidate);
            } else if premium.is_none()
                && (name.contains("premium")
                    || name.contains("completion")
                    || name.contains("code"))
            {
                premium = Some(candidate);
            }
        }
        if premium.is_none() && chat.is_none() {
            chat = first;
        }
    }

    premium = premium.or_else(|| {
        fallback_quota(
            response.monthly_quotas.as_ref(),
            response.limited_user_quotas.as_ref(),
            false,
        )
    });
    chat = chat.or_else(|| {
        fallback_quota(
            response.monthly_quotas.as_ref(),
            response.limited_user_quotas.as_ref(),
            true,
        )
    });
    (premium, chat)
}

fn fallback_quota(
    monthly: Option<&QuotaCounts>,
    limited: Option<&QuotaCounts>,
    chat: bool,
) -> Option<QuotaSnapshot> {
    let monthly = monthly?;
    let limited = limited?;
    let entitlement = if chat {
        monthly.chat
    } else {
        monthly.completions
    }?;
    let remaining = if chat {
        limited.chat
    } else {
        limited.completions
    }?;
    if entitlement <= 0.0 {
        return None;
    }
    Some(QuotaSnapshot {
        entitlement: Some(entitlement.max(0.0)),
        remaining: Some(remaining.max(0.0)),
        percent_remaining: Some((remaining.max(0.0) / entitlement * 100.0).clamp(0.0, 100.0)),
        unlimited: false,
    })
}

fn quota_window(
    id: &str,
    title: &str,
    quota: Option<&QuotaSnapshot>,
    reset: Option<DateTime<Utc>>,
) -> Option<UsageWindow> {
    let quota = quota?;
    let used = quota.used_percent()?;
    let effective_reset = (!quota.unlimited).then_some(reset).flatten();
    Some(UsageWindow::new(id, title, used).with_reset(effective_reset))
}

fn parse_reset(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|date| date.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()?
                .and_hms_opt(0, 0, 0)
                .map(|date| date.and_utc())
        })
}

fn capitalize_plan(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    let mut chars = normalized.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => "Unknown".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderError;
    use chrono::{TimeZone, Utc};

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 8, 0, 0).unwrap()
    }

    #[test]
    fn direct_quota_snapshots_map_premium_and_chat_windows() {
        let snapshot = parse_usage(
            include_bytes!("../../tests/fixtures/copilot/direct.json"),
            now(),
        )
        .expect("direct quota payload");

        assert_eq!(snapshot.provider, crate::model::ProviderId::Copilot);
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
        assert_eq!(snapshot.windows.len(), 2);
        assert_eq!(snapshot.windows[0].id, "premium");
        assert_eq!(snapshot.windows[0].title, "Premium");
        assert_eq!(snapshot.windows[0].used_percent, 75.0);
        assert_eq!(snapshot.windows[1].id, "chat");
        assert_eq!(snapshot.windows[1].used_percent, 20.0);
        assert_eq!(
            snapshot.windows[0].resets_at,
            Some(Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap())
        );
    }

    #[test]
    fn monthly_and_limited_counts_form_fallback_windows() {
        let snapshot = parse_usage(
            include_bytes!("../../tests/fixtures/copilot/monthly-limited.json"),
            now(),
        )
        .expect("monthly quota payload");

        assert_eq!(snapshot.windows.len(), 2);
        assert_eq!(snapshot.windows[0].used_percent, 75.0);
        assert_eq!(snapshot.windows[1].used_percent, 20.0);
    }

    #[test]
    fn token_billing_placeholders_surface_plan_without_fake_usage() {
        let snapshot = parse_usage(
            include_bytes!("../../tests/fixtures/copilot/token-billing.json"),
            now(),
        )
        .expect("token billing payload");

        assert!(snapshot.windows.is_empty());
        assert_eq!(snapshot.plan.as_deref(), Some("Business"));
    }

    #[test]
    fn an_unlimited_chat_quota_has_zero_used_and_no_reset() {
        let snapshot = parse_usage(
            br#"{
              "copilot_plan":"pro",
              "quota_reset_date":"2026-08-01",
              "quota_snapshots":{"chat":{"unlimited":true,"quota_id":"chat"}}
            }"#,
            now(),
        )
        .expect("unlimited quota");

        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.windows[0].id, "chat");
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
        assert_eq!(snapshot.windows[0].resets_at, None);
    }

    #[test]
    fn a_zero_entitlement_snapshot_is_not_rendered() {
        let snapshot = parse_usage(
            br#"{
              "copilot_plan":"business",
              "token_based_billing":true,
              "quota_snapshots":{
                "premium_interactions":{"entitlement":0,"remaining":0,"percent_remaining":100}
              }
            }"#,
            now(),
        )
        .expect("placeholder quota");

        assert!(snapshot.windows.is_empty());
    }

    #[test]
    fn malformed_payload_is_a_provider_parse_error() {
        assert!(matches!(
            parse_usage(b"not-json", now()),
            Err(ProviderError::Parse {
                provider: "Copilot",
                ..
            })
        ));
    }
}
