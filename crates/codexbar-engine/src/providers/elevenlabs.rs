use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use std::env;

pub struct ElevenLabsProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Elevenlabs,
    display_name: "ElevenLabs",
    auth_kind: AuthKind::ApiKey,
    color: "#ebebe6",
    dashboard_url: "https://elevenlabs.io/app/developers/usage",
    credential_hint: "Set an API key in Settings or ELEVENLABS_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Elevenlabs),
};

const SUBSCRIPTION_URL: &str = "https://api.elevenlabs.io/v1/user/subscription";

#[async_trait]
impl Provider for ElevenLabsProvider {
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
            .get(SUBSCRIPTION_URL)
            .header("xi-api-key", &api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "ElevenLabs API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "ElevenLabs",
                status: response.status().as_u16(),
            });
        }
        let subscription: SubscriptionResponse = response.json().await?;
        Ok(map_usage(subscription))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("ELEVENLABS_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing ElevenLabs API key.".into()))
}

#[derive(Debug, Deserialize)]
struct SubscriptionResponse {
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    character_count: i64,
    #[serde(default)]
    character_limit: i64,
    #[serde(default)]
    voice_slots_used: Option<i64>,
    #[serde(default)]
    professional_voice_slots_used: Option<i64>,
    #[serde(default)]
    voice_limit: Option<i64>,
    #[serde(default)]
    professional_voice_limit: Option<i64>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    next_character_count_reset_unix: Option<i64>,
}

fn map_usage(subscription: SubscriptionResponse) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Elevenlabs, "api key");
    snapshot.plan = display_tier(&subscription);

    let used_percent = if subscription.character_limit > 0 {
        (subscription.character_count as f64 / subscription.character_limit as f64 * 100.0).max(0.0)
    } else {
        0.0
    };
    let resets_at = subscription
        .next_character_count_reset_unix
        .and_then(|unix| Utc.timestamp_opt(unix, 0).single());
    snapshot.windows.push(
        UsageWindow::new("credits", "Credits", used_percent)
            .with_reset(resets_at)
            .with_detail(format!(
                "{} / {} credits",
                format_count(subscription.character_count),
                format_count(subscription.character_limit)
            )),
    );

    if let (Some(used), Some(limit)) = (subscription.voice_slots_used, subscription.voice_limit) {
        if limit > 0 {
            snapshot.windows.push(
                UsageWindow::new(
                    "voice-slots",
                    "Voice slots",
                    used as f64 / limit as f64 * 100.0,
                )
                .with_detail(format!("{used} / {limit}")),
            );
        }
    }
    if let (Some(used), Some(limit)) = (
        subscription.professional_voice_slots_used,
        subscription.professional_voice_limit,
    ) {
        if limit > 0 {
            snapshot.windows.push(
                UsageWindow::new(
                    "professional-voices",
                    "Professional voices",
                    used as f64 / limit as f64 * 100.0,
                )
                .with_detail(format!("{used} / {limit}")),
            );
        }
    }

    snapshot.summary.push(SummaryItem::new(
        "Credits",
        format!(
            "{} / {}",
            format_count(subscription.character_count),
            format_count(subscription.character_limit)
        ),
    ));
    snapshot
}

fn display_tier(subscription: &SubscriptionResponse) -> Option<String> {
    let tier = subscription
        .tier
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    match tier {
        None => subscription.status.clone(),
        Some(tier) => {
            let label = titlecase(&tier.replace('_', " "));
            match subscription.status.as_deref() {
                Some(status) if !status.is_empty() && !status.eq_ignore_ascii_case("active") => {
                    Some(format!("{label} · {status}"))
                }
                _ => Some(label),
            }
        }
    }
}

fn titlecase(value: &str) -> String {
    value
        .split(' ')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_count(value: i64) -> String {
    let negative = value < 0;
    let digits = value.unsigned_abs().to_string();
    let mut grouped = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    if negative {
        format!("-{grouped}")
    } else {
        grouped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: serde_json::Value) -> ProviderSnapshot {
        map_usage(serde_json::from_value(json).expect("subscription"))
    }

    #[test]
    fn computes_credit_percentage_and_plan() {
        let snapshot = parse(serde_json::json!({
            "tier": "creator_pro",
            "character_count": 25000,
            "character_limit": 100000,
            "status": "active"
        }));
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("25,000 / 100,000 credits")
        );
        assert_eq!(snapshot.plan.as_deref(), Some("Creator Pro"));
    }

    #[test]
    fn surfaces_voice_slots_when_present() {
        let snapshot = parse(serde_json::json!({
            "tier": "pro",
            "character_count": 0,
            "character_limit": 10,
            "voice_slots_used": 3,
            "voice_limit": 10
        }));
        let voice = snapshot
            .windows
            .iter()
            .find(|window| window.id == "voice-slots")
            .expect("voice window");
        assert_eq!(voice.used_percent, 30.0);
    }

    #[test]
    fn appends_non_active_status_to_plan() {
        let snapshot = parse(serde_json::json!({
            "tier": "starter",
            "character_count": 0,
            "character_limit": 0,
            "status": "canceled"
        }));
        assert_eq!(snapshot.plan.as_deref(), Some("Starter · canceled"));
    }
}
