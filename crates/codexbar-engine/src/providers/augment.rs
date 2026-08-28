use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Response;
use serde::Deserialize;

pub struct AugmentProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for AugmentProvider {
    fn default() -> Self {
        Self {
            base_url: "https://app.augmentcode.com".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Augment,
    display_name: "Augment",
    auth_kind: AuthKind::BrowserCookie,
    color: "#6c5ce7",
    dashboard_url: "https://app.augmentcode.com",
    credential_hint: "Imports app.augmentcode.com cookies from Chrome/Edge with DPAPI, or accepts a \
manual Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Augment),
};

const CREDITS_PATH: &str = "/api/credits";
const SUBSCRIPTION_PATH: &str = "/api/subscription";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

#[async_trait]
impl Provider for AugmentProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let cookie = self.resolve_cookie(account)?;
        let credits: Credits = self.get(context, CREDITS_PATH, &cookie).await?;
        // Subscription (plan, billing period, email) is best-effort enrichment.
        let subscription: Option<Subscription> =
            self.get(context, SUBSCRIPTION_PATH, &cookie).await.ok();
        Ok(map_usage(&credits, subscription.as_ref()))
    }
}

impl AugmentProvider {
    fn resolve_cookie(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            return Ok(value.to_owned());
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste an app.augmentcode.com Cookie header in Settings.".into(),
            ));
        }
        // Augment sends its full session cookie set (Auth0 / NextAuth / AuthJS); take all cookies.
        let imported = chromium::find_cookie_header(
            account.browser,
            &["augmentcode.com", "app.augmentcode.com"],
            &[],
        )?;
        Ok(imported.value)
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        context: &FetchContext<'_>,
        path: &str,
        cookie: &str,
    ) -> Result<T, ProviderError> {
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
        let response = context
            .client
            .get(&url)
            .header("Accept", "application/json")
            .header("Cookie", cookie)
            .header("User-Agent", USER_AGENT)
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Augment session is invalid or expired. Sign in to app.augmentcode.com again."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Augment",
                status: response.status().as_u16(),
            });
        }
        parse_json(response).await
    }
}

async fn parse_json<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T, ProviderError> {
    response.json().await.map_err(|error| ProviderError::Parse {
        provider: "Augment",
        message: error.to_string(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Credits {
    usage_units_remaining: Option<f64>,
    usage_units_consumed_this_billing_cycle: Option<f64>,
    usage_units_available: Option<f64>,
}

impl Credits {
    /// The plan allowance: the explicit `usageUnitsAvailable` when positive, otherwise the sum of
    /// remaining + consumed as a fallback.
    fn limit(&self) -> Option<f64> {
        if let Some(available) = self.usage_units_available {
            if available > 0.0 {
                return Some(available);
            }
        }
        match (
            self.usage_units_remaining,
            self.usage_units_consumed_this_billing_cycle,
        ) {
            (Some(remaining), Some(consumed)) => Some(remaining + consumed),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    plan_name: Option<String>,
    billing_period_end: Option<String>,
    email: Option<String>,
}

fn map_usage(credits: &Credits, subscription: Option<&Subscription>) -> ProviderSnapshot {
    let remaining = credits.usage_units_remaining;
    let used = credits.usage_units_consumed_this_billing_cycle;
    let limit = credits.limit();

    let percent = match (used, limit) {
        (Some(used), Some(limit)) if limit > 0.0 => (used / limit * 100.0).clamp(0.0, 100.0),
        _ => match (remaining, limit) {
            (Some(remaining), Some(limit)) if limit > 0.0 => {
                ((limit - remaining) / limit * 100.0).clamp(0.0, 100.0)
            }
            _ => 0.0,
        },
    };

    let reset = subscription
        .and_then(|subscription| subscription.billing_period_end.as_deref())
        .and_then(parse_iso);

    let mut snapshot = ProviderSnapshot::new(ProviderId::Augment, "web");
    let mut window = UsageWindow::new("credits", "Credits", percent).with_reset(reset);
    if let Some(limit) = limit {
        let used_units = used
            .or_else(|| remaining.map(|remaining| (limit - remaining).max(0.0)))
            .unwrap_or(0.0);
        window = window.with_detail(format!(
            "{} / {} credits",
            format_units(used_units),
            format_units(limit)
        ));
    }
    snapshot.windows.push(window);

    snapshot.plan = subscription.and_then(|subscription| subscription.plan_name.clone());
    snapshot.account_label = subscription.and_then(|subscription| subscription.email.clone());
    if let Some(remaining) = remaining {
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(remaining),
            spend: used,
            currency: None,
        });
    }
    snapshot
}

fn format_units(value: f64) -> String {
    if (value.round() - value).abs() < f64::EPSILON {
        format!("{}", value.round() as i64)
    } else {
        format!("{value:.2}")
    }
}

fn parse_iso(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_value, json};

    #[test]
    fn resolves_manual_cookie_header_passthrough() {
        let provider = AugmentProvider {
            browser_import_enabled: false,
            ..Default::default()
        };
        let account = ProviderAccount {
            cookie_header: Some("_session=abc; auth0=z".into()),
            ..Default::default()
        };
        assert_eq!(
            provider.resolve_cookie(&account).unwrap(),
            "_session=abc; auth0=z"
        );
    }

    #[test]
    fn maps_consumed_and_available_to_percent() {
        let credits: Credits = from_value(json!({
            "usageUnitsRemaining": 700.0,
            "usageUnitsConsumedThisBillingCycle": 300.0,
            "usageUnitsAvailable": 1000.0
        }))
        .unwrap();
        let subscription: Subscription = from_value(json!({
            "planName": "Pro",
            "billingPeriodEnd": "2026-08-01T00:00:00Z",
            "email": "user@example.com"
        }))
        .unwrap();
        let snapshot = map_usage(&credits, Some(&subscription));
        assert_eq!(snapshot.windows[0].used_percent, 30.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("300 / 1000 credits")
        );
        assert!(snapshot.windows[0].resets_at.is_some());
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
        assert_eq!(snapshot.account_label.as_deref(), Some("user@example.com"));
        assert_eq!(snapshot.financials.unwrap().balance, Some(700.0));
    }

    #[test]
    fn derives_limit_from_remaining_plus_consumed_when_available_absent() {
        let credits: Credits = from_value(json!({
            "usageUnitsRemaining": 40.0,
            "usageUnitsConsumedThisBillingCycle": 60.0
        }))
        .unwrap();
        assert_eq!(credits.limit(), Some(100.0));
        let snapshot = map_usage(&credits, None);
        assert_eq!(snapshot.windows[0].used_percent, 60.0);
        assert_eq!(snapshot.plan, None);
    }

    #[test]
    fn zero_limit_yields_zero_percent() {
        let credits: Credits = from_value(json!({
            "usageUnitsRemaining": 0.0,
            "usageUnitsConsumedThisBillingCycle": 0.0,
            "usageUnitsAvailable": 0.0
        }))
        .unwrap();
        let snapshot = map_usage(&credits, None);
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
    }

    #[test]
    fn subscription_enrichment_is_optional() {
        let credits: Credits = from_value(json!({
            "usageUnitsRemaining": 500.0,
            "usageUnitsConsumedThisBillingCycle": 500.0
        }))
        .unwrap();
        let snapshot = map_usage(&credits, None);
        assert_eq!(snapshot.windows[0].used_percent, 50.0);
        assert!(snapshot.windows[0].resets_at.is_none());
        assert_eq!(snapshot.account_label, None);
    }
}
