use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Response;
use serde_json::Value;

pub struct CommandCodeProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for CommandCodeProvider {
    fn default() -> Self {
        Self {
            base_url: "https://api.commandcode.ai".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Commandcode,
    display_name: "Command Code",
    auth_kind: AuthKind::BrowserCookie,
    color: "#000000",
    dashboard_url: "https://commandcode.ai/studio",
    credential_hint: "Imports the commandcode.ai better-auth session cookie from Chrome/Edge with \
DPAPI, or accepts a manual Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Commandcode),
};

const CREDITS_PATH: &str = "/internal/billing/credits";
const SUBSCRIPTIONS_PATH: &str = "/internal/billing/subscriptions";
// better-auth emits the `__Secure-` variant on HTTPS production; a bare token is wrapped in it.
const DEFAULT_SESSION_COOKIE: &str = "__Secure-better-auth.session_token";
const COOKIE_NAMES: &[&str] = &[
    "__Host-better-auth.session_token",
    "__Secure-better-auth.session_token",
    "better-auth.session_token",
];
const WEB_ORIGIN: &str = "https://commandcode.ai";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

#[async_trait]
impl Provider for CommandCodeProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let cookie = self.resolve_cookie(account)?;
        let credits = self.fetch_credits(context, &cookie).await?;
        // Subscription enrichment is best-effort: it supplies the plan total and billing period.
        // Any failure degrades to a remaining-only view rather than failing the whole card.
        let (subscription, enrichment_unavailable) =
            match self.fetch_subscription(context, &cookie).await {
                Ok(subscription) => (subscription, false),
                Err(_) => (None, true),
            };
        map_usage(&credits, subscription.as_ref(), enrichment_unavailable)
    }
}

impl CommandCodeProvider {
    fn resolve_cookie(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            // A full "name=value; …" header passes through; a bare token is wrapped in the default
            // production session cookie name.
            let header = if value.contains('=') {
                value.to_owned()
            } else {
                format!("{DEFAULT_SESSION_COOKIE}={value}")
            };
            return Ok(header);
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a commandcode.ai Cookie header in Settings.".into(),
            ));
        }
        let imported = chromium::find_cookie_header(
            account.browser,
            &["commandcode.ai", "www.commandcode.ai", "api.commandcode.ai"],
            COOKIE_NAMES,
        )?;
        Ok(imported.value)
    }

    async fn fetch_credits(
        &self,
        context: &FetchContext<'_>,
        cookie: &str,
    ) -> Result<Credits, ProviderError> {
        let url = format!("{}{CREDITS_PATH}", self.base_url.trim_end_matches('/'));
        let response = self.get(context, &url, cookie).await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Command Code session is invalid or expired. Sign in to commandcode.ai again or \
replace the manual Cookie header."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Command Code",
                status: response.status().as_u16(),
            });
        }
        let value = json(response).await?;
        parse_credits(&value)
    }

    async fn fetch_subscription(
        &self,
        context: &FetchContext<'_>,
        cookie: &str,
    ) -> Result<Option<Subscription>, ProviderError> {
        let url = format!(
            "{}{SUBSCRIPTIONS_PATH}",
            self.base_url.trim_end_matches('/')
        );
        let response = self.get(context, &url, cookie).await?;
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Command Code",
                status: response.status().as_u16(),
            });
        }
        let value = json(response).await?;
        parse_subscription(&value)
    }

    async fn get(
        &self,
        context: &FetchContext<'_>,
        url: &str,
        cookie: &str,
    ) -> Result<Response, ProviderError> {
        Ok(context
            .client
            .get(url)
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Cookie", cookie)
            .header("Origin", WEB_ORIGIN)
            .header("Referer", format!("{WEB_ORIGIN}/"))
            .header("User-Agent", USER_AGENT)
            .send()
            .await?)
    }
}

async fn json(response: Response) -> Result<Value, ProviderError> {
    response.json().await.map_err(|error| ProviderError::Parse {
        provider: "Command Code",
        message: error.to_string(),
    })
}

/// Remaining USD grants from `/internal/billing/credits`. `monthly_credits` is the remaining
/// balance of the plan's monthly allowance, not the total.
struct Credits {
    monthly_credits: f64,
    purchased_credits: f64,
    premium_monthly_credits: f64,
    opensource_monthly_credits: f64,
}

/// Active subscription from `/internal/billing/subscriptions`; `None` means the free tier.
struct Subscription {
    plan_id: String,
    status: Option<String>,
    current_period_end: Option<DateTime<Utc>>,
}

struct Plan {
    display_name: &'static str,
    monthly_credits_usd: f64,
}

/// Static catalog: `/internal/billing/credits` exposes only the *remaining* monthly credits, so the
/// plan total comes from the published pricing keyed by `planId`.
fn plan_for_id(plan_id: &str) -> Option<Plan> {
    match plan_id.trim().to_ascii_lowercase().as_str() {
        "individual-go" => Some(Plan {
            display_name: "Go",
            monthly_credits_usd: 10.0,
        }),
        "individual-pro" => Some(Plan {
            display_name: "Pro",
            monthly_credits_usd: 30.0,
        }),
        "individual-max" => Some(Plan {
            display_name: "Max",
            monthly_credits_usd: 150.0,
        }),
        "individual-ultra" => Some(Plan {
            display_name: "Ultra",
            monthly_credits_usd: 300.0,
        }),
        _ => None,
    }
}

fn parse_credits(value: &Value) -> Result<Credits, ProviderError> {
    let credits = value.get("credits").ok_or(ProviderError::Parse {
        provider: "Command Code",
        message: "missing 'credits' object".into(),
    })?;
    let monthly_credits = lossy_f64(credits.get("monthlyCredits")).ok_or(ProviderError::Parse {
        provider: "Command Code",
        message: "missing monthlyCredits".into(),
    })?;
    Ok(Credits {
        monthly_credits,
        purchased_credits: lossy_f64(credits.get("purchasedCredits")).unwrap_or(0.0),
        premium_monthly_credits: lossy_f64(credits.get("premiumMonthlyCredits")).unwrap_or(0.0),
        opensource_monthly_credits: lossy_f64(credits.get("opensourceMonthlyCredits"))
            .unwrap_or(0.0),
    })
}

fn parse_subscription(value: &Value) -> Result<Option<Subscription>, ProviderError> {
    // Only an explicit successful null response identifies the free tier; failure envelopes are
    // transient and bubble up so the caller degrades to remaining-only.
    let success = value
        .get("success")
        .and_then(Value::as_bool)
        .ok_or(ProviderError::Parse {
            provider: "Command Code",
            message: "missing success flag".into(),
        })?;
    if !success {
        return Err(ProviderError::Parse {
            provider: "Command Code",
            message: "unsuccessful subscription response".into(),
        });
    }
    let data = value.get("data").ok_or(ProviderError::Parse {
        provider: "Command Code",
        message: "missing data".into(),
    })?;
    if data.is_null() {
        return Ok(None);
    }
    let plan_id = data
        .get("planId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ProviderError::Parse {
            provider: "Command Code",
            message: "missing planId".into(),
        })?
        .to_owned();
    Ok(Some(Subscription {
        plan_id,
        status: data
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned),
        current_period_end: parse_date(data.get("currentPeriodEnd")),
    }))
}

fn map_usage(
    credits: &Credits,
    subscription: Option<&Subscription>,
    enrichment_unavailable: bool,
) -> Result<ProviderSnapshot, ProviderError> {
    let plan = subscription.and_then(|subscription| plan_for_id(&subscription.plan_id));

    // An active subscription with an unrecognised plan id means we cannot show its allowance;
    // surface it rather than silently rendering a wrong total.
    if let Some(subscription) = subscription {
        let active = subscription
            .status
            .as_deref()
            .is_some_and(|status| status.eq_ignore_ascii_case("active"));
        if active && plan.is_none() {
            return Err(ProviderError::Parse {
                provider: "Command Code",
                message: format!("unknown plan id '{}'", subscription.plan_id),
            });
        }
    }

    let mut snapshot = ProviderSnapshot::new(ProviderId::Commandcode, "web");
    let remaining = credits.monthly_credits;
    let billing_end = subscription.and_then(|subscription| subscription.current_period_end);
    let monthly_total = plan.as_ref().map(|plan| plan.monthly_credits_usd);

    match monthly_total {
        Some(total) if total > 0.0 => {
            let used = (total - remaining).clamp(0.0, total);
            let percent = (used / total * 100.0).clamp(0.0, 100.0);
            snapshot.windows.push(
                UsageWindow::new("monthly", "Monthly credits", percent)
                    .with_reset(billing_end)
                    .with_detail(format!("{} of {}", format_usd(used), format_usd(total))),
            );
            snapshot.financials = Some(FinancialSnapshot {
                balance: Some(remaining + credits.purchased_credits),
                spend: Some(used),
                currency: Some("USD".into()),
            });
        }
        _ => {
            // Free / unknown plan with no known allowance: only render a bar when there is a real
            // balance to show, otherwise the card stays window-less.
            if remaining > 0.0 || credits.purchased_credits > 0.0 {
                snapshot.windows.push(
                    UsageWindow::new("monthly", "Monthly credits", 0.0)
                        .with_reset(billing_end)
                        .with_detail(format!("{} remaining", format_usd(remaining))),
                );
                snapshot.financials = Some(FinancialSnapshot {
                    balance: Some(remaining + credits.purchased_credits),
                    spend: None,
                    currency: Some("USD".into()),
                });
            }
        }
    }

    snapshot.plan = plan.map(|plan| plan.display_name.to_owned());

    if credits.purchased_credits > 0.0 {
        snapshot.summary.push(SummaryItem::new(
            "On-demand",
            format!("{} credits", format_usd(credits.purchased_credits)),
        ));
    }
    if credits.premium_monthly_credits > 0.0 {
        snapshot.summary.push(SummaryItem::new(
            "Premium",
            format_usd(credits.premium_monthly_credits),
        ));
    }
    if credits.opensource_monthly_credits > 0.0 {
        snapshot.summary.push(SummaryItem::new(
            "Open source",
            format_usd(credits.opensource_monthly_credits),
        ));
    }
    if enrichment_unavailable {
        snapshot
            .summary
            .push(SummaryItem::new("Subscription", "Enrichment unavailable"));
    }

    Ok(snapshot)
}

fn format_usd(value: f64) -> String {
    if value < 100.0 {
        format!("${value:.2}")
    } else {
        format!("${value:.0}")
    }
}

fn lossy_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn parse_date(value: Option<&Value>) -> Option<DateTime<Utc>> {
    match value? {
        Value::String(text) => DateTime::parse_from_rfc3339(text.trim())
            .ok()
            .map(|value| value.with_timezone(&Utc)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_manual_cookie_bare_token_and_full_header() {
        let provider = CommandCodeProvider {
            browser_import_enabled: false,
            ..Default::default()
        };
        let bare = ProviderAccount {
            cookie_header: Some("abc123".into()),
            ..Default::default()
        };
        assert_eq!(
            provider.resolve_cookie(&bare).unwrap(),
            "__Secure-better-auth.session_token=abc123"
        );
        let full = ProviderAccount {
            cookie_header: Some("better-auth.session_token=xyz; other=1".into()),
            ..Default::default()
        };
        assert_eq!(
            provider.resolve_cookie(&full).unwrap(),
            "better-auth.session_token=xyz; other=1"
        );
    }

    #[test]
    fn active_plan_maps_used_percent_from_catalog_total() {
        // Pro allowance is $30; $18 remaining → $12 used → 40%.
        let credits = parse_credits(&json!({
            "credits": {
                "monthlyCredits": 18.0,
                "purchasedCredits": 5.0
            }
        }))
        .unwrap();
        let subscription = parse_subscription(&json!({
            "success": true,
            "data": {
                "planId": "individual-pro",
                "status": "active",
                "currentPeriodEnd": "2026-08-01T00:00:00Z"
            }
        }))
        .unwrap();
        let snapshot = map_usage(&credits, subscription.as_ref(), false).unwrap();
        let window = &snapshot.windows[0];
        assert_eq!(window.id, "monthly");
        assert_eq!(window.used_percent, 40.0);
        assert_eq!(window.detail.as_deref(), Some("$12.00 of $30.00"));
        assert!(window.resets_at.is_some());
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
        let financials = snapshot.financials.unwrap();
        assert_eq!(financials.balance, Some(23.0)); // 18 remaining + 5 purchased
        assert_eq!(financials.spend, Some(12.0));
        assert_eq!(
            snapshot.summary[0],
            SummaryItem::new("On-demand", "$5.00 credits")
        );
    }

    #[test]
    fn free_tier_renders_remaining_only_window() {
        let credits = parse_credits(&json!({
            "credits": { "monthlyCredits": 4.0 }
        }))
        .unwrap();
        // success:true, data:null → free tier, enrichment succeeded.
        let subscription = parse_subscription(&json!({ "success": true, "data": null })).unwrap();
        assert!(subscription.is_none());
        let snapshot = map_usage(&credits, subscription.as_ref(), false).unwrap();
        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("$4.00 remaining")
        );
        assert_eq!(snapshot.plan, None);
    }

    #[test]
    fn depleted_free_tier_has_no_window() {
        let credits = parse_credits(&json!({
            "credits": { "monthlyCredits": 0.0, "purchasedCredits": 0.0 }
        }))
        .unwrap();
        let snapshot = map_usage(&credits, None, true).unwrap();
        assert!(snapshot.windows.is_empty());
        // Enrichment-unavailable note still surfaces.
        assert!(
            snapshot
                .summary
                .iter()
                .any(|item| item.label == "Subscription")
        );
    }

    #[test]
    fn active_unknown_plan_is_an_error() {
        let credits = parse_credits(&json!({ "credits": { "monthlyCredits": 9.0 } })).unwrap();
        let subscription = parse_subscription(&json!({
            "success": true,
            "data": { "planId": "team-enterprise", "status": "active" }
        }))
        .unwrap();
        let error = map_usage(&credits, subscription.as_ref(), false).unwrap_err();
        assert!(matches!(error, ProviderError::Parse { .. }));
    }

    #[test]
    fn credits_accept_string_encoded_numbers() {
        let credits = parse_credits(&json!({
            "credits": { "monthlyCredits": "7.5", "purchasedCredits": "2" }
        }))
        .unwrap();
        assert_eq!(credits.monthly_credits, 7.5);
        assert_eq!(credits.purchased_credits, 2.0);
    }

    #[test]
    fn missing_monthly_credits_is_a_parse_error() {
        assert!(parse_credits(&json!({ "credits": {} })).is_err());
    }
}
