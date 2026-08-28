use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;

pub struct PerplexityProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for PerplexityProvider {
    fn default() -> Self {
        Self {
            base_url: "https://www.perplexity.ai".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Perplexity,
    display_name: "Perplexity",
    auth_kind: AuthKind::BrowserCookie,
    color: "#20808d",
    dashboard_url: "https://www.perplexity.ai/account/usage",
    credential_hint: "Imports perplexity.ai cookies from Chrome/Edge with DPAPI, or accepts a manual Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Perplexity),
};

const CREDITS_PATH: &str = "/rest/billing/credits?version=2.18&source=default";
const DEFAULT_SESSION_COOKIE: &str = "__Secure-next-auth.session-token";
const COOKIE_NAMES: &[&str] = &[
    "__Secure-authjs.session-token",
    "authjs.session-token",
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
];
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

#[async_trait]
impl Provider for PerplexityProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let cookie = self.resolve_cookie(account)?;
        let url = format!("{}{CREDITS_PATH}", self.base_url.trim_end_matches('/'));
        let response = context
            .client
            .get(&url)
            .header("Accept", "application/json")
            .header("Cookie", cookie)
            .header("Origin", "https://www.perplexity.ai")
            .header("Referer", "https://www.perplexity.ai/account/usage")
            .header("User-Agent", USER_AGENT)
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Perplexity session cookie expired. Sign in to perplexity.ai or replace the manual \
Cookie header."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Perplexity",
                status: response.status().as_u16(),
            });
        }
        let credits: CreditsResponse =
            response
                .json()
                .await
                .map_err(|error| ProviderError::Parse {
                    provider: "Perplexity",
                    message: error.to_string(),
                })?;
        Ok(map_usage(&credits, Utc::now()))
    }
}

impl PerplexityProvider {
    fn resolve_cookie(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            // A full "name=value; …" header passes through; a bare token is wrapped in the default
            // session cookie name.
            let header = if value.contains('=') {
                value.to_owned()
            } else {
                format!("{DEFAULT_SESSION_COOKIE}={value}")
            };
            return Ok(header);
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a perplexity.ai Cookie header in Settings.".into(),
            ));
        }
        let imported = chromium::find_cookie_header(
            account.browser,
            &["perplexity.ai", "www.perplexity.ai"],
            COOKIE_NAMES,
        )?;
        Ok(imported.value)
    }
}

fn map_usage(response: &CreditsResponse, now: DateTime<Utc>) -> ProviderSnapshot {
    let now_ts = now.timestamp() as f64;
    let recurring_total = grant_sum(&response.credit_grants, |grant| {
        grant.type_field == "recurring"
    });
    let promo_total = grant_sum(&response.credit_grants, |grant| {
        grant.type_field == "promotional"
            && grant.expires_at_ts.is_none_or(|expiry| expiry > now_ts)
    });
    // Purchased credits may appear in the grants array, the top-level field, or both; take the larger
    // to catch either source without double-counting.
    let purchased_from_grants = grant_sum(&response.credit_grants, |grant| {
        grant.type_field == "purchased"
    });
    let purchased_total =
        purchased_from_grants.max(response.current_period_purchased_cents.max(0.0));

    // Waterfall attribution of total usage: recurring → purchased → promotional.
    let mut remaining = response.total_usage_cents;
    let recurring_used = remaining.min(recurring_total).max(0.0);
    remaining -= recurring_used;
    let purchased_used = remaining.min(purchased_total).max(0.0);
    remaining -= purchased_used;
    let promo_used = remaining.min(promo_total).max(0.0);

    let renewal_date = timestamp_to_date(response.renewal_date_ts);
    let promo_expiry = response
        .credit_grants
        .iter()
        .filter(|grant| {
            grant.type_field == "promotional"
                && grant.expires_at_ts.is_some_and(|expiry| expiry > now_ts)
        })
        .filter_map(|grant| grant.expires_at_ts)
        .min_by(f64::total_cmp)
        .and_then(timestamp_to_date);

    let mut snapshot = ProviderSnapshot::new(ProviderId::Perplexity, "web");

    // Recurring (monthly) credits — the primary lane. Windows renders bars generically, so unlike the
    // macOS custom UI we only add the promo/purchased lanes when they carry real credits rather than a
    // 100%-of-zero placeholder that would read as a full bar here.
    if recurring_total > 0.0 {
        let percent = (recurring_used / recurring_total * 100.0).clamp(0.0, 100.0);
        snapshot.windows.push(
            UsageWindow::new("recurring", "Monthly credits", percent)
                .with_reset(renewal_date)
                .with_detail(format!(
                    "{}/{} credits",
                    round(recurring_used),
                    round(recurring_total)
                )),
        );
    } else if promo_total <= 0.0 && purchased_total <= 0.0 {
        snapshot.windows.push(
            UsageWindow::new("recurring", "Monthly credits", 100.0)
                .with_reset(renewal_date)
                .with_detail("0/0 credits"),
        );
    }

    if promo_total > 0.0 {
        let percent = (promo_used / promo_total * 100.0).clamp(0.0, 100.0);
        let detail = match promo_expiry {
            Some(expiry) => format!(
                "{}/{} bonus · exp. {}",
                round(promo_used),
                round(promo_total),
                expiry.format("%b %-d")
            ),
            None => format!("{}/{} bonus", round(promo_used), round(promo_total)),
        };
        snapshot
            .windows
            .push(UsageWindow::new("promo", "Bonus credits", percent).with_detail(detail));
    }

    if purchased_total > 0.0 {
        let percent = (purchased_used / purchased_total * 100.0).clamp(0.0, 100.0);
        snapshot.windows.push(
            UsageWindow::new("purchased", "On-demand", percent).with_detail(format!(
                "{}/{} credits",
                round(purchased_used),
                round(purchased_total)
            )),
        );
    }

    snapshot.plan = plan_name(recurring_total);
    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(response.balance_cents / 100.0),
        spend: Some(response.total_usage_cents / 100.0),
        currency: Some("USD".into()),
    });
    snapshot
}

/// Free = no recurring pool; Pro = a small pool (~500–1000); Max = 10,000+.
fn plan_name(recurring_total: f64) -> Option<String> {
    if recurring_total <= 0.0 {
        return None;
    }
    Some(
        if recurring_total < 5000.0 {
            "Pro"
        } else {
            "Max"
        }
        .to_owned(),
    )
}

fn grant_sum(grants: &[CreditGrant], predicate: impl Fn(&CreditGrant) -> bool) -> f64 {
    grants
        .iter()
        .filter(|grant| predicate(grant))
        .map(|grant| grant.amount_cents)
        .sum::<f64>()
        .max(0.0)
}

fn timestamp_to_date(seconds: f64) -> Option<DateTime<Utc>> {
    seconds
        .is_finite()
        .then(|| Utc.timestamp_opt(seconds as i64, 0).single())
        .flatten()
}

fn round(value: f64) -> i64 {
    value.round() as i64
}

#[derive(Debug, Deserialize)]
struct CreditsResponse {
    #[serde(default, rename = "balance_cents")]
    balance_cents: f64,
    #[serde(default, rename = "renewal_date_ts")]
    renewal_date_ts: f64,
    #[serde(default, rename = "current_period_purchased_cents")]
    current_period_purchased_cents: f64,
    #[serde(default, rename = "credit_grants")]
    credit_grants: Vec<CreditGrant>,
    #[serde(default, rename = "total_usage_cents")]
    total_usage_cents: f64,
}

#[derive(Debug, Deserialize)]
struct CreditGrant {
    #[serde(default, rename = "type")]
    type_field: String,
    #[serde(default, rename = "amount_cents")]
    amount_cents: f64,
    #[serde(default, rename = "expires_at_ts")]
    expires_at_ts: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0).unwrap()
    }

    fn parse(value: serde_json::Value) -> CreditsResponse {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn resolves_manual_cookie_bare_token_and_full_header() {
        let provider = PerplexityProvider {
            browser_import_enabled: false,
            ..Default::default()
        };
        let bare = ProviderAccount {
            cookie_header: Some("abc123".into()),
            ..Default::default()
        };
        assert_eq!(
            provider.resolve_cookie(&bare).unwrap(),
            "__Secure-next-auth.session-token=abc123"
        );
        let full = ProviderAccount {
            cookie_header: Some("__Secure-authjs.session-token=xyz; other=1".into()),
            ..Default::default()
        };
        assert_eq!(
            provider.resolve_cookie(&full).unwrap(),
            "__Secure-authjs.session-token=xyz; other=1"
        );
    }

    #[test]
    fn attributes_usage_as_waterfall_recurring_then_purchased_then_promo() {
        // recurring 1000, purchased 500, promo 300; usage 1400 → recurring 1000, purchased 400, promo 0.
        let response = parse(json!({
            "balance_cents": 4000.0,
            "renewal_date_ts": 1_785_000_000,
            "current_period_purchased_cents": 0.0,
            "total_usage_cents": 1400.0,
            "credit_grants": [
                { "type": "recurring", "amount_cents": 1000.0 },
                { "type": "purchased", "amount_cents": 500.0 },
                { "type": "promotional", "amount_cents": 300.0 }
            ]
        }));
        let snapshot = map_usage(&response, now());
        let recurring = snapshot
            .windows
            .iter()
            .find(|w| w.id == "recurring")
            .unwrap();
        assert_eq!(recurring.used_percent, 100.0);
        assert_eq!(recurring.detail.as_deref(), Some("1000/1000 credits"));
        let purchased = snapshot
            .windows
            .iter()
            .find(|w| w.id == "purchased")
            .unwrap();
        assert_eq!(purchased.used_percent, 80.0); // 400/500
        // promo carried no usage but still has a pool → 0% window.
        let promo = snapshot.windows.iter().find(|w| w.id == "promo").unwrap();
        assert_eq!(promo.used_percent, 0.0);
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
        assert_eq!(snapshot.financials.unwrap().balance, Some(40.0));
    }

    #[test]
    fn excludes_expired_promotional_grants() {
        let response = parse(json!({
            "total_usage_cents": 0.0,
            "renewal_date_ts": 1_785_000_000,
            "credit_grants": [
                { "type": "promotional", "amount_cents": 200.0, "expires_at_ts": 1_000_000_000 }
            ]
        }));
        let snapshot = map_usage(&response, now());
        // Expired promo dropped and no recurring/purchased → single 0/0 recurring placeholder.
        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.windows[0].id, "recurring");
        assert_eq!(snapshot.windows[0].detail.as_deref(), Some("0/0 credits"));
    }

    #[test]
    fn max_plan_inferred_from_large_recurring_pool() {
        let response = parse(json!({
            "total_usage_cents": 0.0,
            "renewal_date_ts": 1_785_000_000,
            "credit_grants": [{ "type": "recurring", "amount_cents": 10000.0 }]
        }));
        let snapshot = map_usage(&response, now());
        assert_eq!(snapshot.plan.as_deref(), Some("Max"));
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
    }

    #[test]
    fn prefers_larger_of_purchased_grant_and_field() {
        let response = parse(json!({
            "total_usage_cents": 0.0,
            "renewal_date_ts": 1_785_000_000,
            "current_period_purchased_cents": 700.0,
            "credit_grants": [{ "type": "purchased", "amount_cents": 300.0 }]
        }));
        let snapshot = map_usage(&response, now());
        let purchased = snapshot
            .windows
            .iter()
            .find(|w| w.id == "purchased")
            .unwrap();
        assert_eq!(purchased.detail.as_deref(), Some("0/700 credits"));
    }
}
