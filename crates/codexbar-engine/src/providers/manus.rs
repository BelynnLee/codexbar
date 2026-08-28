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
use serde_json::{Value, json};

pub struct ManusProvider {
    credits_url: String,
    browser_import_enabled: bool,
}

impl Default for ManusProvider {
    fn default() -> Self {
        Self {
            credits_url: "https://api.manus.im/user.v1.UserService/GetAvailableCredits".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Manus,
    display_name: "Manus",
    auth_kind: AuthKind::BrowserCookie,
    color: "#3b3b3b",
    dashboard_url: "https://manus.im",
    credential_hint: "Imports the manus.im session_id cookie from Chrome/Edge with DPAPI, or accepts \
a manual Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Manus),
};

const SESSION_COOKIE: &str = "session_id";
const CREDITS_KEYS: &[&str] = &[
    "totalCredits",
    "freeCredits",
    "periodicCredits",
    "addonCredits",
    "refreshCredits",
    "maxRefreshCredits",
    "proMonthlyCredits",
    "eventCredits",
];

#[async_trait]
impl Provider for ManusProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let token = self.resolve_token(account)?;
        let response = context
            .client
            .post(&self.credits_url)
            .bearer_auth(&token)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Origin", "https://manus.im")
            .header("Referer", "https://manus.im/")
            .header("Connect-Protocol-Version", "1")
            .json(&json!({}))
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Manus session token is invalid. Sign in to manus.im or replace the manual Cookie \
header."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Manus",
                status: response.status().as_u16(),
            });
        }
        let body: Value = response.json().await?;
        map_usage(&body)
    }
}

impl ManusProvider {
    fn resolve_token(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(raw) = ProviderConfig::normalized_secret(&account.cookie_header) {
            if let Some(token) = extract_token(raw) {
                return Ok(token);
            }
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a manus.im Cookie header in Settings.".into(),
            ));
        }
        let imported = chromium::find_cookie_header(
            account.browser,
            &["manus.im", "api.manus.im"],
            &[SESSION_COOKIE],
        )?;
        extract_token(&imported.value).ok_or_else(|| {
            ProviderError::MissingCredentials("Imported manus.im cookies had no session_id.".into())
        })
    }
}

/// Accepts a `session_id=<token>` cookie fragment or a bare token.
fn extract_token(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if !raw.contains('=') && !raw.contains(';') {
        return (!raw.is_empty()).then(|| raw.to_owned());
    }
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            if name.trim().eq_ignore_ascii_case(SESSION_COOKIE) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

fn map_usage(body: &Value) -> Result<ProviderSnapshot, ProviderError> {
    let credits = credits_object(body).ok_or(ProviderError::Parse {
        provider: "Manus",
        message: "response missing expected credits fields".into(),
    })?;

    let total = lossy_f64(credits.get("totalCredits")).unwrap_or(0.0);
    let free = lossy_f64(credits.get("freeCredits")).unwrap_or(0.0);
    let periodic = lossy_f64(credits.get("periodicCredits")).unwrap_or(0.0);
    let pro_monthly = lossy_f64(credits.get("proMonthlyCredits")).unwrap_or(0.0);
    let refresh = lossy_f64(credits.get("refreshCredits")).unwrap_or(0.0);
    let max_refresh = lossy_f64(credits.get("maxRefreshCredits")).unwrap_or(0.0);
    let refresh_interval = credits
        .get("refreshInterval")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let next_refresh = parse_date(credits.get("nextRefreshTime"));

    let mut snapshot = ProviderSnapshot::new(ProviderId::Manus, "web");

    if pro_monthly > 0.0 {
        let used_percent = ((pro_monthly - periodic) / pro_monthly * 100.0).clamp(0.0, 100.0);
        snapshot.windows.push(
            UsageWindow::new("monthly", "Monthly", used_percent).with_detail(format!(
                "Total {} · Free {}",
                compact(total),
                compact(free)
            )),
        );
    }

    if max_refresh > 0.0 {
        let used_percent = ((max_refresh - refresh) / max_refresh * 100.0).clamp(0.0, 100.0);
        let detail = match refresh_interval {
            Some(interval) => format!(
                "{}: {} / {}",
                capitalize(interval),
                compact(refresh),
                compact(max_refresh)
            ),
            None => format!("{} / {}", compact(refresh), compact(max_refresh)),
        };
        snapshot.windows.push(
            UsageWindow::new("refresh", "Refresh", used_percent)
                .with_reset(next_refresh)
                .with_detail(detail),
        );
    }

    snapshot.summary.push(SummaryItem::new(
        "Balance",
        format!("{} credits", compact(total)),
    ));
    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(total),
        spend: None,
        currency: None,
    });
    Ok(snapshot)
}

/// Manus wraps the credits payload in one of several envelope keys, or returns it directly; require a
/// known credits field so an error payload is not silently read as a zero-credit snapshot.
fn credits_object(body: &Value) -> Option<&Value> {
    if has_credits_field(body) {
        return Some(body);
    }
    ["data", "result", "response", "availableCredits"]
        .iter()
        .find_map(|key| body.get(*key).filter(|value| has_credits_field(value)))
}

fn has_credits_field(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| CREDITS_KEYS.iter().any(|key| object.contains_key(*key)))
}

fn lossy_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
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

fn compact(value: f64) -> String {
    let rounded = value.round() as i64;
    let digits = rounded.unsigned_abs().to_string();
    let mut grouped = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    if rounded < 0 {
        format!("-{grouped}")
    } else {
        grouped
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_session_token_from_cookie_or_bare() {
        assert_eq!(
            extract_token("session_id=abc123; other=1").as_deref(),
            Some("abc123")
        );
        assert_eq!(extract_token("baretoken").as_deref(), Some("baretoken"));
        assert_eq!(extract_token("other=1; foo=2"), None);
    }

    #[test]
    fn maps_monthly_and_refresh_windows() {
        let body = json!({
            "totalCredits": 1900, "freeCredits": 300,
            "periodicCredits": 400, "proMonthlyCredits": 1000,
            "refreshCredits": 150, "maxRefreshCredits": 300,
            "refreshInterval": "daily", "nextRefreshTime": "2026-07-20T00:00:00Z"
        });
        let snapshot = map_usage(&body).unwrap();
        // monthly: (1000-400)/1000 = 60%.
        let monthly = snapshot.windows.iter().find(|w| w.id == "monthly").unwrap();
        assert_eq!(monthly.used_percent, 60.0);
        assert_eq!(monthly.detail.as_deref(), Some("Total 1,900 · Free 300"));
        // refresh: (300-150)/300 = 50%.
        let refresh = snapshot.windows.iter().find(|w| w.id == "refresh").unwrap();
        assert_eq!(refresh.used_percent, 50.0);
        assert_eq!(refresh.detail.as_deref(), Some("Daily: 150 / 300"));
        assert_eq!(snapshot.financials.unwrap().balance, Some(1900.0));
    }

    #[test]
    fn reads_envelope_and_lossy_string_numbers() {
        let body = json!({ "data": { "totalCredits": "500", "proMonthlyCredits": "0" } });
        let snapshot = map_usage(&body).unwrap();
        assert!(snapshot.windows.iter().all(|w| w.id != "monthly")); // proMonthly 0 → no window
        assert_eq!(
            snapshot
                .summary
                .iter()
                .find(|s| s.label == "Balance")
                .unwrap()
                .value,
            "500 credits"
        );
    }

    #[test]
    fn rejects_payload_without_credits_fields() {
        assert!(matches!(
            map_usage(&json!({ "error": "session expired" })),
            Err(ProviderError::Parse {
                provider: "Manus",
                ..
            })
        ));
    }
}
