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
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;
use std::collections::BTreeMap;

pub struct MiMoProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for MiMoProvider {
    fn default() -> Self {
        Self {
            base_url: "https://platform.xiaomimimo.com/api/v1".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Mimo,
    display_name: "Xiaomi MiMo",
    auth_kind: AuthKind::BrowserCookie,
    color: "#ff6a00",
    dashboard_url: "https://platform.xiaomimimo.com/#/console/balance",
    credential_hint: "Imports platform.xiaomimimo.com cookies from Chrome/Edge with DPAPI, or \
accepts a manual Cookie header (needs api-platform_serviceToken and userId).",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Mimo),
};

const REQUIRED_COOKIE_NAMES: &[&str] = &["api-platform_serviceToken", "userId"];
const KNOWN_COOKIE_NAMES: &[&str] = &[
    "api-platform_serviceToken",
    "userId",
    "api-platform_ph",
    "api-platform_slh",
];
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

#[async_trait]
impl Provider for MiMoProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let cookie = self.resolve_cookie(account)?;
        let balance_value = self
            .fetch_authenticated(context, "balance", &cookie)
            .await?;
        let balance = parse_balance(&balance_value)?;
        // Plan detail + usage are best-effort enrichment; a failure keeps the balance card.
        let detail = self
            .fetch_authenticated(context, "tokenPlan/detail", &cookie)
            .await
            .ok()
            .and_then(|value| parse_token_detail(&value));
        let usage = self
            .fetch_authenticated(context, "tokenPlan/usage", &cookie)
            .await
            .ok()
            .and_then(|value| parse_token_usage(&value));
        Ok(map_usage(&balance, detail, usage))
    }
}

impl MiMoProvider {
    fn resolve_cookie(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            return normalized_header(value).ok_or_else(|| {
                ProviderError::MissingCredentials(
                    "Xiaomi MiMo requires the api-platform_serviceToken and userId cookies.".into(),
                )
            });
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a platform.xiaomimimo.com Cookie header in Settings.".into(),
            ));
        }
        let imported = chromium::find_cookie_header(
            account.browser,
            &["platform.xiaomimimo.com", "xiaomimimo.com"],
            KNOWN_COOKIE_NAMES,
        )?;
        normalized_header(&imported.value).ok_or_else(|| {
            ProviderError::MissingCredentials(
                "No Xiaomi MiMo session found. Sign in at platform.xiaomimimo.com first.".into(),
            )
        })
    }

    async fn fetch_authenticated(
        &self,
        context: &FetchContext<'_>,
        path: &str,
        cookie: &str,
    ) -> Result<Value, ProviderError> {
        let url = format!("{}/{path}", self.base_url.trim_end_matches('/'));
        let response = context
            .client
            .get(&url)
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("x-timeZone", "UTC+01:00")
            .header("Cookie", cookie)
            .header("Origin", "https://platform.xiaomimimo.com")
            .header(
                "Referer",
                "https://platform.xiaomimimo.com/#/console/balance",
            )
            .header("User-Agent", USER_AGENT)
            .send()
            .await?;
        match response.status().as_u16() {
            401 => Err(ProviderError::Unauthorized(
                "Xiaomi MiMo login required. Sign in again at platform.xiaomimimo.com.".into(),
            )),
            403 => Err(ProviderError::Unauthorized(
                "Xiaomi MiMo browser session expired. Sign in again.".into(),
            )),
            status if (200..300).contains(&status) => {
                response.json().await.map_err(|error| ProviderError::Parse {
                    provider: "Xiaomi MiMo",
                    message: error.to_string(),
                })
            }
            status => Err(ProviderError::Http {
                provider: "Xiaomi MiMo",
                status,
            }),
        }
    }
}

/// Keeps only the known cookies, requires the two mandatory ones, and re-serializes them in a
/// stable order so the header matches what the platform expects.
fn normalized_header(raw: &str) -> Option<String> {
    let mut by_name: BTreeMap<&str, &str> = BTreeMap::new();
    for chunk in raw.split(';') {
        if let Some((name, value)) = chunk.split_once('=') {
            let name = name.trim();
            let value = value.trim();
            if KNOWN_COOKIE_NAMES.contains(&name) && !value.is_empty() {
                by_name.insert(name, value);
            }
        }
    }
    if !REQUIRED_COOKIE_NAMES
        .iter()
        .all(|name| by_name.contains_key(name))
    {
        return None;
    }
    Some(
        by_name
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

#[derive(Debug)]
struct Balance {
    balance: f64,
    currency: String,
    cash: Option<f64>,
    gift: Option<f64>,
}

struct PlanDetail {
    plan_code: Option<String>,
    period_end: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct PlanUsage {
    used: i64,
    limit: i64,
    percent: f64,
}

fn parse_balance(value: &Value) -> Result<Balance, ProviderError> {
    let code = value.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        if code == 401 {
            return Err(ProviderError::Unauthorized(
                "Xiaomi MiMo login required. Sign in again.".into(),
            ));
        }
        if code == 403 {
            return Err(ProviderError::Unauthorized(
                "Xiaomi MiMo browser session expired. Sign in again.".into(),
            ));
        }
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map_or_else(|| format!("code {code}"), str::to_owned);
        return Err(ProviderError::Parse {
            provider: "Xiaomi MiMo",
            message,
        });
    }
    let data = value.get("data").ok_or(ProviderError::Parse {
        provider: "Xiaomi MiMo",
        message: "missing balance payload".into(),
    })?;
    let balance = string_f64(data.get("balance")).ok_or(ProviderError::Parse {
        provider: "Xiaomi MiMo",
        message: "invalid balance value".into(),
    })?;
    let currency = data
        .get("currency")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .ok_or(ProviderError::Parse {
            provider: "Xiaomi MiMo",
            message: "missing currency".into(),
        })?
        .to_owned();
    Ok(Balance {
        balance,
        currency,
        cash: string_f64(data.get("cashBalance")),
        gift: string_f64(data.get("giftBalance")),
    })
}

fn parse_token_detail(value: &Value) -> Option<PlanDetail> {
    if value.get("code").and_then(Value::as_i64) != Some(0) {
        return None;
    }
    let data = value.get("data")?;
    Some(PlanDetail {
        plan_code: data
            .get("planCode")
            .and_then(Value::as_str)
            .map(str::to_owned),
        period_end: data
            .get("currentPeriodEnd")
            .and_then(Value::as_str)
            .and_then(parse_period_end),
    })
}

fn parse_token_usage(value: &Value) -> Option<PlanUsage> {
    if value.get("code").and_then(Value::as_i64) != Some(0) {
        return None;
    }
    let item = value
        .get("data")?
        .get("monthUsage")?
        .get("items")?
        .as_array()?
        .first()?;
    Some(PlanUsage {
        used: item.get("used").and_then(Value::as_i64).unwrap_or(0),
        limit: item.get("limit").and_then(Value::as_i64).unwrap_or(0),
        percent: item.get("percent").and_then(Value::as_f64).unwrap_or(0.0),
    })
}

fn map_usage(
    balance: &Balance,
    detail: Option<PlanDetail>,
    usage: Option<PlanUsage>,
) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Mimo, "web");
    let usage = usage.unwrap_or_default();
    let period_end = detail.as_ref().and_then(|detail| detail.period_end);

    if usage.limit > 0 {
        // `percent` is a 0..1 fraction on the wire.
        let percent = (usage.percent * 100.0).clamp(0.0, 100.0);
        snapshot.windows.push(
            UsageWindow::new("credits", "Credits", percent)
                .with_reset(period_end)
                .with_detail(format!(
                    "{} / {} Credits",
                    group(usage.used),
                    group(usage.limit)
                )),
        );
    }

    snapshot.plan = detail
        .and_then(|detail| detail.plan_code)
        .map(|code| title_case(&code));

    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(balance.balance),
        spend: None,
        currency: Some(balance.currency.clone()),
    });

    if let (Some(cash), Some(gift)) = (balance.cash, balance.gift) {
        snapshot.summary.push(SummaryItem::new(
            "Paid",
            format!("{cash:.2} {}", balance.currency),
        ));
        snapshot.summary.push(SummaryItem::new(
            "Granted",
            format!("{gift:.2} {}", balance.currency),
        ));
    }

    snapshot
}

fn string_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::String(text) => text.trim().parse().ok(),
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        _ => None,
    }
}

fn parse_period_end(raw: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| Utc.from_utc_datetime(&naive))
}

fn title_case(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn group(value: i64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalized_header_requires_both_mandatory_cookies() {
        assert_eq!(
            normalized_header("userId=42; api-platform_serviceToken=tok; junk=x"),
            Some("api-platform_serviceToken=tok; userId=42".into())
        );
        // Missing userId → rejected.
        assert_eq!(normalized_header("api-platform_serviceToken=tok"), None);
    }

    #[test]
    fn balance_envelope_parses_string_amounts() {
        let balance = parse_balance(&json!({
            "code": 0,
            "data": {
                "balance": "12.50",
                "currency": "USD",
                "cashBalance": "10.00",
                "giftBalance": "2.50"
            }
        }))
        .unwrap();
        assert_eq!(balance.balance, 12.5);
        assert_eq!(balance.currency, "USD");
        assert_eq!(balance.cash, Some(10.0));
        assert_eq!(balance.gift, Some(2.5));
    }

    #[test]
    fn balance_error_codes_map_to_unauthorized() {
        assert!(matches!(
            parse_balance(&json!({ "code": 401 })).unwrap_err(),
            ProviderError::Unauthorized(_)
        ));
        assert!(matches!(
            parse_balance(&json!({ "code": 500, "message": "boom" })).unwrap_err(),
            ProviderError::Parse { .. }
        ));
    }

    #[test]
    fn token_plan_builds_window_and_plan() {
        let balance = parse_balance(&json!({
            "code": 0, "data": { "balance": "5", "currency": "USD" }
        }))
        .unwrap();
        let detail = parse_token_detail(&json!({
            "code": 0,
            "data": { "planCode": "coding pro", "currentPeriodEnd": "2026-08-01 00:00:00", "expired": false }
        }));
        let usage = parse_token_usage(&json!({
            "code": 0,
            "data": { "monthUsage": { "percent": 0.5, "items": [{ "name": "tok", "used": 1500, "limit": 3000, "percent": 0.5 }] } }
        }));
        let snapshot = map_usage(&balance, detail, usage);
        assert_eq!(snapshot.windows[0].used_percent, 50.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("1,500 / 3,000 Credits")
        );
        assert!(snapshot.windows[0].resets_at.is_some());
        assert_eq!(snapshot.plan.as_deref(), Some("Coding Pro"));
        assert_eq!(snapshot.financials.as_ref().unwrap().balance, Some(5.0));
    }

    #[test]
    fn no_token_plan_yields_balance_only() {
        let balance = parse_balance(&json!({
            "code": 0, "data": { "balance": "8", "currency": "CNY" }
        }))
        .unwrap();
        let snapshot = map_usage(&balance, None, None);
        assert!(snapshot.windows.is_empty());
        assert_eq!(
            snapshot.financials.unwrap().currency.as_deref(),
            Some("CNY")
        );
    }

    #[test]
    fn best_effort_enrichment_ignores_error_envelopes() {
        assert!(parse_token_detail(&json!({ "code": 1 })).is_none());
        assert!(parse_token_usage(&json!({ "code": 1 })).is_none());
    }
}
