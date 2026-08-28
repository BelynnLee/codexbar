use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use serde_json::Value;

pub struct T3ChatProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for T3ChatProvider {
    fn default() -> Self {
        Self {
            base_url: "https://t3.chat".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::T3chat,
    display_name: "T3 Chat",
    auth_kind: AuthKind::BrowserCookie,
    color: "#e5006a",
    dashboard_url: "https://t3.chat/settings/customization",
    credential_hint: "Imports t3.chat cookies from Chrome/Edge with DPAPI, or accepts a manual \
Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::T3chat),
};

const CUSTOMER_DATA_PATH: &str = "/api/trpc/getCustomerData";
// tRPC batch input captured from t3.chat's getCustomerData request.
const INPUT: &str =
    r#"{"0":{"json":{"sessionId":null},"meta":{"values":{"sessionId":["undefined"]}}}}"#;
const REFERER: &str = "https://t3.chat/settings/customization";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";
const FOUR_HOUR_MINUTES: u32 = 240;

#[async_trait]
impl Provider for T3ChatProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let cookie = self.resolve_cookie(account)?;
        let url = format!(
            "{}{CUSTOMER_DATA_PATH}",
            self.base_url.trim_end_matches('/')
        );
        let response = context
            .client
            .get(&url)
            .query(&[("batch", "1"), ("input", INPUT)])
            .header("Accept", "*/*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("trpc-accept", "application/jsonl")
            .header("x-trpc-source", "web-client")
            .header("x-trpc-batch", "true")
            .header("Origin", self.base_url.trim_end_matches('/').to_owned())
            .header("Referer", REFERER)
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Site", "same-origin")
            .header("User-Agent", USER_AGENT)
            .header("Cookie", cookie)
            .send()
            .await?;
        let status = response.status();
        if matches!(status.as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "T3 Chat session cookie is invalid or expired. Sign in to t3.chat again.".into(),
            ));
        }
        if status.as_u16() == 429
            && response
                .headers()
                .get("x-vercel-mitigated")
                .and_then(|value| value.to_str().ok())
                == Some("challenge")
        {
            return Err(ProviderError::Unauthorized(
                "T3 Chat returned a Vercel security challenge. Sign in to t3.chat again and \
re-import fresh cookies."
                    .into(),
            ));
        }
        if !status.is_success() {
            return Err(ProviderError::Http {
                provider: "T3 Chat",
                status: status.as_u16(),
            });
        }
        let body = response.text().await?;
        let data = parse_customer_data(&body)?;
        Ok(map_usage(&data))
    }
}

impl T3ChatProvider {
    fn resolve_cookie(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            return Ok(value.to_owned());
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a t3.chat Cookie header in Settings.".into(),
            ));
        }
        // T3 Chat authenticates with the full session cookie set; take every cookie for the domain.
        let imported =
            chromium::find_cookie_header(account.browser, &["t3.chat", "www.t3.chat"], &[])?;
        Ok(imported.value)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    product_name: Option<String>,
    current_period_end: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomerData {
    sub_tier: Option<String>,
    subscription: Option<Subscription>,
    usage_band: Option<String>,
    usage_four_hour_percentage: Option<f64>,
    usage_month_percentage: Option<f64>,
    usage_period_percentage: Option<f64>,
    usage_four_hour_next_reset_at: Option<f64>,
    usage_window_next_reset_at: Option<f64>,
}

impl CustomerData {
    fn plan_name(&self) -> Option<String> {
        let raw = self
            .subscription
            .as_ref()
            .and_then(|subscription| subscription.product_name.as_deref())
            .or(self.sub_tier.as_deref())?
            .trim();
        if raw.is_empty() {
            return None;
        }
        // "cerebras-code-pro" → "Cerebras Code Pro" (uppercase the first letter of each segment).
        Some(raw.split('-').map(capitalize).collect::<Vec<_>>().join(" "))
    }
}

/// The tRPC batch response is JSONL; find the first line whose object carries the usage fields.
fn parse_customer_data(body: &str) -> Result<CustomerData, ProviderError> {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(found) = find_customer_data(&value) {
            return serde_json::from_value(found.clone()).map_err(|error| ProviderError::Parse {
                provider: "T3 Chat",
                message: error.to_string(),
            });
        }
    }
    Err(ProviderError::Parse {
        provider: "T3 Chat",
        message: "missing customer data object".into(),
    })
}

fn find_customer_data(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(map) => {
            if map.contains_key("usageFourHourPercentage")
                || map.contains_key("usageMonthPercentage")
                || (map.contains_key("subscription") && map.contains_key("usageBand"))
            {
                return Some(value);
            }
            map.values().find_map(find_customer_data)
        }
        Value::Array(items) => items.iter().find_map(find_customer_data),
        _ => None,
    }
}

fn map_usage(data: &CustomerData) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::T3chat, "web");

    let base_reset = ms_to_date(data.usage_four_hour_next_reset_at)
        .or_else(|| ms_to_date(data.usage_window_next_reset_at));
    snapshot.windows.push(
        UsageWindow::new(
            "four_hour",
            "4h Window",
            clamp_percent(data.usage_four_hour_percentage),
        )
        .with_window_minutes(FOUR_HOUR_MINUTES)
        .with_reset(base_reset)
        .with_detail(base_detail(data.usage_band.as_deref())),
    );

    // The month/period window is the overage lane; its reset tracks the subscription period, not
    // the base usage window, so leave it unknown when subscription metadata is absent.
    let secondary_percent =
        clamp_percent(data.usage_month_percentage.or(data.usage_period_percentage));
    let overage_reset = ms_to_date(
        data.subscription
            .as_ref()
            .and_then(|subscription| subscription.current_period_end),
    );
    snapshot.windows.push(
        UsageWindow::new("overage", "Overage", secondary_percent)
            .with_reset(overage_reset)
            .with_detail("Overage"),
    );

    snapshot.plan = data.plan_name();
    snapshot
}

fn capitalize(segment: &str) -> String {
    let mut chars = segment.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn clamp_percent(raw: Option<f64>) -> f64 {
    raw.unwrap_or(0.0).clamp(0.0, 100.0)
}

fn base_detail(usage_band: Option<&str>) -> String {
    match usage_band.map(str::trim).filter(|band| !band.is_empty()) {
        Some(band) => format!("Base - {band}"),
        None => "Base".to_owned(),
    }
}

/// T3 Chat returns JavaScript epoch milliseconds for usage resets; some subscription fields are in
/// seconds. Values above ~1e10 are treated as milliseconds.
fn ms_to_date(raw: Option<f64>) -> Option<DateTime<Utc>> {
    let raw = raw?;
    if raw <= 0.0 {
        return None;
    }
    let seconds = if raw > 10_000_000_000.0 {
        raw / 1000.0
    } else {
        raw
    };
    Utc.timestamp_opt(seconds as i64, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_manual_cookie_header_passthrough() {
        let provider = T3ChatProvider {
            browser_import_enabled: false,
            ..Default::default()
        };
        let account = ProviderAccount {
            cookie_header: Some("__session=abc; other=1".into()),
            ..Default::default()
        };
        assert_eq!(
            provider.resolve_cookie(&account).unwrap(),
            "__session=abc; other=1"
        );
    }

    #[test]
    fn parses_jsonl_and_maps_base_and_overage_windows() {
        let body = "[[]]\n".to_owned()
            + &json!({
                "result": {
                    "data": {
                        "json": {
                            "subTier": "cerebras-code-pro",
                            "usageBand": "high",
                            "usageFourHourPercentage": 42.5,
                            "usageMonthPercentage": 10.0,
                            "usageFourHourNextResetAt": 1_777_528_800_000_i64,
                            "subscription": {
                                "productName": "cerebras-code-pro",
                                "currentPeriodEnd": 1_780_000_000_000_i64
                            }
                        }
                    }
                }
            })
            .to_string();
        let data = parse_customer_data(&body).unwrap();
        let snapshot = map_usage(&data);
        assert_eq!(snapshot.windows[0].id, "four_hour");
        assert_eq!(snapshot.windows[0].used_percent, 42.5);
        assert_eq!(snapshot.windows[0].window_minutes, Some(240));
        assert_eq!(snapshot.windows[0].detail.as_deref(), Some("Base - high"));
        assert!(snapshot.windows[0].resets_at.is_some());
        assert_eq!(snapshot.windows[1].id, "overage");
        assert_eq!(snapshot.windows[1].used_percent, 10.0);
        assert!(snapshot.windows[1].resets_at.is_some());
        assert_eq!(snapshot.plan.as_deref(), Some("Cerebras Code Pro"));
    }

    #[test]
    fn falls_back_to_period_percentage_and_window_reset() {
        let data: CustomerData = serde_json::from_value(json!({
            "usageFourHourPercentage": 5.0,
            "usagePeriodPercentage": 88.0,
            "usageWindowNextResetAt": 1_777_528_800_000_i64
        }))
        .unwrap();
        let snapshot = map_usage(&data);
        assert!(snapshot.windows[0].resets_at.is_some()); // window reset used as base fallback
        assert_eq!(snapshot.windows[1].used_percent, 88.0);
        assert!(snapshot.windows[1].resets_at.is_none()); // no subscription → overage reset unknown
        assert_eq!(snapshot.plan, None);
    }

    #[test]
    fn percentages_are_clamped() {
        let data: CustomerData = serde_json::from_value(json!({
            "usageFourHourPercentage": 130.0,
            "usageMonthPercentage": -5.0
        }))
        .unwrap();
        let snapshot = map_usage(&data);
        assert_eq!(snapshot.windows[0].used_percent, 100.0);
        assert_eq!(snapshot.windows[1].used_percent, 0.0);
    }

    #[test]
    fn seconds_and_millisecond_timestamps_both_decode() {
        assert_eq!(
            ms_to_date(Some(1_777_528_800.0)),
            ms_to_date(Some(1_777_528_800_000.0))
        );
        assert!(ms_to_date(Some(0.0)).is_none());
        assert!(ms_to_date(None).is_none());
    }

    #[test]
    fn missing_customer_object_is_a_parse_error() {
        assert!(parse_customer_data("{\"result\":{}}\n[1,2,3]").is_err());
    }
}
