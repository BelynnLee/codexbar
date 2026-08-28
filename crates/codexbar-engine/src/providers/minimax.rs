use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;
use std::env;

#[derive(Default)]
pub struct MiniMaxProvider {
    /// Test seam: when set, replaces the resolved remains host so a local fixture server can answer.
    api_base_url: Option<String>,
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Minimax,
    display_name: "MiniMax",
    auth_kind: AuthKind::ApiKey,
    color: "#ff5a5f",
    dashboard_url: "https://platform.minimax.io/user-center/payment/coding-plan",
    credential_hint: "Set an API key in Settings or MINIMAX_CODING_API_KEY / MINIMAX_API_KEY. Pick \
the Global or China mainland region.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Minimax),
};

const TOKEN_PLAN_REMAINS_PATH: &str = "/v1/token_plan/remains";
const CODING_PLAN_REMAINS_PATH: &str = "/v1/api/openplatform/coding_plan/remains";
const GLOBAL_API_BASE: &str = "https://api.minimax.io";
const CHINA_API_BASE: &str = "https://api.minimaxi.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Region {
    Global,
    ChinaMainland,
}

impl Region {
    fn api_base(self) -> &'static str {
        match self {
            Self::Global => GLOBAL_API_BASE,
            Self::ChinaMainland => CHINA_API_BASE,
        }
    }
}

fn parse_region(region: Option<&str>) -> Region {
    match region
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("cn" | "china" | "chinamainland" | "china-mainland") => Region::ChinaMainland,
        _ => Region::Global,
    }
}

#[async_trait]
impl Provider for MiniMaxProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let region = parse_region(account.region.as_deref());

        match self.fetch_region(context, &api_key, region).await {
            Ok(snapshot) => Ok(snapshot),
            // Historically MiniMax API tokens defaulted to a China endpoint; when the global host
            // rejects a token and no region was pinned, retry China before giving up.
            Err(ProviderError::Unauthorized(message)) if region == Region::Global => self
                .fetch_region(context, &api_key, Region::ChinaMainland)
                .await
                .map_err(|_| ProviderError::Unauthorized(message)),
            Err(error) => Err(error),
        }
    }
}

impl MiniMaxProvider {
    async fn fetch_region(
        &self,
        context: &FetchContext<'_>,
        api_key: &str,
        region: Region,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let mut last_error: Option<ProviderError> = None;
        let mut saw_unauthorized = false;
        for path in [TOKEN_PLAN_REMAINS_PATH, CODING_PLAN_REMAINS_PATH] {
            let url = self.remains_url(region, path);
            match self.fetch_once(context, api_key, &url).await {
                Ok(snapshot) => return Ok(snapshot),
                Err(ProviderError::Unauthorized(message)) => {
                    saw_unauthorized = true;
                    last_error = Some(ProviderError::Unauthorized(message));
                }
                Err(error) => last_error = Some(error),
            }
        }
        if saw_unauthorized {
            return Err(ProviderError::Unauthorized(
                "MiniMax API key was rejected.".into(),
            ));
        }
        Err(last_error.unwrap_or(ProviderError::Parse {
            provider: "MiniMax",
            message: "no remains endpoint responded".into(),
        }))
    }

    fn remains_url(&self, region: Region, path: &str) -> String {
        let base = self
            .api_base_url
            .as_deref()
            .map_or_else(|| region.api_base(), |base| base.trim_end_matches('/'));
        format!("{}{path}", base.trim_end_matches('/'))
    }

    async fn fetch_once(
        &self,
        context: &FetchContext<'_>,
        api_key: &str,
        url: &str,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let response = context
            .client
            .get(url)
            .bearer_auth(api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("MM-API-Source", "CodexBar")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "MiniMax API key was rejected.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "MiniMax",
                status: response.status().as_u16(),
            });
        }
        let body: Value = response.json().await?;
        map_usage(&body, Utc::now())
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| env_var("MINIMAX_CODING_API_KEY"))
        .or_else(|| env_var("MINIMAX_API_KEY"))
        .ok_or_else(|| ProviderError::MissingCredentials("Missing MiniMax API key.".into()))
}

fn env_var(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn map_usage(body: &Value, now: DateTime<Utc>) -> Result<ProviderSnapshot, ProviderError> {
    let data = body.get("data").unwrap_or(body);

    if let Some(status) = base_status(body, data) {
        if status != 0 {
            let message =
                base_status_message(body, data).unwrap_or_else(|| format!("status_code {status}"));
            let lower = message.to_ascii_lowercase();
            if status == 1004
                || lower.contains("cookie")
                || lower.contains("log in")
                || lower.contains("login")
            {
                return Err(ProviderError::Unauthorized(message));
            }
            return Err(ProviderError::Parse {
                provider: "MiniMax",
                message,
            });
        }
    }

    let mut snapshot = ProviderSnapshot::new(ProviderId::Minimax, "api key");

    // Preferred: an explicit multi-service quota payload.
    if let Some(services) = data.get("services").and_then(Value::as_array) {
        let windows = multi_service_windows(services);
        if !windows.is_empty() {
            snapshot.windows = windows;
            snapshot.plan = multi_service_plan(services);
            return Ok(snapshot);
        }
    }

    let model_remains = data
        .get("model_remains")
        .and_then(Value::as_array)
        .filter(|models| !models.is_empty())
        .ok_or(ProviderError::Parse {
            provider: "MiniMax",
            message: "missing coding plan data".into(),
        })?;

    for model in model_remains {
        let model_name = get_str(model, "model_name").unwrap_or("");
        let service_type = map_model_name_to_service_type(model_name);

        if let Some(window) = service_window(
            &service_type,
            None,
            ServiceInput {
                total: get_i64(model, "current_interval_total_count"),
                remaining: get_i64(model, "current_interval_usage_count"),
                remaining_percent: get_f64(model, "current_interval_remaining_percent"),
                status: get_i64(model, "current_interval_status"),
                start: get_i64(model, "start_time"),
                end: get_i64(model, "end_time"),
                remains_time: get_i64(model, "remains_time"),
            },
            now,
        ) {
            snapshot.windows.push(window);
        }

        if should_render_weekly_window(model_name) {
            if let Some(window) = service_window(
                &service_type,
                Some("Weekly"),
                ServiceInput {
                    total: get_i64(model, "current_weekly_total_count"),
                    remaining: get_i64(model, "current_weekly_usage_count"),
                    remaining_percent: get_f64(model, "current_weekly_remaining_percent"),
                    status: get_i64(model, "current_weekly_status"),
                    start: get_i64(model, "weekly_start_time"),
                    end: get_i64(model, "weekly_end_time"),
                    remains_time: get_i64(model, "weekly_remains_time"),
                },
                now,
            ) {
                snapshot.windows.push(window);
            }
        }
    }

    if snapshot.windows.is_empty() {
        return Err(ProviderError::Parse {
            provider: "MiniMax",
            message: "coding plan returned no renderable quota windows".into(),
        });
    }

    if let Some(points) = get_f64(data, "points_balance")
        .or_else(|| get_f64(data, "point_balance"))
        .or_else(|| get_f64(data, "credits_balance"))
        .or_else(|| get_f64(data, "credit_balance"))
        .or_else(|| get_f64(data, "balance"))
    {
        snapshot
            .summary
            .push(SummaryItem::new("Points", compact(points)));
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(points),
            spend: None,
            currency: None,
        });
    }

    snapshot.plan = plan_name(data);
    Ok(snapshot)
}

struct ServiceInput {
    total: Option<i64>,
    remaining: Option<i64>,
    remaining_percent: Option<f64>,
    status: Option<i64>,
    start: Option<i64>,
    end: Option<i64>,
    remains_time: Option<i64>,
}

/// Port of the macOS `makeServiceUsage`: derive a single quota window for one lane, dropping quota
/// placeholders that exist in the schema but are not part of the active subscription.
fn service_window(
    service_type: &str,
    window_type_override: Option<&str>,
    input: ServiceInput,
    now: DateTime<Utc>,
) -> Option<UsageWindow> {
    if is_unavailable_placeholder(service_type, &input, window_type_override) {
        return None;
    }

    let start = date_from_epoch(input.start);
    let end = date_from_epoch(input.end);
    let (mut window_type, window_minutes) = window_info(start, end);
    if let Some(override_type) = window_type_override {
        window_type = override_type.to_owned();
    }

    let unlimited = is_unlimited_window(service_type, &input, &window_type);
    let resets_at = if unlimited {
        None
    } else {
        resets_at(end, input.remains_time, now)
    };

    let percent = if unlimited {
        0.0
    } else if let Some(remaining_percent) = input.remaining_percent {
        (100.0 - remaining_percent).clamp(0.0, 100.0)
    } else {
        let total = input.total.filter(|value| *value > 0)?;
        let remaining = input.remaining?;
        let used = (total - remaining).max(0);
        (used as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
    };

    let title = service_display_name(service_type);
    let mut window = UsageWindow::new(service_type, title, percent).with_reset(resets_at);
    if let Some(minutes) = window_minutes {
        window = window.with_window_minutes(minutes);
    }
    let detail = if unlimited {
        "Unlimited".to_owned()
    } else {
        window_type
    };
    window = window.with_detail(detail);
    Some(window)
}

fn is_unavailable_placeholder(
    service_type: &str,
    input: &ServiceInput,
    window_type_override: Option<&str>,
) -> bool {
    if let Some(window_type) = window_type_override {
        if is_unlimited_window(service_type, input, window_type) {
            return false;
        }
    }
    input.status == Some(3)
        && input.total.unwrap_or(0) == 0
        && input.remaining.unwrap_or(0) == 0
        && input.remaining_percent.is_some_and(|value| value >= 100.0)
}

/// Unlimited lanes are the "text generation"/"general" weekly windows the API marks 100% remaining.
fn is_unlimited_window(service_type: &str, input: &ServiceInput, window_type: &str) -> bool {
    let service = service_type.trim().to_ascii_lowercase();
    input.status == Some(3)
        && matches!(service.as_str(), "text generation" | "general")
        && window_type.trim().eq_ignore_ascii_case("weekly")
        && input.remaining_percent.is_some_and(|value| value >= 100.0)
}

fn window_info(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> (String, Option<u32>) {
    let (Some(start), Some(end)) = (start, end) else {
        return ("Unknown".to_owned(), None);
    };
    let duration_hours = (end - start).num_seconds() as f64 / 3600.0;
    if (23.0..=25.0).contains(&duration_hours) {
        ("Today".to_owned(), Some(24 * 60))
    } else if (4.0..=6.0).contains(&duration_hours) {
        ("5 hours".to_owned(), Some(5 * 60))
    } else if (1.0..23.0).contains(&duration_hours) {
        let hours = duration_hours as u32;
        (format!("{hours} hours"), Some(hours * 60))
    } else {
        ("Custom".to_owned(), None)
    }
}

fn resets_at(
    end: Option<DateTime<Utc>>,
    remains_time: Option<i64>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if let Some(end) = end {
        if end > now {
            return Some(end);
        }
    }
    let remains = remains_time.filter(|value| *value > 0)?;
    let seconds = if remains > 1_000_000 {
        remains / 1000
    } else {
        remains
    };
    Some(now + chrono::Duration::seconds(seconds))
}

fn multi_service_windows(services: &[Value]) -> Vec<UsageWindow> {
    let mut windows = Vec::new();
    for service in services {
        let (Some(service_type), Some(window_type), Some(time_range)) = (
            get_str(service, "service_type"),
            get_str(service, "window_type"),
            get_str(service, "time_range"),
        ) else {
            continue;
        };
        let (Some(usage), Some(limit)) = (get_i64(service, "usage"), get_i64(service, "limit"))
        else {
            continue;
        };
        if limit <= 0 {
            continue;
        }
        let percent = get_f64(service, "percent")
            .unwrap_or_else(|| usage as f64 / limit as f64 * 100.0)
            .clamp(0.0, 100.0);
        let id = normalize_service_identifier(service_type);
        let title = service_display_name(&id);
        let mut window = UsageWindow::new(id, title, percent)
            .with_detail(format!("{window_type}: {time_range}"));
        if let Some(minutes) = multi_service_window_minutes(window_type) {
            window = window.with_window_minutes(minutes);
        }
        windows.push(window);
    }
    windows
}

fn multi_service_window_minutes(window_type: &str) -> Option<u32> {
    let lower = window_type.trim().to_ascii_lowercase();
    if lower == "5 hours" {
        return Some(5 * 60);
    }
    if lower == "today" {
        return Some(24 * 60);
    }
    lower
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .map(|hours| hours * 60)
}

fn multi_service_plan(services: &[Value]) -> Option<String> {
    services.iter().find_map(|service| {
        let service_type = get_str(service, "service_type")?;
        let lower = service_type.to_ascii_lowercase();
        (lower.contains("pro") || lower.contains("max")).then(|| service_type.to_owned())
    })
}

fn normalize_service_identifier(service_type: &str) -> String {
    let lower = service_type.to_ascii_lowercase();
    if lower.contains("text") && lower.contains("generation") {
        "text-generation".to_owned()
    } else if lower.contains("text") && lower.contains("speech") {
        "text-to-speech".to_owned()
    } else if lower.contains("image") {
        "image".to_owned()
    } else {
        lower.replace([' ', '_'], "-")
    }
}

fn map_model_name_to_service_type(model_name: &str) -> String {
    let lower = model_name.trim().to_ascii_lowercase();
    if lower == "general" || lower == "video" {
        return lower;
    }
    if is_text_generation_model_name(model_name) {
        return "Text Generation".to_owned();
    }
    if lower.contains("speech") {
        return "Text to Speech".to_owned();
    }
    if lower.contains("hailuo") && lower.contains("fast") {
        return "Image to Video".to_owned();
    }
    if lower.contains("hailuo") {
        return "Text to Video".to_owned();
    }
    if lower.starts_with("image-") {
        return "Image Generation".to_owned();
    }
    if lower.contains("music") {
        return "Music Generation".to_owned();
    }
    model_name.to_owned()
}

fn is_text_generation_model_name(model_name: &str) -> bool {
    let lower = model_name.to_ascii_lowercase();
    lower == "general" || lower.contains("minimax-m") || lower.starts_with("m2.")
}

fn should_render_weekly_window(model_name: &str) -> bool {
    is_text_generation_model_name(model_name)
}

fn service_display_name(service_type: &str) -> String {
    match service_type.to_ascii_lowercase().as_str() {
        "general" => "General",
        "video" => "Video",
        "text-generation" | "text generation" => "Text Generation",
        "text-to-speech" | "text to speech" => "Text to Speech",
        "image" | "image generation" => "Image",
        "text to video" => "Text to Video",
        "image to video" => "Image to Video",
        "music generation" => "Music Generation",
        _ => return service_type.to_owned(),
    }
    .to_owned()
}

fn plan_name(data: &Value) -> Option<String> {
    for key in [
        "current_subscribe_title",
        "plan_name",
        "combo_title",
        "current_plan_title",
    ] {
        if let Some(value) = get_str(data, key) {
            return Some(value.to_owned());
        }
    }
    data.get("current_combo_card")
        .and_then(|card| get_str(card, "title"))
        .map(ToOwned::to_owned)
}

fn base_status(body: &Value, data: &Value) -> Option<i64> {
    data.get("base_resp")
        .and_then(|resp| get_i64(resp, "status_code"))
        .or_else(|| {
            body.get("base_resp")
                .and_then(|resp| get_i64(resp, "status_code"))
        })
}

fn base_status_message(body: &Value, data: &Value) -> Option<String> {
    data.get("base_resp")
        .and_then(|resp| get_str(resp, "status_msg"))
        .or_else(|| {
            body.get("base_resp")
                .and_then(|resp| get_str(resp, "status_msg"))
        })
        .map(ToOwned::to_owned)
}

/// `MiniMax` timestamps arrive as epoch seconds or milliseconds; anything smaller is not a real date.
fn date_from_epoch(value: Option<i64>) -> Option<DateTime<Utc>> {
    let raw = value?;
    if raw > 1_000_000_000_000 {
        Utc.timestamp_millis_opt(raw).single()
    } else if raw > 1_000_000_000 {
        Utc.timestamp_opt(raw, 0).single()
    } else {
        None
    }
}

fn get_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn get_i64(value: &Value, key: &str) -> Option<i64> {
    match value.get(key)? {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64)),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn get_f64(value: &Value, key: &str) -> Option<f64> {
    match value.get(key)? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn compact(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value:.2}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0).unwrap()
    }

    #[test]
    fn region_parses_china_aliases() {
        assert_eq!(parse_region(None), Region::Global);
        assert_eq!(parse_region(Some("global")), Region::Global);
        assert_eq!(parse_region(Some("cn")), Region::ChinaMainland);
        assert_eq!(parse_region(Some(" China ")), Region::ChinaMainland);
    }

    #[test]
    fn maps_multi_service_windows() {
        let body = json!({
            "data": {
                "services": [
                    {
                        "service_type": "Text Generation Pro", "window_type": "5 hours",
                        "time_range": "10:00-15:00(UTC+8)", "usage": 30, "limit": 100
                    }
                ]
            }
        });
        let snapshot = map_usage(&body, now()).unwrap();
        assert_eq!(snapshot.windows.len(), 1);
        assert_eq!(snapshot.windows[0].id, "text-generation");
        assert_eq!(snapshot.windows[0].used_percent, 30.0);
        assert_eq!(snapshot.windows[0].window_minutes, Some(300));
        assert_eq!(snapshot.plan.as_deref(), Some("Text Generation Pro"));
    }

    #[test]
    fn maps_model_remains_interval_and_weekly() {
        let start = now().timestamp();
        let end = (now() + chrono::Duration::hours(5)).timestamp();
        let body = json!({
            "data": {
                "plan_name": "Pro",
                "points_balance": 1500,
                "model_remains": [
                    {
                        "model_name": "MiniMax-M2",
                        "current_interval_total_count": 200,
                        "current_interval_usage_count": 50,
                        "start_time": start,
                        "end_time": end,
                        "current_weekly_total_count": 1000,
                        "current_weekly_usage_count": 250,
                        "current_weekly_status": 1
                    }
                ]
            }
        });
        let snapshot = map_usage(&body, now()).unwrap();
        // interval: 200 total, 50 remaining → 150 used → 75%.
        let interval = &snapshot.windows[0];
        assert_eq!(interval.id, "Text Generation");
        assert_eq!(interval.used_percent, 75.0);
        assert_eq!(interval.window_minutes, Some(300));
        // weekly rendered because MiniMax-M2 is a text-generation model.
        let weekly = snapshot
            .windows
            .iter()
            .find(|w| w.detail.as_deref() == Some("Weekly"))
            .unwrap();
        assert_eq!(weekly.used_percent, 75.0);
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
        assert_eq!(snapshot.financials.unwrap().balance, Some(1500.0));
    }

    #[test]
    fn drops_unavailable_quota_placeholder() {
        let body = json!({
            "data": {
                "model_remains": [
                    {
                        "model_name": "video",
                        "current_interval_status": 3,
                        "current_interval_total_count": 0,
                        "current_interval_usage_count": 0,
                        "current_interval_remaining_percent": 100.0
                    }
                ]
            }
        });
        assert!(matches!(
            map_usage(&body, now()),
            Err(ProviderError::Parse {
                provider: "MiniMax",
                ..
            })
        ));
    }

    #[test]
    fn maps_remaining_percent_lane() {
        let body = json!({
            "data": {
                "model_remains": [
                    {
                        "model_name": "video",
                        "current_interval_remaining_percent": 40.0,
                        "current_interval_status": 1
                    }
                ]
            }
        });
        let snapshot = map_usage(&body, now()).unwrap();
        assert_eq!(snapshot.windows[0].id, "video");
        // 40% remaining → 60% used.
        assert_eq!(snapshot.windows[0].used_percent, 60.0);
    }

    #[test]
    fn surfaces_cookie_status_as_unauthorized() {
        let body = json!({
            "base_resp": { "status_code": 1004, "status_msg": "please log in" },
            "data": {}
        });
        assert!(matches!(
            map_usage(&body, now()),
            Err(ProviderError::Unauthorized(_))
        ));
    }
}
