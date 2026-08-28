use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use std::env;

#[derive(Default)]
pub struct ZaiProvider {
    /// Test seam: overrides the quota host so a local fixture server can answer. Region selection
    /// still resolves the path.
    api_base_url: Option<String>,
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Zai,
    display_name: "z.ai",
    auth_kind: AuthKind::ApiKey,
    color: "#e85a6a",
    dashboard_url: "https://z.ai/manage-apikey/coding-plan/personal/my-plan",
    credential_hint: "Set an API key in Settings or Z_AI_API_KEY. Pick Global or BigModel CN; add \
Organization + Project IDs for team usage.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Zai),
};

const QUOTA_PATH: &str = "/api/monitor/usage/quota/limit";
const GLOBAL_BASE_URL: &str = "https://api.z.ai";
const BIGMODEL_CN_BASE_URL: &str = "https://open.bigmodel.cn";

#[async_trait]
impl Provider for ZaiProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let team = team_context(account);
        let mut url = format!("{}{QUOTA_PATH}", self.base_url(account));
        if team.is_some() {
            url.push_str("?type=2");
        }

        let mut request = context
            .client
            .get(&url)
            .bearer_auth(&api_key)
            .header("Accept", "application/json");
        if let Some((organization_id, project_id)) = &team {
            request = request
                .header("Bigmodel-Organization", organization_id)
                .header("Bigmodel-Project", project_id);
        }

        let response = request.send().await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "z.ai API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "z.ai",
                status: response.status().as_u16(),
            });
        }
        let text = response.text().await?;
        if text.trim().is_empty() {
            return Err(ProviderError::Parse {
                provider: "z.ai",
                message: "empty response body (check region: Global vs BigModel CN)".into(),
            });
        }
        let payload: QuotaResponse =
            serde_json::from_str(&text).map_err(|error| ProviderError::Parse {
                provider: "z.ai",
                message: error.to_string(),
            })?;
        map_usage(payload)
    }
}

impl ZaiProvider {
    fn base_url(&self, account: &ProviderAccount) -> String {
        if let Some(base) = &self.api_base_url {
            return base.trim_end_matches('/').to_owned();
        }
        region_base_url(account.region.as_deref()).to_owned()
    }
}

fn region_base_url(region: Option<&str>) -> &'static str {
    match region
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("bigmodel-cn" | "bigmodel" | "cn") => BIGMODEL_CN_BASE_URL,
        _ => GLOBAL_BASE_URL,
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("Z_AI_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing z.ai API key.".into()))
}

fn team_context(account: &ProviderAccount) -> Option<(String, String)> {
    let organization_id = ProviderConfig::normalized_secret(&account.organization_id)?;
    let project_id = ProviderConfig::normalized_secret(&account.project_id)?;
    Some((organization_id.to_owned(), project_id.to_owned()))
}

fn map_usage(payload: QuotaResponse) -> Result<ProviderSnapshot, ProviderError> {
    if !payload.success || payload.code != 200 {
        let message = payload
            .msg
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("z.ai quota API returned code {}", payload.code));
        return Err(ProviderError::Parse {
            provider: "z.ai",
            message,
        });
    }
    let data = payload.data.ok_or(ProviderError::Parse {
        provider: "z.ai",
        message: "missing data".into(),
    })?;

    let mut token_limits: Vec<LimitEntry> = Vec::new();
    let mut time_limit: Option<LimitEntry> = None;
    for raw in &data.limits {
        let Some(entry) = raw.to_entry() else {
            continue;
        };
        match entry.kind {
            LimitKind::Tokens => token_limits.push(entry),
            LimitKind::Time => time_limit = Some(entry),
        }
    }

    // Multiple TOKENS_LIMIT entries: shortest window is the session lane, longest the primary quota.
    let (token_limit, session_limit) = if token_limits.len() >= 2 {
        token_limits.sort_by_key(|entry| entry.window_minutes().unwrap_or(u32::MAX));
        let session = token_limits.first().cloned();
        let token = token_limits.last().cloned();
        (token, session)
    } else {
        (token_limits.into_iter().next(), None)
    };

    let mut snapshot = ProviderSnapshot::new(ProviderId::Zai, "api key");
    let primary = token_limit.clone().or_else(|| time_limit.clone());
    if let Some(entry) = primary {
        snapshot.windows.push(entry.into_window("tokens", "Tokens"));
    }
    if token_limit.is_some() {
        if let Some(entry) = time_limit {
            snapshot.windows.push(entry.into_window("mcp", "MCP"));
        }
    }
    if let Some(entry) = session_limit {
        snapshot
            .windows
            .push(entry.into_window("session", "Session"));
    }

    snapshot.plan = data
        .plan_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(snapshot)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitKind {
    Tokens,
    Time,
}

#[derive(Debug, Clone)]
struct LimitEntry {
    kind: LimitKind,
    unit: i64,
    number: i64,
    usage: Option<i64>,
    current_value: Option<i64>,
    remaining: Option<i64>,
    percentage: f64,
    next_reset_ms: Option<i64>,
}

impl LimitEntry {
    fn used_percent(&self) -> f64 {
        self.computed_used_percent().unwrap_or(self.percentage)
    }

    /// z.ai sometimes omits quota counters; derive a percent only when the total (`usage`) and a
    /// used figure are both present, otherwise defer to the API's own `percentage`.
    fn computed_used_percent(&self) -> Option<f64> {
        let limit = self.usage.filter(|value| *value > 0)?;
        let used_raw = if let Some(remaining) = self.remaining {
            let from_remaining = limit - remaining;
            self.current_value
                .map_or(from_remaining, |current| from_remaining.max(current))
        } else {
            self.current_value?
        };
        let used = used_raw.clamp(0, limit);
        Some((used as f64 / limit as f64 * 100.0).clamp(0.0, 100.0))
    }

    fn window_minutes(&self) -> Option<u32> {
        if self.number <= 0 {
            return None;
        }
        let factor = match self.unit {
            5 => 1,           // minutes
            3 => 60,          // hours
            1 => 24 * 60,     // days
            6 => 7 * 24 * 60, // weeks
            _ => return None,
        };
        u32::try_from(self.number * factor).ok()
    }

    fn window_description(&self) -> Option<String> {
        if self.number <= 0 {
            return None;
        }
        let unit = match self.unit {
            5 => "minute",
            3 => "hour",
            1 => "day",
            6 => "week",
            _ => return None,
        };
        let suffix = if self.number == 1 {
            unit.to_owned()
        } else {
            format!("{unit}s")
        };
        Some(format!("{} {suffix} window", self.number))
    }

    fn is_mcp_monthly_marker(&self) -> bool {
        self.kind == LimitKind::Time && self.unit == 5 && self.number == 1
    }

    fn into_window(self, id: &str, title: &str) -> UsageWindow {
        let used_percent = self.used_percent();
        let mut window = UsageWindow::new(id, title, used_percent);
        if self.kind == LimitKind::Tokens {
            if let Some(minutes) = self.window_minutes() {
                window = window.with_window_minutes(minutes);
            }
        }
        window = window.with_reset(reset_at(self.next_reset_ms));
        if let Some(detail) = self.reset_description() {
            window = window.with_detail(detail);
        }
        window
    }

    fn reset_description(&self) -> Option<String> {
        if self.is_mcp_monthly_marker() {
            return Some("Monthly".to_owned());
        }
        if let Some(description) = self.window_description() {
            return Some(description);
        }
        (self.kind == LimitKind::Time).then(|| "Monthly".to_owned())
    }
}

fn reset_at(next_reset_ms: Option<i64>) -> Option<chrono::DateTime<Utc>> {
    let millis = next_reset_ms.filter(|value| *value > 0)?;
    Utc.timestamp_millis_opt(millis).single()
}

#[derive(Debug, Deserialize)]
struct QuotaResponse {
    code: i64,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    data: Option<QuotaData>,
    #[serde(default)]
    success: bool,
}

#[derive(Debug, Deserialize)]
struct QuotaData {
    #[serde(default)]
    limits: Vec<RawLimit>,
    #[serde(default, alias = "plan", alias = "plan_type", alias = "packageName")]
    plan_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawLimit {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    unit: i64,
    #[serde(default)]
    number: i64,
    #[serde(default)]
    usage: Option<i64>,
    #[serde(default, rename = "currentValue")]
    current_value: Option<i64>,
    #[serde(default)]
    remaining: Option<i64>,
    #[serde(default)]
    percentage: f64,
    #[serde(default, rename = "nextResetTime")]
    next_reset_time: Option<i64>,
}

impl RawLimit {
    fn to_entry(&self) -> Option<LimitEntry> {
        let kind = match self.kind.as_str() {
            "TOKENS_LIMIT" => LimitKind::Tokens,
            "TIME_LIMIT" => LimitKind::Time,
            _ => return None,
        };
        Some(LimitEntry {
            kind,
            unit: self.unit,
            number: self.number,
            usage: self.usage,
            current_value: self.current_value,
            remaining: self.remaining,
            percentage: self.percentage.clamp(0.0, 100.0),
            next_reset_ms: self.next_reset_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn region_selects_the_matching_base_url() {
        assert_eq!(region_base_url(None), GLOBAL_BASE_URL);
        assert_eq!(region_base_url(Some("global")), GLOBAL_BASE_URL);
        assert_eq!(region_base_url(Some("bigmodel-cn")), BIGMODEL_CN_BASE_URL);
        assert_eq!(region_base_url(Some(" CN ")), BIGMODEL_CN_BASE_URL);
    }

    #[test]
    fn derives_used_percent_from_remaining_over_percentage() {
        let raw: RawLimit = serde_json::from_value(json!({
            "type": "TOKENS_LIMIT", "unit": 3, "number": 5,
            "usage": 1000, "remaining": 250, "percentage": 10
        }))
        .unwrap();
        let entry = raw.to_entry().unwrap();
        // 1000 total, 250 remaining → 750 used → 75%.
        assert_eq!(entry.used_percent(), 75.0);
        assert_eq!(entry.window_minutes(), Some(300));
    }

    #[test]
    fn falls_back_to_percentage_when_counters_missing() {
        let raw: RawLimit = serde_json::from_value(json!({
            "type": "TIME_LIMIT", "unit": 1, "number": 30, "percentage": 40
        }))
        .unwrap();
        let entry = raw.to_entry().unwrap();
        assert_eq!(entry.used_percent(), 40.0);
        // A TIME_LIMIT still computes a raw window span; `into_window` is what suppresses it for the
        // MCP/monthly lane. The unknown unit (0) is the only case that yields no minutes.
        assert_eq!(entry.window_minutes(), Some(30 * 24 * 60));
        let unknown_unit = RawLimit {
            unit: 0,
            ..serde_json::from_value(json!({ "type": "TIME_LIMIT", "number": 1 })).unwrap()
        }
        .to_entry()
        .unwrap();
        assert_eq!(unknown_unit.window_minutes(), None);
    }

    #[test]
    fn orders_token_time_and_session_windows() {
        let payload: QuotaResponse = serde_json::from_value(json!({
            "code": 200, "success": true,
            "data": {
                "plan_name": "Max",
                "limits": [
                    { "type": "TOKENS_LIMIT", "unit": 3, "number": 5, "percentage": 20 },
                    { "type": "TOKENS_LIMIT", "unit": 1, "number": 30, "percentage": 60 },
                    { "type": "TIME_LIMIT", "unit": 5, "number": 1, "percentage": 10 }
                ]
            }
        }))
        .unwrap();
        let snapshot = map_usage(payload).unwrap();
        assert_eq!(snapshot.windows[0].id, "tokens"); // longest token window (30 days)
        assert_eq!(snapshot.windows[0].used_percent, 60.0);
        assert_eq!(snapshot.windows[1].id, "mcp");
        assert_eq!(snapshot.windows[1].detail.as_deref(), Some("Monthly"));
        assert_eq!(snapshot.windows[2].id, "session"); // shortest token window (5 hours)
        assert_eq!(snapshot.plan.as_deref(), Some("Max"));
    }

    #[test]
    fn rejects_unsuccessful_response() {
        let payload: QuotaResponse = serde_json::from_value(json!({
            "code": 401, "success": false, "msg": "unauthorized"
        }))
        .unwrap();
        assert!(matches!(
            map_usage(payload),
            Err(ProviderError::Parse {
                provider: "z.ai",
                ..
            })
        ));
    }
}
