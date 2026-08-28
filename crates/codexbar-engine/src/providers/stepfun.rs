use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use reqwest::Response;
use serde_json::{Value, json};

pub struct StepFunProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for StepFunProvider {
    fn default() -> Self {
        Self {
            base_url: "https://platform.stepfun.com".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Stepfun,
    display_name: "StepFun",
    auth_kind: AuthKind::BrowserCookie,
    color: "#2196f3",
    dashboard_url: "https://platform.stepfun.com/plan-usage",
    credential_hint: "Imports the platform.stepfun.com Oasis-Token cookie from Chrome/Edge with \
DPAPI, or accepts a manually pasted Oasis-Token.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Stepfun),
};

// The rate-limit + plan-status endpoints authenticate with the Oasis-Token cookie the platform sets
// after login. This port covers the token → usage path; the username/password login and token-refresh
// flow the macOS app performs are deferred (a stale token surfaces a re-auth error to re-paste).
const RATE_LIMIT_PATH: &str = "/api/step.openapi.devcenter.Dashboard/QueryStepPlanRateLimit";
const PLAN_STATUS_PATH: &str = "/api/step.openapi.devcenter.Dashboard/GetStepPlanStatus";
const WEB_ID: &str = "c8a1002d2c457e758785a9979832217c7c0b884c";
const APP_ID: &str = "10300";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";
const FIVE_HOUR_MINUTES: u32 = 300;
const WEEKLY_MINUTES: u32 = 10080;

#[async_trait]
impl Provider for StepFunProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let token = self.resolve_token(account)?;
        let rate_limit = self.query(context, RATE_LIMIT_PATH, &token).await?;
        let usage = parse_rate_limit(&rate_limit)?;
        // Plan status is best-effort enrichment; a failure never drops the usage windows.
        let plan = match self.query(context, PLAN_STATUS_PATH, &token).await {
            Ok(value) => parse_plan_name(&value),
            Err(_) => None,
        };
        Ok(map_usage(&usage, plan))
    }
}

impl StepFunProvider {
    fn resolve_token(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            return Ok(normalize_token(value));
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a StepFun Oasis-Token in Settings.".into(),
            ));
        }
        let imported = chromium::find_cookie_header(
            account.browser,
            &["platform.stepfun.com", "stepfun.com"],
            &["Oasis-Token"],
        )?;
        Ok(normalize_token(&imported.value))
    }

    async fn query(
        &self,
        context: &FetchContext<'_>,
        path: &str,
        token: &str,
    ) -> Result<Value, ProviderError> {
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
        let response = context
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("oasis-appid", APP_ID)
            .header("oasis-platform", "web")
            .header("oasis-webid", WEB_ID)
            .header("user-agent", USER_AGENT)
            .header(
                "Cookie",
                format!("Oasis-Token={token}; Oasis-Webid={WEB_ID}"),
            )
            .json(&json!({}))
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "StepFun Oasis-Token is invalid or expired. Sign in to platform.stepfun.com again \
or paste a fresh Oasis-Token."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "StepFun",
                status: response.status().as_u16(),
            });
        }
        json_body(response).await
    }
}

async fn json_body(response: Response) -> Result<Value, ProviderError> {
    response.json().await.map_err(|error| ProviderError::Parse {
        provider: "StepFun",
        message: error.to_string(),
    })
}

/// Extracts the `Oasis-Token` value from a pasted cookie header, or returns a bare token unchanged.
fn normalize_token(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(index) = trimmed.find("Oasis-Token=") {
        let after = &trimmed[index + "Oasis-Token=".len()..];
        return after.split(';').next().unwrap_or(after).trim().to_owned();
    }
    trimmed.to_owned()
}

#[derive(Debug)]
struct RateLimit {
    five_hour_left_rate: f64,
    weekly_left_rate: f64,
    five_hour_reset: DateTime<Utc>,
    weekly_reset: DateTime<Utc>,
}

fn parse_rate_limit(value: &Value) -> Result<RateLimit, ProviderError> {
    // The envelope carries `status: 1` on success; anything else is an API/auth error.
    if value.get("status").and_then(Value::as_i64) != Some(1) {
        let message = ["message", "desc"]
            .into_iter()
            .find_map(|key| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
            })
            .map(str::to_owned)
            .or_else(|| {
                value
                    .get("code")
                    .and_then(Value::as_i64)
                    .map(|code| code.to_string())
            })
            .unwrap_or_else(|| "unknown".to_owned());
        return Err(rate_limit_error(&message));
    }
    let five_hour_left_rate =
        lossy_f64(value.get("five_hour_usage_left_rate")).ok_or(ProviderError::Parse {
            provider: "StepFun",
            message: "missing five_hour_usage_left_rate".into(),
        })?;
    let weekly_left_rate =
        lossy_f64(value.get("weekly_usage_left_rate")).ok_or(ProviderError::Parse {
            provider: "StepFun",
            message: "missing weekly_usage_left_rate".into(),
        })?;
    let five_hour_reset =
        lossy_timestamp(value.get("five_hour_usage_reset_time")).ok_or(ProviderError::Parse {
            provider: "StepFun",
            message: "missing five_hour_usage_reset_time".into(),
        })?;
    let weekly_reset =
        lossy_timestamp(value.get("weekly_usage_reset_time")).ok_or(ProviderError::Parse {
            provider: "StepFun",
            message: "missing weekly_usage_reset_time".into(),
        })?;
    Ok(RateLimit {
        five_hour_left_rate,
        weekly_left_rate,
        five_hour_reset,
        weekly_reset,
    })
}

/// A body-level error with an auth-ish message routes to `Unauthorized` so the UI prompts re-auth.
fn rate_limit_error(message: &str) -> ProviderError {
    let lower = message.to_ascii_lowercase();
    let auth_related = [
        "401",
        "403",
        "unauthorized",
        "unauthenticated",
        "invalid credentials",
        "invalid token",
        "token expired",
        "expired token",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if auth_related {
        ProviderError::Unauthorized(format!("StepFun authentication failed: {message}"))
    } else {
        ProviderError::Parse {
            provider: "StepFun",
            message: message.to_owned(),
        }
    }
}

fn parse_plan_name(value: &Value) -> Option<String> {
    value
        .get("subscription")
        .and_then(|subscription| subscription.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn map_usage(rate_limit: &RateLimit, plan: Option<String>) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Stepfun, "web");
    let five_hour_used = ((1.0 - rate_limit.five_hour_left_rate) * 100.0).clamp(0.0, 100.0);
    let weekly_used = ((1.0 - rate_limit.weekly_left_rate) * 100.0).clamp(0.0, 100.0);
    snapshot.windows.push(
        UsageWindow::new("five_hour", "5h Window", five_hour_used)
            .with_window_minutes(FIVE_HOUR_MINUTES)
            .with_reset(Some(rate_limit.five_hour_reset)),
    );
    snapshot.windows.push(
        UsageWindow::new("weekly", "Weekly Window", weekly_used)
            .with_window_minutes(WEEKLY_MINUTES)
            .with_reset(Some(rate_limit.weekly_reset)),
    );
    snapshot.plan = plan;
    snapshot
}

fn lossy_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Reset times are unix seconds, encoded as either `JSON` numbers or strings.
fn lossy_timestamp(value: Option<&Value>) -> Option<DateTime<Utc>> {
    let seconds = match value? {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }?;
    Utc.timestamp_opt(seconds, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_bare_token_and_cookie_header() {
        assert_eq!(normalize_token("raw-token-value"), "raw-token-value");
        assert_eq!(
            normalize_token("Oasis-Token=abc123; Oasis-Webid=xyz"),
            "abc123"
        );
    }

    #[test]
    fn maps_left_rate_to_used_percent_with_resets() {
        // left_rate 0.25 → 75% used; left_rate 1.0 → 0% used.
        let rate_limit = parse_rate_limit(&json!({
            "status": 1,
            "five_hour_usage_left_rate": 0.25,
            "weekly_usage_left_rate": 1,
            "five_hour_usage_reset_time": "1777528800",
            "weekly_usage_reset_time": 1_777_600_000
        }))
        .unwrap();
        let snapshot = map_usage(&rate_limit, Some("Growth".into()));
        assert_eq!(snapshot.windows[0].id, "five_hour");
        assert_eq!(snapshot.windows[0].used_percent, 75.0);
        assert_eq!(snapshot.windows[0].window_minutes, Some(300));
        assert!(snapshot.windows[0].resets_at.is_some());
        assert_eq!(snapshot.windows[1].used_percent, 0.0);
        assert_eq!(snapshot.windows[1].window_minutes, Some(10080));
        assert_eq!(snapshot.plan.as_deref(), Some("Growth"));
    }

    #[test]
    fn accepts_integer_and_float_left_rates() {
        let rate_limit = parse_rate_limit(&json!({
            "status": 1,
            "five_hour_usage_left_rate": 0.997_815_43,
            "weekly_usage_left_rate": 0,
            "five_hour_usage_reset_time": 1_777_528_800_i64,
            "weekly_usage_reset_time": "1777600000"
        }))
        .unwrap();
        assert!((rate_limit.five_hour_left_rate - 0.997_815_43).abs() < 1e-9);
        assert_eq!(rate_limit.weekly_left_rate, 0.0);
    }

    #[test]
    fn unsuccessful_status_with_auth_message_is_unauthorized() {
        let error = parse_rate_limit(&json!({
            "status": 0,
            "message": "token expired"
        }))
        .unwrap_err();
        assert!(matches!(error, ProviderError::Unauthorized(_)));
    }

    #[test]
    fn unsuccessful_status_without_auth_message_is_parse_error() {
        let error = parse_rate_limit(&json!({
            "status": 0,
            "code": 500
        }))
        .unwrap_err();
        assert!(matches!(error, ProviderError::Parse { .. }));
    }

    #[test]
    fn missing_rate_fields_is_a_parse_error() {
        assert!(parse_rate_limit(&json!({ "status": 1 })).is_err());
    }

    #[test]
    fn plan_name_is_read_from_subscription() {
        assert_eq!(
            parse_plan_name(&json!({ "subscription": { "name": " Pro " } })).as_deref(),
            Some("Pro")
        );
        assert_eq!(parse_plan_name(&json!({ "status": 1 })), None);
    }
}
