use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

pub struct AbacusProvider {
    base_url: String,
    browser_import_enabled: bool,
}

impl Default for AbacusProvider {
    fn default() -> Self {
        Self {
            base_url: "https://apps.abacus.ai".into(),
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Abacus,
    display_name: "Abacus",
    auth_kind: AuthKind::BrowserCookie,
    color: "#2f6df6",
    dashboard_url: "https://apps.abacus.ai",
    credential_hint: "Imports apps.abacus.ai cookies from Chrome/Edge with DPAPI, or accepts a \
manual Cookie header.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Abacus),
};

const COMPUTE_POINTS_PATH: &str = "/api/_getOrganizationComputePoints";
const BILLING_INFO_PATH: &str = "/api/_getBillingInfo";
const MONTH_MINUTES: u32 = 30 * 24 * 60;

#[async_trait]
impl Provider for AbacusProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let cookie = self.resolve_cookie(account)?;
        let base = self.base_url.trim_end_matches('/');

        let compute = self
            .get_result(
                context,
                &format!("{base}{COMPUTE_POINTS_PATH}"),
                &cookie,
                false,
            )
            .await?
            .ok_or(ProviderError::Parse {
                provider: "Abacus",
                message: "compute points response had no result".into(),
            })?;
        // Billing enriches the plan/reset but must never fail the credits card.
        let billing = self
            .get_result(
                context,
                &format!("{base}{BILLING_INFO_PATH}"),
                &cookie,
                true,
            )
            .await
            .ok()
            .flatten();

        map_usage(&compute, billing.as_ref(), Utc::now())
    }
}

impl AbacusProvider {
    async fn get_result(
        &self,
        context: &FetchContext<'_>,
        url: &str,
        cookie: &str,
        post: bool,
    ) -> Result<Option<Value>, ProviderError> {
        let builder = if post {
            context.client.post(url).json(&json!({}))
        } else {
            context.client.get(url)
        };
        let response = builder
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Cookie", cookie)
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Abacus session expired. Sign in to abacus.ai or replace the manual Cookie header."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Abacus",
                status: response.status().as_u16(),
            });
        }
        let body: Value = response.json().await?;
        // Envelope: { success: bool, result: {...}, error?: "..." }.
        if body.get("success").and_then(Value::as_bool) == Some(true) {
            return Ok(body.get("result").cloned());
        }
        let message = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if [
            "expired",
            "session",
            "login",
            "authenticate",
            "unauthorized",
            "unauthenticated",
            "forbidden",
        ]
        .iter()
        .any(|needle| message.contains(needle))
        {
            return Err(ProviderError::Unauthorized(
                "Abacus session expired. Sign in to abacus.ai or replace the manual Cookie header."
                    .into(),
            ));
        }
        Err(ProviderError::Parse {
            provider: "Abacus",
            message: if message.is_empty() {
                "unexpected response envelope".into()
            } else {
                message
            },
        })
    }

    fn resolve_cookie(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            return Ok(value.to_owned());
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste an apps.abacus.ai Cookie header in Settings.".into(),
            ));
        }
        // Empty preferred-name set imports the full cookie header for the domain, which Abacus's
        // session needs (it is not carried by one named token).
        let imported =
            chromium::find_cookie_header(account.browser, &["abacus.ai", "apps.abacus.ai"], &[])?;
        Ok(imported.value)
    }
}

fn map_usage(
    compute: &Value,
    billing: Option<&Value>,
    now: DateTime<Utc>,
) -> Result<ProviderSnapshot, ProviderError> {
    let total = number(compute.get("totalComputePoints"));
    let left = number(compute.get("computePointsLeft"));
    let (Some(total), Some(left)) = (total, left) else {
        return Err(ProviderError::Parse {
            provider: "Abacus",
            message: "compute points response missing credit fields".into(),
        });
    };
    let used = (total - left).max(0.0);

    let mut snapshot = ProviderSnapshot::new(ProviderId::Abacus, "web");
    let used_percent = if total > 0.0 {
        (used / total * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let resets_at = billing
        .and_then(|billing| billing.get("nextBillingDate"))
        .and_then(Value::as_str)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value.trim())
                .ok()
                .map(|value| value.with_timezone(&Utc))
        });
    let window_minutes = resets_at
        .and_then(|reset| u32::try_from((reset - now).num_minutes()).ok())
        .filter(|minutes| *minutes > 0)
        .unwrap_or(MONTH_MINUTES);

    snapshot.windows.push(
        UsageWindow::new("credits", "Credits", used_percent)
            .with_window_minutes(window_minutes)
            .with_reset(resets_at)
            .with_detail(format!("{} / {} credits", compact(used), compact(total))),
    );

    snapshot.plan = billing
        .and_then(|billing| billing.get("currentTier"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(snapshot)
}

fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0).unwrap()
    }

    #[test]
    fn maps_compute_points_and_billing_plan() {
        let compute = json!({ "totalComputePoints": 1000, "computePointsLeft": 250 });
        let billing = json!({ "currentTier": "Pro", "nextBillingDate": "2026-08-01T00:00:00Z" });
        let snapshot = map_usage(&compute, Some(&billing), now()).unwrap();
        // used = 750/1000 = 75%.
        assert_eq!(snapshot.windows[0].used_percent, 75.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("750 / 1,000 credits")
        );
        assert!(snapshot.windows[0].resets_at.is_some());
        assert_eq!(snapshot.plan.as_deref(), Some("Pro"));
    }

    #[test]
    fn works_without_billing_and_uses_default_window() {
        let compute = json!({ "totalComputePoints": 500, "computePointsLeft": 500 });
        let snapshot = map_usage(&compute, None, now()).unwrap();
        assert_eq!(snapshot.windows[0].used_percent, 0.0);
        assert_eq!(snapshot.windows[0].window_minutes, Some(MONTH_MINUTES));
        assert_eq!(snapshot.plan, None);
    }

    #[test]
    fn requires_credit_fields() {
        assert!(matches!(
            map_usage(&json!({ "somethingElse": 1 }), None, now()),
            Err(ProviderError::Parse {
                provider: "Abacus",
                ..
            })
        ));
    }
}
