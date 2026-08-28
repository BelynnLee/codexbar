use crate::{
    auth::chromium,
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

pub struct QoderProvider {
    browser_import_enabled: bool,
}

impl Default for QoderProvider {
    fn default() -> Self {
        Self {
            browser_import_enabled: true,
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Qoder,
    display_name: "Qoder",
    auth_kind: AuthKind::BrowserCookie,
    color: "#6b5bff",
    dashboard_url: "https://qoder.com/account/usage",
    credential_hint: "Imports qoder.com (or qoder.com.cn) cookies from Chrome/Edge with DPAPI, or \
accepts a manual Cookie header. Set region to \"china\" for qoder.com.cn.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Qoder),
};

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

#[derive(Clone, Copy)]
struct Site {
    usage_url: &'static str,
    web_origin: &'static str,
    cookie_domains: &'static [&'static str],
}

const INTERNATIONAL: Site = Site {
    usage_url: "https://qoder.com/api/v2/me/usages/big_model_credits",
    web_origin: "https://qoder.com",
    cookie_domains: &["qoder.com", "www.qoder.com"],
};
const CHINA: Site = Site {
    usage_url: "https://qoder.com.cn/api/v2/me/usages/big_model_credits",
    web_origin: "https://qoder.com.cn",
    cookie_domains: &["qoder.com.cn", "www.qoder.com.cn"],
};

fn site_for(account: &ProviderAccount) -> Site {
    match account.region.as_deref().map(str::to_ascii_lowercase) {
        Some(region) if region.contains("cn") || region.contains("china") => CHINA,
        _ => INTERNATIONAL,
    }
}

#[async_trait]
impl Provider for QoderProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let site = site_for(account);
        let cookie = self.resolve_cookie(account, site)?;
        let response = context
            .client
            .get(site.usage_url)
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Cookie", cookie)
            .header("Origin", site.web_origin)
            .header("Referer", format!("{}/account/usage", site.web_origin))
            .header("User-Agent", USER_AGENT)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Bx-V", "2.5.35")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Qoder session is invalid or expired. Sign in to Qoder again or paste a fresh \
Cookie header."
                    .into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Qoder",
                status: response.status().as_u16(),
            });
        }
        let value: Value = response
            .json()
            .await
            .map_err(|error| ProviderError::Parse {
                provider: "Qoder",
                message: error.to_string(),
            })?;
        let usage = parse_usage(&value)?;
        Ok(map_usage(&usage))
    }
}

impl QoderProvider {
    fn resolve_cookie(
        &self,
        account: &ProviderAccount,
        site: Site,
    ) -> Result<String, ProviderError> {
        if let Some(value) = ProviderConfig::normalized_secret(&account.cookie_header) {
            return Ok(value.to_owned());
        }
        if !self.browser_import_enabled {
            return Err(ProviderError::MissingCredentials(
                "Paste a Qoder Cookie header in Settings.".into(),
            ));
        }
        let imported = chromium::find_cookie_header(account.browser, site.cookie_domains, &[])?;
        Ok(imported.value)
    }
}

struct Summary {
    used: f64,
    limit: f64,
    remaining: Option<f64>,
    percentage: Option<f64>,
}

#[derive(Debug)]
struct Merged {
    used: f64,
    total: f64,
    percentage: f64,
}

#[derive(Debug)]
struct QoderUsage {
    merged: Merged,
    reset: Option<DateTime<Utc>>,
}

/// Qoder returns either `camelCase` or `snake_case` keys depending on the deployment.
fn get_either<'a>(value: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    value.get(camel).or_else(|| value.get(snake))
}

fn parse_usage(value: &Value) -> Result<QoderUsage, ProviderError> {
    let base = get_either(value, "totalQuota", "total_quota")
        .and_then(|quota| get_either(quota, "quotaSummary", "quota_summary"))
        .ok_or(ProviderError::Parse {
            provider: "Qoder",
            message: "missing totalQuota.quotaSummary".into(),
        })?;
    let base = parse_summary(base)?;
    let shared = get_either(value, "sharedQuota", "shared_quota")
        .and_then(|quota| get_either(quota, "quotaSummary", "quota_summary"))
        .map(parse_summary)
        .transpose()?;
    let merged = merge(&base, shared.as_ref())?;
    Ok(QoderUsage {
        merged,
        reset: parse_reset(get_either(value, "nextResetAt", "next_reset_at")),
    })
}

fn parse_summary(value: &Value) -> Result<Summary, ProviderError> {
    let used =
        lossy_f64(get_either(value, "usedValue", "used_value")).ok_or(ProviderError::Parse {
            provider: "Qoder",
            message: "missing usedValue".into(),
        })?;
    let limit =
        lossy_f64(get_either(value, "limitValue", "limit_value")).ok_or(ProviderError::Parse {
            provider: "Qoder",
            message: "missing limitValue".into(),
        })?;
    Ok(Summary {
        used,
        limit,
        remaining: lossy_f64(get_either(value, "remainingValue", "remaining_value")),
        percentage: lossy_f64(get_either(value, "usagePercentage", "usage_percentage")),
    })
}

fn remaining_for(summary: &Summary) -> Result<f64, ProviderError> {
    if summary.used < 0.0
        || summary.limit < 0.0
        || summary.remaining.is_some_and(|remaining| remaining < 0.0)
    {
        return Err(ProviderError::Parse {
            provider: "Qoder",
            message: "quota values must be nonnegative".into(),
        });
    }
    Ok(summary
        .remaining
        .unwrap_or_else(|| (summary.limit - summary.used).max(0.0)))
}

fn usage_percentage(
    used: f64,
    total: f64,
    remaining: f64,
    provided: Option<f64>,
) -> Result<f64, ProviderError> {
    if used < 0.0 || total < 0.0 || remaining < 0.0 {
        return Err(ProviderError::Parse {
            provider: "Qoder",
            message: "quota values must be nonnegative".into(),
        });
    }
    if total <= 0.0 {
        if used == 0.0 && remaining == 0.0 {
            return Ok(provided.unwrap_or(100.0));
        }
        return Err(ProviderError::Parse {
            provider: "Qoder",
            message: "zero total quota must have zero usage and remaining".into(),
        });
    }
    Ok(provided.unwrap_or(used / total * 100.0))
}

fn merge(base: &Summary, shared: Option<&Summary>) -> Result<Merged, ProviderError> {
    let base_remaining = remaining_for(base)?;
    let Some(shared) = shared else {
        let percentage = usage_percentage(base.used, base.limit, base_remaining, base.percentage)?;
        return Ok(Merged {
            used: base.used,
            total: base.limit,
            percentage,
        });
    };
    let shared_remaining = remaining_for(shared)?;
    let used = base.used + shared.used;
    let total = base.limit + shared.limit;
    let remaining = base_remaining + shared_remaining;
    // A merged view ignores any server-provided percentage and recomputes from the combined pools.
    let percentage = usage_percentage(used, total, remaining, None)?;
    Ok(Merged {
        used,
        total,
        percentage,
    })
}

fn map_usage(usage: &QoderUsage) -> ProviderSnapshot {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Qoder, "web");
    snapshot.windows.push(
        UsageWindow::new(
            "credits",
            "Credits",
            usage.merged.percentage.clamp(0.0, 100.0),
        )
        .with_reset(usage.reset)
        .with_detail(format!(
            "{} / {} credits",
            format_credits(usage.merged.used),
            format_credits(usage.merged.total)
        )),
    );
    snapshot
}

fn format_credits(value: f64) -> String {
    if (value.round() - value).abs() < f64::EPSILON {
        format!("{}", value.round() as i64)
    } else {
        format!("{value:.2}")
    }
}

fn lossy_f64(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn parse_reset(value: Option<&Value>) -> Option<DateTime<Utc>> {
    match value? {
        Value::String(text) => DateTime::parse_from_rfc3339(text.trim())
            .ok()
            .map(|value| value.with_timezone(&Utc)),
        Value::Number(number) => {
            let raw = number.as_f64()?;
            let seconds = if raw > 10_000_000_000.0 {
                raw / 1000.0
            } else {
                raw
            };
            Utc.timestamp_opt(seconds as i64, 0).single()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_single_quota_and_derives_percent() {
        let usage = parse_usage(&json!({
            "total_quota": {
                "quota_summary": {
                    "used_value": 30.0,
                    "limit_value": 100.0,
                    "unit": "credits"
                }
            },
            "next_reset_at": "2026-08-01T00:00:00Z"
        }))
        .unwrap();
        let snapshot = map_usage(&usage);
        assert_eq!(snapshot.windows[0].id, "credits");
        assert_eq!(snapshot.windows[0].used_percent, 30.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("30 / 100 credits")
        );
        assert!(snapshot.windows[0].resets_at.is_some());
    }

    #[test]
    fn merges_base_and_shared_quota_camel_case() {
        let usage = parse_usage(&json!({
            "totalQuota": { "quotaSummary": { "usedValue": 20.0, "limitValue": 50.0 } },
            "sharedQuota": { "quotaSummary": { "usedValue": 30.0, "limitValue": 50.0 } }
        }))
        .unwrap();
        // used 50 / total 100 → 50%.
        assert_eq!(usage.merged.percentage, 50.0);
        assert_eq!(usage.merged.total, 100.0);
    }

    #[test]
    fn prefers_provided_percentage_when_not_merged() {
        let usage = parse_usage(&json!({
            "total_quota": {
                "quota_summary": {
                    "used_value": 10.0,
                    "limit_value": 100.0,
                    "usage_percentage": 42.0
                }
            }
        }))
        .unwrap();
        assert_eq!(usage.merged.percentage, 42.0);
    }

    #[test]
    fn zero_total_with_usage_is_a_parse_error() {
        let error = parse_usage(&json!({
            "total_quota": { "quota_summary": { "used_value": 5.0, "limit_value": 0.0 } }
        }))
        .unwrap_err();
        assert!(matches!(error, ProviderError::Parse { .. }));
    }

    #[test]
    fn negative_values_are_rejected() {
        let error = parse_usage(&json!({
            "total_quota": { "quota_summary": { "used_value": -1.0, "limit_value": 100.0 } }
        }))
        .unwrap_err();
        assert!(matches!(error, ProviderError::Parse { .. }));
    }

    #[test]
    fn missing_total_quota_is_a_parse_error() {
        assert!(parse_usage(&json!({ "shared_quota": {} })).is_err());
    }

    #[test]
    fn region_selects_china_site() {
        let cn = ProviderAccount {
            region: Some("China".into()),
            ..Default::default()
        };
        let intl = ProviderAccount::default();
        assert_eq!(site_for(&cn).web_origin, "https://qoder.com.cn");
        assert_eq!(site_for(&intl).web_origin, "https://qoder.com");
    }
}
