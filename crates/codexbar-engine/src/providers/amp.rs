use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
        UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use serde_json::json;
use std::env;

pub struct AmpProvider {
    usage_url: String,
}

impl Default for AmpProvider {
    fn default() -> Self {
        Self {
            usage_url: "https://ampcode.com/api/internal?userDisplayBalanceInfo".into(),
        }
    }
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Amp,
    display_name: "Amp",
    auth_kind: AuthKind::ApiKey,
    color: "#0f172a",
    dashboard_url: "https://ampcode.com/settings",
    credential_hint: "Set an Amp access token in Settings or AMP_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Amp),
};

#[async_trait]
impl Provider for AmpProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let response = context
            .client
            .post(&self.usage_url)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&json!({ "method": "userDisplayBalanceInfo", "params": {} }))
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Amp access token is invalid or expired.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Amp",
                status: response.status().as_u16(),
            });
        }
        let payload: UsageApiResponse =
            response
                .json()
                .await
                .map_err(|error| ProviderError::Parse {
                    provider: "Amp",
                    message: error.to_string(),
                })?;
        if !payload.ok {
            if payload.error.as_ref().and_then(|e| e.code.as_deref()) == Some("auth-required") {
                return Err(ProviderError::Unauthorized(
                    "Amp access token is invalid or expired.".into(),
                ));
            }
            return Err(ProviderError::Parse {
                provider: "Amp",
                message: payload
                    .error
                    .and_then(|e| e.message)
                    .unwrap_or_else(|| "Amp usage API returned an error.".into()),
            });
        }
        let display_text = payload
            .result
            .map(|result| result.display_text)
            .filter(|text| !text.is_empty())
            .ok_or(ProviderError::Parse {
                provider: "Amp",
                message: "missing Amp usage display text".into(),
            })?;
        parse_display_text(&display_text)
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("AMP_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Amp access token.".into()))
}

const AMOUNT: &str = r"([0-9][0-9,]*(?:\.[0-9]+)?)";

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("Amp parser pattern is a valid regex")
}

/// Parses Amp's plain-text balance display (the `userDisplayBalanceInfo` RPC result). Faithful to the
/// macOS parser: a free-tier lane (dollar or percent form), individual credits, and per-workspace
/// balances, plus the signed-in identity.
fn parse_display_text(display_text: &str) -> Result<ProviderSnapshot, ProviderError> {
    let text = strip_ansi(display_text);

    let identity =
        regex(r"(?im)^\s*Signed in as\s+([^\s(]+)(?:\s+\(([^\r\n)]+)\))?\s*$").captures(&text);
    if identity.is_none() && looks_signed_out(&text) {
        return Err(ProviderError::Unauthorized(
            "Not logged in to Amp. Set a valid AMP_API_KEY.".into(),
        ));
    }

    let free = parse_free_tier(&text);
    let individual_credits = regex(&format!(
        r"(?im)^\s*Individual credits:\s*\$?{AMOUNT}\s+remaining"
    ))
    .captures(&text)
    .and_then(|caps| number(caps.get(1)?.as_str()));
    let workspaces: Vec<(String, f64)> = regex(&format!(
        r"(?im)^\s*Workspace\s+(.+?):\s*\$?{AMOUNT}\s+remaining"
    ))
    .captures_iter(&text)
    .filter_map(|caps| {
        let name = caps.get(1)?.as_str().trim();
        let remaining = number(caps.get(2)?.as_str())?;
        (!name.is_empty()).then(|| (name.to_owned(), remaining))
    })
    .collect();

    if free.is_none() && individual_credits.is_none() && workspaces.is_empty() {
        return Err(ProviderError::Parse {
            provider: "Amp",
            message: "missing Amp usage data".into(),
        });
    }

    let mut snapshot = ProviderSnapshot::new(ProviderId::Amp, "api key");
    snapshot.account_label = identity
        .as_ref()
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_owned());
    snapshot.plan = Some(if free.is_some() { "Amp Free" } else { "Amp" }.to_owned());

    if let Some(free) = &free {
        let used_percent = if free.quota > 0.0 {
            (free.used / free.quota * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        let mut window = UsageWindow::new("free", "Amp Free", used_percent);
        if let Some(hours) = free.window_hours {
            if let Ok(minutes) = u32::try_from((hours * 60.0).round() as i64) {
                window = window.with_window_minutes(minutes);
            }
        }
        window = window.with_detail(free.detail());
        snapshot.windows.push(window);
    }

    if let Some(credits) = individual_credits {
        snapshot.summary.push(SummaryItem::new(
            "Individual credits",
            format!("${credits:.2}"),
        ));
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(credits),
            spend: None,
            currency: Some("USD".into()),
        });
    }
    for (name, remaining) in workspaces {
        snapshot.summary.push(SummaryItem::new(
            format!("Workspace {name}"),
            format!("${remaining:.2}"),
        ));
    }
    Ok(snapshot)
}

struct FreeTier {
    quota: f64,
    used: f64,
    window_hours: Option<f64>,
    reset_description: Option<String>,
}

impl FreeTier {
    fn detail(&self) -> String {
        if let Some(description) = &self.reset_description {
            return description.clone();
        }
        format!("${:.2} / ${:.2}", self.used, self.quota)
    }
}

fn parse_free_tier(text: &str) -> Option<FreeTier> {
    // Dollar form: "Amp Free: $X / $Y remaining (replenishes +$Z / hour)".
    let dollar = regex(&format!(
        r"(?im)^\s*Amp Free:\s*\$?{AMOUNT}\s*/\s*\$?{AMOUNT}\s+remaining(?:\s*\(replenishes\s*\+\$?{AMOUNT}\s*/\s*hour\))?"
    ));
    if let Some(caps) = dollar.captures(text) {
        let remaining = number(caps.get(1)?.as_str())?;
        let quota = number(caps.get(2)?.as_str())?;
        let hourly = caps.get(3).and_then(|m| number(m.as_str())).unwrap_or(0.0);
        let window_hours = (hourly > 0.0).then(|| (quota / hourly).round().max(1.0));
        return Some(FreeTier {
            quota,
            used: (quota - remaining).max(0.0),
            window_hours,
            reset_description: None,
        });
    }
    // Percent form: "Amp Free: N% remaining today (resets daily)".
    let percent = regex(&format!(
        r"(?im)^\s*Amp Free:\s*{AMOUNT}\s*%\s+remaining(?:\s+today)?(?:\s*\(resets\s+daily\))?"
    ));
    let caps = percent.captures(text)?;
    let remaining = number(caps.get(1)?.as_str())?.clamp(0.0, 100.0);
    Some(FreeTier {
        quota: 100.0,
        used: 100.0 - remaining,
        window_hours: Some(24.0),
        reset_description: Some("resets daily".into()),
    })
}

fn strip_ansi(text: &str) -> String {
    regex(r"\x1b\[[0-9;]*m").replace_all(text, "").into_owned()
}

fn looks_signed_out(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("sign in") || lower.contains("log in") || lower.contains("login")
}

fn number(raw: &str) -> Option<f64> {
    raw.replace(',', "").trim().parse().ok()
}

#[derive(Debug, Deserialize)]
struct UsageApiResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    result: Option<UsageResult>,
    #[serde(default)]
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct UsageResult {
    #[serde(default, rename = "displayText")]
    display_text: String,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dollar_free_tier_with_credits_and_workspaces() {
        let text = "Signed in as dev@example.com (Acme)\n\
Amp Free: $4.00 / $10.00 remaining (replenishes +$2.00 / hour)\n\
Individual credits: $25.50 remaining\n\
Workspace Platform: $100.00 remaining\n";
        let snapshot = parse_display_text(text).unwrap();
        // used = 10 - 4 = 6 → 60%.
        assert_eq!(snapshot.windows[0].id, "free");
        assert_eq!(snapshot.windows[0].used_percent, 60.0);
        assert_eq!(
            snapshot.windows[0].detail.as_deref(),
            Some("$6.00 / $10.00")
        );
        // window hours = round(10/2) = 5 → 300 minutes.
        assert_eq!(snapshot.windows[0].window_minutes, Some(300));
        assert_eq!(snapshot.account_label.as_deref(), Some("dev@example.com"));
        assert_eq!(snapshot.plan.as_deref(), Some("Amp Free"));
        assert_eq!(snapshot.financials.unwrap().balance, Some(25.5));
        assert!(
            snapshot
                .summary
                .iter()
                .any(|s| s.label == "Workspace Platform" && s.value == "$100.00")
        );
    }

    #[test]
    fn parses_percent_free_tier() {
        let text = "Amp Free: 30% remaining today (resets daily)";
        let snapshot = parse_display_text(text).unwrap();
        // 30% remaining → 70% used.
        assert_eq!(snapshot.windows[0].used_percent, 70.0);
        assert_eq!(snapshot.windows[0].detail.as_deref(), Some("resets daily"));
        assert_eq!(snapshot.windows[0].window_minutes, Some(24 * 60));
    }

    #[test]
    fn strips_ansi_and_reads_credits_only() {
        let text = "\u{1b}[32mIndividual credits: $12.00 remaining\u{1b}[0m";
        let snapshot = parse_display_text(text).unwrap();
        assert!(snapshot.windows.is_empty());
        assert_eq!(snapshot.plan.as_deref(), Some("Amp"));
        assert_eq!(snapshot.financials.unwrap().balance, Some(12.0));
    }

    #[test]
    fn signed_out_text_is_unauthorized() {
        assert!(matches!(
            parse_display_text("Please sign in to continue"),
            Err(ProviderError::Unauthorized(_))
        ));
    }

    #[test]
    fn empty_usage_is_a_parse_error() {
        assert!(matches!(
            parse_display_text("Signed in as dev@example.com\nNothing useful here"),
            Err(ProviderError::Parse {
                provider: "Amp",
                ..
            })
        ));
    }
}
