use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Map, Value};
use std::env;

pub struct KiloProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Kilo,
    display_name: "Kilo",
    auth_kind: AuthKind::ApiKey,
    color: "#7c5cff",
    dashboard_url: "https://app.kilo.ai",
    credential_hint: "Set an API key in Settings or KILO_API_KEY. Add an Organization ID for org \
usage.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Kilo),
};

const DEFAULT_BASE_URL: &str = "https://app.kilo.ai/api/trpc";
const PROCEDURES: [&str; 3] = [
    "user.getCreditBlocks",
    "kiloPass.getState",
    "user.getAutoTopUpPaymentMethod",
];

#[async_trait]
impl Provider for KiloProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let url = batch_url(&base_url(account));

        let mut request = context
            .client
            .get(&url)
            .bearer_auth(&api_key)
            .header("Accept", "application/json");
        if let Some(org_id) = ProviderConfig::normalized_secret(&account.organization_id) {
            request = request.header("X-KILOCODE-ORGANIZATIONID", org_id);
        }

        let response = request.send().await?;
        match response.status().as_u16() {
            401 | 403 => {
                return Err(ProviderError::Unauthorized(
                    "Kilo authentication failed. Refresh the API key.".into(),
                ));
            }
            200 => {}
            status => {
                return Err(ProviderError::Http {
                    provider: "Kilo",
                    status,
                });
            }
        }
        let body: Value = response.json().await?;
        map_usage(&body)
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("KILO_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Kilo API key.".into()))
}

fn base_url(account: &ProviderAccount) -> String {
    ProviderConfig::normalized_secret(&account.base_url).map_or_else(
        || DEFAULT_BASE_URL.to_owned(),
        |value| value.trim_end_matches('/').to_owned(),
    )
}

/// tRPC batch GET: `{base}/proc1,proc2,proc3?batch=1&input=<url-encoded {"0":{"json":null},…}>`.
fn batch_url(base: &str) -> String {
    let joined = PROCEDURES.join(",");
    let input = format!(
        "{{{}}}",
        PROCEDURES
            .iter()
            .enumerate()
            .map(|(index, _)| format!("\"{index}\":{{\"json\":null}}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let encoded: String = url::form_urlencoded::byte_serialize(input.as_bytes()).collect();
    format!("{base}/{joined}?batch=1&input={encoded}")
}

fn map_usage(body: &Value) -> Result<ProviderSnapshot, ProviderError> {
    let entries = batch_entries(body)?;

    // The credit procedure is required; a tRPC error there aborts, but optional procedures are
    // tolerated so an account without Kilo Pass or auto top-up still renders its credits.
    if let Some(entry) = entries.first().copied().flatten() {
        if let Some(error) = trpc_error(entry) {
            return Err(error);
        }
    }
    let credits_payload = entries.first().copied().flatten().and_then(result_payload);
    let pass_payload = entries.get(1).copied().flatten().and_then(result_payload);
    let auto_top_up_payload = entries.get(2).copied().flatten().and_then(result_payload);

    let credits = credit_fields(credits_payload);
    let pass = pass_fields(pass_payload);
    let plan = plan_name(pass_payload);
    let (auto_enabled, auto_method) = auto_top_up_state(auto_top_up_payload);

    let mut snapshot = ProviderSnapshot::new(ProviderId::Kilo, "api key");

    if let Some(total) = credits.resolved_total() {
        let used = credits.resolved_used();
        let used_percent = if total > 0.0 {
            (used / total * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };
        snapshot.windows.push(
            UsageWindow::new("credits", "Credits", used_percent).with_detail(format!(
                "{}/{} credits",
                compact(used),
                compact(total)
            )),
        );
        snapshot.financials = Some(FinancialSnapshot {
            balance: credits.remaining.map(|value| value.max(0.0)),
            spend: None,
            currency: Some("USD".into()),
        });
    }

    if let Some(window) = pass.window() {
        snapshot.windows.push(window);
    }

    snapshot.plan = make_login_method(plan.as_deref(), auto_enabled, auto_method.as_deref());
    Ok(snapshot)
}

#[derive(Default)]
struct CreditFields {
    used: Option<f64>,
    total: Option<f64>,
    remaining: Option<f64>,
}

impl CreditFields {
    fn resolved_total(&self) -> Option<f64> {
        if let Some(total) = self.total {
            return Some(total.max(0.0));
        }
        match (self.used, self.remaining) {
            (Some(used), Some(remaining)) => Some((used + remaining).max(0.0)),
            _ => None,
        }
    }

    fn resolved_used(&self) -> f64 {
        if let Some(used) = self.used {
            return used.max(0.0);
        }
        match (self.resolved_total(), self.remaining) {
            (Some(total), Some(remaining)) => (total - remaining).max(0.0),
            _ => 0.0,
        }
    }
}

fn credit_fields(payload: Option<&Value>) -> CreditFields {
    let Some(payload) = payload else {
        return CreditFields::default();
    };
    let contexts = contexts(payload);

    // Preferred: per-block micro-USD amounts summed into total/remaining.
    if let Some(blocks) = first_array(&contexts, "creditBlocks") {
        let mut total = 0.0;
        let mut remaining = 0.0;
        let mut saw_total = false;
        let mut saw_remaining = false;
        for block in blocks.iter().filter_map(Value::as_object) {
            if let Some(amount) = number(block.get("amount_mUsd")) {
                total += amount / 1_000_000.0;
                saw_total = true;
            }
            if let Some(balance) = number(block.get("balance_mUsd")) {
                remaining += balance / 1_000_000.0;
                saw_remaining = true;
            }
        }
        if saw_total || saw_remaining {
            let total = saw_total.then_some(total.max(0.0));
            let remaining = saw_remaining.then_some(remaining.max(0.0));
            let used = match (total, remaining) {
                (Some(total), Some(remaining)) => Some((total - remaining).max(0.0)),
                _ => None,
            };
            return CreditFields {
                used,
                total,
                remaining,
            };
        }
    }

    let mut used = first_number(
        &contexts,
        &["used", "usedCredits", "creditsUsed", "consumed", "spent"],
    );
    let mut total = first_number(
        &contexts,
        &["total", "totalCredits", "creditsTotal", "limit"],
    );
    let mut remaining = first_number(
        &contexts,
        &["remaining", "remainingCredits", "creditsRemaining"],
    );

    if total.is_none() {
        if let (Some(u), Some(r)) = (used, remaining) {
            total = Some(u + r);
        }
    }
    if used.is_none() && total.is_none() && remaining.is_none() {
        if let Some(balance_milli) = first_number(&contexts, &["totalBalance_mUsd"]) {
            let balance = (balance_milli / 1_000_000.0).max(0.0);
            used = Some(0.0);
            total = Some(balance);
            remaining = Some(balance);
        }
    }

    CreditFields {
        used,
        total,
        remaining,
    }
}

#[derive(Default)]
struct PassFields {
    used: Option<f64>,
    total: Option<f64>,
    bonus: Option<f64>,
    resets_at: Option<DateTime<Utc>>,
}

impl PassFields {
    fn window(&self) -> Option<UsageWindow> {
        let total = self.total.map(|value| value.max(0.0))?;
        let used = self.used.unwrap_or(0.0).max(0.0);
        let bonus = self.bonus.unwrap_or(0.0).max(0.0);
        let base_credits = (total - bonus).max(0.0);
        let used_percent = if total > 0.0 {
            (used / total * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };
        let detail = if bonus > 0.0 {
            format!("${used:.2} / ${base_credits:.2} (+ ${bonus:.2} bonus)")
        } else {
            format!("${used:.2} / ${base_credits:.2}")
        };
        Some(
            UsageWindow::new("pass", "Kilo Pass", used_percent)
                .with_reset(self.resets_at)
                .with_detail(detail),
        )
    }
}

fn pass_fields(payload: Option<&Value>) -> PassFields {
    let Some(subscription) = subscription_data(payload) else {
        return PassFields::default();
    };
    let used = number(subscription.get("currentPeriodUsageUsd")).map(|value| value.max(0.0));
    let base = number(subscription.get("currentPeriodBaseCreditsUsd")).map(|value| value.max(0.0));
    let bonus = number(subscription.get("currentPeriodBonusCreditsUsd"))
        .unwrap_or(0.0)
        .max(0.0);
    let total = base.map(|base| base + bonus);
    let resets_at = ["nextBillingAt", "nextRenewalAt", "renewsAt", "renewAt"]
        .iter()
        .find_map(|key| date(subscription.get(*key)));

    PassFields {
        used,
        total,
        bonus: (bonus > 0.0).then_some(bonus),
        resets_at,
    }
}

fn plan_name(payload: Option<&Value>) -> Option<String> {
    if let Some(subscription) = subscription_data(payload) {
        if let Some(tier) = subscription.get("tier").and_then(Value::as_str) {
            let tier = tier.trim();
            if !tier.is_empty() {
                return Some(plan_name_for_tier(tier));
            }
        }
        return Some("Kilo Pass".to_owned());
    }
    let contexts = payload.map(contexts).unwrap_or_default();
    first_string(
        &contexts,
        &[
            "planName",
            "tier",
            "tierName",
            "passName",
            "subscriptionName",
        ],
    )
}

fn plan_name_for_tier(tier: &str) -> String {
    match tier {
        "tier_19" => "Starter",
        "tier_49" => "Pro",
        "tier_199" => "Expert",
        other => other,
    }
    .to_owned()
}

fn auto_top_up_state(payload: Option<&Value>) -> (Option<bool>, Option<String>) {
    let contexts = payload.map(contexts).unwrap_or_default();
    let enabled = first_bool(&contexts, &["enabled", "isEnabled", "active"])
        .or_else(|| bool_from_status(first_string(&contexts, &["status"]).as_deref()));
    let method = first_string(
        &contexts,
        &["paymentMethod", "paymentMethodType", "method", "cardBrand"],
    );
    (enabled, method)
}

fn make_login_method(
    plan: Option<&str>,
    auto_enabled: Option<bool>,
    auto_method: Option<&str>,
) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(plan) = plan.map(str::trim).filter(|value| !value.is_empty()) {
        parts.push(plan.to_owned());
    }
    if let Some(enabled) = auto_enabled {
        if enabled {
            match auto_method.map(str::trim).filter(|value| !value.is_empty()) {
                Some(method) => parts.push(format!("Auto top-up: {method}")),
                None => parts.push("Auto top-up: enabled".to_owned()),
            }
        } else {
            parts.push("Auto top-up: off".to_owned());
        }
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

fn subscription_data(payload: Option<&Value>) -> Option<&Map<String, Value>> {
    let object = payload?.as_object()?;
    if let Some(subscription) = object.get("subscription").and_then(Value::as_object) {
        return Some(subscription);
    }
    if object.get("subscription").is_some_and(Value::is_null) {
        return None;
    }
    let has_shape = object.contains_key("currentPeriodUsageUsd")
        || object.contains_key("currentPeriodBaseCreditsUsd")
        || object.contains_key("currentPeriodBonusCreditsUsd")
        || object.contains_key("tier");
    has_shape.then_some(object)
}

// --- tRPC batch shape helpers ---

/// Returns entries by index (0..PROCEDURES). Handles both the array batch shape and the object shape
/// keyed by stringified index, plus a lone `{result|error}` object treated as index 0.
fn batch_entries(root: &Value) -> Result<Vec<Option<&Value>>, ProviderError> {
    let mut entries: Vec<Option<&Value>> = vec![None; PROCEDURES.len()];
    if let Some(array) = root.as_array() {
        for (index, slot) in entries.iter_mut().enumerate() {
            *slot = array.get(index);
        }
        return Ok(entries);
    }
    if let Some(object) = root.as_object() {
        if object.contains_key("result") || object.contains_key("error") {
            entries[0] = Some(root);
            return Ok(entries);
        }
        let mut saw_any = false;
        for (key, value) in object {
            if let Ok(index) = key.parse::<usize>() {
                if index < entries.len() {
                    entries[index] = Some(value);
                    saw_any = true;
                }
            }
        }
        if saw_any {
            return Ok(entries);
        }
    }
    Err(ProviderError::Parse {
        provider: "Kilo",
        message: "unexpected tRPC batch shape".into(),
    })
}

fn trpc_error(entry: &Value) -> Option<ProviderError> {
    let error = entry.get("error")?;
    let code = string_at(error, &["json", "data", "code"])
        .or_else(|| string_at(error, &["data", "code"]))
        .or_else(|| string_at(error, &["code"]));
    let message = string_at(error, &["json", "message"]).or_else(|| string_at(error, &["message"]));
    let combined = [code, message]
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    if combined.contains("unauthorized") || combined.contains("forbidden") {
        return Some(ProviderError::Unauthorized(
            "Kilo authentication failed.".into(),
        ));
    }
    Some(ProviderError::Parse {
        provider: "Kilo",
        message: "tRPC error payload".into(),
    })
}

/// Unwraps `result.data.json` (non-null), else `result.data`, else `result.json`.
fn result_payload(entry: &Value) -> Option<&Value> {
    let result = entry.get("result")?;
    if let Some(data) = result.get("data") {
        if let Some(json) = data.get("json") {
            return (!json.is_null()).then_some(json);
        }
        return Some(data);
    }
    let json = result.get("json")?;
    (!json.is_null()).then_some(json)
}

// --- generic value walkers (mirror the macOS defensive `dictionaryContexts` search, depth 2) ---

fn contexts(value: &Value) -> Vec<&Map<String, Value>> {
    let mut out = Vec::new();
    collect_contexts(value, 0, 2, &mut out);
    out
}

fn collect_contexts<'a>(
    value: &'a Value,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<&'a Map<String, Value>>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    out.push(object);
    if depth >= max_depth {
        return;
    }
    for nested in object.values() {
        if nested.is_object() {
            collect_contexts(nested, depth + 1, max_depth, out);
        } else if let Some(array) = nested.as_array() {
            for element in array {
                if element.is_object() {
                    collect_contexts(element, depth + 1, max_depth, out);
                }
            }
        }
    }
}

fn first_array<'a>(contexts: &[&'a Map<String, Value>], key: &str) -> Option<&'a Vec<Value>> {
    contexts
        .iter()
        .find_map(|context| context.get(key).and_then(Value::as_array))
}

fn first_number(contexts: &[&Map<String, Value>], keys: &[&str]) -> Option<f64> {
    contexts
        .iter()
        .find_map(|context| keys.iter().find_map(|key| number(context.get(*key))))
}

fn first_string(contexts: &[&Map<String, Value>], keys: &[&str]) -> Option<String> {
    contexts.iter().find_map(|context| {
        keys.iter().find_map(|key| {
            context
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
    })
}

fn first_bool(contexts: &[&Map<String, Value>], keys: &[&str]) -> Option<bool> {
    contexts
        .iter()
        .find_map(|context| keys.iter().find_map(|key| boolean(context.get(*key))))
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_str()
}

fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn boolean(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(value) => Some(*value),
        Value::String(text) => bool_from_status(Some(text)),
        _ => None,
    }
}

fn bool_from_status(status: Option<&str>) -> Option<bool> {
    match status?.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "enabled" | "active" | "on" => Some(true),
        "false" | "0" | "no" | "disabled" | "inactive" | "off" | "none" => Some(false),
        _ => None,
    }
}

fn date(value: Option<&Value>) -> Option<DateTime<Utc>> {
    match value? {
        Value::Number(number) => epoch_to_date(number.as_f64()?),
        Value::String(text) => {
            let text = text.trim();
            if let Ok(numeric) = text.parse::<f64>() {
                return epoch_to_date(numeric);
            }
            DateTime::parse_from_rfc3339(text)
                .ok()
                .map(|value| value.with_timezone(&Utc))
        }
        _ => None,
    }
}

fn epoch_to_date(value: f64) -> Option<DateTime<Utc>> {
    let seconds = if value.abs() > 10_000_000_000.0 {
        value / 1000.0
    } else {
        value
    };
    Utc.timestamp_opt(seconds as i64, 0).single()
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

    #[test]
    fn builds_batch_url_with_encoded_input() {
        let url = batch_url("https://app.kilo.ai/api/trpc");
        assert!(url.starts_with(
            "https://app.kilo.ai/api/trpc/user.getCreditBlocks,kiloPass.getState,user.getAutoTopUpPaymentMethod?batch=1&input="
        ));
        assert!(url.contains("%7B%220%22%3A%7B%22json%22%3Anull%7D")); // {"0":{"json":null}
    }

    #[test]
    fn maps_credit_blocks_micro_usd_into_a_window() {
        let body = json!([
            { "result": { "data": { "json": { "creditBlocks": [
                { "amount_mUsd": 20000000, "balance_mUsd": 5000000 },
                { "amount_mUsd": 0, "balance_mUsd": 0 }
            ] } } } },
            { "result": { "data": { "json": null } } },
            { "result": { "data": { "json": null } } }
        ]);
        let snapshot = map_usage(&body).unwrap();
        // total = 20, remaining = 5 → used 15 → 75%.
        assert_eq!(snapshot.windows[0].id, "credits");
        assert_eq!(snapshot.windows[0].used_percent, 75.0);
        assert_eq!(snapshot.windows[0].detail.as_deref(), Some("15/20 credits"));
        assert_eq!(snapshot.financials.unwrap().balance, Some(5.0));
    }

    #[test]
    fn maps_kilo_pass_window_and_plan_from_tier() {
        let body = json!([
            { "result": { "data": { "json": { "creditBlocks": [] } } } },
            { "result": { "data": { "json": {
                "subscription": {
                    "tier": "tier_49",
                    "currentPeriodUsageUsd": 12.0,
                    "currentPeriodBaseCreditsUsd": 40.0,
                    "currentPeriodBonusCreditsUsd": 10.0,
                    "nextBillingAt": "2026-08-01T00:00:00Z"
                }
            } } } },
            { "result": { "data": { "json": { "enabled": true, "paymentMethod": "visa" } } } }
        ]);
        let snapshot = map_usage(&body).unwrap();
        let pass = snapshot.windows.iter().find(|w| w.id == "pass").unwrap();
        // total = base 40 + bonus 10 = 50; used 12 → 24%.
        assert_eq!(pass.used_percent, 24.0);
        assert_eq!(
            pass.detail.as_deref(),
            Some("$12.00 / $40.00 (+ $10.00 bonus)")
        );
        assert_eq!(snapshot.plan.as_deref(), Some("Pro · Auto top-up: visa"));
    }

    #[test]
    fn surfaces_unauthorized_trpc_error() {
        let body = json!([
            { "error": { "json": { "message": "UNAUTHORIZED", "data": { "code": "UNAUTHORIZED" } } } }
        ]);
        assert!(matches!(
            map_usage(&body),
            Err(ProviderError::Unauthorized(_))
        ));
    }

    #[test]
    fn zero_balance_renders_exhausted_from_total_balance_fallback() {
        let body = json!([
            { "result": { "data": { "json": { "totalBalance_mUsd": 0 } } } },
            { "result": { "data": { "json": null } } },
            { "result": { "data": { "json": null } } }
        ]);
        let snapshot = map_usage(&body).unwrap();
        assert_eq!(snapshot.windows[0].used_percent, 100.0);
        assert_eq!(snapshot.windows[0].detail.as_deref(), Some("0/0 credits"));
    }

    #[test]
    fn tolerates_object_batch_shape_keyed_by_index() {
        let body = json!({
            "0": { "result": { "data": { "json": { "used": 3.0, "total": 12.0 } } } }
        });
        let snapshot = map_usage(&body).unwrap();
        assert_eq!(snapshot.windows[0].used_percent, 25.0);
    }
}
