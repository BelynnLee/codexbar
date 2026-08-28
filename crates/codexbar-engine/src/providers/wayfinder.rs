use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem},
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::{collections::BTreeMap, env};

pub struct WayfinderProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Wayfinder,
    display_name: "Wayfinder",
    auth_kind: AuthKind::ApiKey,
    color: "#10a37f",
    dashboard_url: "http://127.0.0.1:8088/router",
    credential_hint: "Runs against the local Wayfinder gateway. Start it with \
`wayfinder-router serve`, or set a Gateway URL in Settings / WAYFINDER_GATEWAY_URL.",
    supports_multiple_accounts: false,
    capabilities: crate::model::provider_capabilities(ProviderId::Wayfinder),
};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8088";
const SAVINGS_PERIOD: &str = "30d";
const DECISION_LATENCY_METRIC: &str = "wayfinder_router_decision_latency_seconds";

#[async_trait]
impl Provider for WayfinderProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let base = base_url(account);
        let health: HealthResponse = get_json(context, &format!("{base}/healthz")).await?;
        let models: ModelsResponse = get_json(context, &format!("{base}/router/models")).await?;
        let savings: SavingsResponse = get_json(
            context,
            &format!("{base}/v1/savings?period={SAVINGS_PERIOD}"),
        )
        .await?;
        // Latency is best-effort: a missing/blank /metrics endpoint must never fail the snapshot.
        let metrics_text = get_text(context, &format!("{base}/metrics")).await.ok();
        let avg_decision_ms = metrics_text.and_then(|text| average_decision_milliseconds(&text));

        Ok(map_usage(&health, &models, &savings, avg_decision_ms))
    }
}

async fn get_json<T: for<'de> Deserialize<'de>>(
    context: &FetchContext<'_>,
    url: &str,
) -> Result<T, ProviderError> {
    let response = context.client.get(url).send().await.map_err(|_| {
        ProviderError::Platform(
            "Could not reach the Wayfinder gateway. Start it with `wayfinder-router serve` \
(default http://127.0.0.1:8088) or fix the Gateway URL in Settings."
                .into(),
        )
    })?;
    if !response.status().is_success() {
        return Err(ProviderError::Http {
            provider: "Wayfinder",
            status: response.status().as_u16(),
        });
    }
    response
        .json::<T>()
        .await
        .map_err(|error| ProviderError::Parse {
            provider: "Wayfinder",
            message: error.to_string(),
        })
}

async fn get_text(context: &FetchContext<'_>, url: &str) -> Result<String, ProviderError> {
    let response = context.client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(ProviderError::Http {
            provider: "Wayfinder",
            status: response.status().as_u16(),
        });
    }
    Ok(response.text().await?)
}

/// Wayfinder's gateway defaults to loopback; the account `base_url` (or `WAYFINDER_GATEWAY_URL`)
/// overrides it. Trailing slashes are trimmed so path joins stay clean.
fn base_url(account: &ProviderAccount) -> String {
    ProviderConfig::normalized_secret(&account.base_url)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("WAYFINDER_GATEWAY_URL")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .map_or_else(
            || DEFAULT_BASE_URL.to_owned(),
            |value| value.trim_end_matches('/').to_owned(),
        )
}

fn map_usage(
    health: &HealthResponse,
    models: &ModelsResponse,
    savings: &SavingsResponse,
    avg_decision_ms: Option<f64>,
) -> ProviderSnapshot {
    // No usage window: a local router has no quota, and sub-cent realized spend would render as a
    // meaningless meter. Status, routing mix, and savings surface as summary lines instead.
    let mut snapshot = ProviderSnapshot::new(ProviderId::Wayfinder, "local gateway");
    let model_count = models.models.len();

    snapshot.summary.push(SummaryItem::new(
        "Gateway",
        gateway_summary(health, models, model_count),
    ));
    if let Some(routed) = routed_summary(savings) {
        snapshot.summary.push(SummaryItem::new("Routed", routed));
    }
    if let Some(saved) = saved_summary(savings) {
        snapshot.summary.push(SummaryItem::new("Saved", saved));
    }
    if let Some(ms) = avg_decision_ms {
        snapshot
            .summary
            .push(SummaryItem::new("Avg decision", format!("{ms:.1} ms")));
    }

    snapshot.plan = Some(status_label(health, models));
    snapshot
}

fn status_label(health: &HealthResponse, models: &ModelsResponse) -> String {
    if health.offline {
        return "Offline mode".to_owned();
    }
    if models.dry_run {
        return "Dry run".to_owned();
    }
    if health.status == "degraded" {
        let count = health.missing_keys.len();
        return match count {
            0 => "Degraded".to_owned(),
            1 => "Degraded — 1 key missing".to_owned(),
            n => format!("Degraded — {n} keys missing"),
        };
    }
    "Local gateway".to_owned()
}

fn gateway_summary(health: &HealthResponse, models: &ModelsResponse, model_count: usize) -> String {
    let mut summary = format!("{} · {}", health.status, model_count_label(model_count));
    if health.offline {
        summary.push_str(" · offline");
    }
    if models.dry_run {
        summary.push_str(" · dry run");
    }
    summary
}

fn model_count_label(count: usize) -> String {
    if count == 1 {
        "1 model".to_owned()
    } else {
        format!("{count} models")
    }
}

/// The gateway's own route names and their request counts (top 5). Route names are whatever the user
/// configured, so no local/cloud split is assumed. `None` until the gateway has routed anything.
fn routed_summary(savings: &SavingsResponse) -> Option<String> {
    if savings.requests == 0 {
        return None;
    }
    let mut routes: Vec<(&String, &RouteBucket)> = savings.by_route.iter().collect();
    routes.sort_by(|a, b| b.1.requests.cmp(&a.1.requests).then(a.0.cmp(b.0)));
    let mix = routes
        .into_iter()
        .take(5)
        .map(|(name, bucket)| format!("{name}: {}", compact(bucket.requests)))
        .collect::<Vec<_>>()
        .join(" · ");
    (!mix.is_empty()).then_some(mix)
}

/// "$4.12 · 38.2% vs highest-cost route" when priced; percent-only otherwise (relative units never
/// render as dollars).
fn saved_summary(savings: &SavingsResponse) -> Option<String> {
    if savings.requests == 0 || savings.saved <= 0.0 {
        return None;
    }
    let pct = format!("{}% vs highest-cost route", percent_text(savings.saved_pct));
    if !savings.priced {
        return Some(pct);
    }
    let amount = if savings.saved < 0.01 {
        "<$0.01".to_owned()
    } else {
        format!("${:.2}", savings.saved)
    };
    Some(format!("{amount} · {pct}"))
}

fn percent_text(value: f64) -> String {
    if (value - value.round()).abs() < f64::EPSILON {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

fn compact(value: i64) -> String {
    value.to_string()
}

/// Averages the Prometheus `_sum`/`_count` histogram pair for the router decision latency, returning
/// milliseconds. `None` unless both series are present with a positive count.
fn average_decision_milliseconds(text: &str) -> Option<f64> {
    let mut sum: Option<f64> = None;
    let mut count: Option<f64> = None;
    for line in text.lines() {
        if let Some(value) = metric_value(line, &format!("{DECISION_LATENCY_METRIC}_sum")) {
            sum = Some(value);
        } else if let Some(value) = metric_value(line, &format!("{DECISION_LATENCY_METRIC}_count"))
        {
            count = Some(value);
        }
    }
    let (sum, count) = (sum?, count?);
    (count > 0.0).then(|| sum / count * 1000.0)
}

fn metric_value(line: &str, name: &str) -> Option<f64> {
    let rest = line.strip_prefix(name)?;
    // The metric name must be followed by a value (space) or a label set (`{`), not be a prefix of a
    // longer metric name.
    if !rest.starts_with([' ', '{']) {
        return None;
    }
    rest.split_whitespace()
        .last()
        .and_then(|token| token.parse().ok())
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    #[serde(default)]
    offline: bool,
    #[serde(default, rename = "missing_keys")]
    missing_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ModelsResponse {
    #[serde(default)]
    models: Vec<Model>,
    #[serde(default, rename = "dry_run")]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct Model {
    #[serde(default, rename = "name")]
    _name: String,
}

#[derive(Debug, Deserialize)]
struct SavingsResponse {
    #[serde(default)]
    priced: bool,
    #[serde(default)]
    requests: i64,
    #[serde(default)]
    saved: f64,
    #[serde(default, rename = "saved_pct")]
    saved_pct: f64,
    #[serde(default, rename = "by_route")]
    by_route: BTreeMap<String, RouteBucket>,
}

#[derive(Debug, Deserialize)]
struct RouteBucket {
    #[serde(default)]
    requests: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse<T: for<'de> Deserialize<'de>>(value: serde_json::Value) -> T {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn defaults_to_loopback_gateway() {
        assert_eq!(base_url(&ProviderAccount::default()), DEFAULT_BASE_URL);
        let account = ProviderAccount {
            base_url: Some("http://gateway.local:9000/".into()),
            ..Default::default()
        };
        assert_eq!(base_url(&account), "http://gateway.local:9000");
    }

    #[test]
    fn summarizes_a_healthy_gateway_with_routing_and_savings() {
        let health: HealthResponse = parse(json!({ "status": "healthy", "offline": false }));
        let models: ModelsResponse =
            parse(json!({ "models": [{ "name": "a" }, { "name": "b" }], "dry_run": false }));
        let savings: SavingsResponse = parse(json!({
            "priced": true, "requests": 30, "saved": 4.125, "saved_pct": 38.2,
            "by_route": { "local": { "requests": 20 }, "cloud": { "requests": 10 } }
        }));
        let snapshot = map_usage(&health, &models, &savings, Some(1.234));
        assert!(snapshot.windows.is_empty());
        assert_eq!(snapshot.summary[0].value, "healthy · 2 models");
        assert_eq!(snapshot.summary[1].value, "local: 20 · cloud: 10");
        assert_eq!(
            snapshot.summary[2].value,
            "$4.12 · 38.2% vs highest-cost route"
        );
        assert_eq!(snapshot.summary[3].value, "1.2 ms");
        assert_eq!(snapshot.plan.as_deref(), Some("Local gateway"));
    }

    #[test]
    fn degraded_status_counts_missing_keys() {
        let health: HealthResponse =
            parse(json!({ "status": "degraded", "missing_keys": ["OPENAI_API_KEY"] }));
        let models: ModelsResponse = parse(json!({ "models": [], "dry_run": false }));
        assert_eq!(status_label(&health, &models), "Degraded — 1 key missing");
    }

    #[test]
    fn offline_and_dry_run_take_precedence() {
        let offline: HealthResponse = parse(json!({ "status": "healthy", "offline": true }));
        let models: ModelsResponse = parse(json!({ "models": [], "dry_run": false }));
        assert_eq!(status_label(&offline, &models), "Offline mode");
        let healthy: HealthResponse = parse(json!({ "status": "healthy" }));
        let dry: ModelsResponse = parse(json!({ "models": [], "dry_run": true }));
        assert_eq!(status_label(&healthy, &dry), "Dry run");
    }

    #[test]
    fn routed_and_saved_are_hidden_without_requests() {
        let savings: SavingsResponse = parse(json!({ "requests": 0, "saved": 5.0 }));
        assert!(routed_summary(&savings).is_none());
        assert!(saved_summary(&savings).is_none());
    }

    #[test]
    fn averages_prometheus_decision_latency() {
        let text = "\
# HELP wayfinder_router_decision_latency_seconds Router decision latency\n\
wayfinder_router_decision_latency_seconds_sum 2.5\n\
wayfinder_router_decision_latency_seconds_count 5\n\
wayfinder_router_decision_latency_seconds_bucket{le=\"0.1\"} 3\n";
        // 2.5 / 5 * 1000 = 500 ms.
        assert_eq!(average_decision_milliseconds(text), Some(500.0));
        assert_eq!(average_decision_milliseconds("nothing here"), None);
    }
}
