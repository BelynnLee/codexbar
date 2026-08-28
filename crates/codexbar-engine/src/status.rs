//! Service-status (incident) polling.
//!
//! Independent of usage fetching: a provider maps to an official Statuspage.io source when one
//! exists, and `api/v2/status.json` is normalized to a [`ServiceIndicator`]. Network, parse, and
//! unsupported-provider cases resolve to [`ServiceIndicator::Unknown`] and never change usage status.

use crate::model::ProviderId;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceIndicator {
    None,
    Minor,
    Major,
    Critical,
    Maintenance,
    Unknown,
}

impl ServiceIndicator {
    /// Map the top-level `status.indicator` string from a Statuspage `status.json` feed.
    pub fn from_statuspage_indicator(raw: &str) -> Self {
        match raw {
            "none" => Self::None,
            "minor" => Self::Minor,
            "major" => Self::Major,
            "critical" => Self::Critical,
            "maintenance" => Self::Maintenance,
            _ => Self::Unknown,
        }
    }

    /// Map a per-component `status` string (used when aggregating component feeds).
    pub fn from_component_status(raw: &str) -> Self {
        match raw {
            "operational" => Self::None,
            "degraded_performance" => Self::Minor,
            "partial_outage" => Self::Major,
            "major_outage" | "full_outage" => Self::Critical,
            "under_maintenance" => Self::Maintenance,
            _ => Self::Unknown,
        }
    }

    /// True for a known, actionable incident. `None` (all clear) and `Unknown` (undetermined) are
    /// deliberately excluded so an unreachable status page never lights up an incident badge.
    pub fn is_incident(self) -> bool {
        matches!(
            self,
            Self::Minor | Self::Major | Self::Critical | Self::Maintenance
        )
    }

    /// Ordering used to pick the most severe indicator among several components.
    pub fn severity_rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Unknown => 1,
            Self::Maintenance => 2,
            Self::Minor => 3,
            Self::Major => 4,
            Self::Critical => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub indicator: ServiceIndicator,
    pub description: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum StatusError {
    #[error("status page returned HTTP {0}")]
    Http(u16),
    #[error("status page response was unreadable: {0}")]
    Parse(String),
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
}

/// Official Statuspage.io base URL for a provider, or `None` when no source exists. Providers
/// without a source are simply never polled (their status stays `Unknown`).
pub fn status_source(provider: ProviderId) -> Option<&'static str> {
    match provider {
        ProviderId::Claude => Some("https://status.claude.com/"),
        ProviderId::Copilot => Some("https://www.githubstatus.com/"),
        ProviderId::Cursor => Some("https://status.cursor.com"),
        _ => None,
    }
}

/// Providers that currently have a status source, in declared order. Used by the poller.
pub fn status_polled_providers() -> Vec<ProviderId> {
    ProviderId::ALL
        .into_iter()
        .filter(|&provider| status_source(provider).is_some())
        .collect()
}

/// Parse a Statuspage `api/v2/status.json` payload into a normalized [`ServiceStatus`].
pub fn parse_status_summary(bytes: &[u8]) -> Result<ServiceStatus, StatusError> {
    #[derive(Deserialize)]
    struct Response {
        page: Option<Page>,
        status: StatusField,
    }
    #[derive(Deserialize)]
    struct Page {
        #[serde(default, rename = "updated_at")]
        updated_at: Option<DateTime<Utc>>,
    }
    #[derive(Deserialize)]
    struct StatusField {
        indicator: String,
        #[serde(default)]
        description: Option<String>,
    }
    let response: Response =
        serde_json::from_slice(bytes).map_err(|error| StatusError::Parse(error.to_string()))?;
    Ok(ServiceStatus {
        indicator: ServiceIndicator::from_statuspage_indicator(&response.status.indicator),
        description: response.status.description,
        updated_at: response.page.and_then(|page| page.updated_at),
    })
}

/// Fetch and normalize one provider's status page. Callers treat any error as `Unknown`.
pub async fn fetch_service_status(
    client: &Client,
    base_url: &str,
) -> Result<ServiceStatus, StatusError> {
    let url = format!("{}/api/v2/status.json", base_url.trim_end_matches('/'));
    let response = client
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(StatusError::Http(response.status().as_u16()));
    }
    let bytes = response.bytes().await?;
    parse_status_summary(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_operational_summary() {
        let payload = br#"{
            "page": { "updated_at": "2026-07-15T10:00:00.000-07:00" },
            "status": { "indicator": "none", "description": "All Systems Operational" }
        }"#;
        let status = parse_status_summary(payload).expect("status");
        assert_eq!(status.indicator, ServiceIndicator::None);
        assert!(!status.indicator.is_incident());
        assert_eq!(
            status.description.as_deref(),
            Some("All Systems Operational")
        );
        assert!(status.updated_at.is_some());
    }

    #[test]
    fn parses_major_incident() {
        let payload = br#"{"status":{"indicator":"major","description":"Partial Outage"}}"#;
        let status = parse_status_summary(payload).expect("status");
        assert_eq!(status.indicator, ServiceIndicator::Major);
        assert!(status.indicator.is_incident());
        assert_eq!(status.updated_at, None);
    }

    #[test]
    fn unknown_indicator_is_not_an_incident() {
        let payload = br#"{"status":{"indicator":"wat"}}"#;
        let status = parse_status_summary(payload).expect("status");
        assert_eq!(status.indicator, ServiceIndicator::Unknown);
        assert!(!status.indicator.is_incident());
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        assert!(matches!(
            parse_status_summary(b"not json"),
            Err(StatusError::Parse(_))
        ));
    }

    #[test]
    fn component_status_maps_to_indicator() {
        assert_eq!(
            ServiceIndicator::from_component_status("operational"),
            ServiceIndicator::None
        );
        assert_eq!(
            ServiceIndicator::from_component_status("degraded_performance"),
            ServiceIndicator::Minor
        );
        assert_eq!(
            ServiceIndicator::from_component_status("partial_outage"),
            ServiceIndicator::Major
        );
        assert_eq!(
            ServiceIndicator::from_component_status("full_outage"),
            ServiceIndicator::Critical
        );
        assert_eq!(
            ServiceIndicator::from_component_status("under_maintenance"),
            ServiceIndicator::Maintenance
        );
        assert_eq!(
            ServiceIndicator::from_component_status("other"),
            ServiceIndicator::Unknown
        );
    }

    #[test]
    fn severity_rank_orders_critical_highest() {
        assert!(
            ServiceIndicator::Critical.severity_rank() > ServiceIndicator::Major.severity_rank()
        );
        assert!(ServiceIndicator::Major.severity_rank() > ServiceIndicator::Minor.severity_rank());
        assert!(ServiceIndicator::Minor.severity_rank() > ServiceIndicator::None.severity_rank());
    }

    #[test]
    fn providers_with_official_status_pages_are_polled() {
        assert_eq!(
            status_source(ProviderId::Claude),
            Some("https://status.claude.com/")
        );
        assert_eq!(
            status_source(ProviderId::Copilot),
            Some("https://www.githubstatus.com/")
        );
        assert_eq!(
            status_source(ProviderId::Cursor),
            Some("https://status.cursor.com")
        );
        assert_eq!(status_source(ProviderId::Openrouter), None);
        assert_eq!(
            status_polled_providers(),
            vec![ProviderId::Claude, ProviderId::Copilot, ProviderId::Cursor]
        );
    }
}
