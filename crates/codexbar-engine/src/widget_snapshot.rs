use crate::{
    atomic_file::atomic_write,
    model::{ProviderId, ProviderSnapshot, ProviderState, ProviderStatus},
    redaction::redact,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use std::path::PathBuf;
use thiserror::Error;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WidgetSnapshot {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub providers: Vec<WidgetProviderEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WidgetProviderEntry {
    pub provider: ProviderId,
    pub account_id: String,
    pub account_label: Option<String>,
    pub status: ProviderStatus,
    pub windows: Vec<WidgetWindowEntry>,
    pub balance: Option<f64>,
    pub currency: Option<String>,
    pub service_indicator: Option<String>,
    pub warning_kinds: Vec<String>,
    #[serde(serialize_with = "serialize_redacted_error")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WidgetWindowEntry {
    pub id: String,
    pub title: String,
    pub used_percent: f64,
    pub resets_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum WidgetSnapshotError {
    #[error("unsupported widget snapshot schema version {found}; expected 1")]
    UnsupportedSchemaVersion { found: u32 },
    #[error("widget snapshot serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("widget snapshot write failed: {0}")]
    Write(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct WidgetSnapshotWriter {
    path: PathBuf,
}

impl WidgetSnapshotWriter {
    pub const fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn write(&self, snapshot: &WidgetSnapshot) -> Result<(), WidgetSnapshotError> {
        let normalized = snapshot.normalized_for_write()?;
        let body = serde_json::to_vec_pretty(&normalized)?;
        atomic_write(&self.path, &body)?;
        Ok(())
    }
}

impl WidgetSnapshot {
    pub fn from_states(states: &[ProviderState], generated_at: DateTime<Utc>) -> Self {
        let mut providers = states
            .iter()
            .map(WidgetProviderEntry::from_state)
            .collect::<Vec<_>>();
        providers.sort_by(|left, right| {
            provider_order(left.provider)
                .cmp(&provider_order(right.provider))
                .then_with(|| left.account_id.cmp(&right.account_id))
        });
        Self {
            schema_version: SCHEMA_VERSION,
            generated_at,
            providers,
        }
    }

    fn normalized_for_write(&self) -> Result<Self, WidgetSnapshotError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WidgetSnapshotError::UnsupportedSchemaVersion {
                found: self.schema_version,
            });
        }
        let mut normalized = self.clone();
        for provider in &mut normalized.providers {
            provider.error = provider.error.as_deref().map(redact);
            for window in &mut provider.windows {
                window.used_percent = normalize_used_percent(window.used_percent);
            }
        }
        Ok(normalized)
    }
}

impl WidgetProviderEntry {
    fn from_state(state: &ProviderState) -> Self {
        let snapshot = owned_ready_snapshot(state);
        let windows = snapshot
            .map(|snapshot| {
                snapshot
                    .windows
                    .iter()
                    .map(|window| WidgetWindowEntry {
                        id: window.id.clone(),
                        title: window.title.clone(),
                        used_percent: normalize_used_percent(window.used_percent),
                        resets_at: window.resets_at,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let financials = snapshot.and_then(|snapshot| snapshot.financials.as_ref());
        Self {
            provider: state.descriptor.id,
            account_id: state.account_id.clone(),
            account_label: state.account_label.clone(),
            status: state.status,
            windows,
            balance: financials.and_then(|value| value.balance),
            currency: financials.and_then(|value| value.currency.clone()),
            service_indicator: None,
            warning_kinds: Vec::new(),
            error: state.error.as_deref().map(redact),
        }
    }
}

fn owned_ready_snapshot(state: &ProviderState) -> Option<&ProviderSnapshot> {
    if state.status != ProviderStatus::Ready {
        return None;
    }
    state
        .snapshot
        .as_ref()
        .filter(|snapshot| snapshot.provider == state.descriptor.id)
}

fn provider_order(provider: ProviderId) -> usize {
    ProviderId::ALL
        .iter()
        .position(|candidate| *candidate == provider)
        .expect("all provider ids have a declared order")
}

fn normalize_used_percent(value: f64) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 100.0)
    }
}

#[allow(clippy::ref_option)] // Serde's serialize_with callback receives a reference to the field.
fn serialize_redacted_error<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.as_deref().map(redact).serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot,
        ProviderState, ProviderStatus, UsageWindow,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use std::fs;

    fn descriptor(provider: ProviderId) -> ProviderDescriptor {
        ProviderDescriptor {
            id: provider,
            display_name: "Fixture",
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.invalid",
            credential_hint: "fixture",
            supports_multiple_accounts: true,
            capabilities: crate::model::provider_capabilities(provider),
        }
    }

    fn snapshot_state(provider: ProviderId, account_id: &str, used: f64) -> ProviderState {
        let mut snapshot = ProviderSnapshot::new(provider, "fixture");
        snapshot
            .windows
            .push(UsageWindow::new("weekly", "Weekly", used));
        ProviderState::ready(descriptor(provider), snapshot)
            .with_account(account_id, Some("Work".into()))
    }

    #[test]
    fn snapshot_serialization_matches_schema_v1_exactly() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let reset = Utc.with_ymd_and_hms(2026, 7, 22, 10, 0, 0).unwrap();
        let mut state = snapshot_state(ProviderId::Openrouter, "acc_work", 20.0);
        let provider_snapshot = state.snapshot.as_mut().unwrap();
        provider_snapshot.windows[0].used_percent = 120.0;
        provider_snapshot.windows[0].resets_at = Some(reset);
        provider_snapshot.financials = Some(FinancialSnapshot {
            balance: Some(12.5),
            spend: Some(3.25),
            currency: Some("USD".into()),
        });

        let serialized =
            serde_json::to_string_pretty(&WidgetSnapshot::from_states(&[state], now)).unwrap();

        assert_eq!(
            serialized,
            concat!(
                "{\n",
                "  \"schemaVersion\": 1,\n",
                "  \"generatedAt\": \"2026-07-15T10:00:00Z\",\n",
                "  \"providers\": [\n",
                "    {\n",
                "      \"provider\": \"openrouter\",\n",
                "      \"accountId\": \"acc_work\",\n",
                "      \"accountLabel\": \"Work\",\n",
                "      \"status\": \"ready\",\n",
                "      \"windows\": [\n",
                "        {\n",
                "          \"id\": \"weekly\",\n",
                "          \"title\": \"Weekly\",\n",
                "          \"usedPercent\": 100.0,\n",
                "          \"resetsAt\": \"2026-07-22T10:00:00Z\"\n",
                "        }\n",
                "      ],\n",
                "      \"balance\": 12.5,\n",
                "      \"currency\": \"USD\",\n",
                "      \"serviceIndicator\": null,\n",
                "      \"warningKinds\": [],\n",
                "      \"error\": null\n",
                "    }\n",
                "  ]\n",
                "}",
            )
        );
    }

    #[test]
    fn from_states_normalizes_non_finite_percentages_to_json_numbers() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let mut state = snapshot_state(ProviderId::Openrouter, "acc_work", 20.0);
        let windows = &mut state.snapshot.as_mut().unwrap().windows;
        windows.push(UsageWindow::new("daily", "Daily", 20.0));
        windows.push(UsageWindow::new("monthly", "Monthly", 20.0));
        windows[0].used_percent = f64::NAN;
        windows[1].used_percent = f64::NEG_INFINITY;
        windows[2].used_percent = f64::INFINITY;

        let snapshot = WidgetSnapshot::from_states(&[state], now);
        let percentages = snapshot.providers[0]
            .windows
            .iter()
            .map(|window| window.used_percent)
            .collect::<Vec<_>>();
        let value = serde_json::to_value(&snapshot).unwrap();
        let serialized_windows = value["providers"][0]["windows"].as_array().unwrap();

        assert_eq!(percentages, vec![0.0, 0.0, 100.0]);
        assert!(
            serialized_windows
                .iter()
                .all(|window| window["usedPercent"].is_number()),
            "non-finite percentage serialized as null: {value}"
        );
        assert_eq!(
            serialized_windows
                .iter()
                .map(|window| window["usedPercent"].as_f64().unwrap())
                .collect::<Vec<_>>(),
            vec![0.0, 0.0, 100.0]
        );
    }

    #[test]
    fn disabled_provider_keeps_its_account_but_has_no_usage_payload() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let state = ProviderState::disabled(descriptor(ProviderId::Cursor))
            .with_account("acc_disabled", Some("Work".into()));

        let snapshot = WidgetSnapshot::from_states(&[state], now);

        assert_eq!(snapshot.providers.len(), 1);
        assert_eq!(snapshot.providers[0].provider, ProviderId::Cursor);
        assert_eq!(snapshot.providers[0].account_id, "acc_disabled");
        assert_eq!(snapshot.providers[0].account_label.as_deref(), Some("Work"));
        assert_eq!(snapshot.providers[0].status, ProviderStatus::Disabled);
        assert!(snapshot.providers[0].windows.is_empty());
        assert_eq!(snapshot.providers[0].balance, None);
        assert_eq!(snapshot.providers[0].currency, None);
        assert_eq!(snapshot.providers[0].service_indicator, None);
        assert!(snapshot.providers[0].warning_kinds.is_empty());
        assert_eq!(snapshot.providers[0].error, None);
    }

    #[test]
    fn providers_are_sorted_by_declared_provider_order_then_account_id() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![
            snapshot_state(ProviderId::Deepseek, "acc_a", 40.0),
            snapshot_state(ProviderId::Openrouter, "acc_b", 30.0),
            snapshot_state(ProviderId::Claude, "acc_z", 10.0),
            snapshot_state(ProviderId::Openrouter, "acc_a", 20.0),
        ];

        let snapshot = WidgetSnapshot::from_states(&states, now);
        let identities = snapshot
            .providers
            .iter()
            .map(|entry| (entry.provider, entry.account_id.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            identities,
            vec![
                (ProviderId::Claude, "acc_z"),
                (ProviderId::Openrouter, "acc_a"),
                (ProviderId::Openrouter, "acc_b"),
                (ProviderId::Deepseek, "acc_a"),
            ]
        );
    }

    #[test]
    fn snapshot_does_not_copy_a_different_providers_payload() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let mut foreign_snapshot = ProviderSnapshot::new(ProviderId::Deepseek, "fixture");
        foreign_snapshot
            .windows
            .push(UsageWindow::new("foreign", "Foreign", 90.0));
        foreign_snapshot.financials = Some(FinancialSnapshot {
            balance: Some(99.0),
            spend: None,
            currency: Some("CNY".into()),
        });
        let state = ProviderState::ready(descriptor(ProviderId::Openrouter), foreign_snapshot)
            .with_account("acc_a", Some("Work".into()));

        let snapshot = WidgetSnapshot::from_states(&[state], now);

        assert_eq!(snapshot.providers[0].provider, ProviderId::Openrouter);
        assert!(snapshot.providers[0].windows.is_empty());
        assert_eq!(snapshot.providers[0].balance, None);
        assert_eq!(snapshot.providers[0].currency, None);
    }

    #[test]
    fn snapshot_never_serializes_credentials_or_raw_error_secrets() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let state = ProviderState::failed(
            descriptor(ProviderId::Openrouter),
            concat!(
                "Authorization: Bearer abc.def.ghi for user@example.com\n",
                "api_key=sk-fictional-secret Cookie: sid=fictional-cookie",
            ),
        )
        .with_account("acc_a", None);

        let snapshot = WidgetSnapshot::from_states(&[state], now);
        let value = serde_json::to_value(&snapshot).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();

        assert!(!serialized.contains("abc.def.ghi"));
        assert!(!serialized.contains("user@example.com"));
        assert!(!serialized.contains("sk-fictional-secret"));
        assert!(!serialized.contains("fictional-cookie"));
        assert!(serialized.contains("<redacted>"));
        assert_eq!(
            value["providers"][0]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            vec![
                "accountId",
                "accountLabel",
                "balance",
                "currency",
                "error",
                "provider",
                "serviceIndicator",
                "status",
                "warningKinds",
                "windows",
            ]
        );
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "generatedAt": "2026-07-15T10:00:00Z",
                "providers": [{
                    "provider": "openrouter",
                    "accountId": "acc_a",
                    "accountLabel": null,
                    "status": "error",
                    "windows": [],
                    "balance": null,
                    "currency": null,
                    "serviceIndicator": null,
                    "warningKinds": [],
                    "error": concat!(
                        "Authorization: <redacted>\n",
                        "api_key=<redacted> Cookie: <redacted>",
                    ),
                }],
            })
        );
    }

    #[test]
    fn direct_serialization_redacts_a_public_entries_raw_error() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let mut snapshot = WidgetSnapshot::from_states(
            &[snapshot_state(ProviderId::Openrouter, "acc_a", 20.0)],
            now,
        );
        snapshot.providers[0].error = Some(raw_error().into());

        let value = serde_json::to_value(&snapshot).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();

        assert_error_is_redacted(&serialized, &value["providers"][0]["error"]);
    }

    #[test]
    fn writer_normalizes_a_direct_public_snapshot_without_mutating_the_caller() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let writer = WidgetSnapshotWriter::at(path.clone());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let mut snapshot = WidgetSnapshot::from_states(
            &[snapshot_state(ProviderId::Openrouter, "acc_a", 20.0)],
            now,
        );
        snapshot.providers[0].error = Some(raw_error().into());
        snapshot.providers[0].windows[0].used_percent = f64::NAN;

        writer.write(&snapshot).unwrap();

        let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();
        assert_error_is_redacted(&serialized, &value["providers"][0]["error"]);
        assert_eq!(value["providers"][0]["windows"][0]["usedPercent"], 0.0);
        assert_eq!(snapshot.providers[0].error.as_deref(), Some(raw_error()));
        assert!(snapshot.providers[0].windows[0].used_percent.is_nan());
    }

    #[test]
    fn writer_redacts_a_deserialized_public_snapshots_raw_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let writer = WidgetSnapshotWriter::at(path.clone());
        let snapshot: WidgetSnapshot = serde_json::from_value(json!({
            "schemaVersion": 1,
            "generatedAt": "2026-07-15T10:00:00Z",
            "providers": [{
                "provider": "openrouter",
                "accountId": "acc_a",
                "accountLabel": null,
                "status": "error",
                "windows": [],
                "balance": null,
                "currency": null,
                "serviceIndicator": null,
                "warningKinds": [],
                "error": raw_error(),
            }],
        }))
        .unwrap();

        writer.write(&snapshot).unwrap();

        let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();
        assert_error_is_redacted(&serialized, &value["providers"][0]["error"]);
        assert_eq!(snapshot.providers[0].error.as_deref(), Some(raw_error()));
    }

    #[test]
    fn writer_rejects_an_unknown_schema_without_replacing_the_previous_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        fs::write(&path, b"previous-snapshot").unwrap();
        let writer = WidgetSnapshotWriter::at(path.clone());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let mut snapshot = WidgetSnapshot::from_states(
            &[snapshot_state(ProviderId::Openrouter, "acc_a", 20.0)],
            now,
        );
        snapshot.schema_version = 2;

        let error = writer.write(&snapshot).unwrap_err();

        assert!(matches!(
            error,
            WidgetSnapshotError::UnsupportedSchemaVersion { found: 2 }
        ));
        assert_eq!(
            error.to_string(),
            "unsupported widget snapshot schema version 2; expected 1"
        );
        assert_eq!(fs::read(path).unwrap(), b"previous-snapshot");
    }

    #[test]
    fn snapshot_writer_atomically_replaces_previous_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let writer = WidgetSnapshotWriter::at(path.clone());
        let first_time = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let second_time = first_time + chrono::Duration::minutes(1);
        let first = WidgetSnapshot::from_states(
            &[snapshot_state(ProviderId::Openrouter, "acc_a", 20.0)],
            first_time,
        );
        let second = WidgetSnapshot::from_states(
            &[snapshot_state(ProviderId::Openrouter, "acc_a", 60.0)],
            second_time,
        );

        writer.write(&first).unwrap();
        writer.write(&second).unwrap();

        let body = fs::read(&path).unwrap();
        let decoded: WidgetSnapshot = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded.generated_at, second_time);
        assert_eq!(decoded.providers[0].windows[0].used_percent, 60.0);
        assert_eq!(body, serde_json::to_vec_pretty(&second).unwrap());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    fn raw_error() -> &'static str {
        concat!(
            "Authorization: Bearer abc.def.ghi for user@example.com\n",
            "api_key=sk-fictional-secret Cookie: sid=fictional-cookie",
        )
    }

    fn assert_error_is_redacted(serialized: &str, error: &serde_json::Value) {
        assert!(!serialized.contains("abc.def.ghi"));
        assert!(!serialized.contains("user@example.com"));
        assert!(!serialized.contains("sk-fictional-secret"));
        assert!(!serialized.contains("fictional-cookie"));
        assert_eq!(
            error,
            concat!(
                "Authorization: <redacted>\n",
                "api_key=<redacted> Cookie: <redacted>",
            )
        );
    }
}
