use crate::{
    atomic_file::atomic_write,
    model::{ProviderId, ProviderState, ProviderStatus},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, hash_map::Entry},
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use thiserror::Error;

static HISTORY_WRITE_TRANSACTION: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPoint {
    pub timestamp: DateTime<Utc>,
    pub provider: ProviderId,
    pub account_id: String,
    pub window_id: String,
    pub used_percent: f64,
    pub resets_at: Option<DateTime<Utc>>,
    pub balance: Option<f64>,
    pub spend: Option<f64>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryRange {
    Hours24,
    Days7,
    Days30,
    Days90,
    Since(DateTime<Utc>),
}

impl HistoryRange {
    fn cutoff(self, now: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            Self::Hours24 => now - Duration::hours(24),
            Self::Days7 => now - Duration::days(7),
            Self::Days30 => now - Duration::days(30),
            Self::Days90 => now - Duration::days(90),
            Self::Since(timestamp) => timestamp,
        }
    }
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("history I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("history serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct HistoryStore {
    root: PathBuf,
}

#[derive(Debug)]
pub struct StagedHistoryDelete {
    path: PathBuf,
    previous: Option<Vec<u8>>,
    installed: Option<Vec<u8>>,
}

impl StagedHistoryDelete {
    pub fn rollback(self) -> Result<(), HistoryError> {
        let _guard = begin_history_write()?;
        if read_optional_bytes(&self.path)? != self.installed {
            return Err(std::io::Error::other("history changed during rollback").into());
        }
        match self.previous {
            Some(bytes) => atomic_write(&self.path, &bytes)?,
            None => match fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
        }
        Ok(())
    }

    pub fn commit(self) -> Result<(), HistoryError> {
        let _guard = begin_history_write()?;
        if read_optional_bytes(&self.path)? == self.installed {
            Ok(())
        } else {
            Err(std::io::Error::other("history changed before delete commit").into())
        }
    }
}

impl HistoryStore {
    pub const fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn append_states(
        &self,
        states: &[ProviderState],
        now: DateTime<Utc>,
        retention_days: u32,
    ) -> Result<(), HistoryError> {
        let mut new_points = HashMap::<ProviderId, Vec<HistoryPoint>>::new();
        for state in states {
            let Some(snapshot) = state.snapshot.as_ref() else {
                continue;
            };
            if state.status != ProviderStatus::Ready || snapshot.provider != state.descriptor.id {
                continue;
            }
            let points = new_points.entry(state.descriptor.id).or_default();
            for window in &snapshot.windows {
                let financials = snapshot.financials.as_ref();
                points.push(HistoryPoint {
                    timestamp: snapshot.fetched_at,
                    provider: state.descriptor.id,
                    account_id: state.account_id.clone(),
                    window_id: window.id.clone(),
                    used_percent: window.used_percent,
                    resets_at: window.resets_at,
                    balance: financials.and_then(|value| value.balance),
                    spend: financials.and_then(|value| value.spend),
                    currency: financials.and_then(|value| value.currency.clone()),
                });
            }
        }
        if new_points.is_empty() {
            return Ok(());
        }

        let _guard = begin_history_write()?;

        fs::create_dir_all(&self.root)?;
        let retention_cutoff = now - Duration::days(i64::from(retention_days));
        for (provider, additions) in new_points {
            let path = self.path(provider);
            let mut points = read_points(&path, provider)?;
            points.extend(additions);
            points.retain(|point| point.timestamp >= retention_cutoff && point.timestamp <= now);
            let points = deduplicate_and_sort(points);
            let mut body = Vec::new();
            for point in points {
                serde_json::to_writer(&mut body, &point)?;
                body.push(b'\n');
            }
            atomic_write(&path, &body)?;
        }
        Ok(())
    }

    pub fn query(
        &self,
        provider: ProviderId,
        account_id: Option<&str>,
        range: HistoryRange,
        now: DateTime<Utc>,
    ) -> Result<Vec<HistoryPoint>, HistoryError> {
        let cutoff = range.cutoff(now);
        let points = read_points(&self.path(provider), provider)?
            .into_iter()
            .filter(|point| account_id.is_none_or(|account| point.account_id == account))
            .filter(|point| point.timestamp >= cutoff && point.timestamp <= now)
            .collect();
        Ok(deduplicate_and_sort(points))
    }

    /// Remove only one account's local usage history, preserving sibling accounts and providers.
    pub fn delete_account(
        &self,
        provider: ProviderId,
        account_id: &str,
    ) -> Result<(), HistoryError> {
        let _guard = begin_history_write()?;
        let path = self.path(provider);
        let mut points = read_points(&path, provider)?;
        points.retain(|point| point.account_id != account_id);
        if !path.exists() {
            return Ok(());
        }
        let mut body = Vec::new();
        for point in deduplicate_and_sort(points) {
            serde_json::to_writer(&mut body, &point)?;
            body.push(b'\n');
        }
        atomic_write(&path, &body)?;
        Ok(())
    }

    pub fn stage_delete_account(
        &self,
        provider: ProviderId,
        account_id: &str,
    ) -> Result<StagedHistoryDelete, HistoryError> {
        let _guard = begin_history_write()?;
        let path = self.path(provider);
        let previous = read_optional_bytes(&path)?;
        let mut points = read_points(&path, provider)?;
        points.retain(|point| point.account_id != account_id);
        let installed = if previous.is_some() {
            let mut body = Vec::new();
            for point in deduplicate_and_sort(points) {
                serde_json::to_writer(&mut body, &point)?;
                body.push(b'\n');
            }
            atomic_write(&path, &body)?;
            Some(body)
        } else {
            None
        };
        Ok(StagedHistoryDelete {
            path,
            previous,
            installed,
        })
    }

    fn path(&self, provider: ProviderId) -> PathBuf {
        self.root.join(format!("{}.jsonl", provider.as_str()))
    }
}

fn begin_history_write() -> Result<MutexGuard<'static, ()>, HistoryError> {
    HISTORY_WRITE_TRANSACTION
        .lock()
        .map_err(|_| std::io::Error::other("history write transaction lock was poisoned").into())
}

fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>, std::io::Error> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_points(path: &Path, provider: ProviderId) -> Result<Vec<HistoryPoint>, HistoryError> {
    let body = match fs::read(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice::<HistoryPoint>(line).ok())
        .filter(|point| point.provider == provider)
        .collect())
}

fn deduplicate_and_sort(points: Vec<HistoryPoint>) -> Vec<HistoryPoint> {
    let mut latest = HashMap::new();
    for point in points {
        let key = (
            point.provider,
            point.account_id.clone(),
            point.window_id.clone(),
            point
                .resets_at
                .unwrap_or_else(|| rounded_minute(point.timestamp)),
        );
        match latest.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(point);
            }
            Entry::Occupied(mut entry) if point.timestamp >= entry.get().timestamp => {
                entry.insert(point);
            }
            Entry::Occupied(_) => {}
        }
    }
    let mut points = latest.into_values().collect::<Vec<_>>();
    points.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.account_id.cmp(&right.account_id))
            .then_with(|| left.window_id.cmp(&right.window_id))
            .then_with(|| left.resets_at.cmp(&right.resets_at))
    });
    points
}

fn rounded_minute(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(timestamp.timestamp().div_euclid(60) * 60, 0)
        .expect("a valid UTC timestamp remains valid when rounded to the minute")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot,
        ProviderState, UsageWindow,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use std::{fs, sync::Arc};

    fn ready_state(
        provider: ProviderId,
        account_id: &str,
        used: f64,
        observed: DateTime<Utc>,
        resets_at: Option<DateTime<Utc>>,
    ) -> ProviderState {
        let descriptor = ProviderDescriptor {
            id: provider,
            display_name: "Fixture",
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.invalid",
            credential_hint: "fixture",
            supports_multiple_accounts: true,
            capabilities: crate::model::provider_capabilities(provider),
        };
        let mut snapshot = ProviderSnapshot::new(provider, "fixture");
        snapshot.fetched_at = observed;
        snapshot
            .windows
            .push(UsageWindow::new("weekly", "Weekly", used).with_reset(resets_at));
        ProviderState::ready(descriptor, snapshot).with_account(account_id, None)
    }

    #[test]
    fn history_keeps_latest_point_for_one_reset_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let first = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let second = first + chrono::Duration::minutes(5);
        let reset = first + chrono::Duration::days(7);
        store
            .append_states(
                &[ready_state(
                    ProviderId::Openrouter,
                    "acc_a",
                    40.0,
                    first,
                    Some(reset),
                )],
                first,
                90,
            )
            .unwrap();
        store
            .append_states(
                &[ready_state(
                    ProviderId::Openrouter,
                    "acc_a",
                    55.0,
                    second,
                    Some(reset),
                )],
                second,
                90,
            )
            .unwrap();
        let points = store
            .query(
                ProviderId::Openrouter,
                Some("acc_a"),
                HistoryRange::Days7,
                second,
            )
            .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].used_percent, 55.0);
        assert_eq!(points[0].timestamp, second);
    }

    #[test]
    fn history_without_reset_keeps_latest_point_per_minute() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let first = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 1).unwrap();
        let same_minute = first + chrono::Duration::seconds(48);
        let next_minute = first + chrono::Duration::minutes(1);
        for (used, observed) in [(10.0, first), (20.0, same_minute), (30.0, next_minute)] {
            store
                .append_states(
                    &[ready_state(
                        ProviderId::Openrouter,
                        "acc_a",
                        used,
                        observed,
                        None,
                    )],
                    observed,
                    90,
                )
                .unwrap();
        }

        let points = store
            .query(
                ProviderId::Openrouter,
                Some("acc_a"),
                HistoryRange::Hours24,
                next_minute,
            )
            .unwrap();
        assert_eq!(
            points
                .iter()
                .map(|point| point.used_percent)
                .collect::<Vec<_>>(),
            vec![20.0, 30.0]
        );
    }

    #[test]
    fn history_retention_drops_only_expired_points() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let expired = now - chrono::Duration::days(91);
        let retained = now - chrono::Duration::days(89);
        store
            .append_states(
                &[ready_state(
                    ProviderId::Openrouter,
                    "acc_a",
                    10.0,
                    expired,
                    None,
                )],
                expired,
                90,
            )
            .unwrap();
        store
            .append_states(
                &[ready_state(
                    ProviderId::Openrouter,
                    "acc_a",
                    20.0,
                    retained,
                    None,
                )],
                now,
                90,
            )
            .unwrap();
        let points = store
            .query(
                ProviderId::Openrouter,
                Some("acc_a"),
                HistoryRange::Days90,
                now,
            )
            .unwrap();
        assert_eq!(
            points
                .iter()
                .map(|point| point.used_percent)
                .collect::<Vec<_>>(),
            vec![20.0]
        );
    }

    #[test]
    fn history_query_is_siloed_by_provider_account_and_range() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![
            ready_state(ProviderId::Openrouter, "acc_a", 10.0, now, None),
            ready_state(ProviderId::Openrouter, "acc_b", 20.0, now, None),
            ready_state(ProviderId::Deepseek, "acc_a", 30.0, now, None),
        ];
        store.append_states(&states, now, 90).unwrap();
        let points = store
            .query(
                ProviderId::Openrouter,
                Some("acc_a"),
                HistoryRange::Hours24,
                now,
            )
            .unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].provider, ProviderId::Openrouter);
        assert_eq!(points[0].account_id, "acc_a");
        assert_eq!(points[0].used_percent, 10.0);
    }

    #[test]
    fn history_copies_only_structured_financial_values() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let mut state = ready_state(ProviderId::Openrouter, "acc_a", 10.0, now, None);
        state.snapshot.as_mut().unwrap().financials = Some(FinancialSnapshot {
            balance: Some(12.5),
            spend: Some(3.25),
            currency: Some("USD".into()),
        });

        store.append_states(&[state], now, 90).unwrap();

        let points = store
            .query(
                ProviderId::Openrouter,
                Some("acc_a"),
                HistoryRange::Hours24,
                now,
            )
            .unwrap();
        assert_eq!(points[0].balance, Some(12.5));
        assert_eq!(points[0].spend, Some(3.25));
        assert_eq!(points[0].currency.as_deref(), Some("USD"));
    }

    #[test]
    fn deleting_an_account_keeps_other_account_history() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let path = store.path(ProviderId::Codex);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let now = Utc::now();
        let points = ["acc_a", "acc_b"].map(|account_id| HistoryPoint {
            timestamp: now,
            provider: ProviderId::Codex,
            account_id: account_id.into(),
            window_id: "weekly".into(),
            used_percent: 10.0,
            resets_at: None,
            balance: None,
            spend: None,
            currency: None,
        });
        let mut body = Vec::new();
        for point in points {
            serde_json::to_writer(&mut body, &point).unwrap();
            body.push(b'\n');
        }
        fs::write(&path, body).unwrap();

        store.delete_account(ProviderId::Codex, "acc_a").unwrap();

        assert!(
            store
                .query(ProviderId::Codex, Some("acc_a"), HistoryRange::Days7, now)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .query(ProviderId::Codex, Some("acc_b"), HistoryRange::Days7, now)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn staged_account_delete_restores_exact_previous_history() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let path = store.path(ProviderId::Codex);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = br#"{"timestamp":"2026-07-15T10:00:00Z","provider":"codex","accountId":"acc_a","windowId":"weekly","usedPercent":10.0,"resetsAt":null,"balance":null,"spend":null,"currency":null}
{"timestamp":"2026-07-15T10:00:00Z","provider":"codex","accountId":"acc_b","windowId":"weekly","usedPercent":20.0,"resetsAt":null,"balance":null,"spend":null,"currency":null}
"#;
        fs::write(&path, original).unwrap();

        let staged = store
            .stage_delete_account(ProviderId::Codex, "acc_a")
            .unwrap();
        assert!(!String::from_utf8_lossy(&fs::read(&path).unwrap()).contains("acc_a"));
        staged.rollback().unwrap();

        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn staged_delete_rollback_never_overwrites_a_new_append() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        store
            .append_states(
                &[ready_state(ProviderId::Codex, "acc_a", 10.0, now, None)],
                now,
                90,
            )
            .unwrap();
        let staged = store
            .stage_delete_account(ProviderId::Codex, "acc_a")
            .unwrap();
        store
            .append_states(
                &[ready_state(
                    ProviderId::Codex,
                    "acc_external",
                    20.0,
                    now,
                    None,
                )],
                now,
                90,
            )
            .unwrap();

        assert!(staged.rollback().is_err());
        assert_eq!(
            store
                .query(
                    ProviderId::Codex,
                    Some("acc_external"),
                    HistoryRange::Days7,
                    now
                )
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .query(ProviderId::Codex, Some("acc_a"), HistoryRange::Days7, now)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn staged_delete_commit_rejects_a_new_append() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        store
            .append_states(
                &[ready_state(ProviderId::Codex, "acc_a", 10.0, now, None)],
                now,
                90,
            )
            .unwrap();
        let staged = store
            .stage_delete_account(ProviderId::Codex, "acc_a")
            .unwrap();
        store
            .append_states(
                &[ready_state(
                    ProviderId::Codex,
                    "acc_external",
                    20.0,
                    now,
                    None,
                )],
                now,
                90,
            )
            .unwrap();

        assert!(staged.commit().is_err());
        assert_eq!(
            store
                .query(
                    ProviderId::Codex,
                    Some("acc_external"),
                    HistoryRange::Days7,
                    now,
                )
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn concurrent_appends_to_one_provider_preserve_every_account() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(HistoryStore::at(directory.path().to_path_buf()));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let handles = (0..8)
            .map(|index| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.append_states(
                        &[ready_state(
                            ProviderId::Codex,
                            &format!("acc_{index}"),
                            f64::from(index),
                            now,
                            None,
                        )],
                        now,
                        90,
                    )
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        let points = store
            .query(ProviderId::Codex, None, HistoryRange::Days7, now)
            .unwrap();
        assert_eq!(points.len(), 8);
    }

    #[test]
    fn deleting_missing_account_history_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        store
            .delete_account(ProviderId::Claude, "acc_missing")
            .unwrap();
        store
            .delete_account(ProviderId::Claude, "acc_missing")
            .unwrap();
        assert!(!store.path(ProviderId::Claude).exists());
    }

    #[test]
    fn malformed_lines_are_skipped_without_losing_valid_points() {
        let directory = tempfile::tempdir().unwrap();
        let store = HistoryStore::at(directory.path().to_path_buf());
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let first = HistoryPoint {
            timestamp: now,
            provider: ProviderId::Openrouter,
            account_id: "acc_a".into(),
            window_id: "weekly".into(),
            used_percent: 10.0,
            resets_at: None,
            balance: None,
            spend: None,
            currency: None,
        };
        let second = HistoryPoint {
            timestamp: now + chrono::Duration::minutes(1),
            used_percent: 20.0,
            ..first.clone()
        };
        let body = format!(
            "{}\nnot-json\n{}\n",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        fs::write(directory.path().join("openrouter.jsonl"), body).unwrap();
        let points = store
            .query(
                ProviderId::Openrouter,
                Some("acc_a"),
                HistoryRange::Hours24,
                now + chrono::Duration::minutes(1),
            )
            .unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].used_percent, 10.0);
        assert_eq!(points[1].used_percent, 20.0);
    }
}
