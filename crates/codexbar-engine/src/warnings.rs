//! Usage-threshold warning evaluation.
//!
//! Pure, Tauri-free logic that decides when a usage window crosses a configured threshold. The
//! caller (the Tauri refresh coordinator, or the CLI) keeps a [`WarningTracker`] across refreshes so
//! each crossing fires exactly once. Per the module design:
//!
//! - A warning fires only when a window moves from below to at-or-above a threshold.
//! - Dropping back below the threshold, or entering a new reset period, re-arms it.
//! - Delivery state is keyed by provider, account, window, kind, threshold, and reset boundary.
//! - Quiet hours suppress system Toast delivery but never hide the in-app marker.

use crate::{
    config_sections::NotificationConfig,
    history::HistoryPoint,
    model::{ProviderId, ProviderState, ProviderStatus},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashSet;

/// Synthetic "threshold" recorded for a pace warning so it keys distinctly and never collides with a
/// real 0–100 threshold crossing.
const PACE_THRESHOLD_MILLI: i64 = 100_000;

/// Bucket width for the reset boundary carried in [`WarningKey`]. A provider that derives `resets_at`
/// from a relative "seconds remaining" value produces a slightly different absolute timestamp on every
/// refresh (because `now` advances while the reported seconds stay whole/coarse). Keying on the raw
/// millisecond value would therefore mint a fresh key — and a fresh Toast — every refresh. Bucketing to
/// whole minutes collapses that sub-minute drift onto one stable key while still keeping genuine reset
/// periods, which are hours or days apart, in distinct buckets.
const RESET_BUCKET_MILLIS: i64 = 60_000;

/// Quantize a reset boundary into the stable dedup bucket described on [`RESET_BUCKET_MILLIS`].
fn reset_bucket(reset: DateTime<Utc>) -> i64 {
    reset.timestamp_millis().div_euclid(RESET_BUCKET_MILLIS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WarningKind {
    Threshold,
    /// Predicted to reach 100% before the window resets, based on the recent consumption rate.
    Pace,
}

/// A newly-crossed threshold warning, ready to render in-app and (unless suppressed) as a Toast.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    pub provider: ProviderId,
    pub account_id: String,
    pub window_id: String,
    pub window_title: String,
    pub kind: WarningKind,
    pub threshold: f64,
    pub used_percent: f64,
    /// Reset boundary (RFC3339) that this warning belongs to, when the window declares one.
    pub reset_boundary: Option<String>,
    /// True when quiet hours are active: keep the in-app marker but do not raise a system Toast.
    pub suppress_toast: bool,
}

/// Identity of one armed warning. Encoding the reset boundary means a fresh period is a distinct key
/// that has not fired yet, which is exactly the "new reset period re-arms" rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WarningKey {
    provider: ProviderId,
    account_id: String,
    window_id: String,
    kind: WarningKind,
    /// Threshold in milli-percent so the float becomes a stable hashable key.
    threshold_milli: i64,
    /// Reset boundary bucketed to whole minutes (see [`RESET_BUCKET_MILLIS`]), or `None` for windows
    /// without a declared reset. Bucketing keeps a reset timestamp that drifts a few seconds each
    /// refresh from re-firing the warning every time.
    reset_boundary_bucket: Option<i64>,
}

/// Cross-refresh memory of which warnings have already fired. Cheap to keep in application state.
#[derive(Debug, Default)]
pub struct WarningTracker {
    fired: HashSet<WarningKey>,
}

impl WarningTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of currently-armed (fired-and-not-yet-re-armed) warnings. Exposed for diagnostics.
    pub fn armed_count(&self) -> usize {
        self.fired.len()
    }
}

/// Evaluate the current provider states against notification thresholds and return only the
/// warnings that crossed on this refresh. `now_minute_of_day` is local wall-clock minutes (0..1440)
/// used solely for quiet-hours suppression.
pub fn evaluate_warnings(
    states: &[ProviderState],
    config: &NotificationConfig,
    now_minute_of_day: u16,
    tracker: &mut WarningTracker,
) -> Vec<Warning> {
    let mut fired = Vec::new();
    if !config.enabled {
        return fired;
    }
    let quiet = quiet_hours_active(
        now_minute_of_day,
        config.quiet_start.as_deref(),
        config.quiet_end.as_deref(),
    );

    for state in states {
        if state.status != ProviderStatus::Ready {
            continue;
        }
        let Some(snapshot) = &state.snapshot else {
            continue;
        };
        let provider = state.descriptor.id;
        let thresholds = config
            .provider_thresholds
            .get(&provider)
            .unwrap_or(&config.thresholds);

        for window in &snapshot.windows {
            let boundary_bucket = window.resets_at.map(reset_bucket);
            for &threshold in thresholds {
                let key = WarningKey {
                    provider,
                    account_id: state.account_id.clone(),
                    window_id: window.id.clone(),
                    kind: WarningKind::Threshold,
                    threshold_milli: (threshold * 1000.0).round() as i64,
                    reset_boundary_bucket: boundary_bucket,
                };
                if window.used_percent >= threshold {
                    // `insert` is true only the first time this exact crossing is seen.
                    if tracker.fired.insert(key) {
                        fired.push(Warning {
                            provider,
                            account_id: state.account_id.clone(),
                            window_id: window.id.clone(),
                            window_title: window.title.clone(),
                            kind: WarningKind::Threshold,
                            threshold,
                            used_percent: window.used_percent,
                            reset_boundary: window.resets_at.map(|reset| reset.to_rfc3339()),
                            suppress_toast: quiet,
                        });
                    }
                } else {
                    // Below the threshold again: drop every armed key for this series so a later
                    // crossing (this period or the next) can fire once more.
                    let threshold_milli = key.threshold_milli;
                    tracker.fired.retain(|armed| {
                        !(armed.provider == provider
                            && armed.account_id == state.account_id
                            && armed.window_id == window.id
                            && armed.kind == WarningKind::Threshold
                            && armed.threshold_milli == threshold_milli)
                    });
                }
            }
        }
    }
    fired
}

/// Predictive-pace evaluation: for each ready window with a reset, extrapolate the recent consumption
/// rate from `history` and fire once per window/period if it is on track to hit 100% before the
/// reset. Gated on `config.predictive_pace`; deduped via the same tracker as threshold warnings.
pub fn evaluate_pace_warnings(
    states: &[ProviderState],
    history: &[HistoryPoint],
    config: &NotificationConfig,
    now: DateTime<Utc>,
    now_minute_of_day: u16,
    tracker: &mut WarningTracker,
) -> Vec<Warning> {
    let mut fired = Vec::new();
    if !config.enabled || !config.predictive_pace {
        return fired;
    }
    let quiet = quiet_hours_active(
        now_minute_of_day,
        config.quiet_start.as_deref(),
        config.quiet_end.as_deref(),
    );

    for state in states {
        if state.status != ProviderStatus::Ready {
            continue;
        }
        let Some(snapshot) = &state.snapshot else {
            continue;
        };
        let provider = state.descriptor.id;

        for window in &snapshot.windows {
            let Some(resets_at) = window.resets_at else {
                continue;
            };
            if window.used_percent >= 100.0 {
                continue; // Already full — a threshold warning covers this, not pace.
            }
            let mut series: Vec<(DateTime<Utc>, f64)> = history
                .iter()
                .filter(|point| {
                    point.provider == provider
                        && point.account_id == state.account_id
                        && point.window_id == window.id
                        && point.timestamp <= now
                })
                .map(|point| (point.timestamp, point.used_percent))
                .collect();
            series.sort_by_key(|(timestamp, _)| *timestamp);

            if !projected_reaches_full(&series, window.used_percent, resets_at, now) {
                continue;
            }
            let key = WarningKey {
                provider,
                account_id: state.account_id.clone(),
                window_id: window.id.clone(),
                kind: WarningKind::Pace,
                threshold_milli: PACE_THRESHOLD_MILLI,
                reset_boundary_bucket: Some(reset_bucket(resets_at)),
            };
            if tracker.fired.insert(key) {
                fired.push(Warning {
                    provider,
                    account_id: state.account_id.clone(),
                    window_id: window.id.clone(),
                    window_title: window.title.clone(),
                    kind: WarningKind::Pace,
                    threshold: 100.0,
                    used_percent: window.used_percent,
                    reset_boundary: Some(resets_at.to_rfc3339()),
                    suppress_toast: quiet,
                });
            }
        }
    }
    fired
}

/// Whether the current-period consumption rate projects to ≥100% before `resets_at`. Points are
/// ascending by time; everything up to and including the last reset (a drop in used percent) is
/// dropped so the rate reflects only the current period. Needs at least two rising points.
fn projected_reaches_full(
    points: &[(DateTime<Utc>, f64)],
    current_percent: f64,
    resets_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    let mut period_start = 0;
    for index in 1..points.len() {
        // A meaningful drop marks a reset boundary; the current period starts after it.
        if points[index].1 + 1.0 < points[index - 1].1 {
            period_start = index;
        }
    }
    let period = &points[period_start..];
    if period.len() < 2 {
        return false;
    }
    let (first_time, first_percent) = period[0];
    let (last_time, last_percent) = *period.last().expect("period is non-empty");
    let elapsed = (last_time - first_time).num_seconds();
    if elapsed <= 0 || last_percent <= first_percent {
        return false;
    }
    let remaining = (resets_at - now).num_seconds();
    if remaining <= 0 {
        return false;
    }
    let rate_per_second = (last_percent - first_percent) / elapsed as f64;
    current_percent + rate_per_second * remaining as f64 >= 100.0
}

/// Whether `now` falls inside the `[start, end)` quiet window. Both bounds are `HH:MM`; an empty or
/// malformed bound (or a start equal to end) disables suppression. A window that wraps past midnight
/// (start > end) is handled.
fn quiet_hours_active(now_minute_of_day: u16, start: Option<&str>, end: Option<&str>) -> bool {
    let (Some(start), Some(end)) = (start.and_then(parse_hh_mm), end.and_then(parse_hh_mm)) else {
        return false;
    };
    if start == end {
        return false;
    }
    let now = now_minute_of_day.min(1439);
    if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    }
}

fn parse_hh_mm(value: &str) -> Option<u16> {
    let trimmed = value.trim();
    let (hours, minutes) = trimmed.split_once(':')?;
    let hours: u16 = hours.parse().ok()?;
    let minutes: u16 = minutes.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(hours * 60 + minutes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthKind, ProviderDescriptor, ProviderSnapshot, UsageWindow};
    use chrono::{Duration, Utc};

    fn descriptor(id: ProviderId) -> ProviderDescriptor {
        ProviderDescriptor {
            id,
            display_name: "Test",
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.com",
            credential_hint: "",
            supports_multiple_accounts: true,
            capabilities: crate::model::provider_capabilities(id),
        }
    }

    fn state_with_window(id: ProviderId, window: UsageWindow) -> ProviderState {
        let mut snapshot = ProviderSnapshot::new(id, "test");
        snapshot.windows.push(window);
        ProviderState::ready(descriptor(id), snapshot).with_account("acc_a".to_owned(), None)
    }

    fn config() -> NotificationConfig {
        NotificationConfig::default()
    }

    fn point(window_id: &str, timestamp: chrono::DateTime<Utc>, percent: f64) -> HistoryPoint {
        HistoryPoint {
            timestamp,
            provider: ProviderId::Openrouter,
            account_id: "acc_a".to_owned(),
            window_id: window_id.to_owned(),
            used_percent: percent,
            resets_at: None,
            balance: None,
            spend: None,
            currency: None,
        }
    }

    #[test]
    fn pace_fires_when_projected_to_exceed_before_reset() {
        let now = Utc::now();
        let reset = now + Duration::hours(2);
        let state = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 60.0).with_reset(Some(reset)),
        );
        // 40% → 60% over the last hour is 20%/h; two more hours projects to 100%.
        let history = vec![
            point("session", now - Duration::hours(1), 40.0),
            point("session", now, 60.0),
        ];
        let mut settings = config();
        settings.predictive_pace = true;
        let mut tracker = WarningTracker::new();

        let fired = evaluate_pace_warnings(
            &[state.clone()],
            &history,
            &settings,
            now,
            720,
            &mut tracker,
        );
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].kind, WarningKind::Pace);
        assert!(
            evaluate_pace_warnings(&[state], &history, &settings, now, 720, &mut tracker)
                .is_empty()
        );
    }

    #[test]
    fn pace_is_off_unless_predictive_pace_is_enabled() {
        let now = Utc::now();
        let state = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 90.0).with_reset(Some(now + Duration::hours(1))),
        );
        let history = vec![
            point("session", now - Duration::hours(1), 10.0),
            point("session", now, 90.0),
        ];
        let mut tracker = WarningTracker::new();
        assert!(
            evaluate_pace_warnings(&[state], &history, &config(), now, 720, &mut tracker)
                .is_empty()
        );
    }

    #[test]
    fn steady_usage_does_not_fire_pace() {
        let now = Utc::now();
        let state = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 20.0).with_reset(Some(now + Duration::hours(1))),
        );
        // Flat 20% → zero rate → never projected to reach 100%.
        let history = vec![
            point("session", now - Duration::hours(1), 20.0),
            point("session", now, 20.0),
        ];
        let mut settings = config();
        settings.predictive_pace = true;
        let mut tracker = WarningTracker::new();
        assert!(
            evaluate_pace_warnings(&[state], &history, &settings, now, 720, &mut tracker)
                .is_empty()
        );
    }

    #[test]
    fn fires_once_per_threshold_crossing() {
        let state = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 92.0),
        );
        let mut tracker = WarningTracker::new();

        let first = evaluate_warnings(&[state.clone()], &config(), 720, &mut tracker);
        // Both 75 and 90 crossed on the first observation.
        assert_eq!(first.len(), 2);
        assert!(
            first
                .iter()
                .all(|warning| warning.provider == ProviderId::Openrouter)
        );

        let second = evaluate_warnings(&[state], &config(), 720, &mut tracker);
        assert!(second.is_empty(), "an unchanged window must not re-fire");
    }

    #[test]
    fn dropping_below_threshold_re_arms() {
        let mut tracker = WarningTracker::new();
        let high = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 80.0),
        );
        assert_eq!(
            evaluate_warnings(&[high], &config(), 720, &mut tracker).len(),
            1
        ); // crosses 75

        let low = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 40.0),
        );
        assert!(evaluate_warnings(&[low], &config(), 720, &mut tracker).is_empty());

        let high_again = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 80.0),
        );
        assert_eq!(
            evaluate_warnings(&[high_again], &config(), 720, &mut tracker).len(),
            1,
            "re-crossing after dropping below must fire again"
        );
    }

    #[test]
    fn a_new_reset_boundary_re_arms() {
        let mut tracker = WarningTracker::new();
        let first_period = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 92.0).with_reset(Some(Utc::now())),
        );
        assert_eq!(
            evaluate_warnings(&[first_period], &config(), 720, &mut tracker).len(),
            2
        );

        let next_period = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 92.0)
                .with_reset(Some(Utc::now() + Duration::hours(5))),
        );
        assert_eq!(
            evaluate_warnings(&[next_period], &config(), 720, &mut tracker).len(),
            2,
            "a new reset boundary is a fresh crossing"
        );
    }

    #[test]
    fn sub_minute_reset_drift_does_not_re_fire() {
        // Providers that derive `resets_at` from a relative "seconds remaining" value hand back a
        // slightly different absolute timestamp every refresh as `now` advances. Bucketing the reset
        // boundary must keep that drift from minting a fresh crossing — and a fresh Toast — each poll.
        let mut tracker = WarningTracker::new();
        // Anchored 30s into a minute so a small forward nudge stays inside the same minute bucket.
        let base = DateTime::from_timestamp(1_800_000_030, 0).expect("valid timestamp");
        let first = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 92.0).with_reset(Some(base)),
        );
        assert_eq!(
            evaluate_warnings(&[first], &config(), 720, &mut tracker).len(),
            2
        );

        let drifted = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 92.0)
                .with_reset(Some(base + Duration::milliseconds(1_500))),
        );
        assert!(
            evaluate_warnings(&[drifted], &config(), 720, &mut tracker).is_empty(),
            "a sub-minute drift in the reset timestamp must not re-fire"
        );
    }

    #[test]
    fn quiet_hours_suppress_toast_but_keep_the_warning() {
        let mut tracker = WarningTracker::new();
        let mut settings = config();
        settings.quiet_start = Some("22:00".into());
        settings.quiet_end = Some("07:00".into());
        let state = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 92.0),
        );

        // 23:30 is inside the wrap-around quiet window.
        let warnings = evaluate_warnings(&[state], &settings, 23 * 60 + 30, &mut tracker);
        assert_eq!(warnings.len(), 2);
        assert!(warnings.iter().all(|warning| warning.suppress_toast));
    }

    #[test]
    fn disabled_notifications_emit_nothing() {
        let mut tracker = WarningTracker::new();
        let mut settings = config();
        settings.enabled = false;
        let state = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 99.0),
        );
        assert!(evaluate_warnings(&[state], &settings, 720, &mut tracker).is_empty());
    }

    #[test]
    fn per_provider_thresholds_override_defaults() {
        let mut tracker = WarningTracker::new();
        let mut settings = config();
        settings
            .provider_thresholds
            .insert(ProviderId::Openrouter, vec![95.0]);
        let state = state_with_window(
            ProviderId::Openrouter,
            UsageWindow::new("session", "Session", 92.0),
        );
        // 92 crosses the default 75/90 but not the provider-specific 95.
        assert!(evaluate_warnings(&[state], &settings, 720, &mut tracker).is_empty());
    }

    #[test]
    fn quiet_hours_helper_handles_same_day_and_wrap() {
        assert!(quiet_hours_active(9 * 60, Some("08:00"), Some("10:00")));
        assert!(!quiet_hours_active(7 * 60, Some("08:00"), Some("10:00")));
        assert!(quiet_hours_active(60, Some("22:00"), Some("07:00")));
        assert!(!quiet_hours_active(12 * 60, Some("22:00"), Some("07:00")));
        assert!(!quiet_hours_active(9 * 60, Some("bad"), Some("10:00")));
        assert!(!quiet_hours_active(9 * 60, Some("08:00"), Some("08:00")));
    }
}
