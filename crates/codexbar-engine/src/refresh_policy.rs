use crate::model::{ProviderState, ProviderStatus};
use chrono::{DateTime, Utc};
use std::time::Duration;

const RECOVERY_DELAY: Duration = Duration::from_secs(60);
const MAX_STABLE_INTERVAL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy)]
pub struct RefreshSignals<'a> {
    pub states: &'a [ProviderState],
    pub base_interval: Duration,
    pub max_interval: Duration,
    pub reset_proximity: Duration,
    pub now: DateTime<Utc>,
    pub stable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshDecision {
    pub delay: Duration,
    pub reason: RefreshReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshReason {
    Manual,
    ErrorRetry,
    StaleData,
    ResetProximity,
    StableBackoff,
    BaseInterval,
}

pub fn next_refresh(signals: RefreshSignals<'_>) -> RefreshDecision {
    if signals.base_interval.is_zero() || signals.max_interval.is_zero() {
        return RefreshDecision {
            delay: Duration::ZERO,
            reason: RefreshReason::Manual,
        };
    }

    let recovery_delay = RECOVERY_DELAY.min(signals.max_interval);
    if signals
        .states
        .iter()
        .any(|state| state.status == ProviderStatus::Error)
    {
        return RefreshDecision {
            delay: recovery_delay,
            reason: RefreshReason::ErrorRetry,
        };
    }

    if signals.states.iter().any(|state| {
        state.snapshot.as_ref().is_some_and(|snapshot| {
            signals
                .now
                .signed_duration_since(snapshot.fetched_at)
                .to_std()
                .is_ok_and(|age| age > signals.base_interval)
        })
    }) {
        return RefreshDecision {
            delay: recovery_delay,
            reason: RefreshReason::StaleData,
        };
    }

    if signals.states.iter().any(|state| {
        state.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.windows.iter().any(|window| {
                window.resets_at.is_some_and(|reset| {
                    reset
                        .signed_duration_since(signals.now)
                        .to_std()
                        .is_ok_and(|until_reset| until_reset <= signals.reset_proximity)
                })
            })
        })
    }) {
        return RefreshDecision {
            delay: recovery_delay,
            reason: RefreshReason::ResetProximity,
        };
    }

    if signals.stable {
        let stable_cap = signals.max_interval.min(MAX_STABLE_INTERVAL);
        return RefreshDecision {
            delay: signals
                .base_interval
                .saturating_add(signals.base_interval)
                .min(stable_cap),
            reason: RefreshReason::StableBackoff,
        };
    }

    RefreshDecision {
        delay: signals.base_interval.min(signals.max_interval),
        reason: RefreshReason::BaseInterval,
    }
}

pub fn retry_delay(consecutive_failures: u32, cap: Duration) -> Duration {
    let multiplier = 1_u64
        .checked_shl(consecutive_failures.min(63))
        .unwrap_or(u64::MAX);
    let seconds = RECOVERY_DELAY.as_secs().saturating_mul(multiplier);
    Duration::from_secs(seconds).min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, ProviderState, UsageWindow,
    };
    use chrono::{TimeZone, Utc};
    use std::time::Duration;

    fn descriptor() -> ProviderDescriptor {
        ProviderDescriptor {
            id: ProviderId::Openrouter,
            display_name: "Fixture",
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.invalid",
            credential_hint: "fixture",
            supports_multiple_accounts: true,
            capabilities: crate::model::provider_capabilities(ProviderId::Openrouter),
        }
    }

    fn state_with_reset(
        fetched_at: chrono::DateTime<Utc>,
        reset: chrono::DateTime<Utc>,
    ) -> ProviderState {
        let mut snapshot = ProviderSnapshot::new(ProviderId::Openrouter, "fixture");
        snapshot.fetched_at = fetched_at;
        snapshot
            .windows
            .push(UsageWindow::new("weekly", "Weekly", 50.0).with_reset(Some(reset)));
        ProviderState::ready(descriptor(), snapshot)
    }

    fn signals(states: &[ProviderState], now: chrono::DateTime<Utc>) -> RefreshSignals<'_> {
        RefreshSignals {
            states,
            base_interval: Duration::from_secs(5 * 60),
            max_interval: Duration::from_secs(30 * 60),
            reset_proximity: Duration::from_secs(10 * 60),
            now,
            stable: false,
        }
    }

    #[test]
    fn reset_within_ten_minutes_refreshes_in_one_minute() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now + chrono::Duration::minutes(9))];

        let decision = next_refresh(signals(&states, now));

        assert_eq!(decision.delay, Duration::from_secs(60));
        assert_eq!(decision.reason, RefreshReason::ResetProximity);
    }

    #[test]
    fn reset_at_the_proximity_boundary_refreshes_in_one_minute() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now + chrono::Duration::minutes(10))];

        let decision = next_refresh(signals(&states, now));

        assert_eq!(decision.delay, Duration::from_secs(60));
        assert_eq!(decision.reason, RefreshReason::ResetProximity);
    }

    #[test]
    fn past_reset_does_not_trigger_reset_proximity() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now - chrono::Duration::seconds(1))];

        let decision = next_refresh(signals(&states, now));

        assert_eq!(decision.delay, Duration::from_secs(5 * 60));
        assert_eq!(decision.reason, RefreshReason::BaseInterval);
    }

    #[test]
    fn stable_far_from_reset_can_double_base_but_not_exceed_cap() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now + chrono::Duration::hours(4))];
        let decide = |base_minutes: u64| {
            next_refresh(RefreshSignals {
                states: &states,
                base_interval: Duration::from_secs(base_minutes * 60),
                max_interval: Duration::from_secs(30 * 60),
                reset_proximity: Duration::from_secs(10 * 60),
                now,
                stable: true,
            })
        };

        assert_eq!(decide(8).delay, Duration::from_secs(16 * 60));
        assert_eq!(decide(8).reason, RefreshReason::StableBackoff);
        assert_eq!(decide(20).delay, Duration::from_secs(30 * 60));
        assert_eq!(decide(20).reason, RefreshReason::StableBackoff);
    }

    #[test]
    fn configured_cap_can_be_lower_than_thirty_minutes() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now + chrono::Duration::hours(4))];

        let decision = next_refresh(RefreshSignals {
            base_interval: Duration::from_secs(8 * 60),
            max_interval: Duration::from_secs(12 * 60),
            stable: true,
            ..signals(&states, now)
        });

        assert_eq!(decision.delay, Duration::from_secs(12 * 60));
        assert_eq!(decision.reason, RefreshReason::StableBackoff);
    }

    #[test]
    fn stable_backoff_never_exceeds_thirty_minutes_even_with_a_higher_configured_cap() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now + chrono::Duration::hours(4))];

        let decision = next_refresh(RefreshSignals {
            base_interval: Duration::from_secs(20 * 60),
            max_interval: Duration::from_secs(60 * 60),
            stable: true,
            ..signals(&states, now)
        });

        assert_eq!(decision.delay, Duration::from_secs(30 * 60));
        assert_eq!(decision.reason, RefreshReason::StableBackoff);
    }

    #[test]
    fn configured_cap_also_limits_reset_recovery() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now + chrono::Duration::minutes(5))];

        let decision = next_refresh(RefreshSignals {
            max_interval: Duration::from_secs(30),
            ..signals(&states, now)
        });

        assert_eq!(decision.delay, Duration::from_secs(30));
        assert_eq!(decision.reason, RefreshReason::ResetProximity);
    }

    #[test]
    fn error_state_retries_in_one_minute() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![ProviderState::failed(descriptor(), "fixture failure")];

        let decision = next_refresh(signals(&states, now));

        assert_eq!(decision.delay, Duration::from_secs(60));
        assert_eq!(decision.reason, RefreshReason::ErrorRetry);
    }

    #[test]
    fn state_older_than_base_interval_retries_in_one_minute() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(
            now - chrono::Duration::minutes(6),
            now + chrono::Duration::hours(4),
        )];

        let decision = next_refresh(signals(&states, now));

        assert_eq!(decision.delay, Duration::from_secs(60));
        assert_eq!(decision.reason, RefreshReason::StaleData);
    }

    #[test]
    fn zero_base_or_cap_selects_manual_no_auto_mode() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now + chrono::Duration::minutes(5))];

        for decision in [
            next_refresh(RefreshSignals {
                base_interval: Duration::ZERO,
                ..signals(&states, now)
            }),
            next_refresh(RefreshSignals {
                max_interval: Duration::ZERO,
                ..signals(&states, now)
            }),
        ] {
            assert_eq!(decision.delay, Duration::ZERO);
            assert_eq!(decision.reason, RefreshReason::Manual);
        }
    }

    #[test]
    fn retry_delay_is_bounded_exponential() {
        let cap = Duration::from_secs(30 * 60);

        assert_eq!(retry_delay(0, cap), Duration::from_secs(60));
        assert_eq!(retry_delay(1, cap), Duration::from_secs(2 * 60));
        assert_eq!(retry_delay(2, cap), Duration::from_secs(4 * 60));
        assert_eq!(retry_delay(8, cap), cap);
    }

    #[test]
    fn retry_delay_respects_small_and_zero_configured_caps_without_overflow() {
        assert_eq!(
            retry_delay(0, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(retry_delay(0, Duration::ZERO), Duration::ZERO);
        assert_eq!(
            retry_delay(u32::MAX, Duration::from_secs(30 * 60)),
            Duration::from_secs(30 * 60)
        );
    }

    #[test]
    fn refresh_reason_precedence_is_manual_error_stale_reset_stable_base() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        struct Case {
            name: &'static str,
            states: Vec<ProviderState>,
            base_interval: Duration,
            stable: bool,
            expected_delay: Duration,
            expected_reason: RefreshReason,
        }

        let cases = vec![
            Case {
                name: "manual beats every automatic signal",
                states: vec![
                    ProviderState::failed(descriptor(), "fixture failure"),
                    state_with_reset(
                        now - chrono::Duration::minutes(6),
                        now + chrono::Duration::minutes(5),
                    ),
                ],
                base_interval: Duration::ZERO,
                stable: true,
                expected_delay: Duration::ZERO,
                expected_reason: RefreshReason::Manual,
            },
            Case {
                name: "error beats stale reset and stable",
                states: vec![
                    ProviderState::failed(descriptor(), "fixture failure"),
                    state_with_reset(
                        now - chrono::Duration::minutes(6),
                        now + chrono::Duration::minutes(5),
                    ),
                ],
                base_interval: Duration::from_secs(5 * 60),
                stable: true,
                expected_delay: Duration::from_secs(60),
                expected_reason: RefreshReason::ErrorRetry,
            },
            Case {
                name: "stale beats reset and stable",
                states: vec![state_with_reset(
                    now - chrono::Duration::minutes(6),
                    now + chrono::Duration::minutes(5),
                )],
                base_interval: Duration::from_secs(5 * 60),
                stable: true,
                expected_delay: Duration::from_secs(60),
                expected_reason: RefreshReason::StaleData,
            },
            Case {
                name: "reset beats stable",
                states: vec![state_with_reset(now, now + chrono::Duration::minutes(5))],
                base_interval: Duration::from_secs(5 * 60),
                stable: true,
                expected_delay: Duration::from_secs(60),
                expected_reason: RefreshReason::ResetProximity,
            },
            Case {
                name: "stable beats base",
                states: vec![state_with_reset(now, now + chrono::Duration::hours(4))],
                base_interval: Duration::from_secs(5 * 60),
                stable: true,
                expected_delay: Duration::from_secs(10 * 60),
                expected_reason: RefreshReason::StableBackoff,
            },
            Case {
                name: "base is the fallback",
                states: vec![state_with_reset(now, now + chrono::Duration::hours(4))],
                base_interval: Duration::from_secs(5 * 60),
                stable: false,
                expected_delay: Duration::from_secs(5 * 60),
                expected_reason: RefreshReason::BaseInterval,
            },
        ];

        for case in cases {
            let decision = next_refresh(RefreshSignals {
                states: &case.states,
                base_interval: case.base_interval,
                max_interval: Duration::from_secs(30 * 60),
                reset_proximity: Duration::from_secs(10 * 60),
                now,
                stable: case.stable,
            });
            assert_eq!(decision.delay, case.expected_delay, "{}", case.name);
            assert_eq!(decision.reason, case.expected_reason, "{}", case.name);
        }
    }

    #[test]
    fn exact_stale_boundary_and_future_success_are_not_stale() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        for fetched_at in [
            now - chrono::Duration::minutes(5),
            now + chrono::Duration::hours(1),
        ] {
            let states = vec![state_with_reset(
                fetched_at,
                now + chrono::Duration::hours(4),
            )];
            let decision = next_refresh(signals(&states, now));
            assert_eq!(decision.delay, Duration::from_secs(5 * 60));
            assert_eq!(decision.reason, RefreshReason::BaseInterval);
        }
    }

    #[test]
    fn reset_at_now_matches_zero_reset_proximity() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let states = vec![state_with_reset(now, now)];
        let decision = next_refresh(RefreshSignals {
            reset_proximity: Duration::ZERO,
            ..signals(&states, now)
        });
        assert_eq!(decision.delay, Duration::from_secs(60));
        assert_eq!(decision.reason, RefreshReason::ResetProximity);
    }

    #[test]
    fn duration_max_stable_base_saturates_at_thirty_minutes() {
        let now = Utc.with_ymd_and_hms(2026, 7, 15, 10, 0, 0).unwrap();
        let decision = next_refresh(RefreshSignals {
            states: &[],
            base_interval: Duration::MAX,
            max_interval: Duration::MAX,
            reset_proximity: Duration::from_secs(10 * 60),
            now,
            stable: true,
        });
        assert_eq!(decision.delay, Duration::from_secs(30 * 60));
        assert_eq!(decision.reason, RefreshReason::StableBackoff);
    }
}
