//! Tray metric selection.
//!
//! A pure function over the current provider states plus the menu-bar config that decides which
//! provider/account drives the tray icon and tooltip. Rendering the icon image is a separate
//! OS-level concern; this module only chooses the metric so it can be unit-tested without a GUI.

use crate::{
    config_sections::MenuBarConfig,
    model::{ProviderId, ProviderState, ProviderStatus},
};

/// The provider/account and percentage that should drive the tray icon and tooltip.
#[derive(Debug, Clone, PartialEq)]
pub struct IconMetric {
    pub provider: ProviderId,
    pub provider_name: String,
    pub account_id: String,
    pub account_label: Option<String>,
    pub used_percent: f64,
}

impl IconMetric {
    /// A compact tooltip such as `Claude · Work · 82%` (the account segment is omitted when there is
    /// no distinct label).
    pub fn tooltip(&self) -> String {
        match &self.account_label {
            Some(label) => format!(
                "{} · {} · {:.0}%",
                self.provider_name, label, self.used_percent
            ),
            None => format!("{} · {:.0}%", self.provider_name, self.used_percent),
        }
    }
}

/// Choose the tray metric: the pinned provider/account when it is ready, otherwise the highest used
/// percentage among ready states (or, when highest-usage selection is off, the first ready state in
/// declared order). Returns `None` when no ready state carries a usage window.
pub fn select_tray_metric(
    states: &[ProviderState],
    menu_bar: &MenuBarConfig,
) -> Option<IconMetric> {
    // A ready state contributes only if it has at least one usage window; the metric is that state's
    // most-used window.
    let candidates: Vec<(&ProviderState, f64)> = states
        .iter()
        .filter(|state| state.status == ProviderStatus::Ready)
        .filter_map(|state| max_window_percent(state).map(|percent| (state, percent)))
        .collect();

    // A valid pin wins outright.
    if let Some(pinned) = menu_bar.pinned_provider {
        if let Some((state, percent)) = candidates.iter().find(|(state, _)| {
            state.descriptor.id == pinned
                && menu_bar
                    .pinned_account_id
                    .as_ref()
                    .is_none_or(|account| &state.account_id == account)
        }) {
            return Some(metric(state, *percent));
        }
    }

    let chosen = if menu_bar.highest_usage {
        candidates
            .iter()
            .max_by(|(_, left), (_, right)| left.total_cmp(right))
    } else {
        candidates.first()
    };
    chosen.map(|(state, percent)| metric(state, *percent))
}

fn max_window_percent(state: &ProviderState) -> Option<f64> {
    let snapshot = state.snapshot.as_ref()?;
    snapshot
        .windows
        .iter()
        .map(|window| window.used_percent)
        .fold(None, |accumulator: Option<f64>, percent| {
            Some(accumulator.map_or(percent, |current| current.max(percent)))
        })
}

fn metric(state: &ProviderState, used_percent: f64) -> IconMetric {
    IconMetric {
        provider: state.descriptor.id,
        provider_name: state.descriptor.display_name.to_owned(),
        account_id: state.account_id.clone(),
        account_label: state.account_label.clone(),
        used_percent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthKind, ProviderDescriptor, ProviderSnapshot, UsageWindow};

    fn descriptor(id: ProviderId, name: &'static str) -> ProviderDescriptor {
        ProviderDescriptor {
            id,
            display_name: name,
            auth_kind: AuthKind::ApiKey,
            color: "#000000",
            dashboard_url: "https://example.com",
            credential_hint: "",
            supports_multiple_accounts: true,
            capabilities: crate::model::provider_capabilities(id),
        }
    }

    fn ready(id: ProviderId, name: &'static str, account: &str, percents: &[f64]) -> ProviderState {
        let mut snapshot = ProviderSnapshot::new(id, "test");
        for (index, percent) in percents.iter().enumerate() {
            snapshot
                .windows
                .push(UsageWindow::new(format!("w{index}"), "Window", *percent));
        }
        ProviderState::ready(descriptor(id, name), snapshot)
            .with_account(account.to_owned(), Some(account.to_owned()))
    }

    fn menu_bar() -> MenuBarConfig {
        MenuBarConfig::default()
    }

    #[test]
    fn highest_usage_selects_the_busiest_ready_state() {
        let states = vec![
            ready(ProviderId::Claude, "Claude", "acc_a", &[30.0, 40.0]),
            ready(ProviderId::Openrouter, "OpenRouter", "acc_b", &[88.0]),
        ];
        let metric = select_tray_metric(&states, &menu_bar()).expect("metric");
        assert_eq!(metric.provider, ProviderId::Openrouter);
        assert_eq!(metric.used_percent, 88.0);
        assert_eq!(metric.tooltip(), "OpenRouter · acc_b · 88%");
    }

    #[test]
    fn a_valid_pin_overrides_highest_usage() {
        let mut config = menu_bar();
        config.pinned_provider = Some(ProviderId::Claude);
        let states = vec![
            ready(ProviderId::Claude, "Claude", "acc_a", &[30.0]),
            ready(ProviderId::Openrouter, "OpenRouter", "acc_b", &[88.0]),
        ];
        let metric = select_tray_metric(&states, &config).expect("metric");
        assert_eq!(metric.provider, ProviderId::Claude);
        assert_eq!(metric.used_percent, 30.0);
    }

    #[test]
    fn an_unmatched_pin_falls_back_to_highest_usage() {
        let mut config = menu_bar();
        config.pinned_provider = Some(ProviderId::Cursor); // not present / not ready
        let states = vec![ready(
            ProviderId::Openrouter,
            "OpenRouter",
            "acc_b",
            &[88.0],
        )];
        let metric = select_tray_metric(&states, &config).expect("metric");
        assert_eq!(metric.provider, ProviderId::Openrouter);
    }

    #[test]
    fn pinned_account_id_disambiguates_between_accounts() {
        let mut config = menu_bar();
        config.pinned_provider = Some(ProviderId::Openrouter);
        config.pinned_account_id = Some("acc_b".to_owned());
        let states = vec![
            ready(ProviderId::Openrouter, "OpenRouter", "acc_a", &[10.0]),
            ready(ProviderId::Openrouter, "OpenRouter", "acc_b", &[20.0]),
        ];
        let metric = select_tray_metric(&states, &config).expect("metric");
        assert_eq!(metric.account_id, "acc_b");
        assert_eq!(metric.used_percent, 20.0);
    }

    #[test]
    fn no_ready_usage_yields_no_metric() {
        let disabled = ProviderState::disabled(descriptor(ProviderId::Claude, "Claude"));
        assert_eq!(select_tray_metric(&[disabled], &menu_bar()), None);
        // Ready but window-less states also produce nothing to show.
        let empty = ProviderState::ready(
            descriptor(ProviderId::Claude, "Claude"),
            ProviderSnapshot::new(ProviderId::Claude, "test"),
        );
        assert_eq!(select_tray_metric(&[empty], &menu_bar()), None);
    }
}
