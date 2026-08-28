use crate::model::ProviderId;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MenuBarDisplayMode {
    #[default]
    Icon,
    Percentage,
    IconAndPercentage,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalePreference {
    #[default]
    System,
    En,
    ZhHans,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MenuBarConfig {
    pub display_mode: MenuBarDisplayMode,
    pub highest_usage: bool,
    pub pinned_provider: Option<ProviderId>,
    pub pinned_account_id: Option<String>,
    pub show_percentage: bool,
}

impl Default for MenuBarConfig {
    fn default() -> Self {
        Self {
            display_mode: MenuBarDisplayMode::Icon,
            highest_usage: true,
            pinned_provider: None,
            pinned_account_id: None,
            show_percentage: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HistoryConfig {
    pub enabled: bool,
    pub retention_days: u32,
    pub cost_scan_enabled: bool,
    pub codex_path: Option<PathBuf>,
    pub claude_path: Option<PathBuf>,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 90,
            cost_scan_enabled: true,
            codex_path: None,
            claude_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NotificationConfig {
    pub enabled: bool,
    pub thresholds: Vec<f64>,
    pub provider_thresholds: HashMap<ProviderId, Vec<f64>>,
    pub session_windows: bool,
    pub weekly_windows: bool,
    pub monthly_windows: bool,
    pub predictive_pace: bool,
    pub reset_credit: bool,
    pub quiet_start: Option<String>,
    pub quiet_end: Option<String>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            thresholds: vec![75.0, 90.0],
            provider_thresholds: HashMap::new(),
            session_windows: true,
            weekly_windows: true,
            monthly_windows: true,
            predictive_pace: false,
            reset_credit: false,
            quiet_start: None,
            quiet_end: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StatusPollingConfig {
    pub enabled: bool,
    pub interval_minutes: u64,
}

impl Default for StatusPollingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 10,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ShortcutConfig {
    pub toggle_window: Option<String>,
    pub refresh: Option<String>,
    pub next_provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AdaptiveRefreshConfig {
    pub enabled: bool,
    pub reset_proximity_minutes: u64,
    pub stale_after_seconds: u64,
    pub max_interval_minutes: u64,
    pub provider_timeout_seconds: u64,
}

impl Default for AdaptiveRefreshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reset_proximity_minutes: 10,
            stale_after_seconds: 60,
            max_interval_minutes: 30,
            provider_timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WidgetSnapshotConfig {
    pub enabled: bool,
    pub path: Option<PathBuf>,
}

impl Default for WidgetSnapshotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SecurityConfig {
    pub persist_credentials: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            persist_credentials: true,
        }
    }
}
