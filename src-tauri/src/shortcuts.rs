use codexbar_engine::ShortcutConfig;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
};
use tauri::{AppHandle, Emitter, Manager, Runtime, plugin::TauriPlugin};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};
use thiserror::Error;

use super::{AppState, refresh_and_publish, refresh_if_stale};
use crate::window_activation::show_main_window;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortcutAction {
    ToggleWindow,
    Refresh,
    NextProvider,
}

#[derive(Debug, Error)]
pub enum ShortcutConfigError {
    #[error("invalid {field} shortcut '{value}': {message}")]
    Invalid {
        field: &'static str,
        value: String,
        message: String,
    },
    #[error("shortcut '{0}' is assigned more than once")]
    Duplicate(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementPlan {
    pub additions: Vec<Shortcut>,
    pub removals: Vec<Shortcut>,
}

#[derive(Default)]
pub struct ShortcutRegistry {
    actions: Arc<RwLock<HashMap<Shortcut, ShortcutAction>>>,
    registered: Mutex<HashSet<Shortcut>>,
}

impl ShortcutRegistry {
    pub fn replace_config<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        config: &ShortcutConfig,
    ) -> Result<HashMap<Shortcut, ShortcutAction>, String> {
        let actions = parse_config(config).map_err(|error| error.to_string())?;
        self.replace_actions(app, actions)
    }

    pub fn replace_actions<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        new_actions: HashMap<Shortcut, ShortcutAction>,
    ) -> Result<HashMap<Shortcut, ShortcutAction>, String> {
        let old_actions = self
            .actions
            .read()
            .map_err(|_| "shortcut action map is unavailable".to_owned())?
            .clone();
        let mut registered = self
            .registered
            .lock()
            .map_err(|_| "shortcut registry is unavailable".to_owned())?;
        let new_set = new_actions.keys().copied().collect::<HashSet<_>>();
        let plan = replacement_plan(&registered, &new_set);
        let manager = app.global_shortcut();

        register_additions_transactionally(
            &plan.additions,
            |shortcut| {
                manager
                    .register(*shortcut)
                    .map_err(|error| error.to_string())
            },
            |shortcut| {
                let _ = manager.unregister(*shortcut);
            },
        )?;

        let mut removed = Vec::new();
        for shortcut in &plan.removals {
            if let Err(error) = manager.unregister(*shortcut) {
                for removed_shortcut in &removed {
                    let _ = manager.register(*removed_shortcut);
                }
                for added_shortcut in &plan.additions {
                    let _ = manager.unregister(*added_shortcut);
                }
                return Err(error.to_string());
            }
            removed.push(*shortcut);
        }

        *self
            .actions
            .write()
            .map_err(|_| "shortcut action map is unavailable".to_owned())? = new_actions;
        *registered = new_set;
        Ok(old_actions)
    }

    fn action_for(&self, shortcut: &Shortcut) -> Option<ShortcutAction> {
        self.actions.read().ok()?.get(shortcut).copied()
    }
}

pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri_plugin_global_shortcut::Builder::new()
        .with_handler(|app, shortcut, event| {
            if event.state != ShortcutState::Pressed {
                return;
            }
            let Some(registry) = app.try_state::<ShortcutRegistry>() else {
                return;
            };
            if let Some(action) = registry.action_for(shortcut) {
                dispatch(app, action);
            }
        })
        .build()
}

pub fn parse_config(
    config: &ShortcutConfig,
) -> Result<HashMap<Shortcut, ShortcutAction>, ShortcutConfigError> {
    let values = [
        (
            "toggle window",
            config.toggle_window.as_deref(),
            ShortcutAction::ToggleWindow,
        ),
        (
            "refresh",
            config.refresh.as_deref(),
            ShortcutAction::Refresh,
        ),
        (
            "next provider",
            config.next_provider.as_deref(),
            ShortcutAction::NextProvider,
        ),
    ];
    let mut parsed = HashMap::new();
    for (field, value, action) in values {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            continue;
        };
        let shortcut = value
            .parse::<Shortcut>()
            .map_err(|error| ShortcutConfigError::Invalid {
                field,
                value: value.to_owned(),
                message: error.to_string(),
            })?;
        if parsed.insert(shortcut, action).is_some() {
            return Err(ShortcutConfigError::Duplicate(shortcut.to_string()));
        }
    }
    Ok(parsed)
}

pub fn replacement_plan(old: &HashSet<Shortcut>, new: &HashSet<Shortcut>) -> ReplacementPlan {
    let mut additions = new.difference(old).copied().collect::<Vec<_>>();
    let mut removals = old.difference(new).copied().collect::<Vec<_>>();
    additions.sort_by_key(ToString::to_string);
    removals.sort_by_key(ToString::to_string);
    ReplacementPlan {
        additions,
        removals,
    }
}

fn register_additions_transactionally<E>(
    additions: &[Shortcut],
    mut register: impl FnMut(&Shortcut) -> Result<(), E>,
    mut unregister: impl FnMut(&Shortcut),
) -> Result<(), E> {
    let mut successful = Vec::new();
    for shortcut in additions {
        if let Err(error) = register(shortcut) {
            for registered in successful.iter().rev() {
                unregister(registered);
            }
            return Err(error);
        }
        successful.push(*shortcut);
    }
    Ok(())
}

fn dispatch<R: Runtime>(app: &AppHandle<R>, action: ShortcutAction) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        match action {
            ShortcutAction::ToggleWindow => {
                let visible = app
                    .get_webview_window("main")
                    .and_then(|window| window.is_visible().ok())
                    .unwrap_or(false);
                if visible {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                } else {
                    show_main_window(&app);
                    let state = app.state::<AppState>();
                    refresh_if_stale(&app, &state).await;
                }
            }
            ShortcutAction::Refresh => {
                let state = app.state::<AppState>();
                let _ = refresh_and_publish(&app, &state).await;
            }
            ShortcutAction::NextProvider => {
                show_main_window(&app);
                let _ = app.emit("next-provider", ());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use codexbar_engine::ShortcutConfig;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn empty_config_has_no_shortcuts_and_duplicates_are_rejected() {
        assert_eq!(parse_config(&ShortcutConfig::default()).unwrap().len(), 0);
        assert!(
            parse_config(&ShortcutConfig {
                toggle_window: Some("Ctrl+Shift+U".into()),
                refresh: Some("Ctrl+Shift+U".into()),
                next_provider: None,
            })
            .unwrap_err()
            .to_string()
            .contains("assigned more than once")
        );
    }

    #[test]
    fn swapping_actions_with_the_same_shortcut_set_only_updates_the_map() {
        let first = shortcut("Ctrl+Shift+U");
        let second = shortcut("Ctrl+Shift+R");
        let old_actions = HashMap::from([
            (first, ShortcutAction::ToggleWindow),
            (second, ShortcutAction::Refresh),
        ]);
        let new_actions = HashMap::from([
            (first, ShortcutAction::Refresh),
            (second, ShortcutAction::ToggleWindow),
        ]);

        let plan = replacement_plan(
            &old_actions.keys().copied().collect::<HashSet<_>>(),
            &new_actions.keys().copied().collect::<HashSet<_>>(),
        );

        assert!(plan.additions.is_empty());
        assert!(plan.removals.is_empty());
        assert_ne!(old_actions, new_actions);
    }

    #[test]
    fn failed_registration_rolls_back_exactly_the_successful_additions() {
        let additions = vec![
            shortcut("Ctrl+Shift+U"),
            shortcut("Ctrl+Shift+R"),
            shortcut("Ctrl+Shift+P"),
        ];
        let mut attempts = 0;
        let mut rolled_back = Vec::new();

        let result = register_additions_transactionally(
            &additions,
            |_| {
                attempts += 1;
                if attempts == 3 {
                    Err("third registration failed")
                } else {
                    Ok(())
                }
            },
            |shortcut| rolled_back.push(*shortcut),
        );

        assert_eq!(result.unwrap_err(), "third registration failed");
        assert_eq!(rolled_back, vec![additions[1], additions[0]]);
    }

    fn shortcut(value: &str) -> Shortcut {
        value.parse().unwrap()
    }
}
