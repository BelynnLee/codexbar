use tauri::AppHandle;
use tauri_plugin_autostart::ManagerExt;

const READ_BACK_MISMATCH: &str = "Windows startup registration did not match the requested state";

pub(crate) fn change_and_verify<E: ToString>(
    enabled: bool,
    enable: impl FnOnce() -> Result<(), E>,
    disable: impl FnOnce() -> Result<(), E>,
    verify: impl FnOnce() -> Result<bool, E>,
) -> Result<bool, String> {
    if enabled { enable() } else { disable() }.map_err(|error| error.to_string())?;

    let actual = verify().map_err(|error| error.to_string())?;
    if actual != enabled {
        return Err(READ_BACK_MISMATCH.to_owned());
    }
    Ok(actual)
}

#[tauri::command]
pub(crate) fn get_launch_at_startup(app: AppHandle) -> Result<bool, String> {
    app.autolaunch()
        .is_enabled()
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) fn set_launch_at_startup(app: AppHandle, enabled: bool) -> Result<bool, String> {
    let manager = app.autolaunch();
    change_and_verify(
        enabled,
        || manager.enable(),
        || manager.disable(),
        || manager.is_enabled(),
    )
}

#[cfg(test)]
mod tests {
    use super::change_and_verify;
    use std::cell::Cell;

    #[test]
    fn enabling_is_verified_against_the_operating_system_state() {
        let enabled = Cell::new(false);
        let result = change_and_verify(
            true,
            || {
                enabled.set(true);
                Ok::<_, String>(())
            },
            || Ok::<_, String>(()),
            || Ok::<_, String>(enabled.get()),
        );
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn disabling_is_verified_against_the_operating_system_state() {
        let enabled = Cell::new(true);
        let result = change_and_verify(
            false,
            || Ok::<_, String>(()),
            || {
                enabled.set(false);
                Ok::<_, String>(())
            },
            || Ok::<_, String>(enabled.get()),
        );
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn mismatched_read_back_is_an_error() {
        let result = change_and_verify(
            true,
            || Ok::<_, String>(()),
            || Ok::<_, String>(()),
            || Ok::<_, String>(false),
        );
        assert_eq!(
            result,
            Err("Windows startup registration did not match the requested state".to_owned())
        );
    }
}
