use chrono::DateTime;
use codexbar_engine::{LocalePreference, ProviderId, ProviderState, Warning, WarningKind, redact};
use tauri::{AppHandle, Runtime};
use tauri_plugin_notification::NotificationExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationPayload {
    pub title: String,
    pub body: String,
}

pub fn payload_for(
    warning: &Warning,
    states: &[ProviderState],
    locale: &LocalePreference,
) -> Option<NotificationPayload> {
    if warning.suppress_toast {
        return None;
    }
    let chinese = matches!(locale, LocalePreference::ZhHans);
    let provider = provider_name(warning.provider, states);
    let account = states
        .iter()
        .find(|state| {
            state.descriptor.id == warning.provider && state.account_id == warning.account_id
        })
        .and_then(|state| state.account_label.as_deref())
        .and_then(safe_context);
    let window = safe_context(&warning.window_title).unwrap_or_else(|| {
        if chinese {
            "用量".to_owned()
        } else {
            "Usage".to_owned()
        }
    });
    let used = warning.used_percent.round().clamp(0.0, 100.0) as u8;
    let threshold = warning.threshold.round().clamp(0.0, 100.0) as u8;
    let title = account.map_or_else(
        || format!("CodexBar · {provider}"),
        |account| format!("CodexBar · {provider} · {account}"),
    );
    let mut body = match (chinese, warning.kind) {
        (true, WarningKind::Threshold) => {
            format!("{window} 已使用 {used}%，达到 {threshold}% 警告阈值。")
        }
        (true, WarningKind::Pace) => {
            format!("{window} 按当前速度将在重置前达到 100%（当前 {used}%）。")
        }
        (false, WarningKind::Threshold) => {
            format!("{window} used {used}%, reaching the {threshold}% warning threshold.")
        }
        (false, WarningKind::Pace) => {
            format!("{window} is projected to reach 100% before reset (currently {used}%).")
        }
    };
    if let Some(reset) = reset_phrase(warning.reset_boundary.as_deref(), chinese) {
        body.push(' ');
        body.push_str(&reset);
    }
    Some(NotificationPayload { title, body })
}

pub fn show_warning<R: Runtime>(
    app: &AppHandle<R>,
    warning: &Warning,
    states: &[ProviderState],
    locale: &LocalePreference,
) {
    let Some(payload) = payload_for(warning, states, locale) else {
        return;
    };
    if let Err(error) = app
        .notification()
        .builder()
        .title(payload.title)
        .body(payload.body)
        .show()
    {
        eprintln!(
            "notification delivery failed: {}",
            redact(&error.to_string())
        );
    }
}

/// Display name for a notification title. Copilot keeps its explicit "GitHub Copilot" label; every
/// other provider draws from the engine descriptor carried on `states`, so adding a provider never
/// needs a second edit here. Falls back to the lowercase id if no state is present for the provider.
fn provider_name(provider: ProviderId, states: &[ProviderState]) -> String {
    if provider == ProviderId::Copilot {
        return "GitHub Copilot".to_owned();
    }
    states
        .iter()
        .find(|state| state.descriptor.id == provider)
        .map_or_else(
            || provider.to_string(),
            |state| state.descriptor.display_name.to_owned(),
        )
}

fn safe_context(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 64 {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    let sensitive = [
        "authorization",
        "api_key",
        "apikey",
        "cookie",
        "password",
        "token",
        "sessionid",
        "config.json",
        "gho_",
        "ghp_",
        "sk-",
        "eyj",
    ];
    if value.contains(['@', '\\', '/']) || sensitive.iter().any(|needle| lower.contains(needle)) {
        return None;
    }
    Some(value.to_owned())
}

fn reset_phrase(boundary: Option<&str>, chinese: bool) -> Option<String> {
    let reset = DateTime::parse_from_rfc3339(boundary?).ok()?;
    Some(if chinese {
        format!("将于 {} 重置。", reset.format("%H:%M"))
    } else {
        format!("Resets at {}.", reset.format("%H:%M"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use codexbar_engine::{
        AuthKind, LocalePreference, ProviderDescriptor, ProviderId, ProviderState, ProviderStatus,
        Warning, WarningKind,
    };

    #[test]
    fn chinese_threshold_payload_is_exact() {
        let warning = warning(WarningKind::Threshold);
        let states = vec![state(None)];

        let payload = payload_for(&warning, &states, &LocalePreference::ZhHans).unwrap();

        assert_eq!(payload.title, "CodexBar · Claude");
        assert_eq!(payload.body, "Session 已使用 82%，达到 75% 警告阈值。");
    }

    #[test]
    fn english_pace_payload_includes_only_the_matching_account_label() {
        let warning = warning(WarningKind::Pace);
        let states = vec![
            state(Some("Work")),
            ProviderState {
                descriptor: descriptor(ProviderId::Codex, "Codex"),
                account_id: "other".to_owned(),
                account_label: Some("Wrong Account".to_owned()),
                status: ProviderStatus::Error,
                snapshot: None,
                error: Some("secret".to_owned()),
                fetch_attempts: Vec::new(),
                service_status: None,
            },
        ];

        let payload = payload_for(&warning, &states, &LocalePreference::En).unwrap();

        assert_eq!(payload.title, "CodexBar · Claude · Work");
        assert_eq!(
            payload.body,
            "Session is projected to reach 100% before reset (currently 82%)."
        );
        assert!(!payload.title.contains("Wrong Account"));
    }

    #[test]
    fn sensitive_user_text_never_reaches_the_payload() {
        let mut warning = warning(WarningKind::Threshold);
        warning.window_title = "Cookie gho_secret eyJhbGciOiJIUzI1NiJ9".to_owned();
        let states = vec![state(Some(
            "alice@example.com C:\\Users\\alice\\config.json api_key=sk-secret",
        ))];

        let payload = payload_for(&warning, &states, &LocalePreference::En).unwrap();
        let text = format!("{} {}", payload.title, payload.body).to_ascii_lowercase();

        for secret in [
            "gho_secret",
            "eyjhbgcioijiuzi1nij9",
            "cookie",
            "alice@example.com",
            "c:\\users",
            "config.json",
            "api_key",
            "sk-secret",
        ] {
            assert!(!text.contains(secret), "payload leaked {secret}: {text}");
        }
    }

    #[test]
    fn quiet_hours_suppress_the_native_payload() {
        let mut warning = warning(WarningKind::Threshold);
        warning.suppress_toast = true;

        assert_eq!(
            payload_for(&warning, &[state(None)], &LocalePreference::En),
            None
        );
    }

    #[test]
    fn reset_time_is_localized_and_malformed_boundaries_are_omitted() {
        let mut with_reset = warning(WarningKind::Threshold);
        with_reset.reset_boundary = Some("2026-07-16T18:30:00+08:00".to_owned());
        let payload = payload_for(&with_reset, &[state(None)], &LocalePreference::En).unwrap();
        assert!(payload.body.ends_with("Resets at 18:30."));

        with_reset.reset_boundary = Some("not-a-date".to_owned());
        let payload = payload_for(&with_reset, &[state(None)], &LocalePreference::En).unwrap();
        assert_eq!(
            payload.body,
            "Session used 82%, reaching the 75% warning threshold."
        );
    }

    fn warning(kind: WarningKind) -> Warning {
        Warning {
            provider: ProviderId::Claude,
            account_id: "acc_work".to_owned(),
            window_id: "session".to_owned(),
            window_title: "Session".to_owned(),
            kind,
            threshold: 75.0,
            used_percent: 82.4,
            reset_boundary: None,
            suppress_toast: false,
        }
    }

    fn state(label: Option<&str>) -> ProviderState {
        ProviderState {
            descriptor: descriptor(ProviderId::Claude, "Claude"),
            account_id: "acc_work".to_owned(),
            account_label: label.map(str::to_owned),
            status: ProviderStatus::Ready,
            snapshot: None,
            error: None,
            fetch_attempts: Vec::new(),
            service_status: None,
        }
    }

    fn descriptor(id: ProviderId, display_name: &'static str) -> ProviderDescriptor {
        ProviderDescriptor {
            id,
            display_name,
            auth_kind: AuthKind::CliOAuth,
            color: "#000000",
            dashboard_url: "https://example.test",
            credential_hint: "test",
            supports_multiple_accounts: false,
            capabilities: codexbar_engine::provider_capabilities(id),
        }
    }
}
