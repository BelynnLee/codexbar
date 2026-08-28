use codexbar_engine::{
    AppConfig, ConfigStore, GitHubDeviceFlow, PollOutcome, ProviderAccount, ProviderId,
};
use serde::Serialize;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tauri_plugin_opener::OpenerExt;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopilotDeviceCodeEvent {
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
}

pub async fn connect(app: &AppHandle, store: &ConfigStore) -> Result<(), String> {
    let flow = GitHubDeviceFlow::github_default();
    let device = flow
        .request_code()
        .await
        .map_err(|error| error.to_string())?;
    app.emit(
        "copilot-device-code",
        CopilotDeviceCodeEvent {
            user_code: device.user_code.clone(),
            verification_uri: device.verification_uri.clone(),
            expires_in: device.expires_in,
        },
    )
    .map_err(|error| error.to_string())?;

    let authorization_url = device
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&device.verification_uri);
    app.opener()
        .open_url(authorization_url, None::<&str>)
        .map_err(|error| error.to_string())?;

    let deadline = Instant::now() + Duration::from_secs(device.expires_in);
    let mut interval = device.interval.max(1);
    let access_token = loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        if Instant::now() >= deadline {
            return Err("GitHub device authorization expired".to_owned());
        }
        match flow
            .poll_once(&device.device_code)
            .await
            .map_err(|error| error.to_string())?
        {
            PollOutcome::Pending => {}
            PollOutcome::SlowDown => interval = interval.saturating_add(5),
            PollOutcome::Authorized { access_token } => break access_token,
        }
    };

    let identity = flow
        .identity(&access_token)
        .await
        .map_err(|error| error.to_string())?;
    let mut config = store.load().map_err(|error| error.to_string())?;
    apply_authorized_account(&mut config, access_token, identity.login);
    store.save(&config).map_err(|error| error.to_string())
}

fn apply_authorized_account(config: &mut AppConfig, token: String, login: String) {
    let settings = config.providers.entry(ProviderId::Copilot).or_default();
    settings.enabled = true;
    let mut account = settings
        .accounts
        .first()
        .cloned()
        .unwrap_or_else(ProviderAccount::default);
    account.label = Some(login);
    account.enabled = true;
    account.api_key = Some(token);
    account.cookie_header = None;
    account.workspace_id = None;
    if !account.id.is_empty() {
        settings.active_account_id = Some(account.id.clone());
    }
    settings.accounts.clear();
    settings.accounts.push(account);
}

#[cfg(test)]
mod tests {
    use super::*;
    use codexbar_engine::{AppConfig, ProviderAccount, ProviderId};

    #[test]
    fn authorized_account_is_siloed_and_relogin_preserves_its_id() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_codex".to_owned(),
                api_key: Some("codex-secret".to_owned()),
                ..ProviderAccount::default()
            });
        config
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .accounts
            .push(ProviderAccount {
                id: "acc_claude".to_owned(),
                api_key: Some("claude-secret".to_owned()),
                ..ProviderAccount::default()
            });
        let copilot = config.providers.get_mut(&ProviderId::Copilot).unwrap();
        copilot.accounts = vec![
            ProviderAccount {
                id: "acc_copilot".to_owned(),
                label: Some("old-login".to_owned()),
                api_key: Some("old-token".to_owned()),
                ..ProviderAccount::default()
            },
            ProviderAccount {
                id: "acc_stale".to_owned(),
                api_key: Some("stale-token".to_owned()),
                ..ProviderAccount::default()
            },
        ];

        apply_authorized_account(&mut config, "new-token".to_owned(), "octocat".to_owned());

        let copilot = config.provider(ProviderId::Copilot);
        assert!(copilot.enabled);
        assert_eq!(copilot.accounts.len(), 1);
        assert_eq!(copilot.accounts[0].id, "acc_copilot");
        assert_eq!(copilot.accounts[0].label.as_deref(), Some("octocat"));
        assert_eq!(copilot.accounts[0].api_key.as_deref(), Some("new-token"));
        assert!(copilot.accounts[0].enabled);
        assert_eq!(
            config.provider(ProviderId::Codex).accounts[0]
                .api_key
                .as_deref(),
            Some("codex-secret")
        );
        assert_eq!(
            config.provider(ProviderId::Claude).accounts[0]
                .api_key
                .as_deref(),
            Some("claude-secret")
        );
    }

    #[test]
    fn first_authorization_creates_one_enabled_copilot_account() {
        let mut config = AppConfig::default();

        apply_authorized_account(&mut config, "token".to_owned(), "hubot".to_owned());

        let copilot = config.provider(ProviderId::Copilot);
        assert!(copilot.enabled);
        assert_eq!(copilot.accounts.len(), 1);
        assert_eq!(copilot.accounts[0].label.as_deref(), Some("hubot"));
        assert_eq!(copilot.accounts[0].api_key.as_deref(), Some("token"));
        assert!(copilot.accounts[0].enabled);
    }
}
