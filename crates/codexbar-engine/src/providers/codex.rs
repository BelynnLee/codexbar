use crate::{
    accounts::ProviderCredentialVault,
    auth::{
        credentials::{CodexCredentials, is_safe_managed_account_id},
        dpapi::{DpapiCodec, SecretCodec},
    },
    config::ProviderAccount,
    model::{
        AuthKind, ProviderDescriptor, ProviderId, ProviderSnapshot, ProviderSourceMode,
        ProviderStrategyDescriptor, ProviderStrategyKind, SummaryItem, UsageWindow,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::DateTime;
use reqwest::{Response, StatusCode};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct CodexProvider;

static DPAPI_CODEC: DpapiCodec = DpapiCodec;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Codex,
    display_name: "Codex",
    auth_kind: AuthKind::CliOAuth,
    color: "#10a37f",
    dashboard_url: "https://chatgpt.com/codex/settings/usage",
    credential_hint: "Uses %USERPROFILE%\\.codex\\auth.json (or %CODEX_HOME%\\auth.json).",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Codex),
};

#[async_trait]
impl Provider for CodexProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let mut source = CredentialSource::load(context, account).await?;
        let mut credentials = source.credentials().clone();
        let mut response = request_usage(context, &credentials).await?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            credentials = source.force_refresh(context.client).await?;
            response = request_usage(context, &credentials).await?;
        }
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(ProviderError::Unauthorized(
                "Codex OAuth token was rejected. Run `codex login`.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Codex",
                status: response.status().as_u16(),
            });
        }
        let payload: Value = response.json().await?;
        map_usage(&payload, &credentials)
    }

    fn strategies(&self, source_mode: ProviderSourceMode) -> Vec<ProviderStrategyDescriptor> {
        const OAUTH: ProviderStrategyDescriptor = ProviderStrategyDescriptor {
            id: "oauth",
            kind: ProviderStrategyKind::Oauth,
            source_mode: ProviderSourceMode::Oauth,
        };
        if matches!(
            source_mode,
            ProviderSourceMode::Auto | ProviderSourceMode::Oauth
        ) {
            vec![OAUTH]
        } else {
            Vec::new()
        }
    }
}

enum CredentialSource {
    Default(CodexCredentials),
    Vault {
        config_dir: PathBuf,
        account_id: String,
        identity: crate::ProviderAccountIdentity,
        bundle: crate::ProviderCredentialBundle,
        auth_json: Vec<u8>,
        credentials: Box<CodexCredentials>,
    },
}

impl CredentialSource {
    async fn load(
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<Self, ProviderError> {
        if account.id.trim().is_empty() {
            return Ok(Self::Default(
                CodexCredentials::load_and_refresh(context.client).await?,
            ));
        }
        if !is_safe_managed_account_id(&account.id) {
            return Err(ProviderError::Credential(
                "Managed credential account id or provider was rejected".into(),
            ));
        }
        let config_dir = context.config_dir.ok_or_else(|| {
            ProviderError::MissingCredentials(
                "The selected Codex account has no encrypted credential. Import it and retry."
                    .into(),
            )
        })?;
        let mut source = Self::load_named(config_dir, &account.id, &DPAPI_CODEC)?;
        if source.credentials().needs_refresh() {
            let refreshed = source.credentials().refresh_tokens(context.client).await?;
            let updated = refreshed.updated_auth_json(source.artifact()?)?;
            source.persist_refreshed(refreshed, updated, &DPAPI_CODEC)?;
        }
        Ok(source)
    }

    fn load_named(
        config_dir: &Path,
        account_id: &str,
        codec: &dyn SecretCodec,
    ) -> Result<Self, ProviderError> {
        if !is_safe_managed_account_id(account_id) {
            return Err(ProviderError::Credential(
                "Managed credential account id or provider was rejected".into(),
            ));
        }
        let vault = ProviderCredentialVault::new(config_dir, codec);
        let loaded = vault.load(ProviderId::Codex, account_id).map_err(|_| {
            ProviderError::MissingCredentials(
                "The selected Codex account has no usable encrypted credential. Import it and retry."
                    .into(),
            )
        })?;
        if loaded.credentials.artifact_format.as_deref() != Some("codex-auth-json") {
            return Err(ProviderError::Credential(
                "The selected Codex account credential artifact is invalid".into(),
            ));
        }
        let auth_json = loaded.credentials.artifact.clone().ok_or_else(|| {
            ProviderError::Credential(
                "The selected Codex account credential artifact is invalid".into(),
            )
        })?;
        let credentials = CodexCredentials::parse(&auth_json, PathBuf::from("auth.json"))?;
        let parsed_identity = credentials.provider_identity()?;
        if !parsed_identity.matches_stable_without_namespace_conflicts(&loaded.identity) {
            return Err(ProviderError::Credential(
                "The selected Codex account identity does not match its credential artifact".into(),
            ));
        }
        Ok(Self::Vault {
            config_dir: config_dir.to_path_buf(),
            account_id: account_id.to_owned(),
            identity: loaded.identity,
            bundle: loaded.credentials,
            auth_json,
            credentials: Box::new(credentials),
        })
    }

    fn credentials(&self) -> &CodexCredentials {
        match self {
            Self::Default(credentials) => credentials,
            Self::Vault { credentials, .. } => credentials.as_ref(),
        }
    }

    fn artifact(&self) -> Result<&[u8], ProviderError> {
        match self {
            Self::Vault { auth_json, .. } => Ok(auth_json),
            Self::Default(_) => Err(ProviderError::Credential(
                "The default Codex credential is not a managed artifact".into(),
            )),
        }
    }

    fn persist_refreshed(
        &mut self,
        credentials: CodexCredentials,
        auth_json: Vec<u8>,
        codec: &dyn SecretCodec,
    ) -> Result<(), ProviderError> {
        let Self::Vault {
            config_dir,
            account_id,
            identity,
            bundle,
            auth_json: current_auth_json,
            credentials: current_credentials,
        } = self
        else {
            return Err(ProviderError::Credential(
                "The default Codex credential cannot be written to an account Vault".into(),
            ));
        };
        let parsed_identity = credentials.provider_identity()?;
        let current_identity = current_credentials.provider_identity()?;
        if !parsed_identity.matches_stable_without_namespace_conflicts(identity)
            || !parsed_identity.matches_stable_without_namespace_conflicts(&current_identity)
        {
            return Err(ProviderError::Credential(
                "The refreshed Codex identity does not match the selected account".into(),
            ));
        }
        let mut updated_bundle = bundle.clone();
        updated_bundle.artifact_format = Some("codex-auth-json".into());
        updated_bundle.artifact = Some(auth_json.clone());
        ProviderCredentialVault::new(config_dir, codec)
            .save(ProviderId::Codex, account_id, identity, &updated_bundle)
            .map_err(|_| {
                ProviderError::Credential(
                    "The selected Codex account Vault could not be updated".into(),
                )
            })?;
        *bundle = updated_bundle;
        *current_auth_json = auth_json;
        **current_credentials = credentials;
        Ok(())
    }

    async fn force_refresh(
        &mut self,
        client: &reqwest::Client,
    ) -> Result<CodexCredentials, ProviderError> {
        match self {
            Self::Default(credentials) => {
                let refreshed = credentials.force_refresh_and_save(client).await?;
                *credentials = refreshed.clone();
                Ok(refreshed)
            }
            Self::Vault {
                auth_json,
                credentials,
                ..
            } => {
                if credentials.refresh_token.is_empty() {
                    return Err(ProviderError::Unauthorized(
                        "Codex access token was rejected and no refresh token is available. Run `codex login`.".into(),
                    ));
                }
                let refreshed = credentials.refresh_tokens(client).await?;
                let updated = refreshed.updated_auth_json(auth_json)?;
                self.persist_refreshed(refreshed.clone(), updated, &DPAPI_CODEC)?;
                Ok(refreshed)
            }
        }
    }
}

async fn request_usage(
    context: &FetchContext<'_>,
    credentials: &CodexCredentials,
) -> Result<Response, ProviderError> {
    let mut request = context
        .client
        .get("https://chatgpt.com/backend-api/wham/usage")
        .bearer_auth(&credentials.access_token)
        .header("Accept", "application/json")
        .header("User-Agent", "CodexBar-Windows");
    if let Some(account_id) = &credentials.account_id {
        request = request.header("ChatGPT-Account-Id", account_id);
    }
    Ok(request.send().await?)
}

fn map_usage(
    payload: &Value,
    credentials: &CodexCredentials,
) -> Result<ProviderSnapshot, ProviderError> {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Codex, "oauth");
    snapshot.plan = payload
        .get("plan_type")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    snapshot.account_label = credentials
        .email
        .clone()
        .or_else(|| credentials.account_id.clone());
    if let Some(rate_limit) = payload.get("rate_limit") {
        add_window(
            &mut snapshot,
            "primary",
            "Session",
            rate_limit.get("primary_window"),
        );
        add_window(
            &mut snapshot,
            "secondary",
            "Weekly",
            rate_limit.get("secondary_window"),
        );
    }
    if let Some(additional) = payload
        .get("additional_rate_limits")
        .and_then(Value::as_array)
    {
        for (index, limit) in additional.iter().enumerate() {
            let title = limit
                .get("limit_name")
                .and_then(Value::as_str)
                .or_else(|| limit.get("metered_feature").and_then(Value::as_str))
                .unwrap_or("Additional limit");
            if let Some(rate_limit) = limit.get("rate_limit") {
                add_window(
                    &mut snapshot,
                    &format!("additional-{index}-primary"),
                    title,
                    rate_limit.get("primary_window"),
                );
                add_window(
                    &mut snapshot,
                    &format!("additional-{index}-weekly"),
                    &format!("{title} weekly"),
                    rate_limit.get("secondary_window"),
                );
            }
        }
    }
    if let Some(credits) = payload.get("credits") {
        if credits
            .get("unlimited")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            snapshot
                .summary
                .push(SummaryItem::new("Credits", "Unlimited"));
        } else if let Some(balance) = number_at(credits, &["balance"]) {
            snapshot
                .summary
                .push(SummaryItem::new("Credits", format!("{balance:.2}")));
        }
    }
    let spend = payload
        .get("individual_limit")
        .or_else(|| payload.get("individualLimit"))
        .or_else(|| payload.pointer("/rate_limit/individual_limit"));
    if let Some(spend) = spend {
        if let (Some(used), Some(limit)) =
            (number_at(spend, &["used"]), number_at(spend, &["limit"]))
        {
            snapshot.summary.push(SummaryItem::new(
                "Spend limit",
                format!("${used:.2} / ${limit:.2}"),
            ));
        }
    }
    if snapshot.windows.is_empty() && snapshot.summary.is_empty() {
        return Err(ProviderError::Parse {
            provider: "Codex",
            message: "no recognized quota or credit fields".into(),
        });
    }
    Ok(snapshot)
}

fn add_window(snapshot: &mut ProviderSnapshot, id: &str, title: &str, value: Option<&Value>) {
    let Some(value) = value else { return };
    let Some(percent) = number_at(value, &["used_percent", "usedPercent"]) else {
        return;
    };
    let seconds =
        number_at(value, &["limit_window_seconds", "limitWindowSeconds"]).map(|value| value as u32);
    let reset = number_at(value, &["reset_at", "resetAt"])
        .and_then(|value| DateTime::from_timestamp(value as i64, 0));
    let mut window = UsageWindow::new(id, title, percent).with_reset(reset);
    if let Some(seconds) = seconds {
        window = window.with_window_minutes(seconds / 60);
    }
    snapshot.windows.push(window);
}

fn number_at(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        value.get(key).and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProviderAccountIdentity, ProviderCredentialBundle, ProviderIdentityKey,
        accounts::ProviderCredentialVault,
        auth::dpapi::{SecretCodec, SecretError},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::path::PathBuf;

    #[derive(Debug)]
    struct XorCodec;

    impl SecretCodec for XorCodec {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
            self.protect(ciphertext)
        }
    }

    fn identity(value: &str) -> ProviderAccountIdentity {
        ProviderAccountIdentity::new(
            ProviderId::Codex,
            [ProviderIdentityKey::new("codex-account-id", value)],
            None,
            None,
        )
    }

    fn full_identity(account_id: &str, subject: &str) -> ProviderAccountIdentity {
        ProviderAccountIdentity::new(
            ProviderId::Codex,
            [
                ProviderIdentityKey::new("codex-account-id", account_id),
                ProviderIdentityKey::new("jwt-sub", subject),
            ],
            None,
            None,
        )
    }

    fn id_token(account_id: &str, subject: &str) -> String {
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "chatgpt_account_id": account_id,
                "sub": subject,
            }))
            .unwrap(),
        );
        format!("header.{claims}.signature")
    }

    fn full_bundle(account_id: &str, subject: &str, marker: &str) -> ProviderCredentialBundle {
        ProviderCredentialBundle {
            artifact_format: Some("codex-auth-json".into()),
            artifact: Some(
                serde_json::to_vec(&serde_json::json!({
                    "tokens": {
                        "access_token": format!("access-{marker}"),
                        "refresh_token": format!("refresh-{marker}"),
                        "id_token": id_token(account_id, subject),
                        "account_id": account_id,
                    },
                    "future": {"kept": marker},
                }))
                .unwrap(),
            ),
            ..Default::default()
        }
    }

    fn bundle(account_id: &str, marker: &str) -> ProviderCredentialBundle {
        ProviderCredentialBundle {
            artifact_format: Some("codex-auth-json".into()),
            artifact: Some(
                serde_json::to_vec(&serde_json::json!({
                    "tokens": {
                        "access_token": format!("access-{marker}"),
                        "refresh_token": "",
                        "account_id": account_id,
                    },
                    "marker": marker,
                }))
                .unwrap(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn maps_codex_windows_credits_and_additional_limits() {
        let payload = serde_json::json!({
            "plan_type": "plus",
            "rate_limit": {
                "primary_window": { "used_percent": 15, "reset_at": 1800000000, "limit_window_seconds": 18000 },
                "secondary_window": { "used_percent": 42, "reset_at": 1800100000, "limit_window_seconds": 604800 }
            },
            "additional_rate_limits": [{
                "limit_name": "Fictitious model",
                "rate_limit": { "primary_window": { "used_percent": 7, "reset_at": 1800000000, "limit_window_seconds": 18000 } }
            }],
            "credits": { "has_credits": true, "unlimited": false, "balance": "12.5" }
        });
        let credentials = CodexCredentials::parse(
            br#"{"tokens":{"access_token":"access","refresh_token":"refresh","account_id":"acct"}}"#,
            PathBuf::from("auth.json"),
        )
        .expect("credentials");
        let snapshot = map_usage(&payload, &credentials).expect("usage");
        assert_eq!(snapshot.windows.len(), 3);
        assert_eq!(snapshot.windows[0].window_minutes, Some(300));
        assert_eq!(snapshot.summary[0].value, "12.50");
    }

    #[test]
    fn named_account_loads_only_its_generic_encrypted_vault_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        vault
            .save(
                ProviderId::Codex,
                "acc_named",
                &identity("named"),
                &bundle("named", "named-vault"),
            )
            .unwrap();

        let source =
            CredentialSource::load_named(temporary.path(), "acc_named", &XorCodec).unwrap();

        assert_eq!(source.credentials().account_id.as_deref(), Some("named"));
        assert_eq!(
            source.artifact().unwrap(),
            bundle("named", "named-vault").artifact.unwrap()
        );
        assert!(matches!(
            CredentialSource::load_named(temporary.path(), "acc_missing", &XorCodec),
            Err(ProviderError::MissingCredentials(_))
        ));
    }

    #[test]
    fn named_refresh_writes_back_only_the_same_generic_vault_bundle() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        let first_identity = identity("first");
        let second_identity = identity("second");
        vault
            .save(
                ProviderId::Codex,
                "acc_first",
                &first_identity,
                &bundle("first", "before"),
            )
            .unwrap();
        vault
            .save(
                ProviderId::Codex,
                "acc_second",
                &second_identity,
                &bundle("second", "sibling"),
            )
            .unwrap();
        let sibling_before = vault
            .load(ProviderId::Codex, "acc_second")
            .unwrap()
            .credentials;
        let mut source =
            CredentialSource::load_named(temporary.path(), "acc_first", &XorCodec).unwrap();

        let refreshed_artifact = bundle("first", "after").artifact.unwrap();
        let refreshed =
            CodexCredentials::parse(&refreshed_artifact, PathBuf::from("auth.json")).unwrap();
        source
            .persist_refreshed(refreshed, refreshed_artifact, &XorCodec)
            .unwrap();

        assert_eq!(
            vault
                .load(ProviderId::Codex, "acc_first")
                .unwrap()
                .credentials
                .artifact,
            bundle("first", "after").artifact
        );
        assert_eq!(
            vault
                .load(ProviderId::Codex, "acc_second")
                .unwrap()
                .credentials,
            sibling_before
        );
    }

    #[test]
    fn named_refresh_rejects_changed_account_id_even_when_subject_matches_without_vault_write() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        let identity = full_identity("account-original", "subject-shared");
        vault
            .save(
                ProviderId::Codex,
                "acc_named",
                &identity,
                &full_bundle("account-original", "subject-shared", "before"),
            )
            .unwrap();
        let vault_path = vault.path(ProviderId::Codex, "acc_named").unwrap();
        let before = std::fs::read(&vault_path).unwrap();
        let mut source =
            CredentialSource::load_named(temporary.path(), "acc_named", &XorCodec).unwrap();
        let refreshed_artifact = full_bundle("account-changed", "subject-shared", "after")
            .artifact
            .unwrap();
        let refreshed =
            CodexCredentials::parse(&refreshed_artifact, PathBuf::from("auth.json")).unwrap();

        assert!(
            source
                .persist_refreshed(refreshed, refreshed_artifact, &XorCodec)
                .is_err()
        );
        assert_eq!(std::fs::read(vault_path).unwrap(), before);
    }

    #[test]
    fn named_refresh_rejects_changed_subject_even_when_account_id_matches_without_vault_write() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        let identity = full_identity("account-shared", "subject-original");
        vault
            .save(
                ProviderId::Codex,
                "acc_named",
                &identity,
                &full_bundle("account-shared", "subject-original", "before"),
            )
            .unwrap();
        let vault_path = vault.path(ProviderId::Codex, "acc_named").unwrap();
        let before = std::fs::read(&vault_path).unwrap();
        let mut source =
            CredentialSource::load_named(temporary.path(), "acc_named", &XorCodec).unwrap();
        let refreshed_artifact = full_bundle("account-shared", "subject-changed", "after")
            .artifact
            .unwrap();
        let refreshed =
            CodexCredentials::parse(&refreshed_artifact, PathBuf::from("auth.json")).unwrap();

        assert!(
            source
                .persist_refreshed(refreshed, refreshed_artifact, &XorCodec)
                .is_err()
        );
        assert_eq!(std::fs::read(vault_path).unwrap(), before);
    }

    #[test]
    fn named_refresh_checks_subject_from_current_artifact_when_metadata_has_only_account_id() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        let metadata_identity = identity("account-shared");
        vault
            .save(
                ProviderId::Codex,
                "acc_named",
                &metadata_identity,
                &full_bundle("account-shared", "subject-original", "before"),
            )
            .unwrap();
        let vault_path = vault.path(ProviderId::Codex, "acc_named").unwrap();
        let before = std::fs::read(&vault_path).unwrap();
        let mut source =
            CredentialSource::load_named(temporary.path(), "acc_named", &XorCodec).unwrap();
        let refreshed_artifact = full_bundle("account-shared", "subject-changed", "after")
            .artifact
            .unwrap();
        let refreshed =
            CodexCredentials::parse(&refreshed_artifact, PathBuf::from("auth.json")).unwrap();

        assert!(
            source
                .persist_refreshed(refreshed, refreshed_artifact, &XorCodec)
                .is_err()
        );
        assert_eq!(std::fs::read(vault_path).unwrap(), before);
    }

    #[test]
    fn named_refresh_checks_account_from_current_artifact_when_metadata_has_only_subject() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        let metadata_identity = ProviderAccountIdentity::new(
            ProviderId::Codex,
            [ProviderIdentityKey::new("jwt-sub", "subject-shared")],
            None,
            None,
        );
        vault
            .save(
                ProviderId::Codex,
                "acc_named",
                &metadata_identity,
                &full_bundle("account-original", "subject-shared", "before"),
            )
            .unwrap();
        let vault_path = vault.path(ProviderId::Codex, "acc_named").unwrap();
        let before = std::fs::read(&vault_path).unwrap();
        let mut source =
            CredentialSource::load_named(temporary.path(), "acc_named", &XorCodec).unwrap();
        let refreshed_artifact = full_bundle("account-changed", "subject-shared", "after")
            .artifact
            .unwrap();
        let refreshed =
            CodexCredentials::parse(&refreshed_artifact, PathBuf::from("auth.json")).unwrap();

        assert!(
            source
                .persist_refreshed(refreshed, refreshed_artifact, &XorCodec)
                .is_err()
        );
        assert_eq!(std::fs::read(vault_path).unwrap(), before);
    }

    #[test]
    fn named_refresh_preserves_unknown_json_when_all_identity_namespaces_match() {
        let temporary = tempfile::tempdir().unwrap();
        let vault = ProviderCredentialVault::new(temporary.path(), &XorCodec);
        let identity = full_identity("account", "subject");
        let original = full_bundle("account", "subject", "before");
        vault
            .save(ProviderId::Codex, "acc_named", &identity, &original)
            .unwrap();
        let mut source =
            CredentialSource::load_named(temporary.path(), "acc_named", &XorCodec).unwrap();
        let mut refreshed =
            CodexCredentials::parse(source.artifact().unwrap(), PathBuf::from("auth.json"))
                .unwrap();
        refreshed.access_token = "access-after".into();
        let refreshed_artifact = refreshed
            .updated_auth_json(source.artifact().unwrap())
            .unwrap();

        source
            .persist_refreshed(refreshed, refreshed_artifact, &XorCodec)
            .unwrap();

        let saved = vault.load(ProviderId::Codex, "acc_named").unwrap();
        let saved_json: Value =
            serde_json::from_slice(saved.credentials.artifact.as_deref().unwrap()).unwrap();
        assert_eq!(
            saved_json.pointer("/future/kept").and_then(Value::as_str),
            Some("before")
        );
    }
}
