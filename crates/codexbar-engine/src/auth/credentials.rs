use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use crate::{
    accounts::{ProviderAccountIdentity, ProviderIdentityKey},
    model::ProviderId,
    provider::ProviderError,
};

const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CLAUDE_REFRESH_URL: &str = "https://platform.claude.com/v1/oauth/token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexCredentialStoreMode {
    File,
    Keyring,
    Auto,
    Unset,
    Invalid,
}

impl CodexCredentialStoreMode {
    pub const fn is_switchable(self) -> bool {
        matches!(self, Self::File)
    }
}

pub fn parse_codex_credential_store_mode(contents: &str) -> CodexCredentialStoreMode {
    let Ok(root) = toml::from_str::<toml::Table>(contents) else {
        return CodexCredentialStoreMode::Invalid;
    };
    match root.get("cli_auth_credentials_store") {
        None => CodexCredentialStoreMode::Unset,
        Some(toml::Value::String(value)) if value == "file" => CodexCredentialStoreMode::File,
        Some(toml::Value::String(value)) if value == "keyring" => CodexCredentialStoreMode::Keyring,
        Some(toml::Value::String(value)) if value == "auto" => CodexCredentialStoreMode::Auto,
        Some(_) => CodexCredentialStoreMode::Invalid,
    }
}

#[derive(Debug, Clone)]
pub struct ClaudeCredentials {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub rate_limit_tier: Option<String>,
    pub subscription_type: Option<String>,
    source_path: Option<PathBuf>,
}

impl ClaudeCredentials {
    /// Official CLI credential path (`%CLAUDE_CONFIG_DIR%\.credentials.json` when configured,
    /// otherwise `%USERPROFILE%\.claude\.credentials.json`).
    pub fn default_path() -> Result<PathBuf, ProviderError> {
        let environment = ["CLAUDE_CONFIG_DIR", "USERPROFILE", "HOME"]
            .into_iter()
            .filter_map(|key| env::var(key).ok().map(|value| (key.into(), value)))
            .collect::<HashMap<_, _>>();
        Self::default_path_from_environment(&environment)
    }

    pub fn default_path_from_environment(
        environment: &HashMap<String, String>,
    ) -> Result<PathBuf, ProviderError> {
        if let Some(config_dir) = clean_map_value(environment, "CLAUDE_CONFIG_DIR") {
            return Ok(PathBuf::from(config_dir).join(".credentials.json"));
        }
        let home = clean_map_value(environment, "USERPROFILE")
            .or_else(|| clean_map_value(environment, "HOME"))
            .map(PathBuf::from)
            .ok_or_else(|| ProviderError::Credential("USERPROFILE is not set".into()))?;
        Ok(home.join(".claude").join(".credentials.json"))
    }

    pub async fn load_and_refresh(client: &Client) -> Result<Self, ProviderError> {
        Self::load_and_refresh_with_url(client, CLAUDE_REFRESH_URL).await
    }

    pub fn needs_refresh(&self) -> bool {
        self.expires_at
            .is_none_or(|expires_at| expires_at <= Utc::now() + Duration::seconds(60))
    }

    pub(crate) async fn load_and_refresh_with_url(
        client: &Client,
        refresh_url: &str,
    ) -> Result<Self, ProviderError> {
        if let Some(token) = clean_env("CODEXBAR_CLAUDE_OAUTH_TOKEN") {
            return Ok(Self {
                access_token: token,
                refresh_token: None,
                expires_at: None,
                scopes: clean_env("CODEXBAR_CLAUDE_OAUTH_SCOPES")
                    .map(|value| value.split_whitespace().map(ToOwned::to_owned).collect())
                    .unwrap_or_default(),
                rate_limit_tier: None,
                subscription_type: None,
                source_path: None,
            });
        }
        Self::load_and_refresh_from_with_url(client, Self::default_path()?, refresh_url).await
    }

    /// Load, refresh-if-near-expiry, and write back to the given credential file. Managed per-account
    /// slots pass their own path so account A's refresh never touches account B's file.
    pub async fn load_and_refresh_from(
        client: &Client,
        path: PathBuf,
    ) -> Result<Self, ProviderError> {
        Self::load_and_refresh_from_with_url(client, path, CLAUDE_REFRESH_URL).await
    }

    pub(crate) async fn load_and_refresh_from_with_url(
        client: &Client,
        path: PathBuf,
        refresh_url: &str,
    ) -> Result<Self, ProviderError> {
        let data = fs::read(&path).map_err(|error| {
            ProviderError::MissingCredentials(format!(
                "Claude credentials were not found at {} ({error}). Run `claude login`.",
                path.display()
            ))
        })?;
        let mut credentials = Self::parse(&data, Some(path.clone()))?;
        if credentials.needs_refresh() {
            credentials = credentials.refresh_with_url(client, refresh_url).await?;
            credentials.save_to_cli_file(&path)?;
        }
        Ok(credentials)
    }

    pub fn parse(data: &[u8], source_path: Option<PathBuf>) -> Result<Self, ProviderError> {
        let root: Value = serde_json::from_slice(data).map_err(|error| {
            ProviderError::Credential(format!("Invalid Claude credential JSON: {error}"))
        })?;
        let oauth = root.get("claudeAiOauth").ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Claude credentials do not contain claudeAiOauth. Run `claude login`.".into(),
            )
        })?;
        let access_token = string_at(oauth, &["accessToken", "access_token"]).ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Claude OAuth access token is missing. Run `claude login`.".into(),
            )
        })?;
        let expires_at = number_at(oauth, &["expiresAt", "expires_at"])
            .and_then(|milliseconds| DateTime::from_timestamp_millis(milliseconds as i64));
        let scopes = oauth
            .get("scopes")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            access_token,
            refresh_token: string_at(oauth, &["refreshToken", "refresh_token"]),
            expires_at,
            scopes,
            rate_limit_tier: string_at(oauth, &["rateLimitTier", "rate_limit_tier"]),
            subscription_type: string_at(oauth, &["subscriptionType", "subscription_type"]),
            source_path,
        })
    }

    async fn refresh_with_url(
        &self,
        client: &Client,
        refresh_url: &str,
    ) -> Result<Self, ProviderError> {
        let refresh_token = self.refresh_token.as_deref().ok_or_else(|| {
            ProviderError::Unauthorized(
                "Claude token expired and no refresh token is available. Run `claude login`."
                    .into(),
            )
        })?;
        let response = client
            .post(refresh_url)
            .header("Accept", "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", CLAUDE_CLIENT_ID),
            ])
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ProviderError::Unauthorized(format!(
                "Claude token refresh returned HTTP {}. Run `claude login`.",
                response.status().as_u16()
            )));
        }
        let payload: Value = response.json().await?;
        let access_token = string_at(&payload, &["access_token"]).ok_or_else(|| {
            ProviderError::Credential("Claude token refresh response omitted access_token".into())
        })?;
        let expires_in = number_at(&payload, &["expires_in"]).unwrap_or(3600.0) as i64;
        Ok(Self {
            access_token,
            refresh_token: string_at(&payload, &["refresh_token"])
                .or_else(|| self.refresh_token.clone()),
            expires_at: Some(Utc::now() + Duration::seconds(expires_in)),
            scopes: self.scopes.clone(),
            rate_limit_tier: self.rate_limit_tier.clone(),
            subscription_type: self.subscription_type.clone(),
            source_path: self.source_path.clone(),
        })
    }

    pub async fn force_refresh_and_save(&self, client: &Client) -> Result<Self, ProviderError> {
        self.force_refresh_and_save_with_url(client, CLAUDE_REFRESH_URL)
            .await
    }

    pub(crate) async fn force_refresh_and_save_with_url(
        &self,
        client: &Client,
        refresh_url: &str,
    ) -> Result<Self, ProviderError> {
        let refreshed = self.refresh_with_url(client, refresh_url).await?;
        if let Some(path) = &self.source_path {
            refreshed.save_to_cli_file(path)?;
        }
        Ok(refreshed)
    }

    fn save_to_cli_file(&self, path: &Path) -> Result<(), ProviderError> {
        let existing =
            fs::read(path).map_err(|error| ProviderError::Credential(error.to_string()))?;
        let root: Value = serde_json::from_slice(&self.updated_credentials_json(&existing)?)
            .map_err(|error| ProviderError::Credential(error.to_string()))?;
        write_json_atomically(path, &root)
    }

    pub fn updated_credentials_json(&self, existing: &[u8]) -> Result<Vec<u8>, ProviderError> {
        let mut root: Value = serde_json::from_slice(existing)
            .map_err(|error| ProviderError::Credential(error.to_string()))?;
        let oauth = root
            .get_mut("claudeAiOauth")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                ProviderError::Credential(
                    "Claude credential object disappeared during refresh".into(),
                )
            })?;
        oauth.insert(
            "accessToken".into(),
            Value::String(self.access_token.clone()),
        );
        if let Some(refresh_token) = &self.refresh_token {
            oauth.insert("refreshToken".into(), Value::String(refresh_token.clone()));
        }
        if let Some(expires_at) = self.expires_at {
            oauth.insert("expiresAt".into(), json!(expires_at.timestamp_millis()));
        }
        serde_json::to_vec_pretty(&root)
            .map_err(|error| ProviderError::Credential(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct CodexCredentials {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: Option<String>,
    pub account_id: Option<String>,
    pub subject: Option<String>,
    pub email: Option<String>,
    pub last_refresh: Option<DateTime<Utc>>,
    source_path: PathBuf,
}

impl CodexCredentials {
    /// Default CLI credential path (`%CODEX_HOME%\auth.json` or `%USERPROFILE%\.codex\auth.json`).
    pub fn default_path() -> Result<PathBuf, ProviderError> {
        Ok(codex_home()?.join("auth.json"))
    }

    pub async fn load_and_refresh(client: &Client) -> Result<Self, ProviderError> {
        Self::load_and_refresh_from(client, Self::default_path()?).await
    }

    /// Load, refresh-if-stale, and write back to the given `auth.json`. Managed per-account slots pass
    /// their own path so account A's refresh never overwrites account B's tokens.
    pub async fn load_and_refresh_from(
        client: &Client,
        path: PathBuf,
    ) -> Result<Self, ProviderError> {
        let data = fs::read(&path).map_err(|error| {
            ProviderError::MissingCredentials(format!(
                "Codex credentials were not found at {} ({error}). Run `codex login`.",
                path.display()
            ))
        })?;
        let mut credentials = Self::parse(&data, path.clone())?;
        if credentials.needs_refresh() {
            credentials = credentials.refresh_tokens(client).await?;
            credentials.save(&path)?;
        }
        Ok(credentials)
    }

    pub fn needs_refresh(&self) -> bool {
        !self.refresh_token.is_empty()
            && self
                .last_refresh
                .is_none_or(|last_refresh| Utc::now() - last_refresh > Duration::days(8))
    }

    pub fn provider_identity(&self) -> Result<ProviderAccountIdentity, ProviderError> {
        let mut stable_keys = Vec::new();
        if let Some(account_id) = &self.account_id {
            stable_keys.push(ProviderIdentityKey::new("codex-account-id", account_id));
        }
        if let Some(subject) = &self.subject {
            stable_keys.push(ProviderIdentityKey::new("jwt-sub", subject));
        }
        if stable_keys.is_empty() {
            return Err(ProviderError::Credential(
                "Codex auth.json has no stable official account identity".into(),
            ));
        }
        Ok(ProviderAccountIdentity::new(
            ProviderId::Codex,
            stable_keys,
            self.email.clone(),
            None,
        ))
    }

    pub fn parse(data: &[u8], source_path: PathBuf) -> Result<Self, ProviderError> {
        let root: Value = serde_json::from_slice(data).map_err(|error| {
            ProviderError::Credential(format!("Invalid Codex auth.json: {error}"))
        })?;
        if let Some(api_key) = root
            .get("OPENAI_API_KEY")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return Ok(Self {
                access_token: api_key.to_owned(),
                refresh_token: String::new(),
                id_token: None,
                account_id: None,
                subject: None,
                email: None,
                last_refresh: None,
                source_path,
            });
        }
        let tokens = root.get("tokens").ok_or_else(|| {
            ProviderError::MissingCredentials(
                "Codex auth.json contains no OAuth tokens. Run `codex login`.".into(),
            )
        })?;
        let access_token =
            string_at(tokens, &["access_token", "accessToken"]).ok_or_else(|| {
                ProviderError::MissingCredentials(
                    "Codex OAuth access token is missing. Run `codex login`.".into(),
                )
            })?;
        let refresh_token =
            string_at(tokens, &["refresh_token", "refreshToken"]).unwrap_or_default();
        let id_token = string_at(tokens, &["id_token", "idToken"]);
        let claims = id_token.as_deref().and_then(decode_jwt_claims);
        let explicit_account_id = string_at(tokens, &["account_id", "accountId"]);
        let claimed_account_id = claims.as_ref().and_then(extract_account_id);
        if explicit_account_id.is_some()
            && claimed_account_id.is_some()
            && explicit_account_id != claimed_account_id
        {
            return Err(ProviderError::Credential(
                "Codex auth.json account identity fields conflict".into(),
            ));
        }
        let account_id = explicit_account_id.or(claimed_account_id);
        let subject = claims.as_ref().and_then(|value| string_at(value, &["sub"]));
        let email = claims
            .as_ref()
            .and_then(|value| string_at(value, &["email"]));
        let last_refresh = root
            .get("last_refresh")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc));
        Ok(Self {
            access_token,
            refresh_token,
            id_token,
            account_id,
            subject,
            email,
            last_refresh,
            source_path,
        })
    }

    pub async fn refresh_tokens(&self, client: &Client) -> Result<Self, ProviderError> {
        let response = client
            .post("https://auth.openai.com/oauth/token")
            .json(&json!({
                "client_id": CODEX_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "scope": "openid profile email"
            }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ProviderError::Unauthorized(format!(
                "Codex token refresh returned HTTP {}. Run `codex login`.",
                response.status().as_u16()
            )));
        }
        let payload: Value = response.json().await?;
        self.apply_refresh_payload(&payload)
    }

    fn apply_refresh_payload(&self, payload: &Value) -> Result<Self, ProviderError> {
        let access_token =
            string_at(payload, &["access_token"]).unwrap_or_else(|| self.access_token.clone());
        let refresh_token =
            string_at(payload, &["refresh_token"]).unwrap_or_else(|| self.refresh_token.clone());
        let new_id_token = ["id_token", "idToken"]
            .into_iter()
            .find_map(|key| payload.get(key));
        let (id_token, account_id, subject, email) = match new_id_token {
            None => (
                self.id_token.clone(),
                self.account_id.clone(),
                self.subject.clone(),
                self.email.clone(),
            ),
            Some(Value::String(id_token)) if !id_token.trim().is_empty() => {
                let claims = decode_jwt_claims(id_token).ok_or_else(|| {
                    ProviderError::Credential(
                        "Codex token refresh returned an invalid identity token".into(),
                    )
                })?;
                (
                    Some(id_token.clone()),
                    extract_account_id(&claims),
                    string_at(&claims, &["sub"]),
                    string_at(&claims, &["email"]),
                )
            }
            Some(_) => {
                return Err(ProviderError::Credential(
                    "Codex token refresh returned an invalid identity token".into(),
                ));
            }
        };
        Ok(Self {
            access_token,
            refresh_token,
            account_id,
            subject,
            email,
            id_token,
            last_refresh: Some(Utc::now()),
            source_path: self.source_path.clone(),
        })
    }

    pub async fn force_refresh_and_save(&self, client: &Client) -> Result<Self, ProviderError> {
        if self.refresh_token.is_empty() {
            return Err(ProviderError::Unauthorized(
                "Codex access token was rejected and no refresh token is available. Run `codex login`.".into(),
            ));
        }
        let refreshed = self.refresh_tokens(client).await?;
        refreshed.save(&self.source_path)?;
        Ok(refreshed)
    }

    /// Rebuild an `auth.json` with refreshed fields while preserving fields newer Codex versions
    /// may add. The caller decides where the bytes are persisted (default file or encrypted vault).
    pub fn updated_auth_json(&self, existing: &[u8]) -> Result<Vec<u8>, ProviderError> {
        let mut root: Value = serde_json::from_slice(existing)
            .map_err(|error| ProviderError::Credential(error.to_string()))?;
        self.apply_to_auth_root(&mut root)?;
        serde_json::to_vec_pretty(&root)
            .map_err(|error| ProviderError::Credential(error.to_string()))
    }

    fn save(&self, path: &Path) -> Result<(), ProviderError> {
        let existing =
            fs::read(path).map_err(|error| ProviderError::Credential(error.to_string()))?;
        let mut root: Value = serde_json::from_slice(&existing)
            .map_err(|error| ProviderError::Credential(error.to_string()))?;
        self.apply_to_auth_root(&mut root)?;
        write_json_atomically(path, &root)
    }

    fn apply_to_auth_root(&self, root: &mut Value) -> Result<(), ProviderError> {
        let tokens = root
            .get_mut("tokens")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                ProviderError::Credential("Codex tokens object disappeared during refresh".into())
            })?;
        tokens.insert(
            "access_token".into(),
            Value::String(self.access_token.clone()),
        );
        tokens.insert(
            "refresh_token".into(),
            Value::String(self.refresh_token.clone()),
        );
        tokens.remove("id_token");
        tokens.remove("idToken");
        if let Some(id_token) = &self.id_token {
            tokens.insert("id_token".into(), Value::String(id_token.clone()));
        }
        tokens.remove("account_id");
        tokens.remove("accountId");
        if let Some(account_id) = &self.account_id {
            tokens.insert("account_id".into(), Value::String(account_id.clone()));
        }
        root.as_object_mut()
            .expect("Codex auth root was validated as an object")
            .insert(
                "last_refresh".into(),
                Value::String(Utc::now().to_rfc3339()),
            );
        Ok(())
    }
}

/// Path to a provider account's managed credential slot under the config directory:
/// `<config_dir>/accounts/<provider>/<account_id>.json`. A managed copy here is read and refreshed
/// in isolation, so multiple Codex/Claude accounts never share one CLI file.
pub fn is_safe_managed_account_id(account_id: &str) -> bool {
    let Some(suffix) = account_id.strip_prefix("acc_") else {
        return false;
    };
    !suffix.is_empty()
        && account_id.len() <= 128
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_safe_managed_provider(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 64
        && provider.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

pub fn managed_credential_path(
    config_dir: &Path,
    provider: &str,
    account_id: &str,
) -> Option<PathBuf> {
    if !is_safe_managed_provider(provider) || !is_safe_managed_account_id(account_id) {
        return None;
    }
    let provider_root = config_dir.join("accounts").join(provider);
    let path = provider_root.join(format!("{account_id}.json"));
    (path.parent() == Some(provider_root.as_path())).then_some(path)
}

/// Resolve the credential source for an account. Only a blank legacy account id selects the default
/// CLI credential. A named account must have its own managed copy so it can never silently borrow a
/// global or sibling credential.
pub fn resolve_managed_slot(
    config_dir: Option<&Path>,
    provider: &str,
    account_id: &str,
) -> Result<Option<PathBuf>, ProviderError> {
    if !is_safe_managed_provider(provider) {
        return Err(ProviderError::Credential(
            "Managed credential account id or provider was rejected".into(),
        ));
    }
    if account_id.trim().is_empty() {
        return Ok(None);
    }
    if !is_safe_managed_account_id(account_id) {
        return Err(ProviderError::Credential(
            "Managed credential account id or provider was rejected".into(),
        ));
    }
    let config_dir = config_dir.ok_or_else(|| {
        ProviderError::MissingCredentials(
            "The selected account has no managed credential. Import it and retry.".into(),
        )
    })?;
    let path = managed_credential_path(config_dir, provider, account_id).ok_or_else(|| {
        ProviderError::Credential("Managed credential account id or provider was rejected".into())
    })?;
    if !path.exists() {
        return Err(ProviderError::MissingCredentials(
            "The selected account has no managed credential. Import it and retry.".into(),
        ));
    }
    Ok(Some(path))
}

fn clean_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn clean_map_value(environment: &HashMap<String, String>, key: &str) -> Option<String> {
    environment
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn home_dir() -> Result<PathBuf, ProviderError> {
    clean_env("USERPROFILE")
        .or_else(|| clean_env("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| ProviderError::Credential("USERPROFILE is not set".into()))
}

fn codex_home() -> Result<PathBuf, ProviderError> {
    Ok(clean_env("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or(home_dir()?.join(".codex")))
}

fn write_json_atomically(path: &Path, value: &Value) -> Result<(), ProviderError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ProviderError::Credential(error.to_string()))?;
    let staged = path.with_extension("json.codexbar.tmp");
    fs::write(&staged, bytes).map_err(|error| ProviderError::Credential(error.to_string()))?;
    // Atomic replace so a crash mid-write cannot corrupt the CLI credential file.
    fs::rename(&staged, path).map_err(|error| ProviderError::Credential(error.to_string()))
}

fn string_at(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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

fn decode_jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn extract_account_id(claims: &Value) -> Option<String> {
    string_at(claims, &["chatgpt_account_id", "account_id"]).or_else(|| {
        claims
            .get("https://api.openai.com/auth")
            .and_then(extract_account_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn codex_id_token(account_id: &str, subject: &str) -> String {
        let claims = serde_json::json!({
            "chatgpt_account_id": account_id,
            "sub": subject,
            "email": format!("{subject}@example.test"),
        });
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("header.{claims}.signature")
    }

    fn codex_subject_only_id_token(subject: &str) -> String {
        let claims = serde_json::json!({"sub": subject});
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("header.{claims}.signature")
    }

    fn codex_oauth_credentials(account_id: &str, subject: &str) -> CodexCredentials {
        let id_token = codex_id_token(account_id, subject);
        CodexCredentials::parse(
            serde_json::to_string(&serde_json::json!({
                "tokens": {
                    "access_token": "access-old",
                    "refresh_token": "refresh-old",
                    "id_token": id_token,
                    "account_id": account_id,
                }
            }))
            .unwrap()
            .as_bytes(),
            PathBuf::from("auth.json"),
        )
        .unwrap()
    }

    #[test]
    fn parses_claude_cli_credentials() {
        let credentials = ClaudeCredentials::parse(
            concat!(
                r#"{"claudeAiOauth":{"accessToken":"token","refreshToken":"refresh","expiresAt":1700000000000,"#,
                r#""scopes":["user:profile"],"subscriptionType":"pro"}}"#,
            )
            .as_bytes(),
            None,
        )
        .expect("parse Claude credentials");
        assert_eq!(credentials.access_token, "token");
        assert_eq!(credentials.scopes, ["user:profile"]);
        assert_eq!(credentials.subscription_type.as_deref(), Some("pro"));
    }

    #[test]
    fn claude_default_path_honors_documented_config_directory_without_other_searches() {
        let environment = std::collections::HashMap::from([
            ("CLAUDE_CONFIG_DIR".into(), "D:/isolated-claude".into()),
            ("USERPROFILE".into(), "C:/ignored-user".into()),
        ]);
        assert_eq!(
            ClaudeCredentials::default_path_from_environment(&environment).unwrap(),
            PathBuf::from("D:/isolated-claude/.credentials.json")
        );

        let fallback = std::collections::HashMap::from([("USERPROFILE".into(), "C:/user".into())]);
        assert_eq!(
            ClaudeCredentials::default_path_from_environment(&fallback).unwrap(),
            PathBuf::from("C:/user/.claude/.credentials.json")
        );
    }

    #[test]
    fn claude_refresh_serialization_preserves_complete_unknown_credential_json() {
        let original = br#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-refresh","expiresAt":4070908800000},"future":{"kept":true}}"#;
        let mut credentials = ClaudeCredentials::parse(original, None).unwrap();
        credentials.access_token = "new".into();
        credentials.refresh_token = Some("new-refresh".into());

        let updated: Value =
            serde_json::from_slice(&credentials.updated_credentials_json(original).unwrap())
                .unwrap();

        assert_eq!(updated.pointer("/future/kept"), Some(&Value::Bool(true)));
        assert_eq!(
            updated
                .pointer("/claudeAiOauth/accessToken")
                .and_then(Value::as_str),
            Some("new")
        );
        assert_eq!(
            updated
                .pointer("/claudeAiOauth/refreshToken")
                .and_then(Value::as_str),
            Some("new-refresh")
        );
    }

    #[test]
    fn parses_codex_snake_and_camel_case_tokens() {
        let credentials = CodexCredentials::parse(
            br#"{"tokens":{"accessToken":"access","refresh_token":"refresh","accountId":"acct"},"last_refresh":"2026-07-10T00:00:00Z"}"#,
            PathBuf::from("auth.json"),
        )
        .expect("parse Codex credentials");
        assert_eq!(credentials.access_token, "access");
        assert_eq!(credentials.account_id.as_deref(), Some("acct"));
    }

    #[test]
    fn codex_parse_rejects_explicit_account_id_conflicting_with_id_token_claim() {
        let id_token = codex_id_token("account-from-token", "subject");
        let auth_json = serde_json::to_vec(&serde_json::json!({
            "tokens": {
                "access_token": "access",
                "refresh_token": "refresh",
                "id_token": id_token,
                "account_id": "account-explicit",
            }
        }))
        .unwrap();

        assert!(CodexCredentials::parse(&auth_json, PathBuf::from("auth.json")).is_err());
    }

    #[test]
    fn codex_refresh_serialization_preserves_unknown_auth_fields() {
        let original = br#"{"tokens":{"access_token":"old","refresh_token":"old-refresh","account_id":"acct"},"future":{"kept":true}}"#;
        let mut credentials =
            CodexCredentials::parse(original, PathBuf::from("auth.json")).unwrap();
        credentials.access_token = "new".into();
        credentials.refresh_token = "new-refresh".into();

        let updated: Value =
            serde_json::from_slice(&credentials.updated_auth_json(original).unwrap()).unwrap();

        assert_eq!(updated.pointer("/future/kept"), Some(&Value::Bool(true)));
        assert_eq!(
            updated
                .pointer("/tokens/access_token")
                .and_then(Value::as_str),
            Some("new")
        );
        assert_eq!(
            updated
                .pointer("/tokens/refresh_token")
                .and_then(Value::as_str),
            Some("new-refresh")
        );
    }

    #[test]
    fn codex_refresh_payload_derives_account_and_subject_from_a_new_id_token() {
        let credentials = codex_oauth_credentials("account-old", "subject-old");
        let refreshed = credentials
            .apply_refresh_payload(&serde_json::json!({
                "access_token": "access-new",
                "id_token": codex_id_token("account-new", "subject-new"),
            }))
            .unwrap();

        assert_eq!(refreshed.account_id.as_deref(), Some("account-new"));
        assert_eq!(refreshed.subject.as_deref(), Some("subject-new"));
        assert_eq!(refreshed.email.as_deref(), Some("subject-new@example.test"));
    }

    #[test]
    fn codex_refresh_payload_preserves_identity_only_when_id_token_is_omitted() {
        let credentials = codex_oauth_credentials("account-old", "subject-old");
        let refreshed = credentials
            .apply_refresh_payload(&serde_json::json!({"access_token": "access-new"}))
            .unwrap();

        assert_eq!(refreshed.id_token, credentials.id_token);
        assert_eq!(refreshed.account_id, credentials.account_id);
        assert_eq!(refreshed.subject, credentials.subject);
        assert_eq!(refreshed.email, credentials.email);
    }

    #[test]
    fn codex_refresh_payload_rejects_a_malformed_new_id_token() {
        let credentials = codex_oauth_credentials("account-old", "subject-old");

        assert!(
            credentials
                .apply_refresh_payload(&serde_json::json!({
                    "access_token": "access-new",
                    "id_token": "not-a-jwt",
                }))
                .is_err()
        );
    }

    #[test]
    fn codex_refresh_serialization_does_not_revive_an_old_account_id() {
        let credentials = codex_oauth_credentials("account-old", "subject-old");
        let refreshed = credentials
            .apply_refresh_payload(&serde_json::json!({
                "access_token": "access-new",
                "id_token": codex_subject_only_id_token("subject-new"),
            }))
            .unwrap();
        let original = br#"{"tokens":{"access_token":"old","refresh_token":"old","idToken":"old-token","account_id":"account-old","accountId":"account-old"},"future":true}"#;
        let updated: Value =
            serde_json::from_slice(&refreshed.updated_auth_json(original).unwrap()).unwrap();

        assert_eq!(refreshed.account_id, None);
        assert_eq!(updated.pointer("/tokens/account_id"), None);
        assert_eq!(updated.pointer("/tokens/accountId"), None);
        assert_eq!(updated.pointer("/tokens/idToken"), None);
        assert_eq!(updated.pointer("/future"), Some(&Value::Bool(true)));
    }

    #[test]
    fn managed_credential_path_is_namespaced_by_provider_and_account() {
        let path = managed_credential_path(Path::new("C:/cfg"), "claude", "acc_a").unwrap();
        assert!(path.ends_with("accounts/claude/acc_a.json"));
    }

    #[test]
    fn managed_credential_path_rejects_unsafe_components_and_stays_under_provider_root() {
        let base = Path::new("C:/cfg");
        for account_id in [
            "../escape",
            "acc_a/../../escape",
            "C:\\escape",
            "acc_a.json",
        ] {
            assert!(managed_credential_path(base, "claude", account_id).is_none());
        }
        for provider in ["../claude", "claude/accounts", "C:\\claude"] {
            assert!(managed_credential_path(base, provider, "acc_a").is_none());
        }
        let root = base.join("accounts").join("claude");
        let safe = managed_credential_path(base, "claude", "acc_safe-1").unwrap();
        assert_eq!(safe.parent(), Some(root.as_path()));
        assert!(is_safe_managed_account_id("acc_safe-1"));
        assert!(!is_safe_managed_account_id("../escape"));
    }

    #[test]
    fn named_managed_slot_never_falls_back_to_a_global_credential() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path();
        assert!(matches!(
            resolve_managed_slot(None, "claude", "acc_a"),
            Err(ProviderError::MissingCredentials(_))
        ));
        assert!(resolve_managed_slot(None, "claude", "../escape").is_err());
        assert!(resolve_managed_slot(None, "../claude", "acc_a").is_err());
        // Only the unnamed legacy account can use the default CLI credential.
        assert_eq!(resolve_managed_slot(None, "claude", "  ").unwrap(), None);
        assert_eq!(
            resolve_managed_slot(Some(config_dir), "claude", "  ").unwrap(),
            None
        );
        assert!(matches!(
            resolve_managed_slot(Some(config_dir), "claude", "acc_a"),
            Err(ProviderError::MissingCredentials(_))
        ));
        assert!(resolve_managed_slot(Some(config_dir), "claude", "../escape").is_err());

        let slot = managed_credential_path(config_dir, "claude", "acc_a").unwrap();
        fs::create_dir_all(slot.parent().unwrap()).unwrap();
        fs::write(&slot, b"{}").unwrap();
        assert_eq!(
            resolve_managed_slot(Some(config_dir), "claude", "acc_a").unwrap(),
            Some(slot)
        );
    }

    #[test]
    fn claude_loads_from_an_explicit_managed_path_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.json");
        // Far-future expiry means no refresh, so no network call is attempted.
        fs::write(
            &path,
            concat!(
                r#"{"claudeAiOauth":{"accessToken":"managed-token","refreshToken":"r","#,
                r#""expiresAt":4070908800000,"scopes":["user:profile"]}}"#,
            ),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let credentials = runtime
            .block_on(ClaudeCredentials::load_and_refresh_from(
                &Client::new(),
                path,
            ))
            .expect("load managed credentials");
        assert_eq!(credentials.access_token, "managed-token");
    }
}
