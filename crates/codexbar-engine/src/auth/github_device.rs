use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub const COPILOT_CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubIdentity {
    pub login: String,
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    Pending,
    SlowDown,
    Authorized { access_token: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PollError {
    #[error("the GitHub device code expired")]
    ExpiredToken,
    #[error("GitHub device authorization was denied")]
    AccessDenied,
    #[error("GitHub device authorization is disabled for this OAuth app")]
    DeviceFlowDisabled,
    #[error("the GitHub OAuth client credentials were rejected")]
    IncorrectClientCredentials,
    #[error("GitHub returned an unknown device authorization error: {0}")]
    Unknown(String),
    #[error("the GitHub device authorization response was invalid")]
    InvalidResponse,
}

#[derive(Debug, Error)]
pub enum DeviceFlowError {
    #[error("GitHub device authorization network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("GitHub device authorization returned HTTP {0}")]
    Http(u16),
    #[error(transparent)]
    Poll(#[from] PollError),
    #[error("GitHub rejected the credential")]
    CredentialRejected,
    #[error("GitHub returned an invalid account identity")]
    InvalidIdentity,
}

#[derive(Clone)]
pub struct GitHubDeviceFlow {
    client: Client,
    base_url: Url,
    client_id: &'static str,
}

impl GitHubDeviceFlow {
    pub fn github_default() -> Self {
        Self::github(Client::new())
    }

    pub fn github(client: Client) -> Self {
        Self {
            client,
            base_url: Url::parse("https://github.com/").expect("GitHub base URL is valid"),
            client_id: COPILOT_CLIENT_ID,
        }
    }

    pub async fn request_code(&self) -> Result<DeviceCode, DeviceFlowError> {
        let url = self
            .base_url
            .join("login/device/code")
            .map_err(|_| DeviceFlowError::InvalidIdentity)?;
        let response = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, "CodexBar")
            .form(&[("client_id", self.client_id), ("scope", "read:user")])
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(DeviceFlowError::Http(status.as_u16()));
        }
        serde_json::from_slice(&bytes).map_err(|_| PollError::InvalidResponse.into())
    }

    pub async fn poll_once(&self, device_code: &str) -> Result<PollOutcome, DeviceFlowError> {
        let url = self
            .base_url
            .join("login/oauth/access_token")
            .map_err(|_| DeviceFlowError::InvalidIdentity)?;
        let response = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, "CodexBar")
            .form(&[
                ("client_id", self.client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(DeviceFlowError::Http(status.as_u16()));
        }
        parse_poll_response(&bytes).map_err(Into::into)
    }

    pub async fn identity(&self, access_token: &str) -> Result<GitHubIdentity, DeviceFlowError> {
        let url = if self.base_url.domain() == Some("github.com") {
            Url::parse("https://api.github.com/user").expect("GitHub API URL is valid")
        } else {
            self.base_url
                .join("user")
                .map_err(|_| DeviceFlowError::InvalidIdentity)?
        };
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, "CodexBar")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(DeviceFlowError::CredentialRejected);
        }
        if !status.is_success() {
            return Err(DeviceFlowError::Http(status.as_u16()));
        }
        let identity = response
            .json::<GitHubIdentity>()
            .await
            .map_err(|_| DeviceFlowError::InvalidIdentity)?;
        if identity.login.trim().is_empty() || identity.id == 0 {
            return Err(DeviceFlowError::InvalidIdentity);
        }
        Ok(identity)
    }
}

pub fn parse_poll_response(bytes: &[u8]) -> Result<PollOutcome, PollError> {
    #[derive(Deserialize)]
    struct Response {
        #[serde(default)]
        access_token: Option<String>,
        #[serde(default)]
        error: Option<String>,
    }

    let response =
        serde_json::from_slice::<Response>(bytes).map_err(|_| PollError::InvalidResponse)?;
    if let Some(access_token) = response
        .access_token
        .filter(|access_token| !access_token.trim().is_empty())
    {
        return Ok(PollOutcome::Authorized { access_token });
    }
    match response.error.as_deref() {
        Some("authorization_pending") => Ok(PollOutcome::Pending),
        Some("slow_down") => Ok(PollOutcome::SlowDown),
        Some("expired_token") => Err(PollError::ExpiredToken),
        Some("access_denied") => Err(PollError::AccessDenied),
        Some("device_flow_disabled") => Err(PollError::DeviceFlowDisabled),
        Some("incorrect_client_credentials") => Err(PollError::IncorrectClientCredentials),
        Some(error) => Err(PollError::Unknown(error.to_owned())),
        None => Err(PollError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };
    use url::Url;

    #[test]
    fn poll_responses_have_deterministic_states() {
        assert_eq!(
            parse_poll_response(br#"{"error":"authorization_pending"}"#).unwrap(),
            PollOutcome::Pending,
        );
        assert_eq!(
            parse_poll_response(br#"{"error":"slow_down"}"#).unwrap(),
            PollOutcome::SlowDown,
        );
        assert_eq!(
            parse_poll_response(
                br#"{"access_token":"gho_test","token_type":"bearer","scope":"read:user"}"#
            )
            .unwrap(),
            PollOutcome::Authorized {
                access_token: "gho_test".to_owned(),
            },
        );
        assert_eq!(
            parse_poll_response(br#"{"error":"expired_token"}"#).unwrap_err(),
            PollError::ExpiredToken,
        );
        assert_eq!(
            parse_poll_response(br#"{"error":"access_denied"}"#).unwrap_err(),
            PollError::AccessDenied,
        );
        assert_eq!(
            parse_poll_response(br#"{"error":"device_flow_disabled"}"#).unwrap_err(),
            PollError::DeviceFlowDisabled,
        );
        assert_eq!(
            parse_poll_response(br#"{"error":"incorrect_client_credentials"}"#).unwrap_err(),
            PollError::IncorrectClientCredentials,
        );
        assert_eq!(
            parse_poll_response(br#"{"error":"something_new"}"#).unwrap_err(),
            PollError::Unknown("something_new".to_owned()),
        );
    }

    #[test]
    fn request_code_uses_the_github_form_contract() {
        let (base_url, request) = one_shot_server(
            200,
            br#"{"device_code":"device code","user_code":"ABCD-EFGH","verification_uri":"https://github.com/login/device","verification_uri_complete":"https://github.com/login/device?user_code=ABCD-EFGH","expires_in":900,"interval":5}"#,
        );
        let flow = test_flow(base_url);
        let code = runtime().block_on(flow.request_code()).unwrap();
        let request = request.recv().unwrap();

        assert_eq!(code.user_code, "ABCD-EFGH");
        assert!(request.starts_with("POST /login/device/code HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("accept: application/json\r\n")
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/x-www-form-urlencoded\r\n")
        );
        assert!(request.ends_with("client_id=Iv1.b507a08c87ecfe98&scope=read%3Auser"));
    }

    #[test]
    fn poll_once_form_encodes_the_device_code_and_grant_type() {
        let (base_url, request) = one_shot_server(200, br#"{"error":"authorization_pending"}"#);
        let flow = test_flow(base_url);
        let outcome = runtime()
            .block_on(flow.poll_once("code with spaces"))
            .unwrap();
        let request = request.recv().unwrap();

        assert_eq!(outcome, PollOutcome::Pending);
        assert!(request.starts_with("POST /login/oauth/access_token HTTP/1.1\r\n"));
        assert!(request.contains("client_id=Iv1.b507a08c87ecfe98"));
        assert!(request.contains("device_code=code+with+spaces"));
        assert!(
            request.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
        );
    }

    #[test]
    fn identity_requires_a_non_empty_login_and_numeric_id() {
        let (base_url, request) = one_shot_server(200, br#"{"login":"octocat","id":583231}"#);
        let flow = test_flow(base_url);
        let identity = runtime().block_on(flow.identity("secret-token")).unwrap();
        let request = request.recv().unwrap();

        assert_eq!(
            identity,
            GitHubIdentity {
                login: "octocat".to_owned(),
                id: 583_231,
            }
        );
        assert!(request.starts_with("GET /user HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer secret-token\r\n")
        );
    }

    #[test]
    fn identity_rejects_bad_credentials_without_exposing_the_token() {
        let (base_url, _request) = one_shot_server(401, br#"{"message":"Bad credentials"}"#);
        let flow = test_flow(base_url);
        let error = runtime()
            .block_on(flow.identity("top-secret-token"))
            .unwrap_err();

        assert!(matches!(error, DeviceFlowError::CredentialRejected));
        assert!(!format!("{error:?} {error}").contains("top-secret-token"));
    }

    fn test_flow(base_url: Url) -> GitHubDeviceFlow {
        GitHubDeviceFlow {
            client: Client::new(),
            base_url,
            client_id: COPILOT_CLIENT_ID,
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn one_shot_server(status: u16, body: &'static [u8]) -> (Url, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 2048];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if request_is_complete(&bytes) {
                    break;
                }
            }
            sender.send(String::from_utf8(bytes).unwrap()).unwrap();
            let reason = if status == 200 { "OK" } else { "Unauthorized" };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), receiver)
    }

    fn request_is_complete(bytes: &[u8]) -> bool {
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or_default();
        bytes.len() >= header_end + content_length
    }
}
