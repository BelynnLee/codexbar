use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::env;

#[derive(Default)]
pub struct MoonshotProvider {
    /// Optional transport seam used by local tests and embedders that route requests through an
    /// HTTP fixture. Region validation still runs before this override is applied.
    api_base_url: Option<String>,
}

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Moonshot,
    display_name: "Moonshot",
    auth_kind: AuthKind::ApiKey,
    color: "#1a1a1a",
    dashboard_url: "https://platform.moonshot.ai/console/account",
    credential_hint: "Set an API key in Settings or MOONSHOT_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Moonshot),
};

const INTERNATIONAL_BALANCE_URL: &str = "https://api.moonshot.ai/v1/users/me/balance";
const CHINA_BALANCE_URL: &str = "https://api.moonshot.cn/v1/users/me/balance";
const BALANCE_PATH: &str = "/v1/users/me/balance";

#[async_trait]
impl Provider for MoonshotProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let balance_url = self.balance_url(account)?;
        let api_key = resolve_api_key(account)?;
        let response = context
            .client
            .get(balance_url)
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "Moonshot API key is invalid.".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "Moonshot",
                status: response.status().as_u16(),
            });
        }
        let balance: BalanceResponse = response.json().await?;
        map_usage(balance)
    }
}

impl MoonshotProvider {
    fn balance_url(&self, account: &ProviderAccount) -> Result<String, ProviderError> {
        let regional_url = balance_url_for_region(account.region.as_deref())?;
        Ok(self.api_base_url.as_ref().map_or_else(
            || regional_url.to_owned(),
            |base_url| format!("{}{BALANCE_PATH}", base_url.trim_end_matches('/')),
        ))
    }
}

fn balance_url_for_region(region: Option<&str>) -> Result<&'static str, ProviderError> {
    match region.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("international") => Ok(INTERNATIONAL_BALANCE_URL),
        Some("china") => Ok(CHINA_BALANCE_URL),
        Some(region) => Err(ProviderError::Platform(format!(
            "Unsupported Moonshot region: {region}"
        ))),
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("MOONSHOT_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing Moonshot API key.".into()))
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    code: i64,
    #[serde(default)]
    scode: String,
    status: bool,
    data: BalanceData,
}

#[derive(Debug, Deserialize)]
struct BalanceData {
    available_balance: f64,
    #[allow(dead_code)]
    voucher_balance: f64,
    cash_balance: f64,
}

fn map_usage(balance: BalanceResponse) -> Result<ProviderSnapshot, ProviderError> {
    if balance.code != 0 || !balance.status {
        return Err(ProviderError::Parse {
            provider: "Moonshot",
            message: format!("code {}, scode {}", balance.code, balance.scode),
        });
    }
    let mut snapshot = ProviderSnapshot::new(ProviderId::Moonshot, "api key");
    let available = balance.data.available_balance;
    snapshot.financials = Some(FinancialSnapshot {
        balance: Some(available),
        spend: None,
        currency: Some("USD".into()),
    });
    snapshot
        .summary
        .push(SummaryItem::new("Balance", format!("${available:.2}")));
    if balance.data.cash_balance < 0.0 {
        snapshot.summary.push(SummaryItem::new(
            "Deficit",
            format!("${:.2} in deficit", balance.data.cash_balance.abs()),
        ));
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    fn serve_once(status: u16, body: &'static str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("mock address");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2048];
            loop {
                let read = stream.read(&mut chunk).expect("read mock request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            sender
                .send(String::from_utf8(request).expect("UTF-8 HTTP request"))
                .expect("capture request");
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write mock response");
        });
        (format!("http://{address}"), receiver)
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn region_selects_the_matching_moonshot_balance_url() {
        assert_eq!(
            balance_url_for_region(None).expect("default region"),
            "https://api.moonshot.ai/v1/users/me/balance"
        );
        assert_eq!(
            balance_url_for_region(Some("  ")).expect("blank region"),
            "https://api.moonshot.ai/v1/users/me/balance"
        );
        assert_eq!(
            balance_url_for_region(Some("international")).expect("international region"),
            "https://api.moonshot.ai/v1/users/me/balance"
        );
        assert_eq!(
            balance_url_for_region(Some("china")).expect("China region"),
            "https://api.moonshot.cn/v1/users/me/balance"
        );
        assert!(matches!(
            balance_url_for_region(Some("moon")),
            Err(ProviderError::Platform(_))
        ));
    }

    #[test]
    fn regional_request_uses_local_transport_seam_path_and_bearer_auth() {
        runtime().block_on(async {
            let body = r#"{"code":0,"scode":"0x0","status":true,"data":{"available_balance":12.5,"voucher_balance":2.5,"cash_balance":10.0}}"#;
            let (base_url, request) = serve_once(200, body);
            let provider = MoonshotProvider {
                api_base_url: Some(base_url),
            };
            let client = reqwest::Client::new();
            let config = crate::config::AppConfig::default();
            let context = FetchContext {
                client: &client,
                config: &config,
                config_dir: None,
            };
            let account = ProviderAccount {
                api_key: Some("moonshot-fixture-key".into()),
                region: Some("china".into()),
                ..Default::default()
            };

            let snapshot = provider.fetch(&context, &account).await.expect("usage");

            assert_eq!(snapshot.financials.unwrap().balance, Some(12.5));
            let request = request
                .recv_timeout(Duration::from_secs(5))
                .expect("captured request");
            assert!(request.starts_with("GET /v1/users/me/balance HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer moonshot-fixture-key")
            );
        });
    }

    #[test]
    fn maps_available_balance_as_usd_financials() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "code": 0,
            "scode": "0x0",
            "status": true,
            "data": { "available_balance": 12.5, "voucher_balance": 2.5, "cash_balance": 10.0 }
        }))
        .expect("balance");
        let snapshot = map_usage(balance).expect("usage");
        assert_eq!(snapshot.summary[0].value, "$12.50");
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(financials.balance, Some(12.5));
        assert_eq!(financials.currency.as_deref(), Some("USD"));
        assert!(snapshot.summary.iter().all(|item| item.label != "Deficit"));
    }

    #[test]
    fn surfaces_negative_cash_balance_as_deficit() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "code": 0,
            "scode": "0x0",
            "status": true,
            "data": { "available_balance": 0.0, "voucher_balance": 0.0, "cash_balance": -3.25 }
        }))
        .expect("balance");
        let snapshot = map_usage(balance).expect("usage");
        let deficit = snapshot
            .summary
            .iter()
            .find(|item| item.label == "Deficit")
            .expect("deficit");
        assert_eq!(deficit.value, "$3.25 in deficit");
    }

    #[test]
    fn rejects_error_response_codes() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "code": 1,
            "scode": "0x1",
            "status": false,
            "data": { "available_balance": 0.0, "voucher_balance": 0.0, "cash_balance": 0.0 }
        }))
        .expect("balance");
        assert!(matches!(
            map_usage(balance),
            Err(ProviderError::Parse {
                provider: "Moonshot",
                ..
            })
        ));
    }
}
