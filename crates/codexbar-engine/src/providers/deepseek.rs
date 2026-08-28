use crate::{
    config::{ProviderAccount, ProviderConfig},
    model::{
        AuthKind, FinancialSnapshot, ProviderDescriptor, ProviderId, ProviderSnapshot, SummaryItem,
    },
    provider::{FetchContext, Provider, ProviderError},
};
use async_trait::async_trait;
use chrono::{Datelike, Utc};
use serde::Deserialize;
use std::{collections::HashMap, env};

pub struct DeepSeekProvider;

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: ProviderId::Deepseek,
    display_name: "DeepSeek",
    auth_kind: AuthKind::ApiKey,
    color: "#4d6bfe",
    dashboard_url: "https://platform.deepseek.com/usage",
    credential_hint: "Set an API key in Settings or DEEPSEEK_API_KEY.",
    supports_multiple_accounts: true,
    capabilities: crate::model::provider_capabilities(ProviderId::Deepseek),
};

#[async_trait]
impl Provider for DeepSeekProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn fetch(
        &self,
        context: &FetchContext<'_>,
        account: &ProviderAccount,
    ) -> Result<ProviderSnapshot, ProviderError> {
        let api_key = resolve_api_key(account)?;
        let balance_response = context
            .client
            .get("https://api.deepseek.com/user/balance")
            .bearer_auth(&api_key)
            .header("Accept", "application/json")
            .send()
            .await?;
        if matches!(balance_response.status().as_u16(), 401 | 403) {
            return Err(ProviderError::Unauthorized(
                "DeepSeek API key is invalid.".into(),
            ));
        }
        if !balance_response.status().is_success() {
            return Err(ProviderError::Http {
                provider: "DeepSeek",
                status: balance_response.status().as_u16(),
            });
        }
        let balance: BalanceResponse = balance_response.json().await?;

        // The platform usage APIs are best-effort enrichment and do not invalidate the required balance result.
        let now = Utc::now();
        let query = [
            ("month", now.month().to_string()),
            ("year", now.year().to_string()),
        ];
        let amount = fetch_optional::<AmountPayload>(
            context,
            "https://platform.deepseek.com/api/v0/usage/amount",
            &api_key,
            &query,
        )
        .await;
        let cost = fetch_optional::<CostPayload>(
            context,
            "https://platform.deepseek.com/api/v0/usage/cost",
            &api_key,
            &query,
        )
        .await;
        map_usage(balance, amount.zip(cost))
    }
}

fn resolve_api_key(account: &ProviderAccount) -> Result<String, ProviderError> {
    ProviderConfig::normalized_secret(&account.api_key)
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("DEEPSEEK_API_KEY")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| ProviderError::MissingCredentials("Missing DeepSeek API key.".into()))
}

async fn fetch_optional<T: for<'de> Deserialize<'de>>(
    context: &FetchContext<'_>,
    url: &str,
    api_key: &str,
    query: &[(&str, String)],
) -> Option<T> {
    let response = context
        .client
        .get(url)
        .bearer_auth(api_key)
        .header("Accept", "application/json")
        .query(query)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json().await.ok()
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    is_available: bool,
    balance_infos: Vec<BalanceInfo>,
}

#[derive(Debug, Deserialize)]
struct BalanceInfo {
    currency: String,
    total_balance: String,
    granted_balance: String,
    topped_up_balance: String,
}

#[derive(Debug, Deserialize)]
struct AmountPayload {
    code: Option<i64>,
    data: Option<AmountData>,
}

#[derive(Debug, Deserialize)]
struct AmountData {
    biz_code: Option<i64>,
    biz_data: Option<AmountBizData>,
}

#[derive(Debug, Deserialize)]
struct AmountBizData {
    #[serde(default)]
    total: Vec<ModelUsage>,
    #[serde(default)]
    days: Vec<DayUsage>,
}

#[derive(Debug, Deserialize)]
struct ModelUsage {
    model: Option<String>,
    #[serde(default)]
    usage: Vec<UsageItem>,
}

#[derive(Debug, Deserialize)]
struct DayUsage {
    date: Option<String>,
    #[serde(default)]
    data: Vec<ModelUsage>,
}

#[derive(Debug, Deserialize)]
struct UsageItem {
    #[serde(rename = "type")]
    category: Option<String>,
    amount: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CostPayload {
    code: Option<i64>,
    data: Option<CostData>,
}

#[derive(Debug, Deserialize)]
struct CostData {
    biz_code: Option<i64>,
    #[serde(default)]
    biz_data: Vec<CostBizData>,
}

#[derive(Debug, Deserialize)]
struct CostBizData {
    currency: Option<String>,
    #[serde(default)]
    total: Vec<ModelUsage>,
    #[serde(default)]
    days: Vec<DayUsage>,
}

fn map_usage(
    balance: BalanceResponse,
    detail: Option<(AmountPayload, CostPayload)>,
) -> Result<ProviderSnapshot, ProviderError> {
    let mut snapshot = ProviderSnapshot::new(ProviderId::Deepseek, "api key");
    let balances = balance
        .balance_infos
        .into_iter()
        .filter_map(|balance| {
            Some((
                balance.currency,
                balance.total_balance.parse::<f64>().ok()?,
                balance.granted_balance.parse::<f64>().ok()?,
                balance.topped_up_balance.parse::<f64>().ok()?,
            ))
        })
        .collect::<Vec<_>>();
    let selected = balances
        .iter()
        .find(|(currency, total, _, _)| currency == "USD" && *total > 0.0)
        .or_else(|| balances.iter().find(|(_, total, _, _)| *total > 0.0))
        .or_else(|| {
            balances
                .iter()
                .find(|(currency, _, _, _)| currency == "USD")
        })
        .or_else(|| balances.first());
    if let Some((currency, total, granted, topped_up)) = selected {
        let symbol = currency_symbol(currency);
        snapshot.financials = Some(FinancialSnapshot {
            balance: Some(*total),
            spend: None,
            currency: Some(currency.clone()),
        });
        snapshot.summary.extend([
            SummaryItem::new("Balance", format!("{symbol}{total:.2} {currency}")),
            SummaryItem::new(
                "Paid / granted",
                format!("{symbol}{topped_up:.2} / {symbol}{granted:.2}"),
            ),
            SummaryItem::new(
                "API availability",
                if balance.is_available {
                    "Available"
                } else {
                    "Unavailable"
                },
            ),
        ]);
    } else {
        snapshot
            .summary
            .push(SummaryItem::new("Balance", "No balance returned"));
    }

    if let Some((amount, cost)) = detail {
        if amount.code.unwrap_or(0) == 0
            && amount
                .data
                .as_ref()
                .and_then(|data| data.biz_code)
                .unwrap_or(0)
                == 0
            && cost.code.unwrap_or(0) == 0
            && cost
                .data
                .as_ref()
                .and_then(|data| data.biz_code)
                .unwrap_or(0)
                == 0
        {
            add_usage_summary(&mut snapshot, amount, cost);
        }
    }
    Ok(snapshot)
}

fn add_usage_summary(snapshot: &mut ProviderSnapshot, amount: AmountPayload, cost: CostPayload) {
    let Some(amount) = amount.data.and_then(|data| data.biz_data) else {
        return;
    };
    let cost = cost.data.and_then(|data| data.biz_data.into_iter().next());
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let (month_tokens, month_requests, top_model) = aggregate_totals(&amount.total);
    let (today_tokens, today_requests, _) = amount
        .days
        .iter()
        .find(|day| day.date.as_deref() == Some(today.as_str()))
        .map_or((0, 0, None), |day| aggregate_totals(&day.data));
    snapshot.summary.extend([
        SummaryItem::new("Today", format_tokens(today_tokens, today_requests)),
        SummaryItem::new("This month", format_tokens(month_tokens, month_requests)),
    ]);
    if let Some(model) = top_model {
        snapshot.summary.push(SummaryItem::new("Top model", model));
    }
    if let Some(cost) = cost {
        let currency = cost.currency.unwrap_or_else(|| "CNY".into());
        let symbol = currency_symbol(&currency);
        let month_cost = aggregate_cost(&cost.total);
        let today_cost = cost
            .days
            .iter()
            .find(|day| day.date.as_deref() == Some(today.as_str()))
            .map_or(0.0, |day| aggregate_cost(&day.data));
        let same_currency = snapshot
            .financials
            .as_ref()
            .and_then(|financials| financials.currency.as_deref())
            .is_none_or(|balance_currency| balance_currency.eq_ignore_ascii_case(&currency));
        if same_currency {
            let financials = snapshot
                .financials
                .get_or_insert_with(|| FinancialSnapshot {
                    balance: None,
                    spend: None,
                    currency: Some(currency.clone()),
                });
            financials.spend = Some(month_cost);
        }
        snapshot.summary.push(SummaryItem::new(
            "Cost today / month",
            format!("{symbol}{today_cost:.4} / {symbol}{month_cost:.4} {currency}"),
        ));
    }
}

fn aggregate_totals(models: &[ModelUsage]) -> (u64, u64, Option<String>) {
    let mut tokens = 0_u64;
    let mut requests = 0_u64;
    let mut model_tokens = HashMap::<String, u64>::new();
    for model in models {
        let mut total_for_model = 0_u64;
        for item in &model.usage {
            let amount = item
                .amount
                .as_deref()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            if item.category.as_deref() == Some("REQUEST") {
                requests = requests.saturating_add(amount);
            } else if matches!(
                item.category.as_deref(),
                Some("PROMPT_CACHE_HIT_TOKEN" | "PROMPT_CACHE_MISS_TOKEN" | "RESPONSE_TOKEN")
            ) {
                tokens = tokens.saturating_add(amount);
                total_for_model = total_for_model.saturating_add(amount);
            }
        }
        if let Some(model) = &model.model {
            model_tokens.insert(model.clone(), total_for_model);
        }
    }
    let top_model = model_tokens
        .into_iter()
        .max_by_key(|(_, tokens)| *tokens)
        .map(|(model, _)| model);
    (tokens, requests, top_model)
}

fn aggregate_cost(models: &[ModelUsage]) -> f64 {
    models
        .iter()
        .flat_map(|model| &model.usage)
        .filter(|item| item.category.as_deref() != Some("REQUEST"))
        .filter_map(|item| item.amount.as_deref()?.parse::<f64>().ok())
        .sum()
}

fn format_tokens(tokens: u64, requests: u64) -> String {
    format!("{tokens} tokens · {requests} requests")
}

fn currency_symbol(currency: &str) -> &'static str {
    match currency.to_ascii_uppercase().as_str() {
        "USD" => "$",
        "CNY" => "¥",
        "EUR" => "€",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_known_deepseek_categories() {
        let models = vec![ModelUsage {
            model: Some("deepseek-chat".into()),
            usage: vec![
                UsageItem {
                    category: Some("PROMPT_CACHE_HIT_TOKEN".into()),
                    amount: Some("100".into()),
                },
                UsageItem {
                    category: Some("RESPONSE_TOKEN".into()),
                    amount: Some("50".into()),
                },
                UsageItem {
                    category: Some("REQUEST".into()),
                    amount: Some("3".into()),
                },
                UsageItem {
                    category: Some("UNKNOWN".into()),
                    amount: Some("999".into()),
                },
            ],
        }];
        assert_eq!(
            aggregate_totals(&models),
            (150, 3, Some("deepseek-chat".into()))
        );
    }

    #[test]
    fn chooses_positive_cny_over_empty_usd_balance() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "is_available": true,
            "balance_infos": [
                { "currency": "USD", "total_balance": "0", "granted_balance": "0", "topped_up_balance": "0" },
                { "currency": "CNY", "total_balance": "12.5", "granted_balance": "2.5", "topped_up_balance": "10" }
            ]
        }))
        .expect("balance");
        let snapshot = map_usage(balance, None).expect("usage");
        assert_eq!(snapshot.summary[0].value, "¥12.50 CNY");
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(financials.balance, Some(12.5));
        assert_eq!(financials.spend, None);
        assert_eq!(financials.currency.as_deref(), Some("CNY"));
    }

    #[test]
    fn exposes_monthly_cost_as_structured_spend() {
        let balance: BalanceResponse = serde_json::from_value(serde_json::json!({
            "is_available": true,
            "balance_infos": [
                { "currency": "USD", "total_balance": "8", "granted_balance": "3", "topped_up_balance": "5" }
            ]
        }))
        .expect("balance");
        let amount: AmountPayload = serde_json::from_value(serde_json::json!({
            "code": 0,
            "data": { "biz_code": 0, "biz_data": { "total": [], "days": [] } }
        }))
        .expect("amount");
        let cost: CostPayload = serde_json::from_value(serde_json::json!({
            "code": 0,
            "data": {
                "biz_code": 0,
                "biz_data": [{
                    "currency": "USD",
                    "total": [{
                        "model": "deepseek-chat",
                        "usage": [{ "type": "TOKEN", "amount": "1.25" }]
                    }],
                    "days": []
                }]
            }
        }))
        .expect("cost");

        let snapshot = map_usage(balance, Some((amount, cost))).expect("usage");
        let financials = snapshot.financials.as_ref().expect("financials");
        assert_eq!(financials.balance, Some(8.0));
        assert_eq!(financials.spend, Some(1.25));
        assert_eq!(financials.currency.as_deref(), Some("USD"));
        let cost_summary = snapshot
            .summary
            .iter()
            .find(|item| item.label == "Cost today / month")
            .expect("cost summary");
        assert_eq!(cost_summary.value, "$0.0000 / $1.2500 USD");
    }
}
