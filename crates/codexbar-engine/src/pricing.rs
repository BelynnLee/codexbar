use crate::cost::{CostProvider, TokenUsage};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPrice {
    pub input_per_million: f64,
    pub output_per_million: f64,
    pub cache_creation_per_million: f64,
    pub cache_read_per_million: f64,
}

#[derive(Debug, Clone, Copy)]
struct PriceSchedule {
    standard: ModelPrice,
    threshold_tokens: Option<u64>,
    above_threshold: Option<ModelPrice>,
    priority: Option<ModelPrice>,
}

const fn price(input: f64, output: f64, cache_creation: f64, cache_read: f64) -> ModelPrice {
    ModelPrice {
        input_per_million: input,
        output_per_million: output,
        cache_creation_per_million: cache_creation,
        cache_read_per_million: cache_read,
    }
}

const fn standard(input: f64, output: f64, cache_creation: f64, cache_read: f64) -> PriceSchedule {
    PriceSchedule {
        standard: price(input, output, cache_creation, cache_read),
        threshold_tokens: None,
        above_threshold: None,
        priority: None,
    }
}

const fn long_context(
    standard_price: ModelPrice,
    threshold_tokens: u64,
    above_threshold: ModelPrice,
) -> PriceSchedule {
    PriceSchedule {
        standard: standard_price,
        threshold_tokens: Some(threshold_tokens),
        above_threshold: Some(above_threshold),
        priority: None,
    }
}

const fn with_priority(mut schedule: PriceSchedule, priority: ModelPrice) -> PriceSchedule {
    schedule.priority = Some(priority);
    schedule
}

const GPT_5: PriceSchedule = standard(1.25, 10.0, 1.25, 0.125);
const GPT_5_MINI: PriceSchedule = standard(0.25, 2.0, 0.25, 0.025);
const GPT_5_NANO: PriceSchedule = standard(0.05, 0.4, 0.05, 0.005);
const GPT_5_PRO: PriceSchedule = standard(15.0, 120.0, 15.0, 15.0);
const GPT_5_2: PriceSchedule = standard(1.75, 14.0, 1.75, 0.175);
const GPT_5_2_PRO: PriceSchedule = standard(21.0, 168.0, 21.0, 21.0);
const GPT_5_3_SPARK: PriceSchedule = standard(0.0, 0.0, 0.0, 0.0);
const GPT_5_4: PriceSchedule = with_priority(
    long_context(
        price(2.5, 15.0, 2.5, 0.25),
        272_000,
        price(5.0, 22.5, 5.0, 0.5),
    ),
    price(5.0, 30.0, 5.0, 0.5),
);
const GPT_5_4_MINI: PriceSchedule =
    with_priority(standard(0.75, 4.5, 0.75, 0.075), price(1.5, 9.0, 1.5, 0.15));
const GPT_5_4_NANO: PriceSchedule = standard(0.2, 1.25, 0.2, 0.02);
const GPT_5_4_PRO: PriceSchedule = standard(30.0, 180.0, 30.0, 30.0);
const GPT_5_5: PriceSchedule = with_priority(
    long_context(
        price(5.0, 30.0, 5.0, 0.5),
        272_000,
        price(10.0, 45.0, 10.0, 1.0),
    ),
    price(12.5, 75.0, 12.5, 1.25),
);
const GPT_5_6_SOL: PriceSchedule = with_priority(
    long_context(
        price(5.0, 30.0, 6.25, 0.5),
        272_000,
        price(10.0, 45.0, 12.5, 1.0),
    ),
    price(10.0, 60.0, 12.5, 1.0),
);
const GPT_5_6_TERRA: PriceSchedule = with_priority(
    long_context(
        price(2.5, 15.0, 3.125, 0.25),
        272_000,
        price(5.0, 22.5, 6.25, 0.5),
    ),
    price(5.0, 30.0, 6.25, 0.5),
);
const GPT_5_6_LUNA: PriceSchedule = with_priority(
    long_context(
        price(1.0, 6.0, 1.25, 0.1),
        272_000,
        price(2.0, 9.0, 2.5, 0.2),
    ),
    price(2.0, 12.0, 2.5, 0.2),
);

const CODEX_CATALOG: &[(&str, PriceSchedule)] = &[
    ("gpt-5", GPT_5),
    ("gpt-5-codex", GPT_5),
    ("gpt-5-mini", GPT_5_MINI),
    ("gpt-5-nano", GPT_5_NANO),
    ("gpt-5-pro", GPT_5_PRO),
    ("gpt-5.1", GPT_5),
    ("gpt-5.1-codex", GPT_5),
    ("gpt-5.1-codex-max", GPT_5),
    ("gpt-5.1-codex-mini", GPT_5_MINI),
    ("gpt-5.2", GPT_5_2),
    ("gpt-5.2-codex", GPT_5_2),
    ("gpt-5.2-pro", GPT_5_2_PRO),
    ("gpt-5.3-codex", GPT_5_2),
    ("gpt-5.3-codex-spark", GPT_5_3_SPARK),
    ("gpt-5.4", GPT_5_4),
    ("gpt-5.4-mini", GPT_5_4_MINI),
    ("gpt-5.4-nano", GPT_5_4_NANO),
    ("gpt-5.4-pro", GPT_5_4_PRO),
    ("gpt-5.5", GPT_5_5),
    ("gpt-5.5-pro", GPT_5_4_PRO),
    ("gpt-5.6-sol", GPT_5_6_SOL),
    ("gpt-5.6-terra", GPT_5_6_TERRA),
    ("gpt-5.6-luna", GPT_5_6_LUNA),
];

pub const CODEX_MODELS: &[&str] = &[
    "gpt-5",
    "gpt-5-codex",
    "gpt-5-mini",
    "gpt-5-nano",
    "gpt-5-pro",
    "gpt-5.1",
    "gpt-5.1-codex",
    "gpt-5.1-codex-max",
    "gpt-5.1-codex-mini",
    "gpt-5.2",
    "gpt-5.2-codex",
    "gpt-5.2-pro",
    "gpt-5.3-codex",
    "gpt-5.3-codex-spark",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5.4-pro",
    "gpt-5.5",
    "gpt-5.5-pro",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
];

const CLAUDE_FABLE_5: PriceSchedule = standard(10.0, 50.0, 12.5, 1.0);
const CLAUDE_HAIKU_4_5: PriceSchedule = standard(1.0, 5.0, 1.25, 0.1);
const CLAUDE_OPUS_4_5: PriceSchedule = standard(5.0, 25.0, 6.25, 0.5);
const CLAUDE_SONNET_4_5: PriceSchedule = long_context(
    price(3.0, 15.0, 3.75, 0.3),
    200_000,
    price(6.0, 22.5, 7.5, 0.6),
);
const CLAUDE_SONNET_4_6: PriceSchedule = standard(3.0, 15.0, 3.75, 0.3);
const CLAUDE_OPUS_4: PriceSchedule = standard(15.0, 75.0, 18.75, 1.5);

const CLAUDE_CATALOG: &[(&str, PriceSchedule)] = &[
    ("claude-fable-5", CLAUDE_FABLE_5),
    ("claude-haiku-4-5-20251001", CLAUDE_HAIKU_4_5),
    ("claude-haiku-4-5", CLAUDE_HAIKU_4_5),
    ("claude-opus-4-5-20251101", CLAUDE_OPUS_4_5),
    ("claude-opus-4-5", CLAUDE_OPUS_4_5),
    ("claude-opus-4-6-20260205", CLAUDE_OPUS_4_5),
    ("claude-opus-4-6", CLAUDE_OPUS_4_5),
    ("claude-opus-4-7", CLAUDE_OPUS_4_5),
    ("claude-opus-4-8", CLAUDE_OPUS_4_5),
    ("claude-sonnet-4-5", CLAUDE_SONNET_4_5),
    ("claude-sonnet-4-6", CLAUDE_SONNET_4_6),
    ("claude-sonnet-4-5-20250929", CLAUDE_SONNET_4_5),
    ("claude-opus-4-20250514", CLAUDE_OPUS_4),
    ("claude-opus-4-1", CLAUDE_OPUS_4),
    ("claude-sonnet-4-20250514", CLAUDE_SONNET_4_5),
];

pub const CLAUDE_MODELS: &[&str] = &[
    "claude-fable-5",
    "claude-haiku-4-5-20251001",
    "claude-haiku-4-5",
    "claude-opus-4-5-20251101",
    "claude-opus-4-5",
    "claude-opus-4-6-20260205",
    "claude-opus-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-sonnet-4-5",
    "claude-sonnet-4-6",
    "claude-sonnet-4-5-20250929",
    "claude-opus-4-20250514",
    "claude-opus-4-1",
    "claude-sonnet-4-20250514",
];

const CLAUDE_PRICING_CUTOFF: i64 = 1_773_360_000;
const CLAUDE_OPUS_4_6_HISTORICAL: PriceSchedule = long_context(
    price(5.0, 25.0, 6.25, 0.5),
    200_000,
    price(10.0, 37.5, 12.5, 1.0),
);
const CLAUDE_SONNET_4_6_HISTORICAL: PriceSchedule = long_context(
    price(3.0, 15.0, 3.75, 0.3),
    200_000,
    price(6.0, 22.5, 7.5, 0.6),
);

pub fn canonical_model(provider: CostProvider, raw: &str) -> String {
    match provider {
        CostProvider::Codex => normalize_codex_model(raw),
        CostProvider::Claude => normalize_claude_model(raw),
        CostProvider::Both => raw.trim().to_owned(),
    }
}

pub fn price_for(provider: CostProvider, model: &str) -> Option<ModelPrice> {
    schedule_for(provider, model).map(|schedule| schedule.standard)
}

pub fn priority_price_for(model: &str) -> Option<ModelPrice> {
    codex_schedule(&normalize_codex_model(model)).and_then(|schedule| schedule.priority)
}

pub const CODEX_PRIORITY_INPUT_TOKEN_LIMIT: u64 = 272_000;

pub fn priority_cost_for(model: &str, usage: TokenUsage) -> Option<f64> {
    let context_tokens = usage
        .input
        .saturating_add(usage.cache_creation)
        .saturating_add(usage.cache_read);
    if context_tokens > CODEX_PRIORITY_INPUT_TOKEN_LIMIT {
        return None;
    }
    let selected = priority_price_for(model)?;
    Some(cost_with_price(selected, usage))
}

pub fn cost_for(provider: CostProvider, model: &str, usage: TokenUsage) -> Option<f64> {
    schedule_for(provider, model).map(|schedule| cost_with_schedule(schedule, usage))
}

pub fn cost_for_at(
    provider: CostProvider,
    model: &str,
    usage: TokenUsage,
    timestamp: DateTime<Utc>,
) -> Option<f64> {
    cost_for_at_with_cache_creation_1h(provider, model, usage, 0, timestamp)
}

pub(crate) fn cost_for_at_with_cache_creation_1h(
    provider: CostProvider,
    model: &str,
    usage: TokenUsage,
    cache_creation_1h: u64,
    timestamp: DateTime<Utc>,
) -> Option<f64> {
    let schedule = match provider {
        CostProvider::Claude if timestamp.timestamp() < CLAUDE_PRICING_CUTOFF => {
            let normalized = normalize_claude_model(model);
            match normalized.as_str() {
                "claude-opus-4-6" => Some(CLAUDE_OPUS_4_6_HISTORICAL),
                "claude-sonnet-4-6" => Some(CLAUDE_SONNET_4_6_HISTORICAL),
                _ => claude_schedule(&normalized),
            }
        }
        _ => schedule_for(provider, model),
    }?;
    Some(cost_with_schedule_and_cache_creation_1h(
        schedule,
        usage,
        cache_creation_1h,
    ))
}

fn schedule_for(provider: CostProvider, model: &str) -> Option<PriceSchedule> {
    match provider {
        CostProvider::Codex => codex_schedule(&normalize_codex_model(model)),
        CostProvider::Claude => claude_schedule(&normalize_claude_model(model)),
        CostProvider::Both => None,
    }
}

fn codex_schedule(model: &str) -> Option<PriceSchedule> {
    CODEX_CATALOG
        .iter()
        .find(|entry| entry.0 == model)
        .map(|entry| entry.1)
}

fn claude_schedule(model: &str) -> Option<PriceSchedule> {
    CLAUDE_CATALOG
        .iter()
        .find(|entry| entry.0 == model)
        .map(|entry| entry.1)
}

fn cost_with_schedule(schedule: PriceSchedule, usage: TokenUsage) -> f64 {
    cost_with_schedule_and_cache_creation_1h(schedule, usage, 0)
}

fn cost_with_schedule_and_cache_creation_1h(
    schedule: PriceSchedule,
    usage: TokenUsage,
    cache_creation_1h: u64,
) -> f64 {
    let context_tokens = usage
        .input
        .saturating_add(usage.cache_creation)
        .saturating_add(usage.cache_read);
    let selected = match (schedule.threshold_tokens, schedule.above_threshold) {
        (Some(threshold), Some(above)) if context_tokens > threshold => above,
        _ => schedule.standard,
    };
    let cache_creation_1h = cache_creation_1h.min(usage.cache_creation);
    let cache_creation_5m = usage.cache_creation - cache_creation_1h;
    let standard_cost = cost_with_price(
        selected,
        TokenUsage {
            cache_creation: cache_creation_5m,
            ..usage
        },
    );
    standard_cost + cache_creation_1h as f64 * (selected.input_per_million * 2.0) / 1_000_000.0
}

fn cost_with_price(selected: ModelPrice, usage: TokenUsage) -> f64 {
    (usage.input as f64 * selected.input_per_million
        + usage.output as f64 * selected.output_per_million
        + usage.cache_creation as f64 * selected.cache_creation_per_million
        + usage.cache_read as f64 * selected.cache_read_per_million)
        / 1_000_000.0
}

fn normalize_codex_model(raw: &str) -> String {
    let trimmed = raw.trim().strip_prefix("openai/").unwrap_or(raw.trim());
    if trimmed == "gpt-5.6" {
        return "gpt-5.6-sol".to_owned();
    }
    if codex_schedule(trimmed).is_some() {
        return trimmed.to_owned();
    }
    if let Some(base) = strip_dashed_date(trimmed, false)
        && codex_schedule(base).is_some()
    {
        return base.to_owned();
    }
    trimmed.to_owned()
}

fn normalize_claude_model(raw: &str) -> String {
    let mut normalized = raw.trim().strip_prefix("anthropic.").unwrap_or(raw.trim());
    if normalized.contains("claude-")
        && let Some(tail) = normalized.rsplit('.').next()
        && tail.starts_with("claude-")
    {
        normalized = tail;
    }
    if let Some(base) = strip_vertex_version(normalized) {
        normalized = base;
    }
    if let Some(base) = strip_dashed_date(normalized, true)
        && claude_schedule(base).is_some()
    {
        return base.to_owned();
    }
    normalized.to_owned()
}

fn strip_dashed_date(value: &str, compact: bool) -> Option<&str> {
    let suffix_length = if compact { 9 } else { 11 };
    if value.len() < suffix_length {
        return None;
    }
    let split = value.len() - suffix_length;
    let suffix = &value[split..];
    let bytes = suffix.as_bytes();
    let valid = if compact {
        bytes[0] == b'-' && bytes[1..].iter().all(u8::is_ascii_digit)
    } else {
        bytes[0] == b'-'
            && bytes[1..5].iter().all(u8::is_ascii_digit)
            && bytes[5] == b'-'
            && bytes[6..8].iter().all(u8::is_ascii_digit)
            && bytes[8] == b'-'
            && bytes[9..11].iter().all(u8::is_ascii_digit)
    };
    valid.then_some(&value[..split])
}

fn strip_vertex_version(value: &str) -> Option<&str> {
    let marker = value.rfind("-v")?;
    let suffix = &value[marker + 2..];
    let (major, minor) = suffix.split_once(':')?;
    (!major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit()))
    .then_some(&value[..marker])
}

#[cfg(test)]
mod tests {
    use super::{
        CLAUDE_CATALOG, CLAUDE_MODELS, CLAUDE_OPUS_4_6_HISTORICAL, CLAUDE_SONNET_4_6_HISTORICAL,
        CODEX_CATALOG, CODEX_MODELS, ModelPrice, PriceSchedule, cost_for, cost_for_at, price_for,
        priority_cost_for, priority_price_for,
    };
    use crate::cost::{CostProvider, TokenUsage};
    use chrono::{TimeZone, Utc};

    fn assert_rate(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < f64::EPSILON);
    }

    fn assert_cost(actual: Option<f64>, expected: f64) {
        assert!((actual.unwrap() - expected).abs() < 1e-12);
    }

    type ExpectedSchedule = (
        &'static str,
        [f64; 4],
        Option<(u64, [f64; 4])>,
        Option<[f64; 4]>,
    );

    fn rates(price: ModelPrice) -> [f64; 4] {
        [
            price.input_per_million,
            price.output_per_million,
            price.cache_creation_per_million,
            price.cache_read_per_million,
        ]
    }

    fn assert_schedule(actual: PriceSchedule, expected: &ExpectedSchedule) {
        assert_eq!(
            rates(actual.standard),
            expected.1,
            "standard rates for {}",
            expected.0
        );
        assert_eq!(
            actual
                .threshold_tokens
                .zip(actual.above_threshold.map(rates)),
            expected.2,
            "long-context rates for {}",
            expected.0
        );
        assert_eq!(
            actual.priority.map(rates),
            expected.3,
            "priority rates for {}",
            expected.0
        );
    }

    #[test]
    fn independent_manifest_locks_every_codex_and_claude_schedule() {
        let codex: [ExpectedSchedule; 23] = [
            ("gpt-5", [1.25, 10.0, 1.25, 0.125], None, None),
            ("gpt-5-codex", [1.25, 10.0, 1.25, 0.125], None, None),
            ("gpt-5-mini", [0.25, 2.0, 0.25, 0.025], None, None),
            ("gpt-5-nano", [0.05, 0.4, 0.05, 0.005], None, None),
            ("gpt-5-pro", [15.0, 120.0, 15.0, 15.0], None, None),
            ("gpt-5.1", [1.25, 10.0, 1.25, 0.125], None, None),
            ("gpt-5.1-codex", [1.25, 10.0, 1.25, 0.125], None, None),
            ("gpt-5.1-codex-max", [1.25, 10.0, 1.25, 0.125], None, None),
            ("gpt-5.1-codex-mini", [0.25, 2.0, 0.25, 0.025], None, None),
            ("gpt-5.2", [1.75, 14.0, 1.75, 0.175], None, None),
            ("gpt-5.2-codex", [1.75, 14.0, 1.75, 0.175], None, None),
            ("gpt-5.2-pro", [21.0, 168.0, 21.0, 21.0], None, None),
            ("gpt-5.3-codex", [1.75, 14.0, 1.75, 0.175], None, None),
            ("gpt-5.3-codex-spark", [0.0, 0.0, 0.0, 0.0], None, None),
            (
                "gpt-5.4",
                [2.5, 15.0, 2.5, 0.25],
                Some((272_000, [5.0, 22.5, 5.0, 0.5])),
                Some([5.0, 30.0, 5.0, 0.5]),
            ),
            (
                "gpt-5.4-mini",
                [0.75, 4.5, 0.75, 0.075],
                None,
                Some([1.5, 9.0, 1.5, 0.15]),
            ),
            ("gpt-5.4-nano", [0.2, 1.25, 0.2, 0.02], None, None),
            ("gpt-5.4-pro", [30.0, 180.0, 30.0, 30.0], None, None),
            (
                "gpt-5.5",
                [5.0, 30.0, 5.0, 0.5],
                Some((272_000, [10.0, 45.0, 10.0, 1.0])),
                Some([12.5, 75.0, 12.5, 1.25]),
            ),
            ("gpt-5.5-pro", [30.0, 180.0, 30.0, 30.0], None, None),
            (
                "gpt-5.6-sol",
                [5.0, 30.0, 6.25, 0.5],
                Some((272_000, [10.0, 45.0, 12.5, 1.0])),
                Some([10.0, 60.0, 12.5, 1.0]),
            ),
            (
                "gpt-5.6-terra",
                [2.5, 15.0, 3.125, 0.25],
                Some((272_000, [5.0, 22.5, 6.25, 0.5])),
                Some([5.0, 30.0, 6.25, 0.5]),
            ),
            (
                "gpt-5.6-luna",
                [1.0, 6.0, 1.25, 0.1],
                Some((272_000, [2.0, 9.0, 2.5, 0.2])),
                Some([2.0, 12.0, 2.5, 0.2]),
            ),
        ];
        let claude: [ExpectedSchedule; 15] = [
            ("claude-fable-5", [10.0, 50.0, 12.5, 1.0], None, None),
            (
                "claude-haiku-4-5-20251001",
                [1.0, 5.0, 1.25, 0.1],
                None,
                None,
            ),
            ("claude-haiku-4-5", [1.0, 5.0, 1.25, 0.1], None, None),
            (
                "claude-opus-4-5-20251101",
                [5.0, 25.0, 6.25, 0.5],
                None,
                None,
            ),
            ("claude-opus-4-5", [5.0, 25.0, 6.25, 0.5], None, None),
            (
                "claude-opus-4-6-20260205",
                [5.0, 25.0, 6.25, 0.5],
                None,
                None,
            ),
            ("claude-opus-4-6", [5.0, 25.0, 6.25, 0.5], None, None),
            ("claude-opus-4-7", [5.0, 25.0, 6.25, 0.5], None, None),
            ("claude-opus-4-8", [5.0, 25.0, 6.25, 0.5], None, None),
            (
                "claude-sonnet-4-5",
                [3.0, 15.0, 3.75, 0.3],
                Some((200_000, [6.0, 22.5, 7.5, 0.6])),
                None,
            ),
            ("claude-sonnet-4-6", [3.0, 15.0, 3.75, 0.3], None, None),
            (
                "claude-sonnet-4-5-20250929",
                [3.0, 15.0, 3.75, 0.3],
                Some((200_000, [6.0, 22.5, 7.5, 0.6])),
                None,
            ),
            (
                "claude-opus-4-20250514",
                [15.0, 75.0, 18.75, 1.5],
                None,
                None,
            ),
            ("claude-opus-4-1", [15.0, 75.0, 18.75, 1.5], None, None),
            (
                "claude-sonnet-4-20250514",
                [3.0, 15.0, 3.75, 0.3],
                Some((200_000, [6.0, 22.5, 7.5, 0.6])),
                None,
            ),
        ];

        assert_eq!(CODEX_CATALOG.len(), codex.len());
        assert_eq!(CLAUDE_CATALOG.len(), claude.len());
        assert_eq!(
            CODEX_MODELS,
            codex.iter().map(|expected| expected.0).collect::<Vec<_>>()
        );
        assert_eq!(
            CLAUDE_MODELS,
            claude.iter().map(|expected| expected.0).collect::<Vec<_>>()
        );
        for ((actual_name, actual), expected) in CODEX_CATALOG.iter().zip(codex.iter()) {
            assert_eq!(actual_name, &expected.0);
            assert_schedule(*actual, expected);
        }
        for ((actual_name, actual), expected) in CLAUDE_CATALOG.iter().zip(claude.iter()) {
            assert_eq!(actual_name, &expected.0);
            assert_schedule(*actual, expected);
        }

        let opus_historical = (
            "claude-opus-4-6-historical",
            [5.0, 25.0, 6.25, 0.5],
            Some((200_000, [10.0, 37.5, 12.5, 1.0])),
            None,
        );
        let sonnet_historical = (
            "claude-sonnet-4-6-historical",
            [3.0, 15.0, 3.75, 0.3],
            Some((200_000, [6.0, 22.5, 7.5, 0.6])),
            None,
        );
        assert_schedule(CLAUDE_OPUS_4_6_HISTORICAL, &opus_historical);
        assert_schedule(CLAUDE_SONNET_4_6_HISTORICAL, &sonnet_historical);
    }

    #[test]
    fn fixture_models_have_exact_swift_rates() {
        let codex = price_for(CostProvider::Codex, "gpt-5").unwrap();
        assert_rate(codex.input_per_million, 1.25);
        assert_rate(codex.output_per_million, 10.0);
        assert_rate(codex.cache_creation_per_million, 1.25);
        assert_rate(codex.cache_read_per_million, 0.125);

        let claude = price_for(CostProvider::Claude, "claude-sonnet-4-20250514").unwrap();
        assert_rate(claude.input_per_million, 3.0);
        assert_rate(claude.output_per_million, 15.0);
        assert_rate(claude.cache_creation_per_million, 3.75);
        assert_rate(claude.cache_read_per_million, 0.30);
    }

    #[test]
    fn swift_model_aliases_resolve_to_their_catalog_prices() {
        assert_eq!(
            price_for(CostProvider::Codex, " openai/gpt-5.6 "),
            price_for(CostProvider::Codex, "gpt-5.6-sol")
        );
        assert_eq!(
            price_for(CostProvider::Codex, "openai/gpt-5.4-2026-04-01"),
            price_for(CostProvider::Codex, "gpt-5.4")
        );
        assert_eq!(
            price_for(CostProvider::Claude, "us.anthropic.claude-sonnet-4-5-v1:0"),
            price_for(CostProvider::Claude, "claude-sonnet-4-5")
        );
        assert_eq!(
            price_for(CostProvider::Claude, "anthropic.claude-sonnet-4-5-20250929"),
            price_for(CostProvider::Claude, "claude-sonnet-4-5")
        );
    }

    #[test]
    fn long_context_thresholds_charge_the_full_request_at_the_swift_rate() {
        let at_codex_limit = TokenUsage {
            input: 272_000,
            ..TokenUsage::default()
        };
        let over_codex_limit = TokenUsage {
            input: 272_001,
            ..TokenUsage::default()
        };
        assert_cost(
            cost_for(CostProvider::Codex, "gpt-5.4", at_codex_limit),
            0.68,
        );
        assert_cost(
            cost_for(CostProvider::Codex, "gpt-5.4", over_codex_limit),
            1.360_005,
        );

        let at_claude_limit = TokenUsage {
            input: 200_000,
            ..TokenUsage::default()
        };
        let over_claude_limit = TokenUsage {
            input: 200_001,
            ..TokenUsage::default()
        };
        assert_cost(
            cost_for(CostProvider::Claude, "claude-sonnet-4-5", at_claude_limit),
            0.6,
        );
        assert_cost(
            cost_for(CostProvider::Claude, "claude-sonnet-4-5", over_claude_limit),
            1.200_006,
        );
    }

    #[test]
    fn historical_claude_long_context_rates_follow_the_swift_cutoff() {
        let usage = TokenUsage {
            input: 200_001,
            ..TokenUsage::default()
        };
        let before_cutoff = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
        let after_cutoff = Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap();

        assert_cost(
            cost_for_at(
                CostProvider::Claude,
                "claude-sonnet-4-6",
                usage,
                before_cutoff,
            ),
            1.200_006,
        );
        assert_cost(
            cost_for_at(
                CostProvider::Claude,
                "claude-sonnet-4-6",
                usage,
                after_cutoff,
            ),
            0.600_003,
        );
    }

    #[test]
    fn priority_rates_preserve_explicit_cache_write_prices() {
        let price = priority_price_for("gpt-5.6-sol").unwrap();
        assert_rate(price.input_per_million, 10.0);
        assert_rate(price.output_per_million, 60.0);
        assert_rate(price.cache_creation_per_million, 12.5);
        assert_rate(price.cache_read_per_million, 1.0);
        assert_eq!(priority_price_for("gpt-5"), None);
    }

    #[test]
    fn priority_cost_is_available_only_within_the_token_limit() {
        let at_limit = TokenUsage {
            input: 272_000,
            ..TokenUsage::default()
        };
        let split_at_limit = TokenUsage {
            input: 270_000,
            cache_creation: 1_000,
            cache_read: 1_000,
            ..TokenUsage::default()
        };
        let over_limit = TokenUsage {
            input: 272_001,
            ..TokenUsage::default()
        };

        assert_cost(priority_cost_for("gpt-5.4", at_limit), 1.36);
        assert_cost(priority_cost_for("gpt-5.4", split_at_limit), 1.355_5);
        assert_eq!(priority_cost_for("gpt-5.4", over_limit), None);
        assert_eq!(priority_cost_for("gpt-5", at_limit), None);
        assert_eq!(priority_cost_for("fictional-model-1", at_limit), None);
    }

    #[test]
    fn unknown_models_never_receive_a_guessed_price() {
        let usage = TokenUsage {
            input: 1_000_000,
            ..TokenUsage::default()
        };
        assert_eq!(price_for(CostProvider::Codex, "fictional-model-1"), None);
        assert_eq!(
            cost_for(CostProvider::Claude, "fictional-model-1", usage),
            None
        );
    }
}
