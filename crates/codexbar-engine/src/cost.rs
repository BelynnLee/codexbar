use crate::pricing::{canonical_model, cost_for_at, cost_for_at_with_cache_creation_1h};
use chrono::{DateTime, Duration, NaiveTime, Utc};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CostProvider {
    Codex,
    Claude,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CostRange {
    Today,
    Days7,
    Days30,
    Since(DateTime<Utc>),
}

impl CostRange {
    fn includes(self, timestamp: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        let cutoff = match self {
            Self::Today => {
                DateTime::from_naive_utc_and_offset(now.date_naive().and_time(NaiveTime::MIN), Utc)
            }
            Self::Days7 => now - Duration::days(7),
            Self::Days30 => now - Duration::days(30),
            Self::Since(timestamp) => timestamp,
        };
        timestamp >= cutoff && timestamp <= now
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
    pub input: u64,
    pub output: u64,
    pub cache_creation: u64,
    pub cache_read: u64,
}

impl TokenUsage {
    fn add_assign(&mut self, other: Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cache_creation = self.cache_creation.saturating_add(other.cache_creation);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
    }

    fn is_empty(self) -> bool {
        self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostDay {
    pub day: String,
    pub usage: TokenUsage,
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostModelBreakdown {
    pub model: String,
    pub usage: TokenUsage,
    pub cost_usd: Option<f64>,
}

/// One model's cost/token history across the scanned range, one point per day it was used. Lets the
/// UI chart how each model's spend trends over time (stacked per day) rather than only the range
/// total in `models`. Days are sorted ascending; only days with usage for this model appear.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostModelSeries {
    pub model: String,
    pub daily: Vec<CostDay>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostBreakdown {
    pub provider: CostProvider,
    pub generated_at: DateTime<Utc>,
    pub daily: Vec<CostDay>,
    pub models: Vec<CostModelBreakdown>,
    /// Per-model daily history, ordered by descending range total so the UI can take the top few.
    pub model_daily: Vec<CostModelSeries>,
    pub total_usage: TokenUsage,
    pub total_cost_usd: Option<f64>,
    pub unknown_models: Vec<String>,
    pub skipped_records: u64,
}

#[derive(Debug, Error)]
pub enum CostError {
    #[error("a home directory is unavailable for the default local cost roots")]
    HomeDirectoryUnavailable,
    #[error("{provider:?} cost root is not a directory: {path}")]
    InvalidRoot {
        provider: CostProvider,
        path: PathBuf,
    },
    #[error("{provider:?} cost scan failed at {path}: {source}")]
    Io {
        provider: CostProvider,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct CostScanner {
    codex_root: PathBuf,
    claude_root: PathBuf,
}

impl CostScanner {
    pub const fn new(codex_root: PathBuf, claude_root: PathBuf) -> Self {
        Self {
            codex_root,
            claude_root,
        }
    }

    pub fn from_default_roots() -> Result<Self, CostError> {
        Self::resolve(None, None)
    }

    /// Resolve the scan roots, honoring per-path overrides and otherwise the default
    /// `~/.codex/sessions` and `~/.claude/projects` locations. Shared by the GUI and the CLI so both
    /// obey the same `history.codexPath` / `history.claudePath` config overrides.
    pub fn resolve(
        codex_override: Option<PathBuf>,
        claude_override: Option<PathBuf>,
    ) -> Result<Self, CostError> {
        let home = BaseDirs::new().map(|directories| directories.home_dir().to_path_buf());
        let codex = codex_override
            .or_else(|| home.as_ref().map(|home| home.join(".codex/sessions")))
            .ok_or(CostError::HomeDirectoryUnavailable)?;
        let claude = claude_override
            .or_else(|| home.as_ref().map(|home| home.join(".claude/projects")))
            .ok_or(CostError::HomeDirectoryUnavailable)?;
        Ok(Self::new(codex, claude))
    }

    pub fn scan(
        &self,
        provider: CostProvider,
        range: CostRange,
        now: DateTime<Utc>,
    ) -> Result<CostBreakdown, CostError> {
        let mut records = Vec::new();
        let mut skipped_records = 0_u64;
        if matches!(provider, CostProvider::Codex | CostProvider::Both) {
            let scan = scan_codex_root(&self.codex_root)?;
            records.extend(scan.records);
            skipped_records = skipped_records.saturating_add(scan.skipped_records);
        }
        if matches!(provider, CostProvider::Claude | CostProvider::Both) {
            let scan = scan_claude_root(&self.claude_root)?;
            records.extend(scan.records);
            skipped_records = skipped_records.saturating_add(scan.skipped_records);
        }
        records.retain(|record| range.includes(record.timestamp, now));
        Ok(aggregate(provider, now, records, skipped_records))
    }
}

#[derive(Debug)]
struct ProviderScan {
    records: Vec<UsageRecord>,
    skipped_records: u64,
}

#[derive(Debug, Clone)]
struct UsageRecord {
    timestamp: DateTime<Utc>,
    model: String,
    usage: TokenUsage,
    cost_usd: Option<f64>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CodexRawUsage {
    input: u64,
    output: u64,
    cache_creation: u64,
    cache_read: u64,
}

impl CodexRawUsage {
    fn delta_from(self, previous: Self) -> Self {
        Self {
            input: self.input.saturating_sub(previous.input),
            output: self.output.saturating_sub(previous.output),
            cache_creation: self.cache_creation.saturating_sub(previous.cache_creation),
            cache_read: self.cache_read.saturating_sub(previous.cache_read),
        }
    }

    fn add(self, other: Self) -> Self {
        Self {
            input: self.input.saturating_add(other.input),
            output: self.output.saturating_add(other.output),
            cache_creation: self.cache_creation.saturating_add(other.cache_creation),
            cache_read: self.cache_read.saturating_add(other.cache_read),
        }
    }

    fn component_min(self, other: Self) -> Self {
        Self {
            input: self.input.min(other.input),
            output: self.output.min(other.output),
            cache_creation: self.cache_creation.min(other.cache_creation),
            cache_read: self.cache_read.min(other.cache_read),
        }
    }

    fn component_max(self, other: Self) -> Self {
        Self {
            input: self.input.max(other.input),
            output: self.output.max(other.output),
            cache_creation: self.cache_creation.max(other.cache_creation),
            cache_read: self.cache_read.max(other.cache_read),
        }
    }

    fn at_least(self, other: Self) -> bool {
        self.input >= other.input
            && self.output >= other.output
            && self.cache_creation >= other.cache_creation
            && self.cache_read >= other.cache_read
    }

    fn at_most(self, other: Self) -> bool {
        self.input <= other.input
            && self.output <= other.output
            && self.cache_creation <= other.cache_creation
            && self.cache_read <= other.cache_read
    }

    fn any_below(self, other: Self) -> bool {
        self.input < other.input
            || self.output < other.output
            || self.cache_creation < other.cache_creation
            || self.cache_read < other.cache_read
    }

    fn normalized(self) -> TokenUsage {
        let cache_read = self.cache_read.min(self.input);
        let remaining = self.input - cache_read;
        let cache_creation = self.cache_creation.min(remaining);
        TokenUsage {
            input: remaining - cache_creation,
            output: self.output,
            cache_creation,
            cache_read,
        }
    }
}

#[derive(Debug)]
struct CodexEvent {
    timestamp: DateTime<Utc>,
    session_id: String,
    source: String,
    line_number: usize,
    model: String,
    total: Option<CodexRawUsage>,
    last: Option<CodexRawUsage>,
}

#[derive(Debug, Default)]
struct CodexTotalsTracker {
    counted: Option<CodexRawUsage>,
    raw_baseline: Option<CodexRawUsage>,
    watermark: Option<CodexRawUsage>,
    seen_raw_totals: Vec<CodexRawUsage>,
    saw_interleaved: bool,
    saw_divergent: bool,
}

impl CodexTotalsTracker {
    const SEEN_RAW_TOTALS_LIMIT: usize = 64;

    fn apply(
        &mut self,
        last: Option<CodexRawUsage>,
        total: Option<CodexRawUsage>,
    ) -> CodexRawUsage {
        let base = self.counted.unwrap_or_default();
        if let Some(total) = total {
            if self.seen_raw_totals.contains(&total) {
                return CodexRawUsage::default();
            }
            if self
                .watermark
                .is_some_and(|watermark| total.any_below(watermark))
            {
                self.saw_interleaved = true;
            }
        }
        let watermark_baseline = self.watermark.or(self.raw_baseline);

        let delta = match (last, total) {
            (Some(last), Some(total)) => {
                let mut delta = last;
                if self.saw_interleaved {
                    delta = contained_total_delta(watermark_baseline, self.counted, total)
                        .component_min(last);
                } else {
                    let total_delta = total.delta_from(watermark_baseline.unwrap_or_default());
                    if !self.saw_divergent
                        && watermark_baseline.is_some_and(|baseline| total.at_least(baseline))
                        && total_delta.at_most(last)
                    {
                        delta = total_delta;
                    }
                }
                let next = base.add(delta);
                self.counted = Some(next);
                self.raw_baseline = Some(total);
                if total != next {
                    self.saw_divergent = true;
                }
                delta
            }
            (Some(last), None) => {
                let next = base.add(last);
                self.counted = Some(next);
                self.raw_baseline = Some(next);
                self.raise_watermark(next);
                last
            }
            (None, Some(total)) => {
                let delta = if self.saw_interleaved {
                    contained_total_delta(watermark_baseline, self.counted, total)
                } else if self.saw_divergent {
                    divergent_total_delta(watermark_baseline, self.counted, total)
                } else {
                    total.delta_from(watermark_baseline.unwrap_or_default())
                };
                let next = base.add(delta);
                self.counted = Some(next);
                self.raw_baseline = Some(total);
                if total != next {
                    self.saw_divergent = true;
                }
                delta
            }
            (None, None) => CodexRawUsage::default(),
        };

        if let Some(total) = total {
            self.commit_observed(total);
        }
        delta
    }

    fn raise_watermark(&mut self, totals: CodexRawUsage) {
        self.watermark = Some(
            self.watermark
                .map_or(totals, |watermark| watermark.component_max(totals)),
        );
    }

    fn commit_observed(&mut self, totals: CodexRawUsage) {
        self.raise_watermark(totals);
        if !self.seen_raw_totals.contains(&totals) {
            self.seen_raw_totals.push(totals);
            let excess = self
                .seen_raw_totals
                .len()
                .saturating_sub(Self::SEEN_RAW_TOTALS_LIMIT);
            if excess > 0 {
                self.seen_raw_totals.drain(..excess);
            }
        }
    }
}

fn divergent_total_delta(
    raw_baseline: Option<CodexRawUsage>,
    counted_baseline: Option<CodexRawUsage>,
    current: CodexRawUsage,
) -> CodexRawUsage {
    let raw = raw_baseline.unwrap_or_default();
    let counted = counted_baseline.unwrap_or_default();
    let component = |raw: u64, counted: u64, current: u64| {
        if current >= raw {
            current.saturating_sub(raw)
        } else {
            current.saturating_sub(counted)
        }
    };
    CodexRawUsage {
        input: component(raw.input, counted.input, current.input),
        output: component(raw.output, counted.output, current.output),
        cache_creation: component(
            raw.cache_creation,
            counted.cache_creation,
            current.cache_creation,
        ),
        cache_read: component(raw.cache_read, counted.cache_read, current.cache_read),
    }
}

fn contained_total_delta(
    watermark: Option<CodexRawUsage>,
    counted: Option<CodexRawUsage>,
    current: CodexRawUsage,
) -> CodexRawUsage {
    let watermark = watermark.unwrap_or_default();
    let counted = counted.unwrap_or_default();
    let component = |watermark: u64, counted: u64, current: u64| {
        if current >= watermark {
            current.saturating_sub(watermark.max(counted))
        } else {
            current.saturating_sub(counted)
        }
    };
    CodexRawUsage {
        input: component(watermark.input, counted.input, current.input),
        output: component(watermark.output, counted.output, current.output),
        cache_creation: component(
            watermark.cache_creation,
            counted.cache_creation,
            current.cache_creation,
        ),
        cache_read: component(watermark.cache_read, counted.cache_read, current.cache_read),
    }
}

fn scan_codex_root(root: &Path) -> Result<ProviderScan, CostError> {
    let files = jsonl_files(CostProvider::Codex, root)?;
    let mut events = Vec::new();
    let mut skipped_records = 0_u64;
    for file in files {
        parse_codex_file(&file, &mut events, &mut skipped_records)?;
    }
    events.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.session_id.cmp(&right.session_id))
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.line_number.cmp(&right.line_number))
    });

    let mut trackers = HashMap::<String, CodexTotalsTracker>::new();
    let mut records = Vec::new();
    for event in events {
        let delta = trackers
            .entry(event.session_id)
            .or_default()
            .apply(event.last, event.total);
        let normalized = delta.normalized();
        if normalized.is_empty() {
            continue;
        }
        let model = canonical_model(CostProvider::Codex, &event.model);
        records.push(UsageRecord {
            timestamp: event.timestamp,
            model: model.clone(),
            usage: normalized,
            cost_usd: cost_for_at(CostProvider::Codex, &model, normalized, event.timestamp),
        });
    }
    Ok(ProviderScan {
        records,
        skipped_records,
    })
}

fn parse_codex_file(
    path: &Path,
    events: &mut Vec<CodexEvent>,
    skipped_records: &mut u64,
) -> Result<(), CostError> {
    let file = open_file(CostProvider::Codex, path)?;
    let source = path.display().to_string();
    let mut session_id = source.clone();
    let mut current_model: Option<String> = None;
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                *skipped_records = skipped_records.saturating_add(1);
                continue;
            }
            Err(source) => {
                return Err(CostError::Io {
                    provider: CostProvider::Codex,
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = if let Ok(value) = serde_json::from_str(&line) {
            value
        } else {
            *skipped_records = skipped_records.saturating_add(1);
            continue;
        };
        let record_type = value.get("type").and_then(Value::as_str);
        if record_type == Some("session_meta") {
            let payload = value.get("payload").and_then(Value::as_object);
            if let Some(id) = first_string(payload, &["session_id", "sessionId", "id"])
                .or_else(|| first_string(value.as_object(), &["session_id", "sessionId", "id"]))
            {
                session_id = id.to_owned();
            }
            if let Some(model) = first_string(payload, &["model", "model_name"]) {
                current_model = Some(model.to_owned());
            }
            continue;
        }
        if record_type == Some("turn_context") {
            let payload = value.get("payload").and_then(Value::as_object);
            let info = payload
                .and_then(|payload| payload.get("info"))
                .and_then(Value::as_object);
            if let Some(model) = codex_turn_context_model(payload, info).or_else(|| {
                first_string(value.as_object(), &["model", "model_name"]).map(str::to_owned)
            }) {
                current_model = Some(model);
            }
            continue;
        }
        if record_type != Some("event_msg") {
            continue;
        }
        let Some(payload) = value.get("payload").and_then(Value::as_object) else {
            *skipped_records = skipped_records.saturating_add(1);
            continue;
        };
        if payload.get("type").and_then(Value::as_str) != Some("token_count") {
            continue;
        }
        let Some(info) = payload.get("info").and_then(Value::as_object) else {
            *skipped_records = skipped_records.saturating_add(1);
            continue;
        };
        let Some(timestamp) = value
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_timestamp)
        else {
            *skipped_records = skipped_records.saturating_add(1);
            continue;
        };
        let total = if let Ok(total) = optional_codex_usage(info, "total_token_usage") {
            total
        } else {
            *skipped_records = skipped_records.saturating_add(1);
            continue;
        };
        let last = if let Ok(last) = optional_codex_usage(info, "last_token_usage") {
            last
        } else {
            *skipped_records = skipped_records.saturating_add(1);
            continue;
        };
        if total.is_none() && last.is_none() {
            *skipped_records = skipped_records.saturating_add(1);
            continue;
        }
        let model = first_string(Some(info), &["model", "model_name"])
            .or_else(|| first_string(Some(payload), &["model"]))
            .or_else(|| first_string(value.as_object(), &["model"]))
            .map_or_else(
                || {
                    current_model
                        .clone()
                        .unwrap_or_else(|| "unknown".to_owned())
                },
                str::to_owned,
            );
        current_model = Some(model.clone());
        events.push(CodexEvent {
            timestamp,
            session_id: session_id.clone(),
            source: source.clone(),
            line_number,
            model,
            total,
            last,
        });
    }
    Ok(())
}

fn scan_claude_root(root: &Path) -> Result<ProviderScan, CostError> {
    let files = jsonl_files(CostProvider::Claude, root)?;
    let mut keyed = HashMap::<(String, String), UsageRecord>::new();
    let mut unkeyed = Vec::new();
    let mut skipped_records = 0_u64;
    for path in files {
        let file = open_file(CostProvider::Claude, &path)?;
        let source = path.display().to_string();
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(line) => line,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    skipped_records = skipped_records.saturating_add(1);
                    continue;
                }
                Err(source) => {
                    return Err(CostError::Io {
                        provider: CostProvider::Claude,
                        path: path.clone(),
                        source,
                    });
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = if let Ok(value) = serde_json::from_str(&line) {
                value
            } else {
                skipped_records = skipped_records.saturating_add(1);
                continue;
            };
            if value.get("type").and_then(Value::as_str) != Some("assistant") {
                continue;
            }
            let Some(message) = value.get("message").and_then(Value::as_object) else {
                skipped_records = skipped_records.saturating_add(1);
                continue;
            };
            let Some(usage_value) = message.get("usage").and_then(Value::as_object) else {
                skipped_records = skipped_records.saturating_add(1);
                continue;
            };
            let Some(timestamp) = value
                .get("timestamp")
                .and_then(Value::as_str)
                .and_then(parse_timestamp)
            else {
                skipped_records = skipped_records.saturating_add(1);
                continue;
            };
            let parsed_usage = if let Ok(usage) = claude_usage(usage_value) {
                usage
            } else {
                skipped_records = skipped_records.saturating_add(1);
                continue;
            };
            if parsed_usage.usage.is_empty() {
                continue;
            }
            let raw_model = message
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let model = canonical_model(CostProvider::Claude, raw_model);
            let record = UsageRecord {
                timestamp,
                model: model.clone(),
                usage: parsed_usage.usage,
                cost_usd: cost_for_at_with_cache_creation_1h(
                    CostProvider::Claude,
                    &model,
                    parsed_usage.usage,
                    parsed_usage.cache_creation_1h,
                    timestamp,
                ),
            };
            match message
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            {
                Some(message_id) => {
                    keyed.insert((source.clone(), message_id.to_owned()), record);
                }
                None => unkeyed.push(record),
            }
        }
    }
    let mut records = keyed.into_values().collect::<Vec<_>>();
    records.extend(unkeyed);
    Ok(ProviderScan {
        records,
        skipped_records,
    })
}

fn jsonl_files(provider: CostProvider, root: &Path) -> Result<Vec<PathBuf>, CostError> {
    let metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(CostError::Io {
                provider,
                path: root.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_dir() {
        return Err(CostError::InvalidRoot {
            provider,
            path: root.to_path_buf(),
        });
    }

    let mut directories = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| CostError::Io {
            provider,
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| CostError::Io {
                provider,
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| CostError::Io {
                provider,
                path: path.clone(),
                source,
            })?;
            if file_type.is_dir() {
                directories.push(path);
            } else if file_type.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn open_file(provider: CostProvider, path: &Path) -> Result<File, CostError> {
    File::open(path).map_err(|source| CostError::Io {
        provider,
        path: path.to_path_buf(),
        source,
    })
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn first_string<'a>(object: Option<&'a Map<String, Value>>, names: &[&str]) -> Option<&'a str> {
    let object = object?;
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
}

fn codex_turn_context_model(
    payload: Option<&Map<String, Value>>,
    info: Option<&Map<String, Value>>,
) -> Option<String> {
    let candidates = [
        first_string(payload, &["model"]),
        first_string(payload, &["model_name"]),
        first_string(info, &["model"]),
        first_string(info, &["model_name"]),
    ];
    let mut saw_candidate = false;
    for candidate in candidates.into_iter().flatten() {
        saw_candidate = true;
        let trimmed = candidate.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    saw_candidate.then(String::new)
}

#[derive(Debug, Clone, Copy)]
struct InvalidTokenField;

fn token_count(object: &Map<String, Value>, names: &[&str]) -> Result<u64, InvalidTokenField> {
    let Some(value) = names.iter().find_map(|name| object.get(*name)) else {
        return Ok(0);
    };
    value.as_u64().ok_or(InvalidTokenField)
}

fn optional_codex_usage(
    info: &Map<String, Value>,
    name: &str,
) -> Result<Option<CodexRawUsage>, InvalidTokenField> {
    match info.get(name) {
        None => Ok(None),
        Some(Value::Object(usage)) => codex_raw_usage(usage).map(Some),
        Some(_) => Err(InvalidTokenField),
    }
}

fn codex_raw_usage(usage: &Map<String, Value>) -> Result<CodexRawUsage, InvalidTokenField> {
    Ok(CodexRawUsage {
        input: token_count(usage, &["input_tokens"])?,
        output: token_count(usage, &["output_tokens"])?,
        cache_creation: token_count(
            usage,
            &["cache_creation_input_tokens", "cache_write_input_tokens"],
        )?,
        cache_read: token_count(usage, &["cached_input_tokens", "cache_read_input_tokens"])?,
    })
}

#[derive(Debug, Clone, Copy)]
struct ClaudeUsage {
    usage: TokenUsage,
    cache_creation_1h: u64,
}

fn claude_usage(usage: &Map<String, Value>) -> Result<ClaudeUsage, InvalidTokenField> {
    let parsed = TokenUsage {
        input: token_count(usage, &["input_tokens"])?,
        output: token_count(usage, &["output_tokens"])?,
        cache_creation: token_count(usage, &["cache_creation_input_tokens"])?,
        cache_read: token_count(usage, &["cache_read_input_tokens"])?,
    };
    let cache_creation_1h = match usage.get("cache_creation") {
        None => 0,
        Some(Value::Object(cache_creation)) => {
            token_count(cache_creation, &["ephemeral_1h_input_tokens"])?
        }
        Some(_) => return Err(InvalidTokenField),
    }
    .min(parsed.cache_creation);
    Ok(ClaudeUsage {
        usage: parsed,
        cache_creation_1h,
    })
}

#[derive(Debug)]
struct Aggregate {
    usage: TokenUsage,
    cost_usd: Option<f64>,
}

impl Aggregate {
    const fn new() -> Self {
        Self {
            usage: TokenUsage {
                input: 0,
                output: 0,
                cache_creation: 0,
                cache_read: 0,
            },
            cost_usd: Some(0.0),
        }
    }

    fn add(&mut self, usage: TokenUsage, cost_usd: Option<f64>) {
        self.usage.add_assign(usage);
        self.cost_usd = match (self.cost_usd, cost_usd) {
            (Some(total), Some(cost)) => Some(total + cost),
            _ => None,
        };
    }
}

fn aggregate(
    provider: CostProvider,
    generated_at: DateTime<Utc>,
    records: Vec<UsageRecord>,
    skipped_records: u64,
) -> CostBreakdown {
    let mut daily = BTreeMap::<String, Aggregate>::new();
    let mut models = BTreeMap::<String, Aggregate>::new();
    // Per-model, per-day aggregates. Outer key model, inner key day (both sorted by BTreeMap).
    let mut model_day = BTreeMap::<String, BTreeMap<String, Aggregate>>::new();
    let mut unknown_models = BTreeSet::new();
    let mut total = Aggregate::new();
    for record in records {
        let day = record.timestamp.format("%Y-%m-%d").to_string();
        total.add(record.usage, record.cost_usd);
        daily
            .entry(day.clone())
            .or_insert_with(Aggregate::new)
            .add(record.usage, record.cost_usd);
        models
            .entry(record.model.clone())
            .or_insert_with(Aggregate::new)
            .add(record.usage, record.cost_usd);
        model_day
            .entry(record.model.clone())
            .or_default()
            .entry(day)
            .or_insert_with(Aggregate::new)
            .add(record.usage, record.cost_usd);
        if record.cost_usd.is_none() {
            unknown_models.insert(record.model);
        }
    }
    // Order the per-model history by descending range total (tokens) so the UI can take the top few.
    let mut model_daily: Vec<CostModelSeries> = model_day
        .into_iter()
        .map(|(model, days)| CostModelSeries {
            model,
            daily: days
                .into_iter()
                .map(|(day, aggregate)| CostDay {
                    day,
                    usage: aggregate.usage,
                    cost_usd: aggregate.cost_usd,
                })
                .collect(),
        })
        .collect();
    model_daily.sort_by(|left, right| {
        series_total_tokens(right)
            .cmp(&series_total_tokens(left))
            .then_with(|| left.model.cmp(&right.model))
    });
    CostBreakdown {
        provider,
        generated_at,
        daily: daily
            .into_iter()
            .map(|(day, aggregate)| CostDay {
                day,
                usage: aggregate.usage,
                cost_usd: aggregate.cost_usd,
            })
            .collect(),
        models: models
            .into_iter()
            .map(|(model, aggregate)| CostModelBreakdown {
                model,
                usage: aggregate.usage,
                cost_usd: aggregate.cost_usd,
            })
            .collect(),
        model_daily,
        total_usage: total.usage,
        total_cost_usd: total.cost_usd,
        unknown_models: unknown_models.into_iter().collect(),
        skipped_records,
    }
}

fn series_total_tokens(series: &CostModelSeries) -> u64 {
    series
        .daily
        .iter()
        .map(|point| {
            point.usage.input
                + point.usage.output
                + point.usage.cache_creation
                + point.usage.cache_read
        })
        .fold(0_u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::{CostProvider, CostRange, CostScanner, TokenUsage};
    use chrono::{DateTime, TimeZone, Utc};
    use serde_json::{Map, Value, json};
    use std::fs;

    fn scanner_with_fixtures(codex: &str, claude: &str) -> (tempfile::TempDir, CostScanner) {
        let directory = tempfile::tempdir().unwrap();
        let codex_root = directory.path().join("codex");
        let claude_root = directory.path().join("claude");
        fs::create_dir_all(&codex_root).unwrap();
        fs::create_dir_all(&claude_root).unwrap();
        fs::write(codex_root.join("session.jsonl"), codex).unwrap();
        fs::write(claude_root.join("session.jsonl"), claude).unwrap();
        let scanner = CostScanner::new(codex_root, claude_root);
        (directory, scanner)
    }

    fn fixture_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 15, 12, 0, 0).unwrap()
    }

    fn usage_value(input: u64, cached: u64, output: u64) -> Value {
        json!({
            "input_tokens": input,
            "cached_input_tokens": cached,
            "output_tokens": output,
        })
    }

    fn codex_token_event(
        timestamp: &str,
        total: Option<(u64, u64, u64)>,
        last: Option<(u64, u64, u64)>,
    ) -> String {
        let mut info = Map::new();
        if let Some((input, cached, output)) = total {
            info.insert(
                "total_token_usage".to_owned(),
                usage_value(input, cached, output),
            );
        }
        if let Some((input, cached, output)) = last {
            info.insert(
                "last_token_usage".to_owned(),
                usage_value(input, cached, output),
            );
        }
        json!({
            "timestamp": timestamp,
            "type": "event_msg",
            "payload": {"type": "token_count", "info": info},
        })
        .to_string()
    }

    fn codex_fixture(events: &[String]) -> String {
        let mut lines = vec![
            json!({
                "timestamp": "2026-07-15T09:00:00Z",
                "type": "session_meta",
                "payload": {"id": "session-state", "model": "gpt-5"},
            })
            .to_string(),
        ];
        lines.extend(events.iter().cloned());
        format!("{}\n", lines.join("\n"))
    }

    fn scan_codex_fixture(fixture: &str, range: CostRange) -> super::CostBreakdown {
        let (_directory, scanner) = scanner_with_fixtures(fixture, "");
        scanner
            .scan(CostProvider::Codex, range, fixture_now())
            .unwrap()
    }

    #[test]
    fn model_daily_splits_by_model_and_day_ordered_by_total_tokens() {
        use super::{UsageRecord, aggregate};
        let record = |year, month, day, hour, model: &str, input: u64, cost: f64| UsageRecord {
            timestamp: Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap(),
            model: model.to_string(),
            usage: TokenUsage {
                input,
                output: 0,
                cache_creation: 0,
                cache_read: 0,
            },
            cost_usd: Some(cost),
        };
        let records = vec![
            record(2026, 7, 14, 10, "gpt-5", 100, 0.010),
            record(2026, 7, 15, 10, "gpt-5", 50, 0.005),
            record(2026, 7, 15, 11, "claude", 10, 0.001),
        ];
        let result = aggregate(CostProvider::Both, fixture_now(), records, 0);

        // gpt-5 (150 tokens) outranks claude (10 tokens), so it sorts first.
        assert_eq!(result.model_daily.len(), 2);
        let gpt = &result.model_daily[0];
        assert_eq!(gpt.model, "gpt-5");
        assert_eq!(gpt.daily.len(), 2, "one point per day used, ascending");
        assert_eq!(gpt.daily[0].day, "2026-07-14");
        assert_eq!(gpt.daily[0].usage.input, 100);
        assert_eq!(gpt.daily[1].day, "2026-07-15");
        assert_eq!(gpt.daily[1].usage.input, 50);

        let claude = &result.model_daily[1];
        assert_eq!(claude.model, "claude");
        assert_eq!(claude.daily.len(), 1);
        assert!((claude.daily[0].cost_usd.unwrap() - 0.001).abs() < 1e-12);
    }

    #[test]
    fn codex_cumulative_token_events_do_not_overcount() {
        let (_directory, scanner) = scanner_with_fixtures(
            include_str!("../tests/fixtures/cost/codex-session.jsonl"),
            "",
        );
        let result = scanner
            .scan(CostProvider::Codex, CostRange::Days30, fixture_now())
            .unwrap();
        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 130,
                output: 30,
                cache_creation: 0,
                cache_read: 20
            }
        );
        assert!((result.total_cost_usd.unwrap() - 0.000_465).abs() < 1e-12);
    }

    #[test]
    fn claude_duplicate_assistant_messages_count_once() {
        let (_directory, scanner) = scanner_with_fixtures(
            "",
            include_str!("../tests/fixtures/cost/claude-session.jsonl"),
        );
        let result = scanner
            .scan(CostProvider::Claude, CostRange::Days30, fixture_now())
            .unwrap();
        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 150,
                output: 30,
                cache_creation: 10,
                cache_read: 7
            }
        );
        assert!((result.total_cost_usd.unwrap() - 0.000_939_6).abs() < 1e-12);
    }

    #[test]
    fn claude_one_hour_cache_creation_uses_twice_the_selected_input_rate() {
        let standard = json!({
            "timestamp": "2026-07-15T10:00:00Z",
            "type": "assistant",
            "message": {
                "id": "standard",
                "model": "claude-sonnet-4-20250514",
                "usage": {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cache_creation_input_tokens": 100,
                    "cache_read_input_tokens": 0,
                    "cache_creation": {"ephemeral_1h_input_tokens": 40}
                }
            }
        })
        .to_string();
        let long_context = json!({
            "timestamp": "2026-07-15T10:01:00Z",
            "type": "assistant",
            "message": {
                "id": "long-context",
                "model": "claude-sonnet-4-20250514",
                "usage": {
                    "input_tokens": 200001,
                    "output_tokens": 0,
                    "cache_creation_input_tokens": 100,
                    "cache_read_input_tokens": 0,
                    "cache_creation": {"ephemeral_1h_input_tokens": 40}
                }
            }
        })
        .to_string();
        let fixture = format!("{standard}\n{long_context}\n{long_context}\n");
        let (_directory, scanner) = scanner_with_fixtures("", &fixture);

        let result = scanner
            .scan(CostProvider::Claude, CostRange::Days30, fixture_now())
            .unwrap();

        assert_eq!(result.total_usage.cache_creation, 200);
        assert!((result.total_cost_usd.unwrap() - (0.000_465 + 1.200_936)).abs() < 1e-12);
    }

    #[test]
    fn claude_one_hour_cache_creation_is_clamped_to_the_total_cache_creation() {
        let fixture = format!(
            "{}\n",
            json!({
                "timestamp": "2026-07-15T10:00:00Z",
                "type": "assistant",
                "message": {
                    "id": "clamped",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {
                        "cache_creation_input_tokens": 10,
                        "cache_creation": {"ephemeral_1h_input_tokens": 100}
                    }
                }
            })
        );
        let (_directory, scanner) = scanner_with_fixtures("", &fixture);

        let result = scanner
            .scan(CostProvider::Claude, CostRange::Days30, fixture_now())
            .unwrap();

        assert_eq!(result.total_usage.cache_creation, 10);
        assert!((result.total_cost_usd.unwrap() - 0.000_06).abs() < 1e-12);
    }

    #[test]
    fn invalid_utf8_and_invalid_codex_token_fields_are_line_local() {
        let directory = tempfile::tempdir().unwrap();
        let codex_root = directory.path().join("codex");
        let claude_root = directory.path().join("claude");
        fs::create_dir_all(&codex_root).unwrap();
        fs::create_dir_all(&claude_root).unwrap();
        let valid_before = codex_token_event("2026-07-15T10:00:00Z", Some((100, 0, 10)), None);
        let valid_after = codex_token_event("2026-07-15T10:05:00Z", Some((150, 0, 15)), None);
        let malformed = [json!("10"), json!(10.5), json!([10])]
            .into_iter()
            .enumerate()
            .map(|(offset, value)| {
                json!({
                    "timestamp": format!("2026-07-15T10:0{}:00Z", offset + 1),
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "info": {"total_token_usage": {"input_tokens": value}}
                    }
                })
                .to_string()
            })
            .collect::<Vec<_>>();
        let mut bytes = format!(
            "{}\n{valid_before}\n{}\n",
            json!({
                "timestamp": "2026-07-15T09:00:00Z",
                "type": "session_meta",
                "payload": {"id": "strict-codex", "model": "gpt-5"}
            }),
            malformed.join("\n")
        )
        .into_bytes();
        bytes.extend_from_slice(&[0xff, b'\n']);
        bytes.extend_from_slice(format!("{valid_after}\n").as_bytes());
        fs::write(codex_root.join("session.jsonl"), bytes).unwrap();
        let scanner = CostScanner::new(codex_root, claude_root);

        let result = scanner
            .scan(CostProvider::Codex, CostRange::Days30, fixture_now())
            .unwrap();

        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 150,
                output: 15,
                cache_creation: 0,
                cache_read: 0
            }
        );
        assert_eq!(result.skipped_records, 4);
    }

    #[test]
    fn invalid_utf8_and_invalid_claude_token_fields_are_line_local() {
        let directory = tempfile::tempdir().unwrap();
        let codex_root = directory.path().join("codex");
        let claude_root = directory.path().join("claude");
        fs::create_dir_all(&codex_root).unwrap();
        fs::create_dir_all(&claude_root).unwrap();
        let assistant = |id: &str, timestamp: &str, input: Value| {
            json!({
                "timestamp": timestamp,
                "type": "assistant",
                "message": {
                    "id": id,
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": input}
                }
            })
            .to_string()
        };
        let mut bytes = format!(
            "{}\n{}\n{}\n{}\n",
            assistant("before", "2026-07-15T10:00:00Z", json!(10)),
            assistant("string", "2026-07-15T10:01:00Z", json!("10")),
            assistant("fractional", "2026-07-15T10:02:00Z", json!(10.5)),
            assistant("wrong-type", "2026-07-15T10:03:00Z", json!([10])),
        )
        .into_bytes();
        bytes.extend_from_slice(&[0xff, b'\n']);
        bytes.extend_from_slice(
            format!(
                "{}\n",
                assistant("after", "2026-07-15T10:05:00Z", json!(20))
            )
            .as_bytes(),
        );
        fs::write(claude_root.join("session.jsonl"), bytes).unwrap();
        let scanner = CostScanner::new(codex_root, claude_root);

        let result = scanner
            .scan(CostProvider::Claude, CostRange::Days30, fixture_now())
            .unwrap();

        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 30,
                output: 0,
                cache_creation: 0,
                cache_read: 0
            }
        );
        assert_eq!(result.skipped_records, 4);
    }

    #[test]
    fn codex_divergent_totals_prefer_last_usage_without_double_counting() {
        let fixture = codex_fixture(&[
            codex_token_event(
                "2026-07-15T10:00:00Z",
                Some((100, 20, 10)),
                Some((100, 20, 10)),
            ),
            codex_token_event(
                "2026-07-15T10:01:00Z",
                Some((160, 40, 16)),
                Some((60, 20, 6)),
            ),
            codex_token_event(
                "2026-07-15T10:02:00Z",
                Some((1_000, 900, 100)),
                Some((40, 30, 5)),
            ),
            codex_token_event(
                "2026-07-15T10:03:00Z",
                Some((1_050, 930, 110)),
                Some((50, 30, 10)),
            ),
        ]);

        let result = scan_codex_fixture(&fixture, CostRange::Days30);

        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 150,
                output: 31,
                cache_creation: 0,
                cache_read: 100
            }
        );
    }

    #[test]
    fn codex_repeated_divergent_final_snapshot_counts_last_once() {
        let fixture = codex_fixture(&[
            codex_token_event("2026-07-15T10:00:00Z", Some((50, 0, 0)), Some((100, 0, 0))),
            codex_token_event("2026-07-15T10:01:00Z", Some((50, 0, 0)), Some((100, 0, 0))),
            codex_token_event("2026-07-15T10:02:00Z", Some((50, 0, 0)), Some((100, 0, 0))),
        ]);

        let result = scan_codex_fixture(&fixture, CostRange::Days30);

        assert_eq!(result.total_usage.input, 100);
    }

    #[test]
    fn codex_totals_reset_and_interleave_without_permanent_suppression() {
        let reset = codex_fixture(&[
            codex_token_event("2026-07-15T10:00:00Z", Some((1_000, 0, 0)), None),
            codex_token_event("2026-07-15T10:01:00Z", Some((1_200, 0, 0)), None),
            codex_token_event("2026-07-15T10:02:00Z", Some((300, 0, 0)), None),
            codex_token_event("2026-07-15T10:03:00Z", Some((800, 0, 0)), None),
            codex_token_event("2026-07-15T10:04:00Z", Some((1_500, 0, 0)), None),
        ]);
        let interleaved = codex_fixture(&[
            codex_token_event("2026-07-15T10:00:00Z", Some((100_000, 0, 0)), None),
            codex_token_event("2026-07-15T10:01:00Z", Some((5_000, 0, 0)), None),
            codex_token_event("2026-07-15T10:02:00Z", Some((101_000, 0, 0)), None),
            codex_token_event("2026-07-15T10:03:00Z", Some((6_000, 0, 0)), None),
            codex_token_event("2026-07-15T10:04:00Z", Some((102_000, 0, 0)), None),
        ]);

        assert_eq!(
            scan_codex_fixture(&reset, CostRange::Days30)
                .total_usage
                .input,
            1_500
        );
        assert_eq!(
            scan_codex_fixture(&interleaved, CostRange::Days30)
                .total_usage
                .input,
            102_000
        );
    }

    #[test]
    fn codex_exact_re_emission_and_cache_dimension_drop_do_not_double_count() {
        let fixture = codex_fixture(&[
            codex_token_event(
                "2026-07-15T10:00:00Z",
                Some((100, 20, 10)),
                Some((100, 20, 10)),
            ),
            codex_token_event(
                "2026-07-15T10:01:00Z",
                Some((100, 20, 10)),
                Some((100, 20, 10)),
            ),
            codex_token_event("2026-07-15T10:02:00Z", Some((130, 0, 12)), Some((30, 0, 2))),
        ]);

        let result = scan_codex_fixture(&fixture, CostRange::Days30);

        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 110,
                output: 12,
                cache_creation: 0,
                cache_read: 20
            }
        );
    }

    #[test]
    fn codex_range_uses_full_history_tracker_before_filtering() {
        let fixture = codex_fixture(&[
            codex_token_event("2026-07-14T10:00:00Z", Some((1_000, 0, 0)), None),
            codex_token_event("2026-07-14T10:01:00Z", Some((1_200, 0, 0)), None),
            codex_token_event("2026-07-15T10:02:00Z", Some((300, 0, 0)), None),
            codex_token_event("2026-07-15T10:03:00Z", Some((800, 0, 0)), None),
            codex_token_event("2026-07-15T10:04:00Z", Some((1_500, 0, 0)), None),
        ]);

        let result = scan_codex_fixture(&fixture, CostRange::Today);

        assert_eq!(result.total_usage.input, 300);
    }

    #[test]
    fn codex_turn_context_reads_model_from_payload_info() {
        let fixture = format!(
            "{}\n{}\n{}\n",
            json!({
                "timestamp": "2026-07-15T09:00:00Z",
                "type": "session_meta",
                "payload": {"id": "nested-model"}
            }),
            json!({
                "timestamp": "2026-07-15T09:01:00Z",
                "type": "turn_context",
                "payload": {"info": {"model_name": "gpt-5"}}
            }),
            codex_token_event("2026-07-15T10:00:00Z", Some((100, 0, 10)), None),
        );

        let result = scan_codex_fixture(&fixture, CostRange::Days30);

        assert_eq!(result.models[0].model, "gpt-5");
        assert!(result.total_cost_usd.is_some());
    }

    #[test]
    fn codex_turn_context_prefers_direct_payload_model_over_info_model() {
        let fixture = format!(
            "{}\n{}\n{}\n",
            json!({
                "timestamp": "2026-07-15T09:00:00Z",
                "type": "session_meta",
                "payload": {"id": "conflicting-model"}
            }),
            json!({
                "timestamp": "2026-07-15T09:01:00Z",
                "type": "turn_context",
                "payload": {
                    "model": "gpt-5",
                    "info": {"model": "gpt-5.4"}
                }
            }),
            codex_token_event("2026-07-15T10:00:00Z", Some((100, 0, 10)), None),
        );

        let result = scan_codex_fixture(&fixture, CostRange::Days30);

        assert_eq!(result.models[0].model, "gpt-5");
    }

    #[test]
    fn codex_turn_context_skips_blank_direct_model_before_info_model() {
        let fixture = format!(
            "{}\n{}\n{}\n",
            json!({
                "timestamp": "2026-07-15T09:00:00Z",
                "type": "session_meta",
                "payload": {"id": "blank-direct-model"}
            }),
            json!({
                "timestamp": "2026-07-15T09:01:00Z",
                "type": "turn_context",
                "payload": {
                    "model": "   ",
                    "info": {"model": "gpt-5"}
                }
            }),
            codex_token_event("2026-07-15T10:00:00Z", Some((100, 0, 10)), None),
        );

        let result = scan_codex_fixture(&fixture, CostRange::Days30);

        assert_eq!(result.models[0].model, "gpt-5");
    }

    #[test]
    fn scanner_filters_range_before_aggregation() {
        let old = include_str!("../tests/fixtures/cost/codex-session.jsonl");
        let current = old
            .replace("2026-07-14", "2026-07-15")
            .replace("session-1", "session-2");
        let (directory, scanner) = scanner_with_fixtures(old, "");
        fs::write(directory.path().join("codex/current.jsonl"), current).unwrap();
        let result = scanner
            .scan(CostProvider::Codex, CostRange::Today, fixture_now())
            .unwrap();
        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 130,
                output: 30,
                cache_creation: 0,
                cache_read: 20
            }
        );
        assert_eq!(result.daily.len(), 1);
        assert_eq!(result.daily[0].day, "2026-07-15");
    }

    #[test]
    fn unknown_models_keep_tokens_and_report_unknown_cost() {
        let fixture = include_str!("../tests/fixtures/cost/codex-session.jsonl")
            .replace("gpt-5", "fictional-model-1");
        let (_directory, scanner) = scanner_with_fixtures(&fixture, "");
        let result = scanner
            .scan(CostProvider::Codex, CostRange::Days30, fixture_now())
            .unwrap();
        assert_eq!(result.total_usage.input, 130);
        assert_eq!(result.total_cost_usd, None);
        assert_eq!(result.unknown_models, vec!["fictional-model-1"]);
    }

    #[test]
    fn codex_range_uses_prior_cumulative_snapshot_as_baseline() {
        let fixture = concat!(
            r#"{"timestamp":"2026-07-14T10:00:00Z","type":"session_meta","#,
            r#""payload":{"id":"session-1","model":"gpt-5"}}"#,
            "\n",
            r#"{"timestamp":"2026-07-14T10:01:00Z","type":"event_msg","#,
            r#""payload":{"type":"token_count","info":{"total_token_usage":{"#,
            r#""input_tokens":100,"cached_input_tokens":10,"output_tokens":20}}}}"#,
            "\n",
            r#"{"timestamp":"2026-07-15T10:02:00Z","type":"event_msg","#,
            r#""payload":{"type":"token_count","info":{"total_token_usage":{"#,
            r#""input_tokens":150,"cached_input_tokens":20,"output_tokens":30}}}}"#,
            "\n",
        );
        let (_directory, scanner) = scanner_with_fixtures(fixture, "");

        let result = scanner
            .scan(CostProvider::Codex, CostRange::Today, fixture_now())
            .unwrap();

        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 40,
                output: 10,
                cache_creation: 0,
                cache_read: 10
            }
        );
        assert!((result.total_cost_usd.unwrap() - 0.000_151_25).abs() < 1e-12);
    }

    #[test]
    fn scanner_recurses_and_combines_provider_silos() {
        let directory = tempfile::tempdir().unwrap();
        let codex_root = directory.path().join("codex");
        let claude_root = directory.path().join("claude");
        fs::create_dir_all(codex_root.join("nested/session")).unwrap();
        fs::create_dir_all(claude_root.join("nested/project")).unwrap();
        fs::write(
            codex_root.join("nested/session/codex.jsonl"),
            include_str!("../tests/fixtures/cost/codex-session.jsonl"),
        )
        .unwrap();
        fs::write(
            claude_root.join("nested/project/claude.jsonl"),
            include_str!("../tests/fixtures/cost/claude-session.jsonl"),
        )
        .unwrap();
        let scanner = CostScanner::new(codex_root, claude_root);

        let result = scanner
            .scan(CostProvider::Both, CostRange::Days30, fixture_now())
            .unwrap();

        assert_eq!(result.provider, CostProvider::Both);
        assert_eq!(
            result.total_usage,
            TokenUsage {
                input: 280,
                output: 60,
                cache_creation: 10,
                cache_read: 27
            }
        );
        assert!((result.total_cost_usd.unwrap() - 0.001_404_6).abs() < 1e-12);
    }

    #[test]
    fn malformed_records_are_counted_without_losing_valid_usage() {
        let fixture = format!(
            "not-json\n{}{}\n",
            include_str!("../tests/fixtures/cost/claude-session.jsonl"),
            r#"{"timestamp":"2026-07-14T11:02:00Z","type":"assistant","message":{"id":"broken"}}"#,
        );
        let (_directory, scanner) = scanner_with_fixtures("", &fixture);

        let result = scanner
            .scan(CostProvider::Claude, CostRange::Days30, fixture_now())
            .unwrap();

        assert_eq!(result.total_usage.input, 150);
        assert_eq!(result.skipped_records, 2);
    }

    #[test]
    fn missing_roots_return_an_empty_successful_breakdown() {
        let directory = tempfile::tempdir().unwrap();
        let scanner = CostScanner::new(
            directory.path().join("missing-codex"),
            directory.path().join("missing-claude"),
        );

        let result = scanner
            .scan(CostProvider::Both, CostRange::Days30, fixture_now())
            .unwrap();

        assert_eq!(result.total_usage, TokenUsage::default());
        assert_eq!(result.total_cost_usd, Some(0.0));
        assert!(result.daily.is_empty());
        assert!(result.models.is_empty());
    }

    #[test]
    fn invalid_existing_root_reports_provider_and_path() {
        let directory = tempfile::tempdir().unwrap();
        let codex_root = directory.path().join("codex-root");
        fs::write(&codex_root, "fictional private record").unwrap();
        let scanner = CostScanner::new(codex_root.clone(), directory.path().join("missing-claude"));

        let error = scanner
            .scan(CostProvider::Codex, CostRange::Days30, fixture_now())
            .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Codex"));
        assert!(message.contains(&codex_root.display().to_string()));
        assert!(!message.contains("fictional private record"));
    }
}
