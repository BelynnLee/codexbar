//! `codexbar` command-line interface.
//!
//! Shares the engine's config store, account model, refresh engine, and cost scanner with the GUI
//! (`CODEXBAR_CONFIG_DIR` overrides the config directory for tests and automation). No secrets are
//! ever printed. The argument parser is intentionally dependency-free so the CLI builds offline.

use anyhow::{Context, Result, bail};
use codexbar_engine::{
    AppConfig, ConfigStore, CostBreakdown, CostProvider, CostRange, CostScanner, CredentialField,
    Engine, HistoryPoint, HistoryRange, HistoryStore, ProviderAccount, ProviderConfig, ProviderId,
    ProviderSourceMode, ProviderState, ProviderStatus,
};
use std::io::Read;

const HELP_PREFIX: &str = "\
codexbar — AI coding-provider usage from the command line

USAGE:
    codexbar config providers
    codexbar config enable  --provider <id>
    codexbar config disable --provider <id>
    codexbar config set-secret --provider <id> --field apiKey|secretKey|cookieHeader --stdin [--no-enable]
    codexbar config set-api-key --provider <id> --stdin [--no-enable]
    codexbar refresh [--provider <id>] [--source auto|api|web|cli|oauth] [--json]
    codexbar cost --provider codex|claude|both [--range today|7d|30d] [--json]
    codexbar history --provider <id> [--account <id>] [--range 24h|7d|30d|90d] [--json]";

fn help_text() -> String {
    let providers = ProviderId::ALL
        .into_iter()
        .map(ProviderId::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    format!("{HELP_PREFIX}\n\nProviders: {providers}")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args)
}

fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("config") => run_config(&args[1..]),
        Some("refresh") => run_refresh(&args[1..]),
        Some("cost") => run_cost(&args[1..]),
        Some("history") => run_history(&args[1..]),
        None | Some("help" | "--help" | "-h") => {
            println!("{}", help_text());
            Ok(())
        }
        Some(other) => bail!("unknown command '{other}'\n\n{}", help_text()),
    }
}

// MARK: - config

fn run_config(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("providers") => config_providers(),
        Some("enable") => config_set_enabled(&args[1..], true),
        Some("disable") => config_set_enabled(&args[1..], false),
        Some("set-secret") => config_set_secret(&args[1..], None),
        Some("set-api-key") => config_set_secret(&args[1..], Some(CredentialField::ApiKey)),
        _ => bail!("usage: codexbar config <providers|enable|disable|set-secret|set-api-key>"),
    }
}

fn config_providers() -> Result<()> {
    let store = ConfigStore::discover()?;
    let config = store.load()?;
    println!("{:<13} {:<8} CREDENTIAL", "PROVIDER", "ENABLED");
    for provider in ProviderId::ALL {
        let settings = config.provider(provider);
        let credential = if settings.accounts.iter().any(account_has_secret) {
            "yes"
        } else {
            "—"
        };
        println!(
            "{:<13} {:<8} {credential}",
            provider.as_str(),
            if settings.enabled { "on" } else { "off" }
        );
    }
    Ok(())
}

fn config_set_enabled(args: &[String], enabled: bool) -> Result<()> {
    let provider = required_provider(args)?;
    let store = ConfigStore::discover()?;
    let mut config = store.load()?;
    config.providers.entry(provider).or_default().enabled = enabled;
    store.save(&config)?;
    println!(
        "{} is now {}",
        provider.as_str(),
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

fn config_set_secret(args: &[String], forced_field: Option<CredentialField>) -> Result<()> {
    let provider = required_provider(args)?;
    let no_enable = has_flag(args, "--no-enable");
    let (field, secret) = resolve_secret_input(args, forced_field, &mut std::io::stdin())?;

    let store = ConfigStore::discover()?;
    let mut config = store.load()?;
    let settings = config.providers.entry(provider).or_default();
    if settings.accounts.is_empty() {
        settings.accounts.push(ProviderAccount::default());
    }
    match field {
        CredentialField::ApiKey => settings.accounts[0].api_key = Some(secret),
        CredentialField::SecretKey => settings.accounts[0].secret_key = Some(secret),
        CredentialField::CookieHeader => settings.accounts[0].cookie_header = Some(secret),
        CredentialField::Vault => {
            bail!("managed credential vaults cannot be set with this command")
        }
    }
    if !no_enable {
        settings.enabled = true;
    }
    store.save(&config)?;
    println!(
        "stored {} for {}{}",
        credential_field_name(field),
        provider.as_str(),
        if no_enable { "" } else { " (enabled)" }
    );
    Ok(())
}

/// Resolve a typed secret from a supplied reader. Argument values are never treated as secrets and
/// no error includes the stdin payload.
fn resolve_secret_input(
    args: &[String],
    forced_field: Option<CredentialField>,
    reader: &mut impl Read,
) -> Result<(CredentialField, String)> {
    validate_secret_arguments(args, forced_field.is_some())?;
    if !has_flag(args, "--stdin") {
        bail!("secret values are accepted only via --stdin");
    }

    let field = if let Some(field) = forced_field {
        field
    } else {
        let raw = flag_value(args, "--field").context(
            "missing --field apiKey|secretKey|cookieHeader for codexbar config set-secret",
        )?;
        parse_credential_field(&raw)?
    };
    let mut buffer = String::new();
    reader
        .read_to_string(&mut buffer)
        .context("reading secret from stdin")?;
    let secret = buffer.trim();
    if secret.is_empty() {
        bail!("no secret was provided on stdin");
    }
    Ok((field, secret.to_owned()))
}

fn validate_secret_arguments(args: &[String], field_is_forced: bool) -> Result<()> {
    let mut index = 0;
    let mut provider_count = 0;
    let mut field_count = 0;
    let mut stdin_count = 0;
    let mut no_enable_count = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--stdin" => {
                stdin_count += 1;
                if stdin_count > 1 {
                    bail!("duplicate option in secret command");
                }
                index += 1;
            }
            "--no-enable" => {
                no_enable_count += 1;
                if no_enable_count > 1 {
                    bail!("duplicate option in secret command");
                }
                index += 1;
            }
            "--provider" => {
                provider_count += 1;
                if provider_count > 1 {
                    bail!("duplicate option in secret command");
                }
                let Some(value) = args.get(index + 1) else {
                    bail!("unsupported argument in secret command; use --stdin for secret values");
                };
                if value.starts_with("--") {
                    bail!("unsupported argument in secret command; use --stdin for secret values");
                }
                index += 2;
            }
            "--field" => {
                field_count += 1;
                if field_is_forced || field_count > 1 {
                    bail!("unsupported or duplicate option in secret command");
                }
                let Some(value) = args.get(index + 1) else {
                    bail!("unsupported argument in secret command; use --stdin for secret values");
                };
                if value.starts_with("--") {
                    bail!("unsupported argument in secret command; use --stdin for secret values");
                }
                index += 2;
            }
            _ => {
                bail!("unsupported argument in secret command; use --stdin for secret values");
            }
        }
    }
    Ok(())
}

fn parse_credential_field(value: &str) -> Result<CredentialField> {
    match value {
        "apiKey" => Ok(CredentialField::ApiKey),
        "secretKey" => Ok(CredentialField::SecretKey),
        "cookieHeader" => Ok(CredentialField::CookieHeader),
        _ => bail!("unsupported secret field (expected apiKey, secretKey, or cookieHeader)"),
    }
}

const fn credential_field_name(field: CredentialField) -> &'static str {
    match field {
        CredentialField::ApiKey => "apiKey",
        CredentialField::SecretKey => "secretKey",
        CredentialField::CookieHeader => "cookieHeader",
        CredentialField::Vault => "vault",
    }
}

// MARK: - refresh

fn run_refresh(args: &[String]) -> Result<()> {
    let options = parse_refresh_options(args)?;

    let engine = Engine::new().context("building the refresh engine")?;
    let store = ConfigStore::discover()?;
    let config = store.load()?;
    let refresh_config = options.source_override.map_or_else(
        || config.clone(),
        |source| config_with_source_override(&config, options.provider, source),
    );
    let config_dir = store.path().parent().map(std::path::Path::to_path_buf);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    let mut states = runtime.block_on(engine.refresh_all(&refresh_config, config_dir.as_deref()));
    if let Some(provider) = options.provider {
        states.retain(|state| state.descriptor.id == provider);
    }

    if options.json {
        println!("{}", serde_json::to_string_pretty(&states)?);
    } else {
        print_states(&states);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RefreshOptions {
    provider: Option<ProviderId>,
    source_override: Option<ProviderSourceMode>,
    json: bool,
}

fn parse_refresh_options(args: &[String]) -> Result<RefreshOptions> {
    let provider = optional_provider(args)?;
    let source_override = if has_flag(args, "--source") {
        let source = flag_value(args, "--source")
            .filter(|value| !value.starts_with("--"))
            .context("missing --source value (expected auto|api|web|cli|oauth)")?;
        Some(parse_source_mode(&source)?)
    } else {
        None
    };
    Ok(RefreshOptions {
        provider,
        source_override,
        json: has_flag(args, "--json"),
    })
}

fn parse_source_mode(value: &str) -> Result<ProviderSourceMode> {
    match value {
        "auto" => Ok(ProviderSourceMode::Auto),
        "api" => Ok(ProviderSourceMode::Api),
        "web" => Ok(ProviderSourceMode::Web),
        "cli" => Ok(ProviderSourceMode::Cli),
        "oauth" => Ok(ProviderSourceMode::Oauth),
        other => bail!("unknown source '{other}' (expected auto|api|web|cli|oauth)"),
    }
}

fn config_with_source_override(
    config: &AppConfig,
    provider: Option<ProviderId>,
    source: ProviderSourceMode,
) -> AppConfig {
    let mut overridden = config.clone();
    match provider {
        Some(provider) => {
            overridden
                .providers
                .entry(provider)
                .or_default()
                .source_mode = source;
        }
        None => {
            for provider in ProviderId::ALL {
                overridden
                    .providers
                    .entry(provider)
                    .or_default()
                    .source_mode = source;
            }
        }
    }
    overridden
}

fn print_states(states: &[ProviderState]) {
    if states.is_empty() {
        println!("no matching providers");
        return;
    }
    for state in states {
        let name = state.descriptor.display_name;
        let status = status_label(state.status);
        let detail = state
            .error
            .clone()
            .or_else(|| {
                state.snapshot.as_ref().and_then(|snapshot| {
                    snapshot
                        .windows
                        .first()
                        .map(|window| format!("{} {:.0}%", window.title, window.used_percent))
                        .or_else(|| {
                            snapshot
                                .summary
                                .first()
                                .map(|item| format!("{}: {}", item.label, item.value))
                        })
                })
            })
            .unwrap_or_default();
        println!("{name:<13} {status:<9} {detail}");
    }
}

const fn status_label(status: ProviderStatus) -> &'static str {
    match status {
        ProviderStatus::Ready => "ready",
        ProviderStatus::Error => "error",
        ProviderStatus::Disabled => "disabled",
        ProviderStatus::Loading => "loading",
    }
}

// MARK: - cost

fn run_cost(args: &[String]) -> Result<()> {
    let provider = parse_cost_provider(flag_value(args, "--provider").as_deref())?;
    let range = parse_cost_range(flag_value(args, "--range").as_deref())?;
    let json = has_flag(args, "--json");

    let store = ConfigStore::discover()?;
    let config = store.load()?;
    let scanner = CostScanner::resolve(
        config.history.codex_path.clone(),
        config.history.claude_path.clone(),
    )?;
    let breakdown = scanner.scan(provider, range, chrono::Utc::now())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&breakdown)?);
    } else {
        print_cost(&breakdown);
    }
    Ok(())
}

fn print_cost(breakdown: &CostBreakdown) {
    let usage = breakdown.total_usage;
    let total_tokens = usage.input + usage.output + usage.cache_creation + usage.cache_read;
    println!("provider     {:?}", breakdown.provider);
    println!("total tokens {total_tokens}");
    if let Some(cost) = breakdown.total_cost_usd {
        println!("total cost   ${cost:.4}");
    }
    if !breakdown.daily.is_empty() {
        println!("\nDAY        TOKENS      COST");
        for day in &breakdown.daily {
            let tokens = day.usage.input
                + day.usage.output
                + day.usage.cache_creation
                + day.usage.cache_read;
            let cost = day
                .cost_usd
                .map_or_else(|| "—".to_owned(), |value| format!("${value:.4}"));
            println!("{:<10} {tokens:<11} {cost}", day.day);
        }
    }
    if breakdown.skipped_records > 0 {
        println!(
            "\nskipped {} unparseable record(s)",
            breakdown.skipped_records
        );
    }
}

// MARK: - history

fn run_history(args: &[String]) -> Result<()> {
    let provider = required_provider(args)?;
    let account = flag_value(args, "--account");
    let range = parse_history_range(flag_value(args, "--range").as_deref())?;
    let json = has_flag(args, "--json");

    let store = ConfigStore::discover()?;
    let base = store
        .path()
        .parent()
        .context("could not resolve the config directory")?
        .to_path_buf();
    let history = HistoryStore::at(base.join("history"));
    let points = history.query(provider, account.as_deref(), range, chrono::Utc::now())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&points)?);
    } else {
        print_history(&points);
    }
    Ok(())
}

fn print_history(points: &[HistoryPoint]) {
    if points.is_empty() {
        println!("no history recorded for that provider/range");
        return;
    }
    println!("{:<20} {:<14} USED%   RESETS", "TIMESTAMP", "WINDOW");
    for point in points {
        let resets = point.resets_at.map_or_else(
            || "—".to_owned(),
            |reset| reset.format("%Y-%m-%d %H:%M").to_string(),
        );
        println!(
            "{:<20} {:<14} {:>5.1}   {resets}",
            point.timestamp.format("%Y-%m-%d %H:%M"),
            truncate(&point.window_id, 14),
            point.used_percent,
        );
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        value
            .chars()
            .take(max.saturating_sub(1))
            .collect::<String>()
            + "…"
    }
}

fn parse_history_range(value: Option<&str>) -> Result<HistoryRange> {
    match value {
        Some("24h") => Ok(HistoryRange::Hours24),
        None | Some("7d") => Ok(HistoryRange::Days7),
        Some("30d") => Ok(HistoryRange::Days30),
        Some("90d") => Ok(HistoryRange::Days90),
        Some(other) => bail!("unknown range '{other}' (expected 24h, 7d, 30d, or 90d)"),
    }
}

// MARK: - argument helpers

fn required_provider(args: &[String]) -> Result<ProviderId> {
    let value = flag_value(args, "--provider").context("missing --provider <id>")?;
    parse_provider(&value)
}

fn optional_provider(args: &[String]) -> Result<Option<ProviderId>> {
    flag_value(args, "--provider")
        .map(|value| parse_provider(&value))
        .transpose()
}

fn parse_provider(value: &str) -> Result<ProviderId> {
    ProviderId::ALL
        .into_iter()
        .find(|provider| provider.as_str() == value)
        .with_context(|| format!("unknown provider '{value}'"))
}

fn parse_cost_provider(value: Option<&str>) -> Result<CostProvider> {
    match value {
        Some("codex") => Ok(CostProvider::Codex),
        Some("claude") => Ok(CostProvider::Claude),
        Some("both") => Ok(CostProvider::Both),
        Some(other) => bail!("unknown cost provider '{other}' (expected codex, claude, or both)"),
        None => bail!("missing --provider codex|claude|both"),
    }
}

fn parse_cost_range(value: Option<&str>) -> Result<CostRange> {
    match value {
        None | Some("today") => Ok(CostRange::Today),
        Some("7d") => Ok(CostRange::Days7),
        Some("30d") => Ok(CostRange::Days30),
        Some(other) => bail!("unknown range '{other}' (expected today, 7d, or 30d)"),
    }
}

/// Value of `--name <value>`, or `None` when the flag is absent or has no following token.
fn flag_value(args: &[String], name: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == name)?;
    args.get(index + 1).cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn account_has_secret(account: &ProviderAccount) -> bool {
    ProviderConfig::normalized_secret(&account.api_key).is_some()
        || ProviderConfig::normalized_secret(&account.secret_key).is_some()
        || ProviderConfig::normalized_secret(&account.cookie_header).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codexbar_engine::{AppConfig, CredentialField, ProviderSourceMode};
    use std::io::Cursor;

    fn to_args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_every_known_provider() {
        for provider in ProviderId::ALL {
            assert_eq!(parse_provider(provider.as_str()).unwrap(), provider);
        }
        assert!(parse_provider("not-a-provider").is_err());
    }

    #[test]
    fn refresh_parses_every_source_mode_and_rejects_invalid_or_missing_values() {
        for (raw, expected) in [
            ("auto", ProviderSourceMode::Auto),
            ("api", ProviderSourceMode::Api),
            ("web", ProviderSourceMode::Web),
            ("cli", ProviderSourceMode::Cli),
            ("oauth", ProviderSourceMode::Oauth),
        ] {
            let options = parse_refresh_options(&to_args(&["--source", raw])).unwrap();
            assert_eq!(options.source_override, Some(expected));
        }
        assert!(
            parse_refresh_options(&to_args(&["--source", "ftp"]))
                .unwrap_err()
                .to_string()
                .contains("auto|api|web|cli|oauth")
        );
        assert!(
            parse_refresh_options(&to_args(&["--source"]))
                .unwrap_err()
                .to_string()
                .contains("missing --source")
        );
        assert!(
            parse_refresh_options(&to_args(&["--source", "--json"]))
                .unwrap_err()
                .to_string()
                .contains("missing --source")
        );
    }

    #[test]
    fn refresh_source_override_changes_only_the_in_memory_copy() {
        let mut config = AppConfig::default();
        config
            .providers
            .get_mut(&ProviderId::Claude)
            .unwrap()
            .source_mode = ProviderSourceMode::Cli;
        config
            .providers
            .get_mut(&ProviderId::Codex)
            .unwrap()
            .source_mode = ProviderSourceMode::Web;
        let saved_representation = serde_json::to_string(&config).unwrap();

        let one_provider =
            config_with_source_override(&config, Some(ProviderId::Claude), ProviderSourceMode::Api);
        assert_eq!(
            one_provider.provider(ProviderId::Claude).source_mode,
            ProviderSourceMode::Api
        );
        assert_eq!(
            one_provider.provider(ProviderId::Codex).source_mode,
            ProviderSourceMode::Web
        );
        assert_eq!(
            serde_json::to_string(&config).unwrap(),
            saved_representation
        );

        let all = config_with_source_override(&config, None, ProviderSourceMode::Oauth);
        assert!(
            ProviderId::ALL
                .into_iter()
                .all(|provider| all.provider(provider).source_mode == ProviderSourceMode::Oauth)
        );
    }

    #[test]
    fn help_lists_the_complete_provider_registry() {
        let help = help_text();
        for provider in ProviderId::ALL {
            assert!(
                help.split_whitespace()
                    .any(|value| value == provider.as_str()),
                "help omitted {provider}"
            );
        }
    }

    #[test]
    fn typed_secret_input_accepts_only_supported_fields_and_stdin() {
        for (raw, expected) in [
            ("apiKey", CredentialField::ApiKey),
            ("secretKey", CredentialField::SecretKey),
            ("cookieHeader", CredentialField::CookieHeader),
        ] {
            let mut reader = Cursor::new("  fictional-secret\n");
            let (field, secret) =
                resolve_secret_input(&to_args(&["--field", raw, "--stdin"]), None, &mut reader)
                    .unwrap();
            assert_eq!(field, expected);
            assert_eq!(secret, "fictional-secret");
        }

        let mut reader = Cursor::new("ignored");
        assert!(
            resolve_secret_input(
                &to_args(&["--field", "baseUrl", "--stdin"]),
                None,
                &mut reader,
            )
            .is_err()
        );
        let unsupported_field_error = resolve_secret_input(
            &to_args(&["--field", "do-not-echo-this", "--stdin"]),
            None,
            &mut reader,
        )
        .unwrap_err()
        .to_string();
        assert!(!unsupported_field_error.contains("do-not-echo-this"));
        let error = resolve_secret_input(
            &to_args(&["--field", "apiKey", "--api-key", "do-not-echo-this"]),
            None,
            &mut reader,
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("do-not-echo-this"));
        assert!(error.contains("--stdin"));
    }

    #[test]
    fn api_key_alias_also_requires_stdin() {
        let mut reader = Cursor::new(" legacy-secret ");
        let (field, secret) = resolve_secret_input(
            &to_args(&["--stdin"]),
            Some(CredentialField::ApiKey),
            &mut reader,
        )
        .unwrap();
        assert_eq!(field, CredentialField::ApiKey);
        assert_eq!(secret, "legacy-secret");

        let error = resolve_secret_input(
            &to_args(&["--api-key", "inline-secret"]),
            Some(CredentialField::ApiKey),
            &mut reader,
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("inline-secret"));
    }

    #[test]
    fn secret_input_rejects_equal_form_and_unknown_arguments_without_echoing_values() {
        for args in [
            to_args(&["--field", "apiKey", "--stdin", "--api-key=equal-secret"]),
            to_args(&[
                "--field",
                "apiKey",
                "--stdin",
                "--mystery-secret",
                "unknown-secret",
            ]),
        ] {
            let mut reader = Cursor::new("stdin-secret");
            let error = resolve_secret_input(&args, None, &mut reader)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("equal-secret"));
            assert!(!error.contains("unknown-secret"));
            assert!(error.contains("unsupported argument"));
        }
    }

    #[test]
    fn secret_commands_reject_command_specific_and_duplicate_options_without_echoing_values() {
        let cases = [
            (
                to_args(&["--provider", "openrouter", "--field", "apiKey", "--stdin"]),
                Some(CredentialField::ApiKey),
            ),
            (
                to_args(&[
                    "--provider",
                    "openrouter",
                    "--provider",
                    "secret-provider",
                    "--field",
                    "apiKey",
                    "--stdin",
                ]),
                None,
            ),
            (
                to_args(&[
                    "--provider",
                    "openrouter",
                    "--field",
                    "apiKey",
                    "--field",
                    "secret-field",
                    "--stdin",
                ]),
                None,
            ),
            (
                to_args(&[
                    "--provider",
                    "openrouter",
                    "--field",
                    "apiKey",
                    "--stdin",
                    "--stdin",
                ]),
                None,
            ),
            (
                to_args(&[
                    "--provider",
                    "openrouter",
                    "--field",
                    "apiKey",
                    "--stdin",
                    "--no-enable",
                    "--no-enable",
                ]),
                None,
            ),
        ];
        for (args, forced) in cases {
            let mut reader = Cursor::new("stdin-secret");
            let error = resolve_secret_input(&args, forced, &mut reader)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret-provider"));
            assert!(!error.contains("secret-field"));
            assert!(!error.contains("stdin-secret"));
            assert!(error.contains("unsupported") || error.contains("duplicate"));
        }
    }

    #[test]
    fn credential_presence_includes_secret_key() {
        let account = ProviderAccount {
            secret_key: Some("fictional-secret".into()),
            ..Default::default()
        };
        assert!(account_has_secret(&account));
    }

    #[test]
    fn cost_provider_and_range_parsing() {
        assert_eq!(
            parse_cost_provider(Some("both")).unwrap(),
            CostProvider::Both
        );
        assert!(parse_cost_provider(Some("nope")).is_err());
        assert!(parse_cost_provider(None).is_err());
        assert_eq!(parse_cost_range(None).unwrap(), CostRange::Today);
        assert_eq!(parse_cost_range(Some("7d")).unwrap(), CostRange::Days7);
        assert_eq!(parse_cost_range(Some("30d")).unwrap(), CostRange::Days30);
        assert!(parse_cost_range(Some("1y")).is_err());
    }

    #[test]
    fn flag_extraction_reads_values_and_booleans() {
        let args = to_args(&["--provider", "claude", "--json"]);
        assert_eq!(flag_value(&args, "--provider").as_deref(), Some("claude"));
        assert!(has_flag(&args, "--json"));
        assert!(!has_flag(&args, "--stdin"));
        assert_eq!(flag_value(&args, "--range"), None);
        // A trailing flag with no value is treated as absent, not a panic.
        assert_eq!(flag_value(&to_args(&["--provider"]), "--provider"), None);
    }

    #[test]
    fn history_range_parsing() {
        assert_eq!(parse_history_range(None).unwrap(), HistoryRange::Days7);
        assert_eq!(
            parse_history_range(Some("24h")).unwrap(),
            HistoryRange::Hours24
        );
        assert_eq!(
            parse_history_range(Some("90d")).unwrap(),
            HistoryRange::Days90
        );
        assert!(parse_history_range(Some("5m")).is_err());
    }

    #[test]
    fn truncate_shortens_long_window_ids() {
        assert_eq!(truncate("session", 14), "session");
        assert_eq!(truncate("very-long-window-id", 10), "very-long…");
    }

    #[test]
    fn unknown_top_level_command_is_an_error() {
        assert!(run(&to_args(&["wat"])).is_err());
    }
}
