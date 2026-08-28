use codexbar_engine::{
    Engine, ProviderAuthActionKind, ProviderId, ProviderMaturity, ProviderSettingKey,
    ProviderSettingKind, ProviderSourceMode, providers,
};
use std::{collections::HashSet, fs, path::Path};

#[test]
fn public_capability_enums_use_the_documented_serde_spellings() {
    for (value, expected) in [
        (ProviderMaturity::Experimental, "experimental"),
        (ProviderMaturity::Stable, "stable"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), expected);
    }

    for (value, expected) in [
        (ProviderSettingKey::ApiKey, "apiKey"),
        (ProviderSettingKey::SecretKey, "secretKey"),
        (ProviderSettingKey::CookieHeader, "cookieHeader"),
        (ProviderSettingKey::Browser, "browser"),
        (ProviderSettingKey::BaseUrl, "baseUrl"),
        (ProviderSettingKey::Region, "region"),
        (ProviderSettingKey::WorkspaceId, "workspaceId"),
        (ProviderSettingKey::OrganizationId, "organizationId"),
        (ProviderSettingKey::ProjectId, "projectId"),
        (ProviderSettingKey::Deployment, "deployment"),
        (ProviderSettingKey::EnterpriseHost, "enterpriseHost"),
        (ProviderSettingKey::UsageScope, "usageScope"),
        (ProviderSettingKey::AwsProfile, "awsProfile"),
        (ProviderSettingKey::AwsAuthMode, "awsAuthMode"),
        (
            ProviderSettingKey::KiloOrganizationIds,
            "kiloOrganizationIds",
        ),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), expected);
    }

    for (value, expected) in [
        (ProviderSettingKind::Plain, "plain"),
        (ProviderSettingKind::Secret, "secret"),
        (ProviderSettingKind::Select, "select"),
        (ProviderSettingKind::MultiValue, "multiValue"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), expected);
    }

    for (value, expected) in [
        (ProviderAuthActionKind::BrowserLogin, "browserLogin"),
        (ProviderAuthActionKind::CookieImport, "cookieImport"),
        (ProviderAuthActionKind::CliImport, "cliImport"),
        (ProviderAuthActionKind::DeviceOAuth, "deviceOAuth"),
        (ProviderAuthActionKind::OAuthConnect, "oauthConnect"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), expected);
    }

    let moonshot = Engine::new()
        .unwrap()
        .descriptors()
        .into_iter()
        .find(|descriptor| descriptor.id == ProviderId::Moonshot)
        .unwrap();
    let json = serde_json::to_value(moonshot.capabilities).unwrap();
    assert_eq!(json["maturity"], "experimental");
    assert_eq!(json["sourceModes"], serde_json::json!(["auto", "api"]));
    assert_eq!(json["settings"][1]["key"], "region");
    assert_eq!(json["settings"][1]["kind"], "select");
    assert_eq!(
        json["settings"][1]["choices"],
        serde_json::json!(["international", "china"])
    );
    assert_eq!(json["authActions"], serde_json::json!([]));
}

#[test]
fn registered_capabilities_obey_registry_invariants() {
    let descriptors = Engine::new().unwrap().descriptors();
    assert_eq!(
        descriptors
            .iter()
            .map(|descriptor| descriptor.id)
            .collect::<Vec<_>>(),
        ProviderId::ALL
    );

    for descriptor in descriptors {
        let capability = descriptor.capabilities;
        assert_eq!(capability.maturity, ProviderMaturity::Experimental);
        assert_eq!(
            capability.source_modes.first(),
            Some(&ProviderSourceMode::Auto)
        );
        assert_eq!(
            capability
                .source_modes
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .len(),
            capability.source_modes.len(),
            "{} has duplicate source modes",
            descriptor.id
        );
        assert_eq!(
            capability
                .settings
                .iter()
                .map(|setting| setting.key)
                .collect::<HashSet<_>>()
                .len(),
            capability.settings.len(),
            "{} has duplicate setting keys",
            descriptor.id
        );
        assert_eq!(
            capability
                .auth_actions
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .len(),
            capability.auth_actions.len(),
            "{} has duplicate auth actions",
            descriptor.id
        );

        for setting in capability.settings {
            let is_secret_key = matches!(
                setting.key,
                ProviderSettingKey::ApiKey
                    | ProviderSettingKey::SecretKey
                    | ProviderSettingKey::CookieHeader
            );
            assert_eq!(setting.kind == ProviderSettingKind::Secret, is_secret_key);
            assert_eq!(
                setting.kind == ProviderSettingKind::Select,
                setting.choices.is_some()
            );
            assert_eq!(
                setting.kind == ProviderSettingKind::MultiValue,
                setting.key == ProviderSettingKey::KiloOrganizationIds
            );
        }
    }
}

#[test]
fn every_advertised_source_mode_has_an_executable_strategy() {
    for provider in providers::all_providers() {
        let descriptor = provider.descriptor();
        for source_mode in descriptor
            .capabilities
            .source_modes
            .iter()
            .copied()
            .filter(|source| *source != ProviderSourceMode::Auto)
        {
            let strategies = provider.strategies(source_mode);
            assert!(
                !strategies.is_empty(),
                "{} advertises {source_mode:?} without an executable strategy",
                descriptor.id
            );
            assert!(
                strategies
                    .iter()
                    .all(|strategy| strategy.source_mode == source_mode),
                "{} returned a strategy for a different source than {source_mode:?}",
                descriptor.id
            );
        }
    }
}

#[test]
fn parity_matrix_matches_every_registered_runtime_capability() {
    let matrix_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("docs/provider-parity.json");
    let matrix: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&matrix_path)
            .unwrap_or_else(|error| panic!("reading {} failed: {error}", matrix_path.display())),
    )
    .unwrap_or_else(|error| panic!("parsing {} failed: {error}", matrix_path.display()));
    let entries = matrix.as_array().expect("provider parity matrix array");

    for provider in providers::all_providers() {
        let descriptor = provider.descriptor();
        let entry = entries
            .iter()
            .find(|entry| entry["id"] == descriptor.id.as_str())
            .unwrap_or_else(|| panic!("{} is missing from the parity matrix", descriptor.id));

        let matrix_sources = entry["sourceModes"]
            .as_array()
            .expect("sourceModes array")
            .iter()
            .map(|value| value.as_str().expect("source mode string"))
            .collect::<Vec<_>>();
        let runtime_sources = descriptor
            .capabilities
            .source_modes
            .iter()
            .map(|source| match source {
                ProviderSourceMode::Auto => "auto",
                ProviderSourceMode::Api => "api",
                ProviderSourceMode::Web => "web",
                ProviderSourceMode::Cli => "cli",
                ProviderSourceMode::Oauth => "oauth",
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matrix_sources, runtime_sources,
            "{} source modes",
            descriptor.id
        );

        let matrix_strategies = entry["windowsStrategies"]
            .as_array()
            .expect("windowsStrategies array")
            .iter()
            .map(|value| value.as_str().expect("strategy string"))
            .collect::<Vec<_>>();
        let runtime_strategies = provider
            .strategies(ProviderSourceMode::Auto)
            .into_iter()
            .map(|strategy| serde_json::to_value(strategy.kind).unwrap())
            .map(|value| value.as_str().expect("serialized strategy kind").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            matrix_strategies, runtime_strategies,
            "{} strategies",
            descriptor.id
        );
    }
}

#[test]
fn legacy_multiple_account_flag_remains_serialized_for_transport_compatibility() {
    let descriptors = Engine::new().unwrap().descriptors();
    let descriptor = descriptors
        .into_iter()
        .find(|descriptor| !descriptor.supports_multiple_accounts)
        .expect("fixture with legacy flag disabled");

    let json = serde_json::to_value(descriptor).unwrap();
    assert_eq!(json["supportsMultipleAccounts"], false);
}

#[test]
fn representative_provider_capabilities_match_the_windows_targets() {
    let descriptors = Engine::new().unwrap().descriptors();
    let find = |id| {
        descriptors
            .iter()
            .find(|descriptor| descriptor.id == id)
            .unwrap()
            .capabilities
    };

    assert_eq!(
        find(ProviderId::Claude).source_modes,
        &[
            ProviderSourceMode::Auto,
            ProviderSourceMode::Api,
            ProviderSourceMode::Web,
            ProviderSourceMode::Cli,
            ProviderSourceMode::Oauth,
        ]
    );
    assert_eq!(
        find(ProviderId::Codex).source_modes,
        &[ProviderSourceMode::Auto, ProviderSourceMode::Oauth]
    );
    assert_eq!(
        find(ProviderId::Cursor).source_modes,
        &[
            ProviderSourceMode::Auto,
            ProviderSourceMode::Cli,
            ProviderSourceMode::Web,
        ]
    );
    assert_eq!(
        find(ProviderId::Claude).auth_actions,
        &[
            ProviderAuthActionKind::BrowserLogin,
            ProviderAuthActionKind::CookieImport,
            ProviderAuthActionKind::CliImport,
        ]
    );
    let claude_api_key = find(ProviderId::Claude)
        .settings
        .iter()
        .find(|setting| setting.key == ProviderSettingKey::ApiKey)
        .unwrap();
    assert!(
        !claude_api_key.required,
        "Claude apiKey is only required when the API source is selected"
    );
    assert!(
        find(ProviderId::Codex)
            .auth_actions
            .contains(&ProviderAuthActionKind::CliImport)
    );
    assert_eq!(
        find(ProviderId::Codex).auth_actions,
        &[ProviderAuthActionKind::CliImport]
    );
    assert!(
        find(ProviderId::Cursor)
            .auth_actions
            .contains(&ProviderAuthActionKind::CookieImport)
    );
    assert!(
        !find(ProviderId::Cursor)
            .auth_actions
            .contains(&ProviderAuthActionKind::CliImport)
    );

    let moonshot = find(ProviderId::Moonshot);
    let region = moonshot
        .settings
        .iter()
        .find(|setting| setting.key == ProviderSettingKey::Region)
        .unwrap();
    assert_eq!(region.kind, ProviderSettingKind::Select);
    assert_eq!(region.choices, Some(&["international", "china"][..]));

    let deepgram = find(ProviderId::Deepgram);
    assert!(
        deepgram
            .settings
            .iter()
            .any(|setting| setting.key == ProviderSettingKey::ProjectId)
    );
    assert!(
        deepgram
            .settings
            .iter()
            .all(|setting| setting.key != ProviderSettingKey::WorkspaceId)
    );
}
