# CodexBar for Windows

A Rust + [Tauri](https://tauri.app) rewrite of [CodexBar](https://codexbar.app) for the Windows
notification area. It keeps AI coding-provider usage limits visible from the system tray and reuses the
same local credentials you already have — CLI OAuth files, browser sessions, and API keys — so no
passwords are stored.

The Windows port currently registers 41 providers in the engine and includes the full engine + tray +
settings surface, opt-in autostart, and single-instance window activation. The public repository is
currently source-and-CI only; signed installers and automatic updates are intentionally not enabled.

The parity matrix contains 60 tracked targets (59 upstream providers plus the Windows-only OpenCode
Zen extension): 41 are registered and 19 remain intentionally unimplemented pending protocol evidence.

### Current verification boundary

- Runtime capabilities are checked against executable fetch strategies and authentication handlers;
  UI actions are not advertised until a handler exists.
- All 41 registered providers remain experimental, and no parity entry has completed live QA.
  Parser and fixture tests therefore prove contract handling, not successful access to a real account.
- The 19 unregistered targets need captured protocol responses or installed provider CLIs before they
  can be implemented faithfully. Custom declarative providers and Agent Sessions are also not part of
  the current Windows runtime.
- Saved-account monitoring is generic, while activation of an official client credential is currently
  implemented only for Codex. Claude deliberately refuses activation because its documented credential
  schema has no stable official account identifier.
- Official releases and automatic updates are not configured in the public branch yet.

## Providers

Provider coverage and Windows strategy status are tracked in the
[provider parity matrix](docs/provider-parity.json). Validate it against the Rust and TypeScript provider
definitions with `powershell -NoProfile -ExecutionPolicy Bypass -File ./Scripts/Test-ProviderParity.ps1`.
The table below highlights the original eleven-provider subset and is not the complete registered list.

| Provider   | Auth              | Credential source                                                        |
| ---------- | ----------------- | ------------------------------------------------------------------------ |
| Claude     | CLI OAuth         | `%USERPROFILE%\.claude\.credentials.json` (auto-refreshed)               |
| Codex      | CLI OAuth         | `%CODEX_HOME%\auth.json` or `%USERPROFILE%\.codex\auth.json`             |
| Copilot    | GitHub device OAuth | Settings login, or `COPILOT_API_TOKEN`                                  |
| Cursor     | Browser cookie    | `cursor.com` cookies from Chrome/Edge, or a manual Cookie header         |
| OpenCode   | Browser cookie    | `opencode.ai` cookies from Chrome/Edge, or a manual Cookie header        |
| OpenCode Zen | API key         | Settings, or `OPENCODE_ZEN_API_KEY`                                      |
| OpenRouter | API key           | Settings, or `OPENROUTER_API_KEY`                                        |
| DeepSeek   | API key           | Settings, or `DEEPSEEK_API_KEY`                                          |
| Moonshot   | API key           | Settings, or `MOONSHOT_API_KEY`                                          |
| Venice     | API key           | Settings, or `VENICE_API_KEY`                                           |
| Poe        | API key           | Settings, or `POE_API_KEY`                                              |

## How it works

```
Web frontend (TypeScript, Vite)          src/           tray panel · usage cards · settings
        ▲ Tauri IPC (invoke/emit)
Tauri shell (Rust)                        src-tauri/     tray icon · window · background refresh loop
        │
Engine (Rust crate)                       crates/codexbar-engine/
        ├── provider.rs   trait Provider  one async fetch per provider
        ├── providers/  provider probes   HTTP + JSON → normalized UsageWindow / SummaryItem
        ├── auth/         credential layer OAuth refresh · DPAPI browser-cookie import
        ├── config.rs     settings store   %APPDATA%\CodexBar\config.json
        └── model.rs      shared types     ProviderState serialized straight to the frontend
```

The engine is a standalone crate with no Tauri dependency, so its logic is unit-tested in isolation
(`cargo test -p codexbar-engine`). The Tauri shell only owns the tray, the window, and a background loop
that refreshes every N minutes and emits `usage-updated` to the frontend.

## Requirements

- Windows 10/11
- Rust stable (MSVC toolchain) — 1.85+ for the 2024 edition
- [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/) (preinstalled on current Windows 11)
- Node.js 20 or newer

## Development

```powershell
npm ci
npm run test:public-surface
npm run check              # provider parity validation + tsc type-check
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
npm run build
npm run tauri dev          # launches the tray app with hot-reloaded frontend
```

The window is frameless and starts hidden. Left-click the tray icon to toggle it; the tray menu offers
**Open**, **Refresh**, and **Quit**. Closing the window hides it rather than exiting.

## Building

```powershell
.\node_modules\.bin\tauri.cmd build --bundles nsis
```

The build produces an unsigned per-user x64 NSIS installer under `target\release\bundle\nsis` for local
testing. The public branch does not publish installers, generate updater artifacts, or read signing
credentials. Do not treat a locally built installer as an official release.

### Releases

GitHub Actions currently runs source checks only. A future release workflow must introduce a separate
public updater trust chain and keep all signing keys, certificates, and passwords in the CI secret store;
none of those values belong in the repository or the client binary.

## Configuration

Settings use config schema version 4 and live in `%APPDATA%\CodexBar\config.json`. Set
`CODEXBAR_CONFIG_DIR` to a non-empty directory to use `<directory>\config.json` instead; this override is
intended for tests and controlled automation and does not relocate the history or snapshot files.
Prefer the Settings tab for credentials. Secrets are never echoed back to the UI — the frontend only
learns whether a value is present.

```jsonc
{
  "version": 4,
  "refreshIntervalMinutes": 5,        // clamped to 1–60
  "providers": {
    "openrouter": {
      "enabled": true,
      "activeAccountId": "acc_work",
      "accounts": [
        { "id": "acc_work", "label": "Work", "enabled": true, "apiKey": null, "browser": "auto" }
      ]
    }
  },
  "menuBar": { "displayMode": "icon", "highestUsage": true, "showPercentage": true },
  "history": {
    "enabled": true,
    "retentionDays": 90,
    "costScanEnabled": true,
    "codexPath": null,
    "claudePath": null
  },
  "notifications": { "enabled": true, "thresholds": [75.0, 90.0] },
  "statusPolling": { "enabled": true, "intervalMinutes": 10 },
  "shortcuts": {},
  "locale": "system",
  "adaptiveRefresh": { "enabled": true, "resetProximityMinutes": 10 },
  "widgetSnapshot": { "enabled": true, "path": null },
  "security": { "persistCredentials": true }
}
```

Each provider has `enabled`, optional `activeAccountId`, and an `accounts` array. Account fields include
the stable `id`, optional `label`, `enabled`, `apiKey`, `cookieHeader`, `workspaceId`, and `browser`
(`auto` | `chrome` | `edge`). Provider keys are lowercase (`claude`, `codex`, `copilot`, `cursor`, `opencode`,
`opencodezen`, `openrouter`, `deepseek`, `moonshot`, `venice`, `poe`). Schema v4 adds typed
provider/account fields and externalizes managed credentials into provider-scoped encrypted vaults.
Existing v1-v3 files migrate to v4 while preserving account order, metadata, and credentials.

### Local data files

- Usage history is retained for 90 days by default in one JSONL file per provider under
  `%APPDATA%\CodexBar\history\` (for example, `openrouter.jsonl`).
- Local cost scanning reads Codex sessions from `%USERPROFILE%\.codex\sessions` and Claude sessions
  from `%USERPROFILE%\.claude\projects` by default. `history.codexPath` and `history.claudePath` can
  override those roots. Scans are local and on demand.
- The reduced third-party widget snapshot defaults to `%APPDATA%\CodexBar\snapshot.json` and can be
  relocated with `widgetSnapshot.path`. See the [Widget Snapshot JSON Schema v1](docs/widget-snapshot-schema.md)
  for its versioning, privacy, and atomic-update contract.

### Credential resolution order

- **API key providers** (OpenRouter, DeepSeek): the value in Settings wins; otherwise the environment
  variable (`OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`) is used.
- **CLI OAuth providers** (Claude, Codex): the local CLI credential file is read and its OAuth token is
  refreshed and written back automatically when it is near expiry or rejected. `CODEXBAR_CLAUDE_OAUTH_TOKEN`
  overrides the Claude file; `CODEX_HOME` relocates the Codex file. A `codex login` that stored a raw
  `OPENAI_API_KEY` in `auth.json` is also honored.
- **GitHub device OAuth** (Copilot): Settings starts GitHub's device authorization flow and stores the
  resulting token through the same DPAPI-at-rest account path. `COPILOT_API_TOKEN` is a controlled CLI
  and automation fallback.
- **Browser cookie providers** (Cursor, OpenCode): a manual `cookieHeader` wins; otherwise cookies are
  imported from the browser (below).

### Browser cookie import (DPAPI)

For Cursor and OpenCode, CodexBar reads the Chrome/Edge cookie database directly:

1. It decrypts the browser's master key from `Local State` with user-context **DPAPI**
   (`CryptUnprotectData`).
2. It decrypts each `v10`/`v11` cookie with **AES-256-GCM** and strips the host-hash prefix.
3. It walks the `Default`, `Guest Profile`, and `Profile N` profiles for the provider's domains.

Two situations fall back to a manual Cookie header (paste it in Settings — copy the request `Cookie`
header from the site's DevTools → Network tab):

- **The browser locks its live cookie database while running** (`os error 32`,
  `ERROR_SHARING_VIOLATION`). Edge is the common case: its **Startup boost** keeps background
  processes alive that hold the database open with no read sharing even after every window closes, so
  no user-mode copy can snapshot it. Fully quit the browser (end its background processes in Task
  Manager, or disable Startup boost) — or just paste a Cookie header.
- **Cookies stored with Chromium App-Bound encryption** (`v20`, newer Chrome/Edge) cannot be
  decrypted by third-party apps: the wrapping key is protected by the browser's SYSTEM-level
  elevation service, out of reach of a normal user process. When only `v20` cookies are found,
  CodexBar asks you to paste a Cookie header instead.

Set `browser` to pin Chrome or Edge if auto-detection picks the wrong one.

## Security notes

- Saved API keys and Cookie headers are encrypted at rest with current-user Windows DPAPI and stored as
  `enc:v1:<base64>` envelopes in `config.json`. Legacy plaintext values remain readable for migration
  and are rewritten as DPAPI ciphertext on the next save. If `security.persistCredentials` is `false`,
  secrets are omitted from the saved config instead of being written as plaintext. Windows Credential
  Manager is not used.
- OAuth refresh writes are staged to a temp file and copied over the CLI credential file.
- The frontend has no network permission; all provider requests happen in Rust, and the CSP restricts the
  webview to IPC and local assets.

## Command line (`codexbar`)

The `codexbar-cli` crate builds a `codexbar` binary that shares the engine's config store, account
model, refresh engine, and local cost scanner with the tray app. It reads the same
`%APPDATA%\CodexBar\config.json` (or `CODEXBAR_CONFIG_DIR` when set) and never prints secrets.

```powershell
cargo run -p codexbar-cli -- config providers
cargo run -p codexbar-cli -- config enable  --provider openrouter
cargo run -p codexbar-cli -- config set-api-key --provider deepseek --stdin   # reads key from stdin
cargo run -p codexbar-cli -- refresh --provider claude --json
cargo run -p codexbar-cli -- refresh --provider copilot --json
cargo run -p codexbar-cli -- cost --provider both --range 7d --json
cargo run -p codexbar-cli -- history --provider openrouter --range 7d --json
```

`set-api-key` stores the key through the same DPAPI-at-rest path as the GUI (no plaintext in
`config.json`). `refresh` performs live provider requests; `cost` only scans local Codex/Claude
session logs; `history` reads the usage points the tray app records under
`%APPDATA%\CodexBar\history\`.

## Project layout

```
.
├── crates/codexbar-engine/   provider engine (no Tauri dependency, fully unit-tested)
├── crates/codexbar-cli/      `codexbar` CLI over the shared engine (config · refresh · cost)
├── src-tauri/                Tauri shell: tray, window, IPC commands, background refresh
├── src/                      TypeScript frontend (main.ts, styles.css, types.ts)
├── index.html                Vite entry
└── package.json / Cargo.toml workspace + toolchain config
```

> **Note:** `dist/`, `node_modules/`, `target/`, generated release metadata, and local signing overrides
> are ignored and do not need to be committed.

## Relationship to upstream

This is an independent Windows port. It reimplements each provider's usage endpoints and parsing against
the same APIs as the macOS app, but it does not share code and will track upstream changes manually. See
[`AGENTS.md`](AGENTS.md) for contributor guidance; the original Swift project is preserved on the `main`
branch.

Licensed under MIT, matching the parent project.
