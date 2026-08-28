import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../src/provider-account-actions.ts", import.meta.url), "utf8");
const mainSource = await readFile(new URL("../src/main.ts", import.meta.url), "utf8");
const typesSource = await readFile(new URL("../src/types.ts", import.meta.url), "utf8");
const stylesSource = await readFile(new URL("../src/styles/provider-accounts.css", import.meta.url), "utf8");
const settingsStylesSource = await readFile(new URL("../src/styles/settings.css", import.meta.url), "utf8");
const styleManifestSource = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
const i18nSource = await readFile(new URL("../src/i18n.ts", import.meta.url), "utf8");
const packageSource = await readFile(new URL("../package.json", import.meta.url), "utf8");
const backendSource = await readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
const javascript = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const actions = await import(`data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`);

test("inactive official account can switch only through a supported adapter", () => {
  assert.equal(actions.accountActivationDisabled({ isActive: false, canActivate: true }, false), false);
  assert.equal(actions.accountActivationDisabled({ isActive: false, canActivate: false }, false), true);
  assert.equal(actions.accountActivationDisabled({ isActive: true, canActivate: true }, false), true);
  assert.equal(actions.accountActivationDisabled({ isActive: false, canActivate: true }, true), true);
});

test("all provider account activation and deletion actions require confirmation", () => {
  for (const provider of ["codex", "claude", "openrouter"]) {
    assert.equal(actions.providerAccountActionRequiresConfirmation(provider, "activate"), true);
    assert.equal(actions.providerAccountActionRequiresConfirmation(provider, "delete"), true);
  }
});

test("provider busy state is scoped to that provider", () => {
  assert.equal(actions.providerActionBusy("codex", "codex"), true);
  assert.equal(actions.providerActionBusy("codex", "claude"), false);
  assert.equal(actions.providerActionBusy(undefined, "codex"), false);
});

test("feedback distinguishes rollback, retained recovery, external writes, and unsupported adapters", () => {
  assert.equal(actions.providerAccountFeedbackKind("rolledBack"), "rolledBack");
  assert.equal(actions.providerAccountFeedbackKind("recoveryRequired"), "recovery");
  assert.equal(actions.providerAccountFeedbackKind("recoveryFailed"), "recovery");
  assert.equal(actions.providerAccountFeedbackKind("externalWrite"), "externalWrite");
  assert.equal(actions.providerAccountFeedbackKind("unsupportedActivation"), "unsupported");
  assert.equal(actions.providerAccountFeedbackKind("invalidCredential"), "error");
});

test("successful reauthentication of the active account requires explicit credential reapplication", () => {
  assert.equal(
    actions.shouldReapplyAfterReauthentication(
      { status: "succeeded", accountId: "work" },
      "work",
      "work",
      "work",
      false,
      true,
    ),
    true,
  );
  assert.equal(
    actions.shouldReapplyAfterReauthentication(
      { status: "succeeded", accountId: "other" },
      "work",
      "work",
      "work",
      false,
      true,
    ),
    false,
  );
  assert.equal(
    actions.shouldReapplyAfterReauthentication(
      { status: "failed", accountId: "work" },
      "work",
      "work",
      "work",
      false,
      true,
    ),
    false,
  );
  assert.equal(
    actions.shouldReapplyAfterReauthentication(
      { status: "succeeded", accountId: "work" },
      "work",
      "work",
      undefined,
      false,
      true,
    ),
    false,
  );
  assert.equal(
    actions.shouldReapplyAfterReauthentication(
      { status: "succeeded", accountId: "work" },
      "work",
      "work",
      "work",
      true,
      true,
    ),
    false,
  );
  assert.equal(
    actions.shouldReapplyAfterReauthentication(
      { status: "succeeded", accountId: "work" },
      "work",
      "work",
      "work",
      false,
      false,
    ),
    false,
  );
});

test("activation freezes a safe expected current identity for managed, external, and empty states", () => {
  const managedIdentity = {
    provider: "codex",
    stableKeys: [{ namespace: "accountId", value: "managed-1" }],
    email: "managed@example.com",
    displayName: "Managed",
    accessToken: "must-not-be-copied",
  };
  const externalIdentity = {
    provider: "codex",
    stableKeys: [{ namespace: "subject", value: "external-1" }],
    email: "external@example.com",
    displayName: "External",
  };
  const managedPool = {
    activeAccountId: "managed",
    accounts: [{ accountId: "managed", identity: managedIdentity }],
    externalIdentity,
  };
  const managed = actions.snapshotExpectedCurrentProviderIdentity(managedPool);
  assert.equal(managed.source, "managed");
  assert.deepEqual(managed.identity, {
    provider: managedIdentity.provider,
    stableKeys: managedIdentity.stableKeys,
    email: managedIdentity.email,
    displayName: managedIdentity.displayName,
  });
  assert.notEqual(managed.identity, managedIdentity);
  assert.equal("accessToken" in managed.identity, false);

  managedPool.accounts[0].identity.displayName = "Changed after dialog opened";
  managedPool.externalIdentity.displayName = "Changed external";
  assert.equal(managed.identity.displayName, "Managed");

  const external = actions.snapshotExpectedCurrentProviderIdentity({
    accounts: [],
    externalIdentity,
  });
  assert.equal(external.source, "external");
  assert.deepEqual(external.identity.stableKeys, externalIdentity.stableKeys);

  const empty = actions.snapshotExpectedCurrentProviderIdentity({ accounts: [] });
  assert.deepEqual(empty, { source: "none", identity: undefined });
});

test("activation submits the same frozen identity shown by the dialog", () => {
  assert.match(mainSource, /expectedCurrentIdentity\?:\s*ProviderAccountIdentity/);
  assert.match(mainSource, /snapshotExpectedCurrentProviderIdentity/);
  assert.match(mainSource, /currentIdentitySnapshot\.identity/);
  assert.match(mainSource, /expectedCurrentIdentity:\s*currentIdentitySnapshot\.identity/);
  assert.match(mainSource, /"activate_provider_account"[\s\S]{0,180}expectedCurrentIdentity,/);
  assert.match(
    mainSource,
    /activateProviderAccount\(\s*action\.providerId,\s*action\.accountId,\s*action\.expectedCurrentIdentity/,
  );
  assert.match(mainSource, /freshActiveAccount\?\.identity/);
  assert.match(
    mainSource,
    /activateProviderAccount\(\s*payload\.providerId,\s*payload\.accountId,\s*freshCurrentIdentity/,
  );
});

test("generic helpers contain no Codex-special or Profile behavior", () => {
  assert.doesNotMatch(source, /CodexProfile|codex-profile|activate_codex_profile|profile\./);
  assert.doesNotMatch(source, /provider\s*===?\s*["']codex["']/);
});

test("frontend runtime uses only generic Provider account commands and events", () => {
  for (const legacy of [
    "CodexProfile",
    "codex-profile",
    "activate_codex_profile",
    "begin_codex_profile_login",
    "delete_codex_profile",
    "recover_codex_default_auth",
    "profile.",
  ]) {
    const pattern = new RegExp(legacy.replaceAll(".", "\\."));
    assert.doesNotMatch(mainSource, pattern);
    assert.doesNotMatch(typesSource, pattern);
  }
  for (const generic of [
    "provider-account-login-updated",
    "provider-account-pools-updated",
    "begin_provider_account_login",
    "activate_provider_account",
    "delete_provider_account",
    "recover_provider_auth",
  ]) {
    assert.match(mainSource, new RegExp(generic));
  }
  assert.match(packageSource, /provider-account-actions\.test\.mjs/);
  assert.doesNotMatch(packageSource, /profile-actions\.test\.mjs/);
});

test("backend exposes only generic Provider account lifecycle commands", () => {
  for (const legacy of [
    "activate_codex_profile",
    "begin_codex_profile_login",
    "cancel_codex_profile_login",
    "delete_codex_profile",
    "import_current_codex_profile",
    "recover_codex_default_auth",
  ]) {
    assert.doesNotMatch(backendSource, new RegExp(`fn ${legacy}\\b`));
  }
  for (const generic of [
    "activate_provider_account",
    "begin_provider_account_login",
    "cancel_provider_account_login",
    "delete_provider_account",
    "import_current_provider_account",
    "recover_provider_auth",
  ]) {
    assert.match(backendSource, new RegExp(`fn ${generic}\\b`));
  }
});

test("declared enrollment independently gates add, import, and CLI login actions", () => {
  assert.equal(actions.providerAccountAddMode(["cliLogin"]), "login");
  assert.equal(actions.providerAccountAddMode(["manualSecret"]), "local");
  assert.equal(actions.providerAccountAddMode(["browserLogin"]), undefined);
  assert.equal(actions.providerAccountAddMode(["deviceOAuth"]), undefined);
  assert.equal(actions.providerAccountAddMode(["importCurrent"]), undefined);
  assert.equal(actions.providerAccountAddMode([]), undefined);

  assert.equal(actions.providerSupportsEnrollment(["importCurrent"], "importCurrent"), true);
  assert.equal(actions.providerSupportsEnrollment(["cliLogin"], "importCurrent"), false);
  assert.equal(actions.providerSupportsEnrollment([], "cliLogin"), false);

  assert.match(typesSource, /enrollment:\s*ProviderEnrollmentKind\[\]/);
  assert.match(
    mainSource,
    /providerAccountAddMode\(pool\.enrollment\)/,
  );
  assert.match(
    mainSource,
    /providerSupportsEnrollment\(pool\.enrollment,\s*["']importCurrent["']\)/,
  );
  assert.match(
    mainSource,
    /providerSupportsEnrollment\(pool\.enrollment,\s*["']cliLogin["']\)/,
  );
});

test("busy providers are omitted from a settings save without blocking other providers", () => {
  assert.equal(actions.providerSettingsIncludedInSave(false, false), true);
  assert.equal(actions.providerSettingsIncludedInSave(true, false), false);
  assert.equal(actions.providerSettingsIncludedInSave(false, true), false);
  assert.match(typesSource, /providers:\s*Partial<Record<ProviderId,\s*ProviderSettingsUpdate>>/);
  assert.match(mainSource, /providerSettingsIncludedInSave\(\s*providerBusy\.has\(descriptor\.id\),\s*pool\?\.operationInProgress/);
});

test("fail-closed pools stay visible while ordinary paused accounts stay hidden", () => {
  assert.equal(actions.providerAccountVisibleOnUsage(false, false), false);
  assert.equal(actions.providerAccountVisibleOnUsage(false, true), true);
  assert.equal(actions.providerAccountVisibleOnUsage(true, false), true);
  // Normal login, switch, and recovery only change operation/recovery state; projection remains
  // available, so a paused sibling must stay hidden until stateUnavailable is explicitly true.
  for (const _normalOperation of ["login", "switch", "recovery"]) {
    assert.equal(actions.providerAccountVisibleOnUsage(false, false), false);
  }
  assert.match(typesSource, /stateUnavailable:\s*boolean/);
  assert.match(mainSource, /providerAccountVisibleOnUsage\(account\.enabled,\s*pool\.stateUnavailable\)/);
  assert.doesNotMatch(
    mainSource,
    /providerAccountVisibleOnUsage\([^)]*(?:operationInProgress|recoveryState)/,
  );
  assert.match(mainSource, /!state\s*\?[^:]*provider\.account\.quotaUnavailable/s);
  assert.match(mainSource, /providerStateVisibleOnUsage/);
  assert.match(mainSource, /nextEnabledProviderCardIndex[\s\S]*providerStateVisibleOnUsage/);
});

test("login flow binds sessions from waiting events and ignores late command responses", () => {
  const starting = actions.beginProviderLoginFlow(4, "codex", "work", "work");
  assert.equal(starting.phase, "starting");
  assert.equal(starting.sessionId, undefined);
  const waiting = actions.applyProviderLoginEvent(starting, {
    sessionId: "session-a", providerId: "codex", status: "waiting",
  });
  assert.equal(waiting.phase, "waiting");
  assert.equal(waiting.sessionId, "session-a");
  const terminalBeforeResponse = actions.applyProviderLoginEvent(starting, {
    sessionId: "session-a", providerId: "codex", status: "succeeded", accountId: "work",
  });
  assert.equal(terminalBeforeResponse.phase, "terminal");
  assert.equal(actions.applyProviderLoginResponse(terminalBeforeResponse, 4, "session-a"), terminalBeforeResponse);
  const newer = actions.beginProviderLoginFlow(5, "codex", "other", "work");
  assert.equal(actions.applyProviderLoginResponse(newer, 4, "stale"), newer);
  assert.match(mainSource, /beginProviderLoginFlow/);
  assert.match(mainSource, /applyProviderLoginEvent/);
  assert.match(mainSource, /applyProviderLoginResponse/);
});

test("events are buffered until bootstrap exists and listener failures disable unsafe actions", () => {
  assert.match(mainSource, /pendingProviderLoginEvents/);
  assert.match(mainSource, /pendingProviderPoolEvents/);
  assert.match(mainSource, /drainPendingProviderEvents/);
  assert.match(mainSource, /providerLoginListenerReady/);
  assert.match(mainSource, /providerPoolListenerReady/);
  assert.equal(actions.providerLifecycleUnavailable(false, true), true);
  assert.equal(actions.providerLifecycleUnavailable(true, false), true);
  assert.equal(actions.providerLifecycleUnavailable(true, true), false);
});

test("settings account-pool updates and active operations preserve drafts and secrets", () => {
  assert.match(mainSource, /captureProviderSettingsDraft/);
  assert.match(mainSource, /restoreProviderSettingsDraft/);
  assert.match(mainSource, /refreshProviderSettingsSection/);
  assert.match(mainSource, /renderProviderAccountUi/);
  assert.doesNotMatch(mainSource, /provider-account-pools-updated"[\s\S]{0,300}else render\(\)/);
  const activateStart = mainSource.indexOf("async function activateProviderAccount");
  const activateEnd = mainSource.indexOf("async function beginProviderAccountLogin", activateStart);
  const activateBody = mainSource.slice(activateStart, activateEnd);
  assert.doesNotMatch(activateBody, /\brender\(\)/);
  assert.match(activateBody, /renderProviderAccountUi\(providerId\)/);
  assert.match(mainSource, /value:\s*control\.value/);
  assert.match(mainSource, /control\.value\s*=\s*saved\.value/);
  assert.match(mainSource, /clearSecret:\s*control\.dataset\.clear === "true"/);
  assert.match(mainSource, /\[data-settings-provider="\$\{providerId\}"\]/);
});

test("official managed rows never expose legacy auth commands", () => {
  assert.match(mainSource, /allowLegacyQuotaSourceActions/);
  assert.match(mainSource, /hasOfficialIdentity/);
  assert.match(mainSource, /pool\.enrollment\.length === 0/);
});

test("active providers cannot be disabled and external accounts are explicit in switch confirmation", () => {
  assert.match(mainSource, /provider\.account\.activeProviderCannotDisable/);
  assert.match(mainSource, /pool\.activeAccountId\s*\?\s*"disabled"/);
  assert.match(mainSource, /provider\.account\.externalCurrent/);
  assert.match(mainSource, /expectedCurrentSource === "external"/);
});

test("provider account CSS wins the settings cascade and styles add actions", () => {
  assert.match(stylesSource, /\.account-row\.provider-account-settings-row\s*\{/);
  assert.match(stylesSource, /\.add-provider-account\s*\{/);
  assert.match(stylesSource, /\.add-provider-account:hover/);
  assert.match(stylesSource, /\.add-provider-account:disabled/);
  assert.match(stylesSource, /\.add-provider-account:focus-visible/);
  assert.match(stylesSource, /\.provider-account-dialog \.primary\s*\{/);
  assert.match(stylesSource, /\.provider-account-dialog \.primary:hover/);
  assert.match(stylesSource, /\.provider-account-dialog \.primary:focus-visible/);
  assert.match(stylesSource, /\.provider-account-dialog \.primary:disabled/);
  assert.ok(
    styleManifestSource.indexOf("provider-accounts.css") < styleManifestSource.indexOf("settings.css"),
  );
  assert.match(settingsStylesSource, /\.account-row\s*\{/);
  assert.match(settingsStylesSource, /\.primary\s*\{/);
  const specificity = (selector) => [
    (selector.match(/#[\w-]+/g) ?? []).length,
    (selector.match(/\.[\w-]+|\[[^\]]+\]|:(?!:)[\w-]+/g) ?? []).length,
    (selector.match(/(^|[\s>+~])(?:[a-z][\w-]*)/gi) ?? []).length,
  ];
  assert.deepEqual(specificity(".account-row.provider-account-settings-row"), [0, 2, 0]);
  assert.deepEqual(specificity(".account-row"), [0, 1, 0]);
  assert.deepEqual(specificity(".provider-account-dialog .primary"), [0, 2, 0]);
  assert.deepEqual(specificity(".primary"), [0, 1, 0]);
  assert.match(
    stylesSource,
    /\.provider-account-dialog \.primary\s*\{[^}]*background:\s*var\(--accent\)/s,
  );
});

test("all structured provider errors use localized safe messages", () => {
  const codes = [
    "unsupportedActivation", "invalidCredential", "identityMismatch", "externalWrite",
    "rolledBack", "recoveryRequired", "recoveryFailed", "loginFailure",
    "operationInProgress", "accountNotFound", "accountActive", "accountDisabled", "internal",
  ];
  for (const code of codes) {
    const key = `provider.account.error.${code}`;
    assert.equal(actions.providerAccountErrorTranslationKey(code), key);
    assert.equal(i18nSource.split(`"${key}"`).length - 1, 2, `${key} must exist in EN and zh-Hans`);
  }
  assert.doesNotMatch(mainSource, /default:\s*\n\s*return error\.message/);
});
