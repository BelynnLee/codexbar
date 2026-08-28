import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { resolveLocale, setLocale, t } from "./i18n";
import { authActionViewState } from "./auth-action-state";
import {
  accountActivationDisabled,
  applyProviderLoginEvent,
  applyProviderLoginResponse,
  beginProviderLoginFlow,
  credentialStateNeedsReauthentication,
  providerAccountActionRequiresConfirmation,
  providerAccountErrorTranslationKey,
  providerAccountFeedbackKind,
  providerAccountAddMode,
  providerAccountVisibleOnUsage,
  providerLifecycleUnavailable,
  providerSettingsIncludedInSave,
  snapshotExpectedCurrentProviderIdentity,
  providerSupportsEnrollment,
  providerActionBusy,
  shouldReapplyAfterReauthentication,
  showsExternalProviderAccount,
} from "./provider-account-actions";
import { CHART_W, lineChart, ring } from "./charts";
import { morphHtml } from "./dom";
import { createStore } from "./store";
import type { ProviderLoginFlowState } from "./provider-account-actions";
import "./styles.css";
import type {
  AccountUpdate,
  AccountView,
  Bootstrap,
  ConfigView,
  ProviderAuthActionKind,
  ProviderDescriptor,
  ProviderId,
  ProviderSettingDescriptor,
  ProviderSettingKey,
  ProviderSourceMode,
  ProviderSettingsUpdate,
  ProviderState,
  SettingsUpdate,
  UsageWindow,
  Warning,
  HistoryPoint,
  CostBreakdown,
  CopilotDeviceCodeEvent,
  ProviderAccountCommandError,
  ProviderAccountIdentity,
  ProviderAccountImportResult,
  ProviderAccountLoginEvent,
  ProviderAccountLoginStarted,
  ProviderAccountPoolAccountView,
  ProviderAccountPoolView,
  ProviderAccountSwitchResult,
} from "./types";

const app = document.querySelector<HTMLElement>("#app") ?? fail("Missing #app root");

let bootstrap: Bootstrap;
let bootstrapReady = false;
let activeTab: "usage" | "settings" = "usage";
// The tab the current DOM was rendered for, so render() only carries the scroll position across
// re-renders that stay on the same tab (background refreshes) and resets to top when the tab changes.
let renderedTab: "usage" | "settings" | undefined;
let refreshing = false;
let launchAtStartup = false;
let changingLaunchAtStartup = false;
let launchAtStartupError: string | undefined;
// Threshold warnings from the most recent refresh (backend "warnings-updated" event). Each entry is
// a crossing that just occurred; the banner surfaces them until the next refresh replaces the set.
let warnings: Warning[] = [];
// Per-card usage-history trend: which cards are expanded, and a cache of the fetched points keyed by
// `provider:accountId`. `undefined` in the cache means "fetch in flight".
const expandedTrends = new Set<string>();
// History is cached per `${trendKey}::${range}` so switching range keeps each range's fetch.
const historyCache = new Map<string, HistoryPoint[] | undefined>();
type TrendRange = "24h" | "7d" | "30d" | "90d";
const TREND_RANGES: TrendRange[] = ["24h", "7d", "30d", "90d"];
const trendRanges = new Map<string, TrendRange>();
// Chart hover crosshair: mousemove is coalesced onto one hit-test + repaint per animation frame
// (it can fire far more often than that), and we track which chart's overlay is currently shown so
// leaving it — or crossing straight into a different chart — hides the right one.
let hoverRaf = 0;
let hoverClientX = 0;
let hoverClientY = 0;
let hoverActiveSvg: SVGSVGElement | undefined;
// Local cost panel state (on-demand scan of Codex/Claude session logs).
let costProvider: "codex" | "claude" | "both" = "both";
let costRange: "today" | "7d" | "30d" = "7d";
let costResult: CostBreakdown | undefined;
let costScanning = false;
let costError: string | undefined;
let copilotDeviceCode: CopilotDeviceCodeEvent | undefined;
let copilotConnecting = false;
let copilotConnectError: string | undefined;
let activeProviderCardIndex = -1;
// When set (to a `provider:accountId` trend key), the usage tab shows that one provider's deep view
// instead of the card list. Cleared by the back button or if the provider stops being configured.
let activeDetail: string | undefined;
const providerBusy = new Set<ProviderId>();
const providerLoginFlows = new Map<ProviderId, ProviderLoginFlowState>();
let providerLoginGeneration = 0;
let providerLoginListenerReady = false;
let providerPoolListenerReady = false;
let pendingProviderEventSequence = 0;
const pendingProviderLoginEvents: Array<{ sequence: number; payload: ProviderAccountLoginEvent }> = [];
const pendingProviderPoolEvents: Array<{
  sequence: number;
  payload: Bootstrap["providerAccountPools"];
}> = [];
let providerAccountNotice: {
  providerId?: ProviderId;
  kind: "success" | "error" | "rolledBack" | "recovery" | "externalWrite" | "unsupported";
  message: string;
} | undefined;
let pendingProviderAccountAction:
  | {
      kind: "activate";
      providerId: ProviderId;
      accountId: string;
      expectedCurrentIdentity?: ProviderAccountIdentity;
      expectedCurrentSource: "managed" | "external" | "none";
      expectedCurrentQuota: string;
    }
  | { kind: "delete"; providerId: ProviderId; accountId: string; label: string }
  | undefined;

// Reactive store driving usage-tab repaints. Backend events (`usage-updated`, `warnings-updated`)
// bump the revision instead of calling `patchUsage()` directly; the store batches those back-to-back
// events onto one microtask, so a refresh that emits both collapses into a single node-diff pass.
const usageStore = createStore({ revision: 0 });
function requestUsagePatch(): void {
  usageStore.update((state) => ({ revision: state.revision + 1 }));
}

function applyLocale(): void {
  setLocale(resolveLocale(bootstrap.config.locale, navigator.language));
}

async function registerProviderAccountListeners(): Promise<void> {
  if (!providerLoginListenerReady) {
    try {
      await listen<ProviderAccountLoginEvent>("provider-account-login-updated", ({ payload }) => {
        if (!bootstrapReady) {
          pendingProviderLoginEvents.push({ sequence: pendingProviderEventSequence++, payload });
          return;
        }
        void handleProviderLoginEvent(payload);
      });
      providerLoginListenerReady = true;
    } catch {
      providerLoginListenerReady = false;
    }
  }
  if (!providerPoolListenerReady) {
    try {
      await listen<Bootstrap["providerAccountPools"]>("provider-account-pools-updated", ({ payload }) => {
        if (!bootstrapReady) {
          pendingProviderPoolEvents.push({ sequence: pendingProviderEventSequence++, payload });
          return;
        }
        handleProviderPoolEvent(payload);
      });
      providerPoolListenerReady = true;
    } catch {
      providerPoolListenerReady = false;
    }
  }
}

async function drainPendingProviderEvents(): Promise<void> {
  const events = [
    ...pendingProviderLoginEvents.map((event) => ({ ...event, kind: "login" as const })),
    ...pendingProviderPoolEvents.map((event) => ({ ...event, kind: "pool" as const })),
  ].sort((left, right) => left.sequence - right.sequence);
  pendingProviderLoginEvents.length = 0;
  pendingProviderPoolEvents.length = 0;
  for (const event of events) {
    if (event.kind === "login") await handleProviderLoginEvent(event.payload);
    else handleProviderPoolEvent(event.payload);
  }
}

function updateProviderListenerFailureNotice(): void {
  if (!providerLifecycleUnavailable(providerLoginListenerReady, providerPoolListenerReady)) return;
  providerAccountNotice = {
    kind: "error",
    message: t("provider.account.listenerUnavailable"),
  };
}

async function retryProviderAccountListeners(): Promise<void> {
  await registerProviderAccountListeners();
  if (providerLifecycleUnavailable(providerLoginListenerReady, providerPoolListenerReady)) {
    updateProviderListenerFailureNotice();
  } else {
    providerAccountNotice = undefined;
    await reloadBootstrap();
  }
  if (bootstrapReady) renderProviderAccountUi();
}

function handleProviderPoolEvent(payload: Bootstrap["providerAccountPools"]): void {
  bootstrap.providerAccountPools = payload;
  if (activeTab === "usage") requestUsagePatch();
  else {
    for (const descriptor of bootstrap.descriptors) refreshProviderSettingsSection(descriptor.id);
  }
}

async function handleProviderLoginEvent(payload: ProviderAccountLoginEvent): Promise<void> {
  const existing = providerLoginFlows.get(payload.providerId) ?? beginProviderLoginFlow(
    ++providerLoginGeneration,
    payload.providerId,
  );
  const next = applyProviderLoginEvent(existing, payload);
  if (next === existing && existing.sessionId && existing.sessionId !== payload.sessionId) return;
  if (payload.status === "waiting") {
    providerLoginFlows.set(payload.providerId, next);
    providerBusy.add(payload.providerId);
    renderProviderAccountUi(payload.providerId);
    return;
  }

  providerLoginFlows.delete(payload.providerId);
  providerBusy.delete(payload.providerId);
  if (payload.status === "succeeded") {
    try {
      const freshBootstrap = await invoke<Bootstrap>("bootstrap");
      bootstrap = freshBootstrap;
      applyLocale();
      const freshPool = freshBootstrap.providerAccountPools[payload.providerId];
      const freshActiveAccount = freshPool?.accounts.find((account) =>
        account.accountId === freshPool.activeAccountId,
      );
      const freshCurrentIdentity = freshActiveAccount?.identity && freshPool
        ? snapshotExpectedCurrentProviderIdentity(freshPool).identity
        : undefined;
      const reauthenticationWasActive = Boolean(
        next.requestedAccountId &&
        next.activeAccountIdAtStart === next.requestedAccountId,
      );
      if (
        payload.accountId &&
        shouldReapplyAfterReauthentication(
          payload,
          next.requestedAccountId,
          next.activeAccountIdAtStart,
          freshPool?.activeAccountId,
          Boolean(freshPool?.externalIdentity),
          Boolean(freshCurrentIdentity),
        )
      ) {
        await activateProviderAccount(
          payload.providerId,
          payload.accountId,
          freshCurrentIdentity,
          true,
        );
        return;
      }
      providerAccountNotice = {
        providerId: payload.providerId,
        kind: reauthenticationWasActive ? "externalWrite" : "success",
        message: reauthenticationWasActive
          ? t("provider.account.reauthenticationNotReapplied", { provider: providerName(payload.providerId) })
          : t("provider.account.loginSucceeded", { provider: providerName(payload.providerId) }),
      };
    } catch {
      setProviderAccountError({
        code: "internal",
        providerId: payload.providerId,
        message: "provider bootstrap reconciliation failed",
      });
    }
  } else if (payload.status === "failed" && payload.error) {
    setProviderAccountError({ ...payload.error, providerId: payload.error.providerId ?? payload.providerId });
  } else if (payload.status === "cancelled") {
    providerAccountNotice = {
      providerId: payload.providerId,
      kind: "error",
      message: t("provider.account.loginCancelled"),
    };
  } else if (payload.status === "timedOut") {
    providerAccountNotice = {
      providerId: payload.providerId,
      kind: "error",
      message: t("provider.account.loginTimedOut"),
    };
  }
  renderProviderAccountUi(payload.providerId);
}

async function start(): Promise<void> {
  try {
    await listen<CopilotDeviceCodeEvent>("copilot-device-code", ({ payload }) => {
      copilotDeviceCode = payload;
      if (bootstrapReady) render();
    });
  } catch (error) {
    app.innerHTML = `<section class="fatal"><h1>${escapeHtml(t("app.fatalListen"))}</h1><p>${escapeHtml(String(error))}</p></section>`;
    return;
  }

  await registerProviderAccountListeners();

  try {
    bootstrap = await invoke<Bootstrap>("bootstrap");
  } catch (error) {
    app.innerHTML = `<section class="fatal"><h1>${escapeHtml(t("app.fatalStart"))}</h1><p>${escapeHtml(String(error))}</p></section>`;
    return;
  }
  bootstrapReady = true;
  applyLocale();
  await drainPendingProviderEvents();
  updateProviderListenerFailureNotice();

  try {
    launchAtStartup = await invoke<boolean>("get_launch_at_startup");
  } catch (error) {
    launchAtStartupError = String(error);
  }

  render();
  // A single batched subscription repaints the usage tab when the store's revision advances.
  usageStore.subscribe(() => {
    if (activeTab === "usage") patchUsage();
  });
  try {
    await listen<ProviderState[]>("usage-updated", (event) => {
      bootstrap.states = event.payload;
      requestUsagePatch();
    });
  } catch (error) {
    app.innerHTML = `<section class="fatal"><h1>${escapeHtml(t("app.fatalListen"))}</h1><p>${escapeHtml(String(error))}</p></section>`;
    return;
  }

  try {
    await listen<Warning[]>("warnings-updated", (event) => {
      warnings = event.payload;
      requestUsagePatch();
    });
  } catch (error) {
    // Warning delivery is a best-effort enhancement; its absence must not break the usage view.
    console.error("warnings-updated listener failed", error);
  }

  try {
    await listen("next-provider", () => cycleNextProvider());
  } catch (error) {
    console.error("next-provider listener failed", error);
  }

}

function render(): void {
  // Carry the scroll position across re-renders that stay on the same tab (background refreshes,
  // trend toggles and cost scans all rebuild the DOM); switching tabs starts at the top.
  const keepScroll = renderedTab === activeTab ? (app.querySelector<HTMLElement>(".content")?.scrollTop ?? 0) : 0;
  app.innerHTML = `
    <header class="topbar" data-tauri-drag-region>
      <div data-tauri-drag-region><span class="wordmark">CodexBar</span><span class="platform">WINDOWS</span></div>
      <div class="window-actions">
        <button class="icon-button refresh" aria-label="${t("action.refresh")}" title="${t("action.refresh")}" ${refreshing ? "disabled" : ""}>↻</button>
        <button class="icon-button minimize" aria-label="${t("action.minimize")}" title="${t("action.minimize")}"></button>
        <button class="icon-button close" aria-label="${t("action.close")}" title="${t("action.closeTitle")}">✕</button>
      </div>
    </header>
    <nav class="tabs" aria-label="${t("nav.main")}">
      <button data-tab="usage" class="${activeTab === "usage" ? "active" : ""}">${t("tab.usage")}</button>
      <button data-tab="settings" class="${activeTab === "settings" ? "active" : ""}">${t("tab.settings")}</button>
    </nav>
    <div class="provider-account-feedback">${renderProviderAccountNotice()}</div>
    <section class="content">${activeTab === "usage" ? renderUsage() : renderSettings()}</section>
    ${renderProviderAccountDialog()}
  `;
  wireChrome();
  const content = app.querySelector<HTMLElement>(".content");
  if (activeTab === "usage") {
    if (content) wireUsage(content);
  } else {
    wireSettings();
  }
  if (keepScroll > 0 && content) content.scrollTop = keepScroll;
  renderedTab = activeTab;
}

// Background usage refreshes (usage-updated / warnings-updated) patch only the `.content` subtree,
// so the topbar (refresh spinner, focus) and tab bar keep their live DOM. Rather than
// swap `content.innerHTML` wholesale, `morphHtml` node-diffs the new markup into the existing tree:
// scroll position, input focus/selection and the live SVG chart nodes are all preserved, and only
// the nodes that actually changed are touched — no flicker. The content node itself is never
// replaced, so the delegated handlers bound by `wireUsage()` survive without re-wiring.
function patchUsage(): void {
  if (activeTab !== "usage") return;
  const content = app.querySelector<HTMLElement>(".content");
  if (!content) {
    render();
    return;
  }
  morphHtml(content, renderUsage());
}

function wireProviderAccountFeedback(): void {
  const dismiss = app.querySelector<HTMLButtonElement>(".dismiss-provider-account-notice");
  if (dismiss && dismiss.dataset.wired !== "true") {
    dismiss.dataset.wired = "true";
    dismiss.addEventListener("click", () => {
      providerAccountNotice = undefined;
      patchProviderAccountFeedback();
    });
  }
  const retry = app.querySelector<HTMLButtonElement>(".retry-provider-account-listeners");
  if (retry && retry.dataset.wired !== "true") {
    retry.dataset.wired = "true";
    retry.addEventListener("click", () => void retryProviderAccountListeners());
  }
}

function patchProviderAccountFeedback(): void {
  const feedback = app.querySelector<HTMLElement>(".provider-account-feedback");
  if (!feedback) return;
  morphHtml(feedback, renderProviderAccountNotice());
  wireProviderAccountFeedback();
}

interface ProviderSettingsDraftControl {
  accountKey: string;
  controlKey: string;
  value: string;
  checked?: boolean;
  clearSecret?: boolean;
}

interface ProviderSettingsDraft {
  controls: ProviderSettingsDraftControl[];
  accountOrder: string[];
}

function providerDraftAccountKey(row: HTMLElement, fallbackIndex: number): string {
  if (row.dataset.accountId) return `saved:${row.dataset.accountId}`;
  if (!row.dataset.draftAccountKey) row.dataset.draftAccountKey = `new:${fallbackIndex}`;
  return row.dataset.draftAccountKey;
}

function providerDraftControlKey(
  section: HTMLElement,
  control: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
): Pick<ProviderSettingsDraftControl, "accountKey" | "controlKey"> | undefined {
  const row = control.closest<HTMLElement>(".provider-account-settings-row");
  if (!row) {
    if (control.classList.contains("enabled")) return { accountKey: "provider", controlKey: "enabled" };
    if (control.classList.contains("source-mode")) return { accountKey: "provider", controlKey: "sourceMode" };
    return undefined;
  }
  const rows = Array.from(section.querySelectorAll<HTMLElement>(".provider-account-settings-row"));
  const accountKey = providerDraftAccountKey(row, rows.indexOf(row));
  if (control.classList.contains("account-label")) return { accountKey, controlKey: "label" };
  if (control.closest(".account-enabled")) return { accountKey, controlKey: "enabled" };
  const settingKey = control.dataset.settingKey;
  if (settingKey) return { accountKey, controlKey: `setting:${settingKey}` };
  return undefined;
}

function captureProviderSettingsDraft(section: HTMLElement): ProviderSettingsDraft {
  const rows = Array.from(section.querySelectorAll<HTMLElement>(".provider-account-settings-row"));
  const controls = Array.from(
    section.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
      "input, select, textarea",
    ),
  ).flatMap((control) => {
    const key = providerDraftControlKey(section, control);
    if (!key) return [];
    return [{
      ...key,
      value: control.value,
      checked: control instanceof HTMLInputElement ? control.checked : undefined,
      clearSecret: control.dataset.clear === "true",
    }];
  });
  return {
    controls,
    accountOrder: rows.map((row, index) => providerDraftAccountKey(row, index)),
  };
}

function restoreProviderSettingsDraft(
  section: HTMLElement,
  draft: ProviderSettingsDraft,
): void {
  const controls = Array.from(
    section.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
      "input, select, textarea",
    ),
  );
  for (const control of controls) {
    const key = providerDraftControlKey(section, control);
    if (!key) continue;
    const saved = draft.controls.find((entry) =>
      entry.accountKey === key.accountKey && entry.controlKey === key.controlKey,
    );
    if (!saved) continue;
    control.value = saved.value;
    const row = control.closest<HTMLElement>(".provider-account-settings-row");
    const activeGuard =
      (key.accountKey === "provider" && key.controlKey === "enabled" &&
        Boolean(section.querySelector('[data-provider-account-active="true"]'))) ||
      (key.controlKey === "enabled" && row?.dataset.providerAccountActive === "true");
    if (control instanceof HTMLInputElement && saved.checked !== undefined && !activeGuard) {
      control.checked = saved.checked;
    }
    if (saved.clearSecret) {
      control.dataset.clear = "true";
      const clear = control.parentElement?.querySelector<HTMLButtonElement>(".clear-secret");
      if (clear) clear.disabled = true;
    }
  }
  const accounts = section.querySelector<HTMLElement>(".accounts");
  if (!accounts) return;
  const rows = Array.from(accounts.querySelectorAll<HTMLElement>(".provider-account-settings-row"));
  const restoredRows = new Set<HTMLElement>();
  for (const accountKey of draft.accountOrder) {
    const row = rows.find((entry, index) => providerDraftAccountKey(entry, index) === accountKey);
    if (row) {
      accounts.appendChild(row);
      restoredRows.add(row);
    }
  }
  for (const row of rows) if (!restoredRows.has(row)) accounts.appendChild(row);
}

function refreshProviderSettingsSection(providerId: ProviderId): void {
  if (activeTab !== "settings") return;
  const existing = app.querySelector<HTMLElement>(`[data-settings-provider="${providerId}"]`);
  const descriptor = descriptorFor(providerId);
  if (!existing || !descriptor) return;
  const draft = captureProviderSettingsDraft(existing);
  const template = document.createElement("template");
  template.innerHTML = renderProviderSettings(descriptor, bootstrap.config);
  const next = template.content.firstElementChild;
  if (!(next instanceof HTMLElement)) return;
  morphHtml(existing, next.innerHTML, { isFocused: () => true });
  const accounts = existing.querySelector<HTMLElement>(".accounts");
  const draftNewKeys = draft.accountOrder.filter((accountKey) => accountKey.startsWith("new:"));
  const existingNewRows = Array.from(
    existing.querySelectorAll<HTMLElement>(".provider-account-settings-row"),
  ).filter((row) => !row.dataset.accountId);
  for (let index = 0; index < draftNewKeys.length; index += 1) {
    let row: HTMLElement | undefined = existingNewRows[index];
    if (!row && accounts) {
      accounts.insertAdjacentHTML("beforeend", renderCapabilityAccount(
        descriptor,
        bootstrap.providerAccountPools[providerId],
      ));
      row = accounts.lastElementChild as HTMLElement | undefined;
    }
    if (row) row.dataset.draftAccountKey = draftNewKeys[index];
  }
  restoreProviderSettingsDraft(existing, draft);
}

function renderProviderAccountUi(providerId?: ProviderId): void {
  if (!bootstrapReady) return;
  patchProviderAccountFeedback();
  if (activeTab === "usage") {
    requestUsagePatch();
    return;
  }
  if (providerId) refreshProviderSettingsSection(providerId);
  else for (const descriptor of bootstrap.descriptors) refreshProviderSettingsSection(descriptor.id);
}

function providerStateVisibleOnUsage(state: ProviderState): boolean {
  const pool = bootstrap.providerAccountPools[state.descriptor.id];
  if (!pool) return false;
  const account = pool.accounts.find((entry) => entry.accountId === state.accountId);
  return account
    ? providerAccountVisibleOnUsage(account.enabled, pool.stateUnavailable)
    : pool.stateUnavailable;
}

function renderUsage(): string {
  if (activeDetail) {
    const detail = bootstrap.states.find((entry) =>
      entry.configured && providerStateVisibleOnUsage(entry) && trendKey(entry) === activeDetail,
    );
    if (detail) return renderDetail(detail);
    activeDetail = undefined; // provider no longer configured — fall through to the list
  }
  // Render only providers the user has configured (the backend marks each card). Keep each card's
  // descriptor index so `data-state-index` stays stable for the next-provider shortcut. While the
  // first refresh is still in flight, show a neutral loading line (implicit CLI
  // providers only become configured once they return data); once it settles with nothing configured,
  // guide the user to Settings instead of showing a blank list.
  const cards = bootstrap.descriptors
    .map((descriptor, index) => {
      const pool = bootstrap.providerAccountPools[descriptor.id];
      if (!pool) return "";
      const visibleAccounts = pool.accounts.filter((account) =>
        providerAccountVisibleOnUsage(account.enabled, pool.stateUnavailable),
      );
      const states = visibleAccounts
        .map((account) => bootstrap.states.find((state) =>
          state.descriptor.id === descriptor.id && state.accountId === account.accountId,
        ))
        .filter((state): state is ProviderState => Boolean(state));
      const failClosed = pool.stateUnavailable;
      return states.some((state) => state.configured) || failClosed
        ? renderProviderPool(descriptor, pool, states, index)
        : "";
    })
    .join("");
  const hasVisible = Boolean(cards);
  const stillLoading = bootstrap.states.some((state) => state.status === "loading");
  const body = hasVisible
    ? `<div class="provider-list">${cards}</div>`
    : stillLoading
      ? `<p class="provider-loading muted">${t("card.loadingHint")}</p>`
      : renderEmptyProviders();
  return `
    ${renderWarningBanner()}
    ${body}
    ${renderCost()}
    <p class="last-note">${escapeHtml(t("usage.lastNote", { minutes: bootstrap.config.refreshIntervalMinutes }))}</p>
  `;
}

function renderEmptyProviders(): string {
  return `
    <section class="provider-empty">
      <strong>${t("usage.emptyTitle")}</strong>
      <p class="muted">${t("usage.emptyHint")}</p>
      <button class="primary go-settings" type="button">${t("usage.emptyAction")}</button>
    </section>
  `;
}

function renderCost(): string {
  const providerOptions = (["both", "codex", "claude"] as const)
    .map((value) => `<option value="${value}" ${costProvider === value ? "selected" : ""}>${value === "both" ? "Codex + Claude" : value === "codex" ? "Codex" : "Claude"}</option>`)
    .join("");
  const rangeOptions = (["today", "7d", "30d"] as const)
    .map((value) => `<option value="${value}" ${costRange === value ? "selected" : ""}>${value === "today" ? t("cost.range.today") : value === "7d" ? t("cost.range.7d") : t("cost.range.30d")}</option>`)
    .join("");
  return `
    <section class="cost-panel">
      <div class="cost-controls">
        <strong>${t("cost.header")}</strong>
        <select id="cost-provider">${providerOptions}</select>
        <select id="cost-range">${rangeOptions}</select>
        <button id="cost-scan" type="button" class="trend-toggle" ${costScanning ? "disabled" : ""}>${costScanning ? t("cost.scanning") : t("cost.scan")}</button>
      </div>
      ${costError ? `<p class="trend-note">${escapeHtml(t("cost.error", { message: costError }))}</p>` : renderCostResult()}
    </section>
  `;
}

function renderCostResult(): string {
  if (!costResult) return "";
  const usage = costResult.totalUsage;
  const totalTokens = usage.input + usage.output + usage.cacheCreation + usage.cacheRead;
  if (totalTokens === 0 && costResult.daily.length === 0) {
    return `<p class="trend-note">${t("cost.empty")}</p>`;
  }
  const cost = costResult.totalCostUsd !== undefined ? ` · ${t("cost.totalCost")} $${costResult.totalCostUsd.toFixed(4)}` : "";
  const skipped = costResult.skippedRecords > 0 ? `<small class="cost-skipped">${escapeHtml(t("cost.skipped", { count: costResult.skippedRecords }))}</small>` : "";
  return `
    <p class="cost-totals">${t("cost.totalTokens")} ${totalTokens.toLocaleString()}${cost}</p>
    ${renderCostBars(costResult.daily)}
    ${renderModelDailyChart(costResult)}
    ${renderModelBreakdown(costResult.models)}
    ${renderUnknownModels(costResult.unknownModels)}
    ${skipped}
  `;
}

// A fixed palette for the per-model daily stack. Distinct hues that stay legible over the muted panel
// background in both themes; the last (grey) is reserved for the lumped "other" models.
const MODEL_COLORS = ["#bd5225", "#2f9e6f", "#3b76c9", "#c98a10", "#8a5cd1", "#c94f8a"];
const OTHER_COLOR = "#9a9086";

function modelTokens(usage: { input: number; output: number; cacheCreation: number; cacheRead: number }): number {
  return usage.input + usage.output + usage.cacheCreation + usage.cacheRead;
}

/// Stacked per-day columns surfacing `CostBreakdown.modelDaily`: each day is one column, split into
/// token segments for the top models (by range total) plus a lumped "other". Column height compares
/// day-over-day totals; segments show that day's model composition. Needs ≥2 days to be a trend.
function renderModelDailyChart(breakdown: CostBreakdown): string {
  const days = breakdown.daily.map((day) => day.day);
  if (days.length < 2 || breakdown.modelDaily.length === 0) return "";
  const top = breakdown.modelDaily.slice(0, MODEL_COLORS.length);
  const hasOther = breakdown.modelDaily.length > top.length;
  const perModelDay = new Map<string, Map<string, number>>();
  for (const series of top) {
    const byDay = new Map<string, number>();
    for (const point of series.daily) byDay.set(point.day, modelTokens(point.usage));
    perModelDay.set(series.model, byDay);
  }
  const dayTotals = new Map(breakdown.daily.map((day) => [day.day, modelTokens(day.usage)]));
  const max = Math.max(1, ...days.map((day) => dayTotals.get(day) ?? 0));
  const columns = days
    .map((day) => {
      const total = dayTotals.get(day) ?? 0;
      let topSum = 0;
      const segments = top
        .map((series, index) => {
          const value = perModelDay.get(series.model)?.get(day) ?? 0;
          topSum += value;
          if (value <= 0) return "";
          return `<span class="mday-seg" style="height:${((value / max) * 100).toFixed(2)}%;background:${MODEL_COLORS[index]}"></span>`;
        })
        .join("");
      const otherValue = hasOther ? Math.max(0, total - topSum) : 0;
      const otherSegment =
        otherValue > 0
          ? `<span class="mday-seg" style="height:${((otherValue / max) * 100).toFixed(2)}%;background:${OTHER_COLOR}"></span>`
          : "";
      return `<span class="mday-col" title="${escapeAttribute(`${day}: ${total.toLocaleString()} tokens`)}">${segments}${otherSegment}</span>`;
    })
    .join("");
  const legend =
    top
      .map(
        (series, index) =>
          `<li><span class="legend-swatch" style="background:${MODEL_COLORS[index]}"></span><span class="model-name" title="${escapeAttribute(series.model)}">${escapeHtml(series.model)}</span></li>`,
      )
      .join("") +
    (hasOther
      ? `<li><span class="legend-swatch" style="background:${OTHER_COLOR}"></span><span>${t("cost.otherModels")}</span></li>`
      : "");
  return `
    <div class="model-daily-block">
      <strong class="model-head">${t("cost.perModelDaily")}</strong>
      <div class="model-daily-bars" role="img" aria-label="${t("cost.perModelDaily")}">${columns}</div>
      <ul class="model-legend">${legend}</ul>
    </div>
  `;
}

/// Per-model cost/token breakdown (top 8) — surfaces `CostBreakdown.models`, previously unused. The
/// bar scale is by cost when every row is priced, otherwise by tokens, so the comparison stays honest.
function renderModelBreakdown(models: CostBreakdown["models"]): string {
  if (models.length === 0) return "";
  const rows = models
    .map((entry) => ({
      model: entry.model,
      tokens: entry.usage.input + entry.usage.output + entry.usage.cacheCreation + entry.usage.cacheRead,
      cost: entry.costUsd,
    }))
    .sort((left, right) => (right.cost ?? 0) - (left.cost ?? 0) || right.tokens - left.tokens)
    .slice(0, 8);
  const priced = rows.every((row) => row.cost !== undefined);
  const max = Math.max(1, ...rows.map((row) => (priced ? (row.cost ?? 0) : row.tokens)));
  const items = rows
    .map((row) => {
      const magnitude = priced ? (row.cost ?? 0) : row.tokens;
      const width = Math.max(2, Math.round((magnitude / max) * 100));
      const value = row.cost !== undefined ? `$${row.cost.toFixed(4)}` : row.tokens.toLocaleString();
      return `<li class="model-row"><span class="model-name" title="${escapeAttribute(row.model)}">${escapeHtml(row.model)}</span><span class="model-bar"><span style="width:${width}%"></span></span><span class="model-value">${escapeHtml(value)}</span></li>`;
    })
    .join("");
  return `<div class="model-breakdown-block"><strong class="model-head">${t("cost.byModel")}</strong><ul class="model-breakdown">${items}</ul></div>`;
}

function renderUnknownModels(models: string[]): string {
  if (models.length === 0) return "";
  const shown = models.slice(0, 5).join(", ");
  const suffix = models.length > 5 ? ` +${models.length - 5}` : "";
  return `<small class="cost-unknown">${escapeHtml(t("cost.unknownModels", { models: shown + suffix }))}</small>`;
}

function renderCostBars(daily: CostBreakdown["daily"]): string {
  if (daily.length === 0) return "";
  const values = daily.map((day) => day.usage.input + day.usage.output + day.usage.cacheCreation + day.usage.cacheRead);
  const max = Math.max(1, ...values);
  const bars = daily
    .map((day, index) => {
      const height = Math.round((values[index] / max) * 100);
      const label = `${day.day}: ${values[index].toLocaleString()} tokens${day.costUsd !== undefined ? ` · $${day.costUsd.toFixed(4)}` : ""}`;
      return `<span class="cost-bar" style="height:${Math.max(2, height)}%" title="${escapeAttribute(label)}"></span>`;
    })
    .join("");
  return `<div class="cost-bars" role="img" aria-label="${t("cost.header")}">${bars}</div>`;
}

async function scanCost(): Promise<void> {
  if (costScanning) return;
  costScanning = true;
  costError = undefined;
  render();
  try {
    costResult = await invoke<CostBreakdown>("scan_cost", { provider: costProvider, range: costRange });
  } catch (error) {
    costError = String(error);
    costResult = undefined;
  } finally {
    costScanning = false;
    render();
  }
}

function renderWarningBanner(): string {
  if (!warnings.length) return "";
  // One line per provider/window at its highest crossed threshold, most-used first.
  const highest = new Map<string, Warning>();
  for (const warning of warnings) {
    const key = `${warning.provider}:${warning.accountId}:${warning.windowId}`;
    const current = highest.get(key);
    if (!current || warning.threshold > current.threshold) highest.set(key, warning);
  }
  const rows = [...highest.values()]
    .sort((left, right) => right.usedPercent - left.usedPercent)
    .map((warning) => {
      const name = descriptorFor(warning.provider)?.displayName ?? warning.provider;
      const message =
        warning.kind === "pace"
          ? t("warn.pace", { name, window: warning.windowTitle, used: formatPercent(warning.usedPercent) })
          : t("warn.item", { name, window: warning.windowTitle, used: formatPercent(warning.usedPercent), threshold: formatPercent(warning.threshold) });
      return `<li><span class="warn-dot" aria-hidden="true"></span>${escapeHtml(message)}</li>`;
    })
    .join("");
  return `<section class="warning-banner" role="status"><strong>${t("warn.title")}</strong><ul>${rows}</ul></section>`;
}

function descriptorFor(provider: ProviderId): ProviderDescriptor | undefined {
  return bootstrap.descriptors.find((descriptor) => descriptor.id === provider);
}

function providerName(providerId: ProviderId): string {
  return descriptorFor(providerId)?.displayName ?? providerId;
}

function isProviderBusy(providerId: ProviderId): boolean {
  return (
    !bootstrapReady ||
    providerLifecycleUnavailable(providerLoginListenerReady, providerPoolListenerReady) ||
    bootstrap.providerAccountPools[providerId]?.operationInProgress === true ||
    [...providerBusy].some((busyProviderId) => providerActionBusy(busyProviderId, providerId))
  );
}

function providerAccountIdentityLabel(identity?: ProviderAccountIdentity): string {
  return (
    identity?.displayName ??
    identity?.email ??
    identity?.stableKeys[0]?.value ??
    t("provider.account.unknown")
  );
}

function providerAccountName(
  account: ProviderAccountPoolAccountView,
  state?: ProviderState,
): string {
  return (
    account.label ??
    state?.accountLabel ??
    state?.snapshot?.accountLabel ??
    providerAccountIdentityLabel(account.identity)
  );
}

function providerStateName(state?: ProviderState): string {
  if (!state) return t("provider.account.unknown");
  const account = bootstrap.providerAccountPools[state.descriptor.id]?.accounts.find(
    (entry) => entry.accountId === state.accountId,
  );
  return account ? providerAccountName(account, state) : state.accountLabel ?? t("provider.account.unknown");
}

function providerQuotaSummary(state?: ProviderState): string {
  return state?.snapshot?.windows.length
    ? state.snapshot.windows
        .map((window) => `${window.title}: ${formatPercent(window.usedPercent)}`)
        .join(" · ")
    : t("provider.account.quotaUnavailable");
}

function providerAccountErrorMessage(error: ProviderAccountCommandError): string {
  const provider = error.providerId ? providerName(error.providerId) : t("provider.account.thisProvider");
  return t(providerAccountErrorTranslationKey(error.code), { provider });
}

function renderProviderPool(
  descriptor: ProviderDescriptor,
  pool: ProviderAccountPoolView,
  states: ProviderState[],
  index = 0,
): string {
  const status = states.some((state) => state.status === "error")
    ? "error"
    : states.some((state) => state.status === "loading")
      ? "loading"
      : states.some((state) => state.status === "ready")
        ? "ready"
        : "disabled";
  const badge = status === "ready" ? t("badge.ready") : status === "disabled" ? t("badge.disabled") : status === "loading" ? t("badge.loading") : t("badge.error");
  const current = pool.accounts.find((account) => account.isActive);
  const currentState = current
    ? states.find((state) => state.accountId === current.accountId)
    : states[0];
  const rows = pool.accounts
    .filter((account) =>
      providerAccountVisibleOnUsage(account.enabled, pool.stateUnavailable),
    )
    .map((account) => {
      const state = states.find((entry) => entry.accountId === account.accountId);
      return renderProviderPoolAccount(descriptor, pool, account, state);
    })
    .join("");
  return `
    <article class="provider-card provider-pool-card ${status}" style="--provider:${descriptor.color}" data-provider="${descriptor.id}" data-account-id="${escapeAttribute(currentState?.accountId ?? "")}" data-state-index="${index}" tabindex="-1">
      <header>
        <button class="provider-title dashboard" data-provider="${descriptor.id}">
          <span class="provider-icon">${initials(descriptor.displayName)}</span>
          <span><strong>${descriptor.displayName}</strong><small>${escapeHtml(t("provider.account.poolSummary", { count: pool.accounts.length }))}</small></span>
        </button>
        <span class="header-status">${renderIncidentBadge(states.find((state) => state.serviceStatus)?.serviceStatus)}<span class="badge">${badge}</span></span>
      </header>
      ${renderProviderPoolStatus(pool, false)}
      <div class="provider-account-usage-list">${rows}</div>
      <footer class="provider-pool-footer"><button class="manage-provider-accounts" type="button" data-provider="${descriptor.id}">${t("provider.account.manage")}</button></footer>
    </article>
  `;
}

function renderProviderPoolAccount(
  descriptor: ProviderDescriptor,
  pool: ProviderAccountPoolView,
  account: ProviderAccountPoolAccountView,
  state?: ProviderState,
): string {
  const busy = isProviderBusy(descriptor.id);
  const blockedReason = account.activationBlockedReason ?? pool.activation.blockedReason;
  const action = account.isActive
    ? `<span class="provider-account-current">${t("provider.account.current")}</span>`
    : `<button class="activate-provider-account" type="button" data-provider="${descriptor.id}" data-account-id="${escapeAttribute(account.accountId)}" ${accountActivationDisabled(account, busy) ? "disabled" : ""} title="${escapeAttribute(blockedReason ?? t("provider.account.activate"))}">${t("provider.account.activate")}</button>`;
  const blocked = !account.isActive && !account.canActivate && blockedReason
    ? `<small class="provider-account-blocked">${escapeHtml(blockedReason)}</small>`
    : "";
  return `
    <section class="provider-account-usage-row ${account.isActive ? "active" : ""}" data-account-id="${escapeAttribute(account.accountId)}">
      <header>
        <button class="provider-account-identity dashboard" type="button" data-provider="${descriptor.id}" data-account-id="${escapeAttribute(account.accountId)}">
          <strong>${escapeHtml(providerAccountName(account, state))}</strong>
          <small>${escapeHtml(providerAccountIdentityLabel(account.identity))}</small>
        </button>
        <div class="provider-account-action">${action}${blocked}</div>
      </header>
      <span class="credential-state ${account.managedCredentialState}">${escapeHtml(t(`provider.account.credential.${account.managedCredentialState}`))}</span>
      ${state?.error ? `<p class="error-message">${escapeHtml(state.error)}</p>` : ""}
      ${state?.snapshot?.windows.map(renderWindow).join("") ?? ""}
      ${state?.snapshot?.summary.length ? `<dl class="summary">${state.snapshot.summary.map((item) => `<div><dt>${escapeHtml(item.label)}</dt><dd>${escapeHtml(item.value)}</dd></div>`).join("")}</dl>` : ""}
      ${state?.status === "ready" && state.snapshot?.windows.length ? renderTrend(state) : ""}
      ${state?.status === "loading" ? `<p class="muted">${t("card.loadingHint")}</p>` : ""}
      ${!state ? `<p class="muted">${t("provider.account.quotaUnavailable")}</p>` : ""}
    </section>
  `;
}

function renderProviderAccountNotice(): string {
  if (!providerAccountNotice) return "";
  const retry = providerLifecycleUnavailable(providerLoginListenerReady, providerPoolListenerReady)
    ? `<button class="retry-provider-account-listeners" type="button">${t("provider.account.retryListeners")}</button>`
    : `<button class="dismiss-provider-account-notice" type="button" aria-label="${t("provider.account.dismiss")}">×</button>`;
  return `<section class="provider-account-notice ${providerAccountNotice.kind}" role="status"><span>${escapeHtml(providerAccountNotice.message)}</span>${retry}</section>`;
}

function renderProviderPoolStatus(
  pool: ProviderAccountPoolView,
  managementActions: boolean,
): string {
  const parts: string[] = [];
  if (showsExternalProviderAccount(pool.externalIdentity)) {
    const importAction = managementActions && providerSupportsEnrollment(pool.enrollment, "importCurrent")
      ? `<button class="import-current-provider-account" data-provider="${pool.providerId}" type="button" ${isProviderBusy(pool.providerId) ? "disabled" : ""}>${t("provider.account.importCurrent")}</button>`
      : "";
    parts.push(`<section class="provider-account-notice external"><span>${escapeHtml(t("provider.account.external", { name: providerAccountIdentityLabel(pool.externalIdentity) }))}</span>${importAction}</section>`);
  }
  if (pool.recoveryState !== "none") {
    const recoveryActions = managementActions
      ? `<div><button class="recover-provider-auth" data-provider="${pool.providerId}" data-recovery-action="restoreOriginal" type="button" ${isProviderBusy(pool.providerId) ? "disabled" : ""}>${t("provider.account.restoreOriginal")}</button><button class="recover-provider-auth" data-provider="${pool.providerId}" data-recovery-action="keepCurrent" type="button" ${isProviderBusy(pool.providerId) ? "disabled" : ""}>${t("provider.account.keepCurrent")}</button></div>`
      : "";
    parts.push(`<section class="provider-account-notice recovery"><span>${t(pool.recoveryState === "corrupt" ? "provider.account.recoveryCorrupt" : "provider.account.recoveryRequired")}</span>${recoveryActions}</section>`);
  }
  return parts.join("");
}

function createProviderActivationAction(
  providerId: ProviderId,
  accountId: string,
): Extract<NonNullable<typeof pendingProviderAccountAction>, { kind: "activate" }> {
  const pool = bootstrap.providerAccountPools[providerId];
  const currentIdentitySnapshot = pool
    ? snapshotExpectedCurrentProviderIdentity(pool)
    : { source: "none" as const, identity: undefined };
  const currentState = pool?.activeAccountId
    ? bootstrap.states.find((state) =>
        state.descriptor.id === providerId && state.accountId === pool.activeAccountId,
      )
    : undefined;
  return {
    kind: "activate",
    providerId,
    accountId,
    expectedCurrentIdentity: currentIdentitySnapshot.identity,
    expectedCurrentSource: currentIdentitySnapshot.source,
    expectedCurrentQuota: providerQuotaSummary(currentState),
  };
}

function renderProviderAccountDialog(): string {
  const action = pendingProviderAccountAction;
  if (!action) return "";
  const descriptor = descriptorFor(action.providerId);
  const provider = descriptor?.displayName ?? action.providerId;
  if (action.kind === "delete") {
    return `<div class="provider-account-dialog-backdrop"><section class="provider-account-dialog" role="dialog" aria-modal="true"><h2>${escapeHtml(t("provider.account.deleteTitle", { provider }))}</h2><p>${escapeHtml(t("provider.account.deleteConfirm", { name: action.label, provider }))}</p><div class="provider-account-dialog-actions"><button class="cancel-provider-account-action" type="button">${t("provider.account.cancel")}</button><button class="confirm-provider-account-action danger" type="button">${t("provider.account.delete")}</button></div></section></div>`;
  }
  const pool = bootstrap.providerAccountPools[action.providerId];
  const target = bootstrap.states.find((state) => state.descriptor.id === action.providerId && state.accountId === action.accountId);
  const targetAccount = pool?.accounts.find((account) => account.accountId === action.accountId);
  const frozenCurrentIdentity = action.expectedCurrentIdentity;
  const currentName = action.expectedCurrentSource === "external" && frozenCurrentIdentity
    ? t("provider.account.externalCurrent", { name: providerAccountIdentityLabel(frozenCurrentIdentity) })
    : providerAccountIdentityLabel(frozenCurrentIdentity);
  const currentIdentity = action.expectedCurrentSource === "external"
    ? t("provider.account.externalMarker")
    : frozenCurrentIdentity?.email ?? frozenCurrentIdentity?.stableKeys[0]?.value ?? t("provider.account.unknown");
  const currentQuota = action.expectedCurrentQuota;
  const targetDescription = pool?.activation.targetDescription ?? pool?.activation.blockedReason ?? t("provider.account.officialTargetUnknown");
  return `<div class="provider-account-dialog-backdrop"><section class="provider-account-dialog" role="dialog" aria-modal="true"><h2>${escapeHtml(t("provider.account.switchTitle", { provider }))}</h2><p>${escapeHtml(t("provider.account.switchWarning", { provider, target: targetDescription }))}</p><div class="provider-account-comparison"><div><small>${t("provider.account.from")}</small><strong>${escapeHtml(currentName)}</strong><small>${escapeHtml(currentIdentity)}</small><span>${escapeHtml(currentQuota)}</span></div><div><small>${t("provider.account.to")}</small><strong>${escapeHtml(providerStateName(target))}</strong><small>${escapeHtml(providerAccountIdentityLabel(targetAccount?.identity))}</small><span>${escapeHtml(providerQuotaSummary(target))}</span></div></div><p class="provider-account-restart-guidance">${escapeHtml(t("provider.account.restartGuidance"))}</p><div class="provider-account-dialog-actions"><button class="cancel-provider-account-action" type="button">${t("provider.account.cancel")}</button><button class="confirm-provider-account-action primary" type="button">${t("provider.account.confirmSwitch")}</button></div></section></div>`;
}

function openProviderAccountDialog(action: NonNullable<typeof pendingProviderAccountAction>): void {
  if (!providerAccountActionRequiresConfirmation(action.providerId, action.kind)) return;
  pendingProviderAccountAction = action;
  app.querySelector(".provider-account-dialog-backdrop")?.remove();
  app.insertAdjacentHTML("beforeend", renderProviderAccountDialog());
  wireProviderAccountDialogActions();
}

function wireProviderAccountDialogActions(): void {
  app.querySelector<HTMLButtonElement>(".cancel-provider-account-action")?.addEventListener("click", () => {
    pendingProviderAccountAction = undefined;
    app.querySelector(".provider-account-dialog-backdrop")?.remove();
  });
  app.querySelector<HTMLButtonElement>(".confirm-provider-account-action")?.addEventListener("click", () => {
    const action = pendingProviderAccountAction;
    pendingProviderAccountAction = undefined;
    app.querySelector(".provider-account-dialog-backdrop")?.remove();
    if (!action) return;
    if (action.kind === "activate") {
      void activateProviderAccount(
        action.providerId,
        action.accountId,
        action.expectedCurrentIdentity,
      );
    } else {
      void deleteProviderAccount(action.providerId, action.accountId);
    }
  });
}

function trendKey(state: ProviderState): string {
  return `${state.descriptor.id}:${state.accountId}`;
}

/// Single-provider deep view (F5): the whole card list collapses to one provider showing every usage
/// window (with reset rings), the always-expanded usage-history chart with range switch + burn-rate
/// projection, the balance trend, the account summary, and a link out to the web dashboard. Reachable
/// by clicking a card title; prev/next step through the other configured providers.
function renderDetail(state: ProviderState): string {
  const { descriptor, snapshot } = state;
  const key = trendKey(state);
  const range = trendRangeFor(key);
  const badge = state.status === "ready" ? t("badge.ready") : state.status === "disabled" ? t("badge.disabled") : state.status === "loading" ? t("badge.loading") : t("badge.error");
  const identity = state.accountLabel ?? snapshot?.accountLabel ?? snapshot?.plan ?? snapshot?.source ?? authLabel(descriptor);
  const steppers = detailKeys().length > 1
    ? `<div class="detail-steppers"><button class="detail-prev" type="button" aria-label="${t("detail.prev")}" title="${t("detail.prev")}">‹</button><button class="detail-next" type="button" aria-label="${t("detail.next")}" title="${t("detail.next")}">›</button></div>`
    : "";
  const charts = state.status === "ready" && snapshot?.windows.length
    ? `${renderRangeSwitcher(key, range)}${renderTrendCharts(historyCache.get(historyCacheKey(key, range)))}`
    : "";
  const summary = snapshot?.summary.length
    ? `<dl class="summary">${snapshot.summary.map((item) => `<div><dt>${escapeHtml(item.label)}</dt><dd>${escapeHtml(item.value)}</dd></div>`).join("")}</dl>`
    : "";
  return `
    <section class="detail ${state.status}" style="--provider:${descriptor.color}">
      <div class="detail-nav">
        <button class="detail-back" type="button">← ${t("detail.back")}</button>
        ${steppers}
      </div>
      <header class="detail-head">
        <span class="provider-icon">${initials(descriptor.displayName)}</span>
        <div><strong>${descriptor.displayName}</strong><small>${escapeHtml(identity)}</small></div>
        <span class="header-status">${renderIncidentBadge(state.serviceStatus)}<span class="badge">${badge}</span></span>
      </header>
      ${state.error ? `<p class="error-message">${escapeHtml(state.error)}</p>` : ""}
      ${snapshot?.windows.map(renderWindow).join("") ?? ""}
      ${charts}
      ${summary}
      <button class="detail-web" type="button" data-provider="${descriptor.id}">${t("detail.openWeb")} ↗</button>
    </section>
  `;
}

/// Trend keys of every configured provider, in list order — the ring the prev/next steppers walk.
function detailKeys(): string[] {
  return bootstrap.states
    .filter((entry) => entry.configured && providerStateVisibleOnUsage(entry))
    .map(trendKey);
}

async function openDetail(key: string): Promise<void> {
  activeDetail = key;
  patchUsage();
  await ensureHistory(key, trendRangeFor(key));
}

function closeDetail(): void {
  activeDetail = undefined;
  patchUsage();
}

function detailStep(delta: number): void {
  const keys = detailKeys();
  if (keys.length === 0) return;
  const current = activeDetail ? keys.indexOf(activeDetail) : -1;
  void openDetail(keys[(current + delta + keys.length) % keys.length]);
}

function renderTrend(state: ProviderState): string {
  const key = trendKey(state);
  const expanded = expandedTrends.has(key);
  const range = trendRangeFor(key);
  const body = expanded
    ? `${renderRangeSwitcher(key, range)}${renderTrendCharts(historyCache.get(historyCacheKey(key, range)))}`
    : "";
  return `
    <div class="trend-block">
      <button class="trend-toggle" type="button" data-trend="${escapeAttribute(key)}">${expanded ? t("trend.hide") : t("trend.show")}</button>
      ${body}
    </div>
  `;
}

function trendRangeFor(key: string): TrendRange {
  return trendRanges.get(key) ?? "7d";
}

function historyCacheKey(key: string, range: TrendRange): string {
  return `${key}::${range}`;
}

function rangeLabel(range: TrendRange): string {
  switch (range) {
    case "24h":
      return t("range.24h");
    case "7d":
      return t("range.7d");
    case "30d":
      return t("range.30d");
    case "90d":
      return t("range.90d");
  }
}

function renderRangeSwitcher(key: string, active: TrendRange): string {
  const buttons = TREND_RANGES.map(
    (range) =>
      `<button type="button" class="range-option ${range === active ? "active" : ""}" data-range-key="${escapeAttribute(key)}" data-range-value="${range}" aria-pressed="${range === active ? "true" : "false"}">${rangeLabel(range)}</button>`,
  ).join("");
  return `<div class="range-switch" role="group" aria-label="${t("range.aria")}">${buttons}</div>`;
}

function renderTrendCharts(points: HistoryPoint[] | undefined): string {
  if (points === undefined) return `<p class="trend-note">${t("trend.loading")}</p>`;
  const series = dominantWindowSeries(points);
  if (series.length === 0) return `<p class="trend-note">${t("trend.empty")}</p>`;
  // Usage-over-time is always available; the balance chart only appears for credit providers whose
  // history carries a `balance` (previously dropped on the floor by the frontend).
  return `<div class="trend-charts">${renderUsageChart(series)}${renderBalanceChart(points)}</div>`;
}

/// Usage-percent line chart with 75/90/100 threshold bands (replacing the old fixed-height sparkline)
/// plus a burn-rate projection to 100% and a pace note.
function renderUsageChart(series: HistoryPoint[]): string {
  const last = series[series.length - 1];
  const pace = estimatePace(series);
  // Only draw the projection when the burn actually reaches 100% before the reset — otherwise the
  // reset interrupts it and a line to 100% would mislead.
  const projection = pace && pace.beforeReset === true ? { x: pace.fullAt, y: 100, className: "proj-danger" } : undefined;
  const chart = lineChart({
    points: series.map((point) => ({ x: Date.parse(point.timestamp), y: point.usedPercent })),
    yMin: 0,
    yMax: 100,
    area: true,
    bands: [
      { from: 75, to: 90, className: "chart-band-warn" },
      { from: 90, to: 100, className: "chart-band-danger" },
    ],
    projection,
    className: "chart-usage",
    ariaLabel: t("trend.aria"),
    valueFormat: (value) => formatPercent(value),
  });
  return `
    <figure class="trend-chart">
      ${chart}
      <figcaption>${escapeHtml(t("trend.caption", { window: last.windowId, latest: formatPercent(last.usedPercent), count: series.length }))}</figcaption>
      ${renderPaceNote(pace)}
    </figure>
  `;
}

interface PaceEstimate {
  hoursToFull: number;
  fullAt: number;
  /// vs the window's reset: true = hits 100% first, false = resets first, undefined = no reset time.
  beforeReset: boolean | undefined;
}

/// Least-squares slope of usedPercent over time → projected hours to 100% and whether that lands
/// before the window resets. Returns undefined when usage is flat/decreasing, already full, or there
/// aren't enough points to fit a line. Client-side sibling of the engine's pace warnings (macOS
/// HistoricalUsagePace), but always-on rather than only at a threshold crossing.
function estimatePace(series: HistoryPoint[]): PaceEstimate | undefined {
  if (series.length < 2) return undefined;
  const last = series[series.length - 1];
  const current = last.usedPercent;
  if (current >= 100) return undefined;
  const t0 = Date.parse(series[0].timestamp);
  const samples = series
    .map((point) => ({ h: (Date.parse(point.timestamp) - t0) / 3_600_000, y: point.usedPercent }))
    .filter((sample) => Number.isFinite(sample.h));
  if (samples.length < 2) return undefined;
  const n = samples.length;
  const sumH = samples.reduce((sum, sample) => sum + sample.h, 0);
  const sumY = samples.reduce((sum, sample) => sum + sample.y, 0);
  const sumHY = samples.reduce((sum, sample) => sum + sample.h * sample.y, 0);
  const sumHH = samples.reduce((sum, sample) => sum + sample.h * sample.h, 0);
  const denom = n * sumHH - sumH * sumH;
  if (denom === 0) return undefined;
  const slopePerHour = (n * sumHY - sumH * sumY) / denom;
  if (slopePerHour <= 0.01) return undefined; // flat or draining — nothing to project
  const hoursToFull = (100 - current) / slopePerHour;
  const fullAt = Date.parse(last.timestamp) + hoursToFull * 3_600_000;
  const resetAt = last.resetsAt ? Date.parse(last.resetsAt) : Number.NaN;
  const beforeReset = Number.isNaN(resetAt) ? undefined : fullAt < resetAt;
  return { hoursToFull, fullAt, beforeReset };
}

function renderPaceNote(pace: PaceEstimate | undefined): string {
  if (!pace) return "";
  const eta = shortDuration(pace.hoursToFull * 3_600_000);
  const message =
    pace.beforeReset === undefined
      ? t("pace.eta", { time: eta })
      : pace.beforeReset
        ? t("pace.beforeReset", { time: eta })
        : t("pace.afterReset", { time: eta });
  const severity = pace.beforeReset === true ? "danger" : pace.beforeReset === false ? "ok" : "warn";
  return `<p class="pace-note ${severity}">${escapeHtml(message)}</p>`;
}

interface BalancePoint {
  timestamp: string;
  balance: number;
  spend?: number;
  currency?: string;
}

/// Balance is account-level, so it repeats across a timestamp's windows — dedupe to one point per
/// timestamp (first wins) and drop points that never recorded a balance.
function balanceSeries(points: HistoryPoint[]): BalancePoint[] {
  const byTime = new Map<number, BalancePoint>();
  for (const point of points) {
    if (point.balance === undefined || point.balance === null) continue;
    const at = Date.parse(point.timestamp);
    if (Number.isNaN(at) || byTime.has(at)) continue;
    byTime.set(at, { timestamp: point.timestamp, balance: point.balance, spend: point.spend, currency: point.currency });
  }
  return [...byTime.entries()].sort((left, right) => left[0] - right[0]).map(([, value]) => value);
}

/// Balance-over-time line chart with the latest balance and (if present) spend in the caption.
function renderBalanceChart(points: HistoryPoint[]): string {
  const series = balanceSeries(points);
  if (series.length === 0) return "";
  const last = series[series.length - 1];
  const chart = lineChart({
    points: series.map((point) => ({ x: Date.parse(point.timestamp), y: point.balance })),
    area: true,
    className: "chart-balance",
    ariaLabel: t("balance.aria"),
    valueFormat: (value) => formatMoney(value, last.currency),
  });
  const spend = last.spend !== undefined ? ` · ${t("balance.spend", { amount: formatMoney(last.spend, last.currency) })}` : "";
  return `
    <figure class="trend-chart balance">
      ${chart}
      <figcaption>${escapeHtml(t("balance.caption", { balance: formatMoney(last.balance, last.currency) }) + spend)}</figcaption>
    </figure>
  `;
}

/// Format a monetary amount, honoring an ISO-4217 `currency` when the provider reports one and
/// gracefully falling back to a plain number (optionally suffixed) for non-standard codes.
function formatMoney(value: number, currency?: string): string {
  if (currency && /^[A-Za-z]{3}$/.test(currency)) {
    try {
      return new Intl.NumberFormat(undefined, { style: "currency", currency: currency.toUpperCase(), maximumFractionDigits: 2 }).format(value);
    } catch {
      // Unknown ISO code — fall through to plain formatting.
    }
  }
  const formatted = value.toLocaleString(undefined, { maximumFractionDigits: 2 });
  return currency ? `${formatted} ${currency}` : formatted;
}

/// Reduce mixed-window history to the single most-represented window and sort it in time order, so
/// the sparkline shows one coherent series rather than interleaved windows.
function dominantWindowSeries(points: HistoryPoint[]): HistoryPoint[] {
  if (points.length === 0) return [];
  const counts = new Map<string, number>();
  for (const point of points) counts.set(point.windowId, (counts.get(point.windowId) ?? 0) + 1);
  let dominant = points[0].windowId;
  for (const [windowId, count] of counts) {
    if (count > (counts.get(dominant) ?? 0)) dominant = windowId;
  }
  return points
    .filter((point) => point.windowId === dominant)
    .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));
}

async function toggleTrend(key: string): Promise<void> {
  if (expandedTrends.has(key)) {
    expandedTrends.delete(key);
    patchUsage();
    return;
  }
  expandedTrends.add(key);
  patchUsage();
  await ensureHistory(key, trendRangeFor(key));
}

async function setTrendRange(key: string, range: TrendRange): Promise<void> {
  if (trendRangeFor(key) === range) return;
  trendRanges.set(key, range);
  patchUsage();
  await ensureHistory(key, range);
}

/// Fetch (once) and cache the history for a (trend, range) pair, then re-render if that pair is still
/// the one on screen. `range` flows straight to the backend, which supports 24h/7d/30d/90d.
async function ensureHistory(key: string, range: TrendRange): Promise<void> {
  const cacheKey = historyCacheKey(key, range);
  if (historyCache.has(cacheKey)) return;
  historyCache.set(cacheKey, undefined); // mark in-flight
  const [provider, accountId] = splitTrendKey(key);
  try {
    const points = await invoke<HistoryPoint[]>("provider_history", { provider, accountId, range });
    historyCache.set(cacheKey, points);
  } catch {
    historyCache.set(cacheKey, []);
  }
  if (expandedTrends.has(key) && activeTab === "usage" && trendRangeFor(key) === range) patchUsage();
}

function splitTrendKey(key: string): [string, string] {
  const separator = key.indexOf(":");
  return separator < 0 ? [key, ""] : [key.slice(0, separator), key.slice(separator + 1)];
}

function renderIncidentBadge(status: ProviderState["serviceStatus"]): string {
  // Only real, known incidents light up. `none` (all clear) and `unknown` (unreachable) stay silent.
  if (!status || status.indicator === "none" || status.indicator === "unknown") return "";
  const severity = status.indicator === "critical" || status.indicator === "major" ? "major" : "minor";
  const title = status.description ? `${incidentLabel(status.indicator)} · ${status.description}` : incidentLabel(status.indicator);
  return `<span class="incident-dot ${severity}" title="${escapeAttribute(title)}" aria-label="${escapeAttribute(title)}"></span>`;
}

function incidentLabel(indicator: NonNullable<ProviderState["serviceStatus"]>["indicator"]): string {
  switch (indicator) {
    case "minor":
      return t("incident.minor");
    case "major":
      return t("incident.major");
    case "critical":
      return t("incident.critical");
    case "maintenance":
      return t("incident.maintenance");
    default:
      return t("incident.unknown");
  }
}

function renderWindow(window: UsageWindow): string {
  const percent = Math.max(0, Math.min(100, window.usedPercent));
  // Cosmetic bar severity mirrors the default 75/90 notification thresholds.
  const severity = percent >= 90 ? "danger" : percent >= 75 ? "warn" : "ok";
  const resetRing = renderResetRing(window);
  return `
    <div class="quota ${severity}">
      <div class="quota-main">
        <div class="quota-label"><span>${escapeHtml(window.title)}</span><strong>${formatPercent(percent)}</strong></div>
        <div class="track" role="progressbar" aria-valuenow="${percent}" aria-valuemin="0" aria-valuemax="100">
          <span style="width:${percent}%"></span>
        </div>
        <small>${window.detail ? escapeHtml(window.detail) : resetLabel(window.resetsAt)}</small>
      </div>
      ${resetRing}
    </div>
  `;
}

/// A reset-countdown ring for a window that reports both its reset time and its window length. The
/// arc fills as the window elapses. `windowMinutes` (previously unused by the frontend) is what lets
/// us compute the elapsed fraction; without it we fall back to the plain reset text and draw nothing.
function renderResetRing(window: UsageWindow): string {
  if (!window.resetsAt || !window.windowMinutes || window.windowMinutes <= 0) return "";
  const resetsAt = Date.parse(window.resetsAt);
  if (Number.isNaN(resetsAt)) return "";
  const msUntil = resetsAt - Date.now();
  if (msUntil <= 0) return "";
  const windowMs = window.windowMinutes * 60_000;
  const elapsed = Math.max(0, Math.min(1, 1 - msUntil / windowMs));
  const label = shortDuration(msUntil);
  return `<div class="quota-ring">${ring({ fraction: elapsed, label, ariaLabel: t("reset.ariaRing", { time: label }) })}</div>`;
}

/// Compact "3h" / "45m" / "2d" duration for the ring center label.
function shortDuration(ms: number): string {
  const minutes = Math.ceil(ms / 60_000);
  if (minutes < 60) return t("dur.minutesShort", { value: minutes });
  const hours = Math.round(minutes / 60);
  if (hours < 48) return t("dur.hoursShort", { value: hours });
  return t("dur.daysShort", { value: Math.round(hours / 24) });
}

function renderSettings(): string {
  return `
    <form id="settings-form">
      ${renderReleaseSettings()}
      <section class="settings-block general">
        <label>${t("settings.refreshInterval")} <input id="refresh-interval" type="number" min="1" max="60" value="${bootstrap.config.refreshIntervalMinutes}" /> ${t("settings.minutes")}</label>
        <label>${t("settings.language")}
          <select id="locale-select">
            ${localeOption("system", t("locale.system"))}${localeOption("en", "English")}${localeOption("zh-hans", t("locale.zhHans"))}
          </select>
        </label>
        <p>${t("settings.configFile")} <code>${escapeHtml(bootstrap.configPath)}</code></p>
      </section>
      ${renderMenuBarSettings()}
      ${renderNotificationSettings()}
      ${renderShortcutSettings()}
      ${bootstrap.descriptors.map((descriptor) => renderProviderSettings(descriptor, bootstrap.config)).join("")}
      <div class="save-row"><span id="save-status"></span><button class="primary" type="submit">${t("settings.save")}</button></div>
    </form>
  `;
}

function renderShortcutSettings(): string {
  const shortcuts = bootstrap.config.shortcuts;
  const field = (id: string, label: string, value?: string) => `
    <label class="field">${label}
      <input id="${id}" type="text" value="${escapeAttribute(value ?? "")}" placeholder="Ctrl+Shift+U" autocomplete="off" />
    </label>
  `;
  return `
    <section class="settings-block shortcut-settings">
      <header><strong>${t("shortcut.header")}</strong></header>
      <p class="cookie-help">${t("shortcut.hint")}</p>
      <div class="shortcut-grid">
        ${field("shortcut-toggle-window", t("shortcut.toggleWindow"), shortcuts.toggleWindow)}
        ${field("shortcut-refresh", t("shortcut.refresh"), shortcuts.refresh)}
        ${field("shortcut-next-provider", t("shortcut.nextProvider"), shortcuts.nextProvider)}
      </div>
      ${bootstrap.shortcutError ? `<p class="shortcut-error">${escapeHtml(t("shortcut.error", { message: bootstrap.shortcutError }))}</p>` : ""}
    </section>
  `;
}

function localeOption(value: string, label: string): string {
  return `<option value="${value}" ${bootstrap.config.locale === value ? "selected" : ""}>${escapeHtml(label)}</option>`;
}

function renderMenuBarSettings(): string {
  const menu = bootstrap.config.menuBar;
  const option = (value: string, label: string) =>
    `<option value="${value}" ${menu.displayMode === value ? "selected" : ""}>${escapeHtml(label)}</option>`;
  return `
    <section class="settings-block menu-bar-settings">
      <header><strong>${t("menu.header")}</strong></header>
      <label>${t("menu.displayMode")}
        <select id="menu-display-mode">
          ${option("icon", t("menu.icon"))}${option("percentage", t("menu.percentage"))}${option("icon_and_percentage", t("menu.iconAndPercentage"))}
        </select>
      </label>
      <label class="setting-row">
        <span><strong>${t("menu.highestUsage")}</strong><small>${t("menu.highestUsageHint")}</small></span>
        <span class="switch"><input id="menu-highest-usage" type="checkbox" ${menu.highestUsage ? "checked" : ""} /><span></span></span>
      </label>
      <label class="setting-row">
        <span><strong>${t("menu.showPercentage")}</strong></span>
        <span class="switch"><input id="menu-show-percentage" type="checkbox" ${menu.showPercentage ? "checked" : ""} /><span></span></span>
      </label>
    </section>
  `;
}

function renderNotificationSettings(): string {
  const note = bootstrap.config.notifications;
  return `
    <section class="settings-block notification-settings">
      <header><strong>${t("notify.header")}</strong></header>
      <label class="setting-row">
        <span><strong>${t("notify.enable")}</strong><small>${t("notify.enableHint")}</small></span>
        <span class="switch"><input id="notify-enabled" type="checkbox" ${note.enabled ? "checked" : ""} /><span></span></span>
      </label>
      <label>${t("notify.thresholds")}
        <input id="notify-thresholds" type="text" value="${escapeAttribute(note.thresholds.join(", "))}" placeholder="75, 90" />
      </label>
      <label class="setting-row">
        <span><strong>${t("notify.pace")}</strong><small>${t("notify.paceHint")}</small></span>
        <span class="switch"><input id="notify-pace" type="checkbox" ${note.predictivePace ? "checked" : ""} /><span></span></span>
      </label>
      <label class="field">${t("notify.quiet")}
        <span class="quiet-range">
          <input id="notify-quiet-start" type="time" value="${escapeAttribute(note.quietStart ?? "")}" />
          <span>${t("notify.quietTo")}</span>
          <input id="notify-quiet-end" type="time" value="${escapeAttribute(note.quietEnd ?? "")}" />
        </span>
      </label>
    </section>
  `;
}

function renderReleaseSettings(): string {
  return `
    <section class="settings-block release-settings">
      <header><strong>Windows</strong></header>
      <label class="setting-row">
        <span><strong>${t("release.autostart")}</strong><small>${t("release.autostartHint")}</small></span>
        <span class="switch"><input id="launch-at-startup" type="checkbox" ${launchAtStartup ? "checked" : ""} ${changingLaunchAtStartup ? "disabled" : ""} /><span></span></span>
      </label>
      ${launchAtStartupError ? `<p class="release-error">${escapeHtml(launchAtStartupError)}</p>` : ""}
    </section>
  `;
}

function renderProviderSettings(descriptor: ProviderDescriptor, config: ConfigView): string {
  const settings = config.providers[descriptor.id];
  // Defensive: a descriptor with no matching providers entry would otherwise throw on `.accounts`
  // and blank the entire settings tab. Skip just that provider's block instead.
  if (!settings) return "";
  const pool = bootstrap.providerAccountPools[descriptor.id];
  if (!pool) return "";
  const busy = isProviderBusy(descriptor.id);
  const rows = (settings.accounts.length ? settings.accounts : [undefined])
    .map((account) => renderCapabilityAccount(descriptor, pool, account))
    .join("");
  const sourceOptions = descriptor.capabilities.sourceModes
    .map((mode) => `<option value="${mode}" ${settings.sourceMode === mode ? "selected" : ""}>${escapeHtml(sourceModeLabel(mode))}</option>`)
    .join("");
  const loginFlow = providerLoginFlows.get(descriptor.id);
  const loginSession = loginFlow?.phase === "waiting" ? loginFlow.sessionId : undefined;
  const capabilityGuidance = pool.activation.kind === "unsupported"
    ? `<p class="provider-account-guidance">${escapeHtml(t("provider.account.monitoringOnly", { reason: pool.activation.blockedReason ?? t("provider.account.switchingUnsupported") }))}</p>`
    : `<p class="provider-account-guidance supported">${escapeHtml(t("provider.account.officialTarget", { target: pool.activation.targetDescription ?? t("provider.account.officialTargetUnknown") }))}</p>`;
  const loginGuidance = loginSession
    ? `<p class="provider-account-guidance">${t("provider.account.loginWaiting")} <button class="cancel-provider-account-login" data-provider="${descriptor.id}" type="button">${t("provider.account.cancelLogin")}</button></p>`
    : "";
  const addMode = providerAccountAddMode(pool.enrollment);
  const addAction = addMode
    ? `<button class="add-provider-account" type="button" data-provider="${descriptor.id}" data-add-mode="${addMode}" ${busy ? "disabled" : ""}>${escapeHtml(t("provider.account.add", { provider: descriptor.displayName }))}</button>`
    : "";
  const unavailableEnrollment = !addMode && pool.enrollment.some((kind) =>
    kind === "browserLogin" || kind === "deviceOAuth",
  )
    ? `<p class="provider-account-guidance">${t("provider.account.enrollmentUnavailable")}</p>`
    : "";
  const providerToggleDisabled = pool.activeAccountId ? "disabled" : busy ? "disabled" : "";
  const providerToggleTitle = pool.activeAccountId
    ? t("provider.account.activeProviderCannotDisable")
    : "";
  return `
    <section class="settings-block provider-settings" data-settings-provider="${descriptor.id}">
      <header>
        <span class="provider-icon" style="--provider:${descriptor.color}">${initials(descriptor.displayName)}</span>
        <div><strong>${descriptor.displayName}</strong><small>${escapeHtml(descriptor.credentialHint)} · ${escapeHtml(t(`maturity.${descriptor.capabilities.maturity}`))}</small></div>
        <label class="switch" title="${escapeAttribute(providerToggleTitle)}"><input class="enabled" type="checkbox" ${settings.enabled ? "checked" : ""} ${providerToggleDisabled} /><span></span></label>
      </header>
      <label class="field">${t("source.label")}<select class="source-mode" ${busy ? "disabled" : ""}>${sourceOptions}</select></label>
      ${capabilityGuidance}
      ${loginGuidance}
      ${renderProviderPoolStatus(pool, true)}
      <div class="accounts">${rows}</div>
      ${addAction}
      ${unavailableEnrollment}
      ${pool.activeAccountId ? `<small class="provider-account-active-guard">${t("provider.account.activeProviderCannotDisable")}</small>` : ""}
    </section>
  `;
}

function renderCapabilityAccount(
  descriptor: ProviderDescriptor,
  pool: ProviderAccountPoolView,
  account?: AccountView,
): string {
  const poolAccount = account
    ? pool.accounts.find((entry) => entry.accountId === account.id)
    : undefined;
  const busy = isProviderBusy(descriptor.id);
  const isActive = poolAccount?.isActive ?? false;
  const fields = descriptor.capabilities.settings
    .map((setting) => renderCapabilitySetting(setting, account))
    .join("");
  const managed = account
    ? `<div class="provider-account-settings-actions"><span class="credential-state ${account.managedCredentialState}">${escapeHtml(t(`provider.account.credential.${account.managedCredentialState}`))}</span>${providerSupportsEnrollment(pool.enrollment, "cliLogin") ? `<button class="reauth-provider-account" type="button" data-provider="${descriptor.id}" data-account-id="${escapeAttribute(account.id)}" ${busy ? "disabled" : ""}>${credentialStateNeedsReauthentication(account.managedCredentialState) ? t("provider.account.login") : t("provider.account.reauthenticate")}</button>` : ""}</div>`
    : "";
  const hasOfficialIdentity = Boolean(poolAccount?.identity || account?.hasManagedCredential);
  const allowLegacyQuotaSourceActions =
    pool.enrollment.length === 0 &&
    !hasOfficialIdentity &&
    pool.activation.kind === "unsupported";
  const actions = allowLegacyQuotaSourceActions
    ? `<div class="provider-account-legacy-source"><small>${t("provider.account.legacyQuotaSource")}</small>${descriptor.capabilities.authActions
        .map((action) => renderCapabilityAction(action, descriptor, account))
        .join("")}</div>`
    : "";
  return `
    <div class="account-row provider-account-settings-row" data-account-id="${escapeAttribute(account?.id ?? "")}" data-provider-account-active="${isActive ? "true" : "false"}" data-provider-busy="${busy ? "true" : "false"}" ${account && !busy ? "draggable=\"true\"" : ""}>
      ${account ? `<span class="provider-account-drag" title="${t("provider.account.drag")}">⋮⋮</span>` : ""}
      <input class="account-label" value="${escapeAttribute(account?.label ?? "")}" placeholder="${escapeAttribute(t("account.labelPlaceholder"))}" ${busy ? "disabled" : ""} />
      <label class="account-enabled"><input type="checkbox" ${account?.enabled !== false ? "checked" : ""} ${isActive || busy ? "disabled" : ""} /> ${isActive ? t("provider.account.current") : t("provider.account.monitoringEnabled")}</label>
      ${poolAccount?.identity ? `<small class="provider-account-safe-identity">${escapeHtml(providerAccountIdentityLabel(poolAccount.identity))}</small>` : ""}
      <fieldset class="account-fields" ${busy ? "disabled" : ""}>${fields}</fieldset>
      <div class="auth-actions">${managed}${actions}</div>
      <button class="remove-account" type="button" title="${escapeAttribute(t("provider.account.remove"))}" aria-label="${escapeAttribute(t("provider.account.remove"))}" data-provider="${descriptor.id}" data-managed="${account?.hasManagedCredential ? "true" : "false"}" ${isActive || busy ? "disabled" : ""}>×</button>
    </div>
  `;
}

function renderCapabilitySetting(setting: ProviderSettingDescriptor, account?: AccountView): string {
  const raw = account?.values[setting.key];
  const label = settingLabel(setting.key);
  if (setting.kind === "secret") {
    const configured = account?.configuredSecrets.includes(setting.key) ?? false;
    return `<label class="field">${escapeHtml(label)}${setting.required ? " *" : ""}
      <span class="secret-row"><input type="password" autocomplete="off" data-setting-key="${setting.key}" data-setting-kind="secret" placeholder="${escapeAttribute(configured ? t("account.keyConfigured") : t("secret.unset"))}" /><button class="clear-secret" type="button" ${configured ? "" : "disabled"}>${t("account.clear")}</button></span>
    </label>`;
  }
  if (setting.kind === "select") {
    const value = typeof raw === "string" ? raw : "";
    const options = (setting.choices ?? [])
      .map((choice) => `<option value="${escapeAttribute(choice)}" ${value === choice ? "selected" : ""}>${escapeHtml(settingChoiceLabel(setting.key, choice))}</option>`)
      .join("");
    return `<label class="field">${escapeHtml(label)}${setting.required ? " *" : ""}<select data-setting-key="${setting.key}" data-setting-kind="select">${options}</select></label>`;
  }
  if (setting.kind === "multiValue") {
    const value = Array.isArray(raw) ? raw.join("\n") : "";
    return `<label class="field">${escapeHtml(label)}${setting.required ? " *" : ""}<textarea data-setting-key="${setting.key}" data-setting-kind="multiValue">${escapeHtml(value)}</textarea></label>`;
  }
  const value = typeof raw === "string" ? raw : "";
  return `<label class="field">${escapeHtml(label)}${setting.required ? " *" : ""}<input data-setting-key="${setting.key}" data-setting-kind="plain" value="${escapeAttribute(value)}" /></label>`;
}

function renderCapabilityAction(
  action: ProviderAuthActionKind,
  descriptor: ProviderDescriptor,
  account?: AccountView,
): string {
  const viewState = authActionViewState(action, true, account);
  const disabled = viewState.disabled || isProviderBusy(descriptor.id) || (action === "deviceOAuth" && copilotConnecting)
    ? "disabled"
    : "";
  const status = viewState.status === "imported"
    ? t("account.imported")
    : viewState.status === "notImported"
      ? t("account.notImported")
      : viewState.status === "connected"
        ? t("connect.connected")
        : t("connect.disconnected");
  const deviceCode = action === "deviceOAuth" && copilotDeviceCode
    ? `<div class="device-code" role="status"><strong>${t("copilot.waiting")}</strong><span>${t("copilot.code")} <code>${escapeHtml(copilotDeviceCode.userCode)}</code></span><span>${t("copilot.url")} <code>${escapeHtml(copilotDeviceCode.verificationUri)}</code></span></div>`
    : "";
  const error = action === "deviceOAuth" ? copilotConnectError : undefined;
  return `<div class="connect-row">
    <button class="auth-action primary" type="button" data-provider="${descriptor.id}" data-auth-action="${action}" ${disabled}>${copilotConnecting && action === "deviceOAuth" ? t("connect.loggingIn") : escapeHtml(authActionLabel(action, viewState.connected, viewState.imported))}</button>
    <span class="connect-status ${error ? "error" : viewState.connected || viewState.imported ? "ok" : ""}">${escapeHtml(error ?? status)}</span>
    ${deviceCode}
  </div>`;
}

// The persistent shell (topbar, tab bar). Wired on every full `render()`; a background
// `patchUsage()` leaves this DOM in place, so these handlers survive without re-wiring.
function wireChrome(): void {
  wireProviderAccountDialogActions();
  wireProviderAccountFeedback();
  app.querySelectorAll<HTMLButtonElement>(".import-current-provider-account").forEach((button) => {
    button.addEventListener("click", () => {
      const providerId = button.dataset.provider as ProviderId | undefined;
      if (providerId) void importCurrentProviderAccount(providerId);
    });
  });
  app.querySelectorAll<HTMLButtonElement>(".recover-provider-auth").forEach((button) => {
    button.addEventListener("click", () => {
      const providerId = button.dataset.provider as ProviderId | undefined;
      const action = button.dataset.recoveryAction as "restoreOriginal" | "keepCurrent" | undefined;
      if (providerId && action) void recoverProviderAuth(providerId, action);
    });
  });
  app.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      activeTab = button.dataset.tab === "settings" ? "settings" : "usage";
      render();
    });
  });
  app.querySelector<HTMLButtonElement>(".refresh")?.addEventListener("click", () => void refresh());
  const win = getCurrentWindow();
  app.querySelector<HTMLButtonElement>(".minimize")?.addEventListener("click", () => void win.minimize());
  app.querySelector<HTMLButtonElement>(".close")?.addEventListener("click", () => void win.close());
}

// Usage-tab content actions, delegated on the stable `.content` node. `patchUsage()` morphs new
// markup into this same node without replacing it, so these listeners are bound once per full render
// and survive every background node-diff — no per-patch re-wiring, and dynamically revealed controls
// (an expanded trend's range switch) work without extra binding.
function wireUsage(content: HTMLElement): void {
  content.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    if (target.closest(".go-settings")) {
      activeTab = "settings";
      render();
      return;
    }
    const activate = target.closest<HTMLButtonElement>(".activate-provider-account");
    const activateProviderId = activate?.dataset.provider as ProviderId | undefined;
    if (activateProviderId && activate?.dataset.accountId) {
      openProviderAccountDialog(createProviderActivationAction(
        activateProviderId,
        activate.dataset.accountId,
      ));
      return;
    }
    const manage = target.closest<HTMLButtonElement>(".manage-provider-accounts");
    if (manage?.dataset.provider) {
      activeTab = "settings";
      render();
      app.querySelector<HTMLElement>(`[data-settings-provider="${manage.dataset.provider}"]`)?.scrollIntoView({ block: "start" });
      return;
    }
    const importCurrent = target.closest<HTMLButtonElement>(".import-current-provider-account");
    const importProviderId = importCurrent?.dataset.provider as ProviderId | undefined;
    if (importProviderId) {
      void importCurrentProviderAccount(importProviderId);
      return;
    }
    const recovery = target.closest<HTMLButtonElement>(".recover-provider-auth");
    const recoveryProviderId = recovery?.dataset.provider as ProviderId | undefined;
    if (recoveryProviderId && recovery?.dataset.recoveryAction) {
      void recoverProviderAuth(recoveryProviderId, recovery.dataset.recoveryAction as "restoreOriginal" | "keepCurrent");
      return;
    }
    if (target.closest(".dismiss-provider-account-notice")) {
      providerAccountNotice = undefined;
      patchUsage();
      return;
    }
    const dashboard = target.closest<HTMLElement>(".dashboard");
    if (dashboard) {
      const card = dashboard.closest<HTMLElement>(".provider-card");
      const provider = dashboard.dataset.provider ?? card?.dataset.provider;
      const accountId = dashboard.dataset.accountId ?? card?.dataset.accountId;
      if (provider && accountId) void openDetail(`${provider}:${accountId}`);
      return;
    }
    if (target.closest(".detail-back")) {
      closeDetail();
      return;
    }
    if (target.closest(".detail-prev")) {
      detailStep(-1);
      return;
    }
    if (target.closest(".detail-next")) {
      detailStep(1);
      return;
    }
    const web = target.closest<HTMLElement>(".detail-web");
    if (web) {
      const provider = web.dataset.provider;
      if (provider) void invoke("open_dashboard", { provider });
      return;
    }
    const trend = target.closest<HTMLElement>("[data-trend]");
    if (trend) {
      const key = trend.dataset.trend;
      if (key) void toggleTrend(key);
      return;
    }
    const range = target.closest<HTMLElement>("[data-range-key]");
    if (range) {
      const key = range.dataset.rangeKey;
      const value = range.dataset.rangeValue as TrendRange | undefined;
      if (key && value) void setTrendRange(key, value);
      return;
    }
    if (target.closest("#cost-scan")) void scanCost();
  });
  content.addEventListener("change", (event) => {
    const target = event.target as HTMLElement;
    if (target.matches("#cost-provider")) {
      costProvider = (target as HTMLSelectElement).value as typeof costProvider;
    } else if (target.matches("#cost-range")) {
      costRange = (target as HTMLSelectElement).value as typeof costRange;
    }
  });
  // Coalesce onto rAF: a mousemove burst should cost at most one hit-test + DOM write per frame.
  content.addEventListener("mousemove", (event) => {
    hoverClientX = event.clientX;
    hoverClientY = event.clientY;
    if (hoverRaf) return;
    hoverRaf = requestAnimationFrame(() => {
      hoverRaf = 0;
      updateChartHover(hoverClientX, hoverClientY);
    });
  });
  // Direct (non-delegated) listener: `content` itself is the stable node the mousemove above is
  // bound to, and mouseleave doesn't bubble, so this only needs to fire for the container's own edge.
  content.addEventListener("mouseleave", () => {
    if (hoverRaf) {
      cancelAnimationFrame(hoverRaf);
      hoverRaf = 0;
    }
    clearChartHover();
  });
}

/// Finds the chart under the last-known cursor position and snaps its crosshair/tooltip to the
/// nearest point by pixel x, reading the hit-test data `lineChart()` embedded in `data-hover-points`.
/// A background refresh mid-hover re-renders that chart's overlay back to its default hidden state
/// (morph syncs attributes from the freshly rendered markup) — the user just needs to move the mouse
/// again to bring it back, which is an acceptable trade-off for not special-casing live interaction
/// state in the morph algorithm.
function updateChartHover(clientX: number, clientY: number): void {
  const svg = document.elementFromPoint(clientX, clientY)?.closest<SVGSVGElement>("svg.chart[data-hover-points]");
  if (!svg) {
    clearChartHover();
    return;
  }
  if (hoverActiveSvg && hoverActiveSvg !== svg) deactivateHover(hoverActiveSvg);
  hoverActiveSvg = svg;

  const rect = svg.getBoundingClientRect();
  if (rect.width === 0) return;
  const viewX = ((clientX - rect.left) / rect.width) * CHART_W;

  let raw: unknown;
  try {
    raw = JSON.parse(svg.getAttribute("data-hover-points") ?? "[]");
  } catch {
    return;
  }
  const points = raw as [number, number, string][];
  if (points.length === 0) return;
  let nearest = points[0];
  let bestDistance = Math.abs(nearest[0] - viewX);
  for (const point of points) {
    const distance = Math.abs(point[0] - viewX);
    if (distance < bestDistance) {
      nearest = point;
      bestDistance = distance;
    }
  }

  const line = svg.querySelector<SVGLineElement>(".chart-hover-line");
  const dot = svg.querySelector<SVGCircleElement>(".chart-hover-dot");
  const tip = svg.querySelector<SVGGElement>(".chart-hover-tip");
  const text = svg.querySelector<SVGTextElement>(".chart-hover-tip-text");
  const bg = svg.querySelector<SVGRectElement>(".chart-hover-tip-bg");
  const group = svg.querySelector<SVGGElement>(".chart-hover");
  if (!line || !dot || !tip || !text || !bg || !group) return;

  const [px, py, label] = nearest;
  line.setAttribute("x1", String(px));
  line.setAttribute("x2", String(px));
  dot.setAttribute("cx", String(px));
  dot.setAttribute("cy", String(py));
  positionHoverTip(tip, text, bg, px, py, label);
  group.setAttribute("data-active", "true");
}

/// Sizes and places the tooltip from the *measured* label (`getBBox`, taken after setting
/// `textContent`) rather than an estimated character count — labels mix Latin and CJK text (the app
/// is bilingual) whose glyph widths differ too much for a fixed-width guess to stay legible.
function positionHoverTip(tipGroup: SVGGElement, text: SVGTextElement, bg: SVGRectElement, px: number, py: number, label: string): void {
  text.textContent = label;
  const box = text.getBBox();
  const padX = 3;
  const padY = 2;
  const width = box.width + padX * 2;
  const height = box.height + padY * 2;
  // Flip to whichever side/edge has room, so the tooltip never runs outside the chart's viewBox.
  const tipX = px > CHART_W / 2 ? px - width - 4 : px + 4;
  const tipY = py > 18 ? py - height - 4 : py + 6;
  tipGroup.setAttribute("transform", `translate(${tipX}, ${tipY})`);
  bg.setAttribute("width", String(width));
  bg.setAttribute("height", String(height));
  text.setAttribute("x", String(padX));
  text.setAttribute("y", String(padY + box.height / 2));
}

function clearChartHover(): void {
  if (hoverActiveSvg) deactivateHover(hoverActiveSvg);
  hoverActiveSvg = undefined;
}

function deactivateHover(svg: SVGSVGElement): void {
  svg.querySelector(".chart-hover")?.setAttribute("data-active", "false");
}

function wireSettings(): void {
  const form = app.querySelector<HTMLFormElement>("#settings-form");
  if (!form) return;
  form.querySelector<HTMLInputElement>("#launch-at-startup")?.addEventListener("change", (event) => {
    void setLaunchAtStartup((event.currentTarget as HTMLInputElement).checked);
  });
  form.addEventListener("input", (event) => {
    const input = (event.target as HTMLElement).closest<HTMLInputElement>(
      'input[data-setting-kind="secret"]',
    );
    if (!input || !input.value.trim()) return;
    delete input.dataset.clear;
    const clear = input.parentElement?.querySelector<HTMLButtonElement>(".clear-secret");
    if (clear) clear.disabled = false;
  });
  // Delegate clicks so dynamically added account rows work without re-wiring.
  form.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    const cancelLogin = target.closest<HTMLButtonElement>(".cancel-provider-account-login");
    const cancelProviderId = cancelLogin?.dataset.provider as ProviderId | undefined;
    if (cancelProviderId) {
      void cancelProviderAccountLogin(cancelProviderId);
      return;
    }
    const clear = target.closest<HTMLButtonElement>(".clear-secret");
    if (clear) {
      const input = clear.parentElement?.querySelector<HTMLInputElement>("input");
      if (input) {
        input.value = "";
        input.dataset.clear = "true";
        input.placeholder = t("secret.clearOnSave");
        clear.disabled = true;
      }
      return;
    }
    const remove = target.closest<HTMLButtonElement>(".remove-account");
    if (remove) {
      const provider = remove.dataset.provider as ProviderId | undefined;
      const row = remove.closest<HTMLElement>(".account-row");
      const accountId = row?.dataset.accountId;
      if (provider && accountId) {
        const poolAccount = bootstrap.providerAccountPools[provider]?.accounts.find((entry) => entry.accountId === accountId);
        if (!poolAccount || poolAccount.isActive || isProviderBusy(provider)) return;
        openProviderAccountDialog({
          kind: "delete",
          providerId: provider,
          accountId,
          label: row.querySelector<HTMLInputElement>(".account-label")?.value.trim() || providerAccountIdentityLabel(poolAccount.identity),
        });
        return;
      }
      target.closest(".account-row")?.remove();
      return;
    }
    const addAccount = target.closest<HTMLButtonElement>(".add-provider-account");
    const addProviderId = addAccount?.dataset.provider as ProviderId | undefined;
    if (addAccount && addProviderId) {
      if (addAccount.dataset.addMode === "login") {
        void beginProviderAccountLogin(addProviderId);
        return;
      }
      const providerSection = addAccount.closest<HTMLElement>(".provider-settings");
      const container = providerSection?.querySelector(".accounts");
      const descriptor = descriptorFor(addProviderId);
      const pool = bootstrap.providerAccountPools[addProviderId];
      if (descriptor && pool) container?.insertAdjacentHTML("beforeend", renderCapabilityAccount(descriptor, pool));
      return;
    }
    const action = target.closest<HTMLButtonElement>(".auth-action");
    if (action) {
      void runAuthAction(action);
      return;
    }
    const reauthenticate = target.closest<HTMLButtonElement>(".reauth-provider-account");
    const reauthProviderId = reauthenticate?.dataset.provider as ProviderId | undefined;
    if (reauthProviderId && reauthenticate?.dataset.accountId) {
      void beginProviderAccountLogin(reauthProviderId, reauthenticate.dataset.accountId);
    }
  });
  let dragged: HTMLElement | undefined;
  let draggedProvider: string | undefined;
  form.addEventListener("dragstart", (event) => {
    dragged = (event.target as HTMLElement).closest<HTMLElement>(".provider-settings .account-row") ?? undefined;
    draggedProvider = dragged?.closest<HTMLElement>(".provider-settings")?.dataset.settingsProvider;
    dragged?.classList.add("dragging");
  });
  form.addEventListener("dragover", (event) => {
    if (!dragged) return;
    const target = (event.target as HTMLElement).closest<HTMLElement>(".provider-settings .account-row");
    const targetProvider = target?.closest<HTMLElement>(".provider-settings")?.dataset.settingsProvider;
    if (!target || target === dragged || targetProvider !== draggedProvider) return;
    event.preventDefault();
    const rect = target.getBoundingClientRect();
    target.parentElement?.insertBefore(dragged, event.clientY < rect.top + rect.height / 2 ? target : target.nextSibling);
  });
  form.addEventListener("dragend", () => {
    dragged?.classList.remove("dragging");
    dragged = undefined;
    draggedProvider = undefined;
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void saveSettings();
  });
}

async function refresh(): Promise<void> {
  if (refreshing) return;
  refreshing = true;
  render();
  try {
    bootstrap.states = await invoke<ProviderState[]>("refresh_all");
  } finally {
    refreshing = false;
    render();
  }
}

async function setLaunchAtStartup(enabled: boolean): Promise<void> {
  if (changingLaunchAtStartup) return;
  const previous = launchAtStartup;
  launchAtStartup = enabled;
  changingLaunchAtStartup = true;
  launchAtStartupError = undefined;
  render();
  try {
    launchAtStartup = await invoke<boolean>("set_launch_at_startup", { enabled });
  } catch (error) {
    launchAtStartup = previous;
    launchAtStartupError = String(error);
  } finally {
    changingLaunchAtStartup = false;
    render();
  }
}

const authCommands: Record<ProviderAuthActionKind, string> = {
  browserLogin: "browser_login",
  cookieImport: "cookie_import",
  cliImport: "cli_import",
  deviceOAuth: "device_oauth",
  oauthConnect: "oauth_connect",
};

async function runAuthAction(button: HTMLButtonElement): Promise<void> {
  const provider = button.dataset.provider as ProviderId | undefined;
  const action = button.dataset.authAction as ProviderAuthActionKind | undefined;
  const accountId = button.closest<HTMLElement>(".account-row")?.dataset.accountId || undefined;
  if (!provider || !action || button.disabled) return;
  const isDevice = action === "deviceOAuth";
  const status = button.parentElement?.querySelector<HTMLElement>(".connect-status");
  const original = button.textContent;
  button.disabled = true;
  if (isDevice) {
    copilotConnecting = true;
    copilotDeviceCode = undefined;
    copilotConnectError = undefined;
    render();
  } else {
    button.textContent = t("connect.loggingIn");
    if (status) {
      status.textContent = t("connect.loginPrompt");
      status.classList.remove("ok", "error");
    }
  }
  try {
    bootstrap = await invoke<Bootstrap>(authCommands[action], { provider, accountId });
    render();
  } catch (error) {
    if (isDevice) {
      copilotConnectError = String(error);
    } else {
      button.disabled = false;
      button.textContent = original;
      if (status) {
        status.textContent = String(error);
        status.classList.add("error");
      }
    }
  } finally {
    if (isDevice) {
      copilotConnecting = false;
      copilotDeviceCode = undefined;
      render();
    }
  }
}

async function activateProviderAccount(
  providerId: ProviderId,
  accountId: string,
  expectedCurrentIdentity: ProviderAccountIdentity | undefined,
  reapplyAfterReauthentication = false,
): Promise<void> {
  // A terminal reauthentication event is emitted only after the backend has closed that Provider's
  // login session. Ignore a possibly stale projected busy bit in that one path so refreshed active
  // credentials are always reinstalled; the backend still serializes and validates the operation.
  if (!reapplyAfterReauthentication && isProviderBusy(providerId)) return;
  providerBusy.add(providerId);
  providerAccountNotice = undefined;
  renderProviderAccountUi(providerId);
  try {
    const result = await invoke<ProviderAccountSwitchResult>("activate_provider_account", {
      providerId,
      accountId,
      expectedCurrentIdentity,
    });
    bootstrap = result.bootstrap;
    const provider = providerName(providerId);
    const client = result.restartHint.clientName ?? provider;
    providerAccountNotice = {
      providerId,
      kind: "success",
      message: reapplyAfterReauthentication
        ? t("provider.account.reauthenticatedReapplied", { provider, client })
        : result.restartHint.required
          ? t("provider.account.switchedRestart", { provider, client })
          : t("provider.account.switched", { provider }),
    };
  } catch (error) {
    setProviderAccountError(parseProviderAccountError(error, providerId));
  } finally {
    providerBusy.delete(providerId);
    renderProviderAccountUi(providerId);
  }
}

async function beginProviderAccountLogin(providerId: ProviderId, accountId?: string): Promise<void> {
  if (isProviderBusy(providerId)) return;
  providerBusy.add(providerId);
  providerAccountNotice = undefined;
  const activeAccountIdAtStart = bootstrap.providerAccountPools[providerId]?.activeAccountId;
  const generation = ++providerLoginGeneration;
  providerLoginFlows.set(
    providerId,
    beginProviderLoginFlow(generation, providerId, accountId, activeAccountIdAtStart),
  );
  renderProviderAccountUi(providerId);
  try {
    const result = await invoke<ProviderAccountLoginStarted>("begin_provider_account_login", {
      providerId,
      accountId,
    });
    const current = providerLoginFlows.get(providerId);
    if (current) {
      providerLoginFlows.set(
        providerId,
        applyProviderLoginResponse(current, generation, result.sessionId),
      );
    }
  } catch (error) {
    const current = providerLoginFlows.get(providerId);
    if (current?.generation === generation && current.phase !== "terminal") {
      providerLoginFlows.delete(providerId);
      providerBusy.delete(providerId);
      setProviderAccountError(parseProviderAccountError(error, providerId));
    }
  }
  renderProviderAccountUi(providerId);
}

async function cancelProviderAccountLogin(providerId: ProviderId): Promise<void> {
  const sessionId = providerLoginFlows.get(providerId)?.sessionId;
  if (!sessionId) return;
  await invoke("cancel_provider_account_login", { sessionId }).catch(() => undefined);
}

async function importCurrentProviderAccount(providerId: ProviderId): Promise<void> {
  if (isProviderBusy(providerId)) return;
  providerBusy.add(providerId);
  providerAccountNotice = undefined;
  renderProviderAccountUi(providerId);
  try {
    const result = await invoke<ProviderAccountImportResult>("import_current_provider_account", { providerId });
    bootstrap = result.bootstrap;
    providerAccountNotice = {
      providerId,
      kind: "success",
      message: t("provider.account.importedCurrent", { provider: providerName(providerId) }),
    };
  } catch (error) {
    setProviderAccountError(parseProviderAccountError(error, providerId));
  } finally {
    providerBusy.delete(providerId);
    renderProviderAccountUi(providerId);
  }
}

async function deleteProviderAccount(providerId: ProviderId, accountId: string): Promise<void> {
  if (isProviderBusy(providerId)) return;
  providerBusy.add(providerId);
  providerAccountNotice = undefined;
  renderProviderAccountUi(providerId);
  try {
    bootstrap = await invoke<Bootstrap>("delete_provider_account", { providerId, accountId });
    providerAccountNotice = {
      providerId,
      kind: "success",
      message: t("provider.account.deleted", { provider: providerName(providerId) }),
    };
  } catch (error) {
    setProviderAccountError(parseProviderAccountError(error, providerId));
  } finally {
    providerBusy.delete(providerId);
    renderProviderAccountUi(providerId);
  }
}

async function recoverProviderAuth(
  providerId: ProviderId,
  action: "restoreOriginal" | "keepCurrent",
): Promise<void> {
  if (isProviderBusy(providerId)) return;
  providerBusy.add(providerId);
  providerAccountNotice = undefined;
  renderProviderAccountUi(providerId);
  try {
    bootstrap = await invoke<Bootstrap>("recover_provider_auth", { providerId, action });
    providerAccountNotice = {
      providerId,
      kind: "success",
      message: t("provider.account.recovered", { provider: providerName(providerId) }),
    };
  } catch (error) {
    setProviderAccountError(parseProviderAccountError(error, providerId));
  } finally {
    providerBusy.delete(providerId);
    renderProviderAccountUi(providerId);
  }
}

async function reloadBootstrap(providerId?: ProviderId): Promise<void> {
  try {
    bootstrap = await invoke<Bootstrap>("bootstrap");
    applyLocale();
    renderProviderAccountUi(providerId);
  } catch (error) {
    setProviderAccountError(parseProviderAccountError(error, providerId));
    renderProviderAccountUi(providerId);
  }
}

function parseProviderAccountError(
  error: unknown,
  fallbackProviderId?: ProviderId,
): ProviderAccountCommandError {
  if (error && typeof error === "object" && "code" in error && "message" in error) {
    return error as ProviderAccountCommandError;
  }
  if (typeof error === "string") {
    try {
      const parsed = JSON.parse(error) as ProviderAccountCommandError;
      if (parsed.code && parsed.message) return parsed;
    } catch {
      // Tauri may return a plain string for transport-level failures.
    }
    return { code: "internal", message: error, providerId: fallbackProviderId };
  }
  return { code: "internal", message: String(error), providerId: fallbackProviderId };
}

function setProviderAccountError(error: ProviderAccountCommandError): void {
  const kind = providerAccountFeedbackKind(error.code);
  providerAccountNotice = {
    providerId: error.providerId,
    kind,
    message: providerAccountErrorMessage(error),
  };
  if (kind === "recovery") void reloadBootstrap(error.providerId);
}

async function saveSettings(): Promise<void> {
  const providers: Partial<Record<ProviderId, ProviderSettingsUpdate>> = {};
  for (const descriptor of bootstrap.descriptors) {
    const section = app.querySelector<HTMLElement>(`[data-settings-provider="${descriptor.id}"]`);
    if (!section) continue;
    const pool = bootstrap.providerAccountPools[descriptor.id];
    if (!providerSettingsIncludedInSave(
      providerBusy.has(descriptor.id),
      pool?.operationInProgress === true,
    )) continue;
    providers[descriptor.id] = {
      enabled: section.querySelector<HTMLInputElement>(".enabled")?.checked ?? false,
      sourceMode: (section.querySelector<HTMLSelectElement>(".source-mode")?.value ?? "auto") as ProviderSourceMode,
      accounts: collectAccounts(descriptor, section),
    };
  }
  const localeValue = (app.querySelector<HTMLSelectElement>("#locale-select")?.value ??
    bootstrap.config.locale) as SettingsUpdate["locale"];
  // Guard against an empty/invalid interval field: Number("") is 0, which would store a 0-minute
  // refresh loop. Clamp to the input's own 1–60 range, falling back to the saved value.
  const parsedInterval = Number.parseInt(app.querySelector<HTMLInputElement>("#refresh-interval")?.value ?? "", 10);
  const refreshIntervalMinutes = Number.isFinite(parsedInterval)
    ? Math.min(60, Math.max(1, parsedInterval))
    : bootstrap.config.refreshIntervalMinutes;
  const update: SettingsUpdate = {
    refreshIntervalMinutes,
    locale: localeValue,
    menuBar: collectMenuBar(),
    notifications: collectNotifications(),
    shortcuts: collectShortcuts(),
    providers,
  };
  const status = app.querySelector<HTMLElement>("#save-status");
  if (status) status.textContent = t("settings.saving");
  try {
    bootstrap = await invoke<Bootstrap>("save_settings", { update });
    applyLocale();
    if (status) status.textContent = t("settings.saved");
    render();
  } catch (error) {
    if (status) status.textContent = String(error);
  }
}

function collectShortcuts(): SettingsUpdate["shortcuts"] {
  const value = (selector: string) =>
    app.querySelector<HTMLInputElement>(selector)?.value.trim() || undefined;
  return {
    toggleWindow: value("#shortcut-toggle-window"),
    refresh: value("#shortcut-refresh"),
    nextProvider: value("#shortcut-next-provider"),
  };
}

function collectMenuBar(): SettingsUpdate["menuBar"] {
  const displayMode = (app.querySelector<HTMLSelectElement>("#menu-display-mode")?.value ??
    bootstrap.config.menuBar.displayMode) as SettingsUpdate["menuBar"]["displayMode"];
  return {
    displayMode,
    highestUsage: app.querySelector<HTMLInputElement>("#menu-highest-usage")?.checked ?? true,
    showPercentage: app.querySelector<HTMLInputElement>("#menu-show-percentage")?.checked ?? true,
  };
}

function collectNotifications(): SettingsUpdate["notifications"] {
  const thresholds = (app.querySelector<HTMLInputElement>("#notify-thresholds")?.value ?? "")
    .split(",")
    .map((part) => Number.parseFloat(part.trim()))
    .filter((value) => Number.isFinite(value));
  const quietStart = app.querySelector<HTMLInputElement>("#notify-quiet-start")?.value || undefined;
  const quietEnd = app.querySelector<HTMLInputElement>("#notify-quiet-end")?.value || undefined;
  return {
    enabled: app.querySelector<HTMLInputElement>("#notify-enabled")?.checked ?? true,
    thresholds,
    predictivePace: app.querySelector<HTMLInputElement>("#notify-pace")?.checked ?? false,
    quietStart,
    quietEnd,
  };
}

function collectAccounts(descriptor: ProviderDescriptor, section: HTMLElement): AccountUpdate[] {
  return [...section.querySelectorAll<HTMLElement>(".account-row")].map((row) => {
    const update = blankAccountUpdate();
    update.id = row.dataset.accountId || undefined;
    update.label = row.querySelector<HTMLInputElement>(".account-label")?.value.trim() || undefined;
    update.enabled = row.querySelector<HTMLInputElement>(".account-enabled input")?.checked ?? true;
    for (const setting of descriptor.capabilities.settings) {
      const input = row.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
        `[data-setting-key="${setting.key}"]`,
      );
      if (!input) continue;
      if (setting.kind === "secret") {
        const value = input.value.trim();
        if (value) update.secrets[setting.key] = value;
        if (input.dataset.clear === "true") update.clearSecrets.push(setting.key);
      } else if (setting.kind === "multiValue") {
        update.values[setting.key] = normalizeMultiValue(input.value);
      } else {
        update.values[setting.key] = input.value.trim();
      }
    }
    return update;
  });
}

function blankAccountUpdate(): AccountUpdate {
  return {
    id: undefined,
    label: undefined,
    enabled: true,
    values: {},
    secrets: {},
    clearSecrets: [],
  };
}

function normalizeMultiValue(value: string): string[] {
  return [...new Set(value.split(/[\n,]/).map((part) => part.trim()).filter(Boolean))].sort();
}

function nextEnabledProviderCardIndex(current: number): number {
  const enabled = bootstrap.descriptors
    .map((descriptor, index) => ({ descriptor, index }))
    .filter(({ descriptor }) =>
      bootstrap.states.some((state) =>
        state.descriptor.id === descriptor.id &&
        state.configured &&
        providerStateVisibleOnUsage(state),
      ),
    );
  if (enabled.length === 0) return -1;
  const position = enabled.findIndex(({ index }) => index === current);
  return enabled[(position + 1 + enabled.length) % enabled.length].index;
}

function cycleNextProvider(): void {
  // In the deep view the shortcut steps the detail to the next provider instead of focusing a card.
  if (activeDetail) {
    detailStep(1);
    return;
  }
  activeProviderCardIndex = nextEnabledProviderCardIndex(activeProviderCardIndex);
  if (activeProviderCardIndex < 0) return;
  activeTab = "usage";
  render();
  requestAnimationFrame(() => {
    const card = app.querySelector<HTMLElement>(
      `.provider-card[data-state-index="${activeProviderCardIndex}"]`,
    );
    if (!card) return;
    card.scrollIntoView({ block: "nearest", behavior: "smooth" });
    card.focus({ preventScroll: true });
    card.classList.add("shortcut-target");
    window.setTimeout(() => card.classList.remove("shortcut-target"), 1200);
  });
}

function sourceModeLabel(mode: ProviderSourceMode): string {
  const labels = {
    auto: t("source.auto"),
    api: t("source.api"),
    web: t("source.web"),
    cli: t("source.cli"),
    oauth: t("source.oauth"),
  } satisfies Record<ProviderSourceMode, string>;
  return labels[mode];
}

function settingLabel(key: ProviderSettingKey): string {
  const labels = {
    apiKey: t("setting.apiKey"),
    secretKey: t("setting.secretKey"),
    cookieHeader: t("setting.cookieHeader"),
    browser: t("setting.browser"),
    baseUrl: t("setting.baseUrl"),
    region: t("setting.region"),
    workspaceId: t("setting.workspaceId"),
    organizationId: t("setting.organizationId"),
    projectId: t("setting.projectId"),
    deployment: t("setting.deployment"),
    enterpriseHost: t("setting.enterpriseHost"),
    usageScope: t("setting.usageScope"),
    awsProfile: t("setting.awsProfile"),
    awsAuthMode: t("setting.awsAuthMode"),
    kiloOrganizationIds: t("setting.kiloOrganizationIds"),
  } satisfies Record<ProviderSettingKey, string>;
  return labels[key];
}

function settingChoiceLabel(key: ProviderSettingKey, choice: string): string {
  if (key === "browser") {
    if (choice === "auto") return t("browser.auto");
    if (choice === "chrome") return "Chrome";
    if (choice === "edge") return "Edge";
  }
  if (key === "region") {
    if (choice === "international") return t("choice.international");
    if (choice === "china") return t("choice.china");
  }
  return choice;
}

function authActionLabel(action: ProviderAuthActionKind, connected: boolean, imported: boolean): string {
  if ((action === "cliImport" || action === "oauthConnect") && imported) return t("account.reimport");
  if (action === "browserLogin" && connected) return t("connect.relogin");
  const labels = {
    browserLogin: t("action.browserLogin"),
    cookieImport: t("action.cookieImport"),
    cliImport: t("action.cliImport"),
    deviceOAuth: t("action.deviceOAuth"),
    oauthConnect: t("action.oauthConnect"),
  } satisfies Record<ProviderAuthActionKind, string>;
  return labels[action];
}

function authLabel(descriptor: ProviderDescriptor): string {
  return descriptor.authKind === "api_key"
    ? "API key"
    : descriptor.authKind === "browser_cookie"
      ? t("auth.cookie")
      : descriptor.authKind === "device_oauth"
        ? t("auth.deviceOAuth")
        : "CLI OAuth";
}

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase();
}

function formatPercent(value: number): string {
  return value < 1 && value > 0 ? `${value.toFixed(2)}%` : `${Math.round(value)}%`;
}

function resetLabel(value?: string): string {
  if (!value) return t("reset.none");
  const date = new Date(value);
  const delta = date.getTime() - Date.now();
  if (delta <= 0) return t("reset.soon");
  const minutes = Math.ceil(delta / 60_000);
  if (minutes < 60) return t("reset.minutes", { minutes });
  const hours = Math.ceil(minutes / 60);
  if (hours < 48) return t("reset.hours", { hours });
  return t("reset.days", { days: Math.ceil(hours / 24) });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character] ?? character);
}

function escapeAttribute(value: string): string {
  return escapeHtml(value);
}

function fail(message: string): never {
  throw new Error(message);
}

void start();
