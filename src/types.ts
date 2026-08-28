export type ProviderId =
  | "claude"
  | "codex"
  | "copilot"
  | "cursor"
  | "opencode"
  | "opencodezen"
  | "openrouter"
  | "deepseek"
  | "moonshot"
  | "venice"
  | "poe"
  | "groq"
  | "elevenlabs"
  | "deepgram"
  | "kimik2"
  | "crossmodel"
  | "clawrouter"
  | "crof"
  | "codebuff"
  | "llmproxy"
  | "openai"
  | "chutes"
  | "synthetic"
  | "azureopenai"
  | "litellm"
  | "sub2api"
  | "zai"
  | "minimax"
  | "wayfinder"
  | "kilo"
  | "perplexity"
  | "kimi"
  | "manus"
  | "abacus"
  | "amp"
  | "commandcode"
  | "stepfun"
  | "t3chat"
  | "qoder"
  | "mimo"
  | "augment";
export type ProviderStatus = "ready" | "error" | "disabled" | "loading";
export type BrowserPreference = "auto" | "chrome" | "edge";
export type ProviderMaturity = "experimental" | "stable";
export type ProviderSourceMode = "auto" | "api" | "web" | "cli" | "oauth";
export type ProviderSettingKey =
  | "apiKey"
  | "secretKey"
  | "cookieHeader"
  | "browser"
  | "baseUrl"
  | "region"
  | "workspaceId"
  | "organizationId"
  | "projectId"
  | "deployment"
  | "enterpriseHost"
  | "usageScope"
  | "awsProfile"
  | "awsAuthMode"
  | "kiloOrganizationIds";
export type ProviderSettingKind = "plain" | "secret" | "select" | "multiValue";
export type ProviderAuthActionKind =
  | "browserLogin"
  | "cookieImport"
  | "cliImport"
  | "deviceOAuth"
  | "oauthConnect";

export interface ProviderSettingDescriptor {
  key: ProviderSettingKey;
  kind: ProviderSettingKind;
  required: boolean;
  choices?: string[];
}

export interface ProviderCapabilityDescriptor {
  maturity: ProviderMaturity;
  sourceModes: ProviderSourceMode[];
  settings: ProviderSettingDescriptor[];
  authActions: ProviderAuthActionKind[];
}

export interface ProviderDescriptor {
  id: ProviderId;
  displayName: string;
  authKind: "cli_oauth" | "browser_cookie" | "api_key" | "device_oauth";
  color: string;
  dashboardUrl: string;
  credentialHint: string;
  supportsMultipleAccounts: boolean;
  capabilities: ProviderCapabilityDescriptor;
}

export interface CopilotDeviceCodeEvent {
  userCode: string;
  verificationUri: string;
  expiresIn: number;
}

export interface UsageWindow {
  id: string;
  title: string;
  usedPercent: number;
  windowMinutes?: number;
  resetsAt?: string;
  detail?: string;
}

export interface SummaryItem {
  label: string;
  value: string;
}

export interface ProviderSnapshot {
  provider: ProviderId;
  source: string;
  windows: UsageWindow[];
  summary: SummaryItem[];
  accountLabel?: string;
  plan?: string;
  fetchedAt: string;
}

export type ServiceIndicator = "none" | "minor" | "major" | "critical" | "maintenance" | "unknown";

export interface ServiceStatus {
  indicator: ServiceIndicator;
  description?: string;
  updatedAt?: string;
}

export interface ProviderState {
  descriptor: ProviderDescriptor;
  accountId: string;
  accountLabel?: string;
  status: ProviderStatus;
  snapshot?: ProviderSnapshot;
  error?: string;
  serviceStatus?: ServiceStatus;
  /// Whether the user has configured this provider (stored/managed credential, or it is returning
  /// data). The usage page renders only configured cards; the backend computes this per card.
  configured: boolean;
  isActive: boolean;
  canActivate: boolean;
  activationBlockedReason?: string;
}

export interface HistoryPoint {
  timestamp: string;
  provider: ProviderId;
  accountId: string;
  windowId: string;
  usedPercent: number;
  resetsAt?: string;
  balance?: number;
  spend?: number;
  currency?: string;
}

export interface TokenUsage {
  input: number;
  output: number;
  cacheCreation: number;
  cacheRead: number;
}

export interface CostDay {
  day: string;
  usage: TokenUsage;
  costUsd?: number;
}

export interface CostModelSeries {
  model: string;
  daily: CostDay[];
}

export interface CostBreakdown {
  provider: "codex" | "claude" | "both";
  generatedAt: string;
  daily: CostDay[];
  models: { model: string; usage: TokenUsage; costUsd?: number }[];
  /// Per-model daily history, ordered by descending range total (see backend `model_daily`).
  modelDaily: CostModelSeries[];
  totalUsage: TokenUsage;
  totalCostUsd?: number;
  unknownModels: string[];
  skippedRecords: number;
}

export type WarningKind = "threshold" | "pace";

export interface Warning {
  provider: ProviderId;
  accountId: string;
  windowId: string;
  windowTitle: string;
  kind: WarningKind;
  threshold: number;
  usedPercent: number;
  resetBoundary?: string;
  suppressToast: boolean;
}

export interface AccountView {
  id: string;
  label?: string;
  enabled: boolean;
  values: Partial<Record<ProviderSettingKey, string | string[]>>;
  configuredSecrets: ProviderSettingKey[];
  hasManagedCredential: boolean;
  identity?: ProviderAccountIdentity;
  managedCredentialState: ManagedCredentialState;
  isActive: boolean;
}

export interface ProviderIdentityKey {
  namespace: string;
  value: string;
}

export interface ProviderAccountIdentity {
  provider: ProviderId;
  stableKeys: ProviderIdentityKey[];
  email?: string;
  displayName?: string;
}

export type ManagedCredentialState =
  | "available"
  | "missing"
  | "invalid"
  | "undecryptable"
  | "migrationFailed";

export type ActivationTargetKind =
  | "cliFile"
  | "windowsCredential"
  | "desktopClient"
  | "browserProfile"
  | "unsupported";

export interface ProviderActivationSupport {
  kind: ActivationTargetKind;
  targetDescription?: string;
  blockedReason?: string;
}

export interface ProviderAccountPoolAccountView {
  accountId: string;
  label?: string;
  enabled: boolean;
  identity?: ProviderAccountIdentity;
  managedCredentialState: ManagedCredentialState;
  isActive: boolean;
  canActivate: boolean;
  activationBlockedReason?: string;
}

export type ProviderRecoveryState = "none" | "required" | "corrupt";
export type ProviderEnrollmentKind =
  | "manualSecret"
  | "browserLogin"
  | "deviceOAuth"
  | "cliLogin"
  | "importCurrent";


export interface ProviderAccountPoolView {
  providerId: ProviderId;
  enrollment: ProviderEnrollmentKind[];
  activeAccountId?: string;
  accounts: ProviderAccountPoolAccountView[];
  activation: ProviderActivationSupport;
  externalIdentity?: ProviderAccountIdentity;
  recoveryState: ProviderRecoveryState;
  operationInProgress: boolean;
  stateUnavailable: boolean;
}

export type ProviderAccountCommandErrorCode =
  | "unsupportedActivation"
  | "invalidCredential"
  | "identityMismatch"
  | "externalWrite"
  | "rolledBack"
  | "recoveryRequired"
  | "recoveryFailed"
  | "loginFailure"
  | "operationInProgress"
  | "accountNotFound"
  | "accountActive"
  | "accountDisabled"
  | "internal";

export interface ProviderAccountCommandError {
  code: ProviderAccountCommandErrorCode;
  providerId?: ProviderId;
  message: string;
  accountId?: string;
}

export interface ProviderRestartHint {
  required: boolean;
  clientName?: string;
  message?: string;
}

export interface ProviderAccountSwitchResult {
  bootstrap: Bootstrap;
  providerId: ProviderId;
  previousAccountId?: string;
  activeAccountId: string;
  restartHint: ProviderRestartHint;
}

export interface ProviderAccountLoginEvent {
  sessionId: string;
  providerId: ProviderId;
  status: "waiting" | "succeeded" | "failed" | "cancelled" | "timedOut";
  accountId?: string;
  error?: ProviderAccountCommandError;
}

export interface ProviderAccountLoginStarted {
  sessionId: string;
}

export interface ProviderAccountImportResult {
  bootstrap: Bootstrap;
  providerId: ProviderId;
  accountId: string;
  updatedExisting: boolean;
}

export interface ProviderSettingsView {
  enabled: boolean;
  sourceMode: ProviderSourceMode;
  accounts: AccountView[];
}

export type MenuBarDisplayMode = "icon" | "percentage" | "icon_and_percentage";

export interface MenuBarView {
  displayMode: MenuBarDisplayMode;
  highestUsage: boolean;
  showPercentage: boolean;
}

export interface NotificationsView {
  enabled: boolean;
  thresholds: number[];
  predictivePace: boolean;
  quietStart?: string;
  quietEnd?: string;
}

export interface ShortcutsView {
  toggleWindow?: string;
  refresh?: string;
  nextProvider?: string;
}

export type LocalePreference = "system" | "en" | "zh-hans";

export interface ConfigView {
  refreshIntervalMinutes: number;
  locale: LocalePreference;
  menuBar: MenuBarView;
  notifications: NotificationsView;
  shortcuts: ShortcutsView;
  providers: Record<ProviderId, ProviderSettingsView>;
}

export interface Bootstrap {
  descriptors: ProviderDescriptor[];
  config: ConfigView;
  configPath: string;
  states: ProviderState[];
  shortcutError?: string;
  providerAccountPools: Record<ProviderId, ProviderAccountPoolView>;
}

export interface AccountUpdate {
  id?: string;
  label?: string;
  enabled: boolean;
  values: Partial<Record<ProviderSettingKey, string | string[]>>;
  secrets: Partial<Record<ProviderSettingKey, string>>;
  clearSecrets: ProviderSettingKey[];
}

export interface ProviderSettingsUpdate {
  enabled: boolean;
  sourceMode: ProviderSourceMode;
  accounts: AccountUpdate[];
}

export interface SettingsUpdate {
  refreshIntervalMinutes: number;
  locale: LocalePreference;
  menuBar: MenuBarView;
  notifications: NotificationsView;
  shortcuts: ShortcutsView;
  providers: Partial<Record<ProviderId, ProviderSettingsUpdate>>;
}
