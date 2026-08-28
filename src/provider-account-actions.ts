import type {
  ManagedCredentialState,
  ProviderAccountCommandErrorCode,
  ProviderAccountLoginEvent,
  ProviderAccountIdentity,
  ProviderAccountPoolView,
  ProviderEnrollmentKind,
  ProviderId,
} from "./types";

export type ProviderAccountFeedbackKind =
  | "error"
  | "rolledBack"
  | "recovery"
  | "externalWrite"
  | "unsupported";

export type ProviderAccountErrorTranslationKey =
  `provider.account.error.${ProviderAccountCommandErrorCode}`;

export interface ProviderLoginFlowState {
  generation: number;
  providerId: ProviderId;
  requestedAccountId?: string;
  activeAccountIdAtStart?: string;
  phase: "starting" | "waiting" | "terminal";
  sessionId?: string;
  terminalStatus?: Exclude<ProviderAccountLoginEvent["status"], "waiting">;
}

export interface ExpectedCurrentProviderIdentitySnapshot {
  source: "managed" | "external" | "none";
  identity?: ProviderAccountIdentity;
}

function cloneSafeProviderIdentity(
  identity: ProviderAccountIdentity,
): ProviderAccountIdentity {
  return {
    provider: identity.provider,
    stableKeys: identity.stableKeys.map((key) => ({
      namespace: key.namespace,
      value: key.value,
    })),
    email: identity.email,
    displayName: identity.displayName,
  };
}

export function snapshotExpectedCurrentProviderIdentity(
  pool: Pick<ProviderAccountPoolView, "activeAccountId" | "accounts" | "externalIdentity">,
): ExpectedCurrentProviderIdentitySnapshot {
  const managedIdentity = pool.accounts.find((account) =>
    account.accountId === pool.activeAccountId,
  )?.identity;
  if (managedIdentity) {
    return { source: "managed", identity: cloneSafeProviderIdentity(managedIdentity) };
  }
  if (pool.externalIdentity) {
    return { source: "external", identity: cloneSafeProviderIdentity(pool.externalIdentity) };
  }
  return { source: "none", identity: undefined };
}

export function providerAccountFeedbackKind(
  code: ProviderAccountCommandErrorCode,
): ProviderAccountFeedbackKind {
  if (code === "rolledBack") return "rolledBack";
  if (code === "recoveryFailed" || code === "recoveryRequired") return "recovery";
  if (code === "externalWrite") return "externalWrite";
  if (code === "unsupportedActivation") return "unsupported";
  return "error";
}

export function providerAccountErrorTranslationKey(
  code: ProviderAccountCommandErrorCode,
): ProviderAccountErrorTranslationKey {
  const knownCodes: readonly ProviderAccountCommandErrorCode[] = [
    "unsupportedActivation",
    "invalidCredential",
    "identityMismatch",
    "externalWrite",
    "rolledBack",
    "recoveryRequired",
    "recoveryFailed",
    "loginFailure",
    "operationInProgress",
    "accountNotFound",
    "accountActive",
    "accountDisabled",
    "internal",
  ];
  const safeCode = knownCodes.includes(code) ? code : "internal";
  return `provider.account.error.${safeCode}`;
}

export function accountActivationDisabled(
  account: Pick<{ isActive: boolean; canActivate: boolean }, "isActive" | "canActivate">,
  providerBusy: boolean,
): boolean {
  return providerBusy || account.isActive || !account.canActivate;
}

export function credentialStateNeedsReauthentication(state: ManagedCredentialState): boolean {
  return state !== "available";
}

export function providerAccountActionRequiresConfirmation(
  _providerId: ProviderId,
  action: "activate" | "delete",
): boolean {
  return action === "activate" || action === "delete";
}

export function providerActionBusy(
  busyProviderId: ProviderId | undefined,
  providerId: ProviderId,
): boolean {
  return busyProviderId === providerId;
}

export function shouldReapplyAfterReauthentication(
  event: Pick<ProviderAccountLoginEvent, "status" | "accountId">,
  requestedAccountId: string | undefined,
  activeAccountIdAtStart: string | undefined,
  freshActiveAccountId: string | undefined,
  hasFreshExternalIdentity: boolean,
  hasFreshActiveIdentity: boolean,
): boolean {
  return (
    event.status === "succeeded" &&
    Boolean(requestedAccountId) &&
    event.accountId === requestedAccountId &&
    activeAccountIdAtStart === requestedAccountId &&
    freshActiveAccountId === requestedAccountId &&
    !hasFreshExternalIdentity &&
    hasFreshActiveIdentity
  );
}

export function providerSupportsEnrollment(
  enrollment: readonly ProviderEnrollmentKind[],
  kind: ProviderEnrollmentKind,
): boolean {
  return enrollment.includes(kind);
}

export function providerAccountAddMode(
  enrollment: readonly ProviderEnrollmentKind[],
): "login" | "local" | undefined {
  if (providerSupportsEnrollment(enrollment, "cliLogin")) return "login";
  if (providerSupportsEnrollment(enrollment, "manualSecret")) return "local";
  return undefined;
}

export function providerSettingsIncludedInSave(
  providerBusy: boolean,
  operationInProgress: boolean,
): boolean {
  return !providerBusy && !operationInProgress;
}

export function providerAccountVisibleOnUsage(
  enabled: boolean,
  stateUnavailable: boolean,
): boolean {
  return enabled || stateUnavailable;
}

export function providerLifecycleUnavailable(
  loginListenerReady: boolean,
  poolListenerReady: boolean,
): boolean {
  return !loginListenerReady || !poolListenerReady;
}

export function beginProviderLoginFlow(
  generation: number,
  providerId: ProviderId,
  requestedAccountId?: string,
  activeAccountIdAtStart?: string,
): ProviderLoginFlowState {
  return {
    generation,
    providerId,
    requestedAccountId,
    activeAccountIdAtStart,
    phase: "starting",
  };
}

export function applyProviderLoginEvent(
  state: ProviderLoginFlowState,
  event: ProviderAccountLoginEvent,
): ProviderLoginFlowState {
  if (state.providerId !== event.providerId || state.phase === "terminal") return state;
  if (state.sessionId && state.sessionId !== event.sessionId) return state;
  if (event.status === "waiting") {
    return { ...state, phase: "waiting", sessionId: event.sessionId };
  }
  return {
    ...state,
    phase: "terminal",
    sessionId: event.sessionId,
    terminalStatus: event.status,
  };
}

export function applyProviderLoginResponse(
  state: ProviderLoginFlowState,
  generation: number,
  _sessionId: string,
): ProviderLoginFlowState {
  if (state.generation !== generation || state.phase === "terminal") return state;
  // The waiting event is the authoritative session binding. A command response arriving late must
  // never recreate a flow that a terminal event has already completed.
  return state;
}

export function showsExternalProviderAccount<T>(identity: T | null | undefined): identity is T {
  return Boolean(identity);
}
