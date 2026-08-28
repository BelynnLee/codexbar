import type { AccountView, ProviderAuthActionKind } from "./types";

export interface AuthActionViewState {
  connected: boolean;
  imported: boolean;
  disabled: boolean;
  status: "connected" | "disconnected" | "imported" | "notImported";
}

// Kept separate from DOM rendering so authentication state cannot accidentally depend on an
// unrelated secret field when more providers gain multiple source modes.
export function authActionViewState(
  action: ProviderAuthActionKind,
  supportsMultipleAccounts: boolean,
  account?: AccountView,
): AuthActionViewState {
  const isManagedImport = action === "cliImport" || action === "oauthConnect";
  const isCookieAction = action === "browserLogin" || action === "cookieImport";
  const hasSavedAccount = Boolean(account?.id.trim());
  const connected = isManagedImport
    ? false
    : isCookieAction
      ? account?.configuredSecrets.includes("cookieHeader") ?? false
      : account?.configuredSecrets.includes("apiKey") ?? false;
  const imported = isManagedImport && (account?.hasManagedCredential ?? false);
  return {
    connected,
    imported,
    disabled: !hasSavedAccount && (isManagedImport || (isCookieAction && supportsMultipleAccounts)),
    status: isManagedImport
      ? imported ? "imported" : "notImported"
      : connected ? "connected" : "disconnected",
  };
}
