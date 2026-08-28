import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../src/auth-action-state.ts", import.meta.url), "utf8");
const javascript = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;
const { authActionViewState } = await import(
  `data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`
);

const account = (overrides = {}) => ({
  id: "acc_saved",
  enabled: true,
  values: {},
  configuredSecrets: [],
  hasManagedCredential: false,
  ...overrides,
});

test("managed CLI and OAuth actions use only managed credential presence", () => {
  for (const action of ["cliImport", "oauthConnect"]) {
    assert.deepEqual(
      authActionViewState(action, true, account({ configuredSecrets: ["apiKey"] })),
      {
        connected: false,
        imported: false,
        disabled: false,
        status: "notImported",
      },
    );
    assert.equal(
      authActionViewState(action, true, account({ hasManagedCredential: true })).status,
      "imported",
    );
    assert.equal(authActionViewState(action, true, undefined).disabled, true);
  }
});

test("browser actions use only cookie presence and require a saved multi-account target", () => {
  for (const action of ["browserLogin", "cookieImport"]) {
    assert.deepEqual(
      authActionViewState(
        action,
        true,
        account({ configuredSecrets: ["apiKey"], hasManagedCredential: true }),
      ),
      {
        connected: false,
        imported: false,
        disabled: false,
        status: "disconnected",
      },
    );
    assert.equal(
      authActionViewState(action, true, account({ configuredSecrets: ["apiKey"] })).status,
      "disconnected",
    );
    assert.equal(
      authActionViewState(action, true, account({ configuredSecrets: ["cookieHeader"] })).status,
      "connected",
    );
    assert.equal(authActionViewState(action, true, undefined).disabled, true);
    assert.equal(authActionViewState(action, false, undefined).disabled, false);
  }
});
