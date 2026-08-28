# Widget Snapshot JSON Schema v1

CodexBar can publish a reduced, read-only JSON snapshot for third-party desktop integrations. This
contract is an interchange file only. It is not a native Windows Widgets Board provider and does
not add MSIX widget packaging, a widget host, or any Windows Widget runtime integration.

## File location and updates

The default path is:

```text
%APPDATA%\CodexBar\snapshot.json
```

`widgetSnapshot.path` can override that location. Snapshot publishing is controlled separately by
`widgetSnapshot.enabled`, which defaults to `true`. A disabled publisher may leave no file or a
previous file, so consumers must use `generatedAt` when deciding whether a snapshot is fresh.

The file is UTF-8 JSON. CodexBar serializes a complete document to a same-directory temporary file
and atomically replaces `snapshot.json`. A reader therefore observes either the previous complete
document or the new complete document, never a partially written document. Readers should open the
path for each refresh instead of retaining an open handle across replacements.

CodexBar validates and serializes the complete replacement before calling the atomic file writer.
Validation or serialization failure leaves an existing `snapshot.json` unchanged.

## Version compatibility

Consumers must read `schemaVersion` before interpreting the rest of the document and must require
the integer value `1`. An unsupported or missing version is not v1 and must be rejected rather than
parsed using guessed field meanings. Any future incompatible field, type, or nullability change
requires a new schema version.

The CodexBar writer likewise accepts only `schemaVersion: 1`. It returns an unsupported-version
validation error without replacing the destination when passed a public or deserialized snapshot
with any other version.

Every v1 field listed below is emitted. Nullable values are represented by JSON `null`; they are not
omitted. JSON object member order is not semantically significant. Array order is defined where
noted below.

## Top-level object

| Field | JSON type | Nullable | Meaning |
| --- | --- | --- | --- |
| `schemaVersion` | integer | no | Exactly `1` for this contract. |
| `generatedAt` | string | no | UTC RFC 3339 timestamp for creation of the complete snapshot. |
| `providers` | array of provider entries | no | One entry per provider/account state. May be empty. |

`providers` is ordered first by CodexBar's declared provider order and then by `accountId` in
ascending string order. The v1 provider order is `claude`, `codex`, `cursor`, `opencode`,
`opencodezen`, `openrouter`, `deepseek`.

## Provider entry

| Field | JSON type | Nullable | Meaning |
| --- | --- | --- | --- |
| `provider` | string | no | One of the v1 provider identifiers listed above. |
| `accountId` | string | no | Stable account id. It can be an empty string for an implicit single account. |
| `accountLabel` | string | yes | User-visible label for this account, or `null`. |
| `status` | string | no | One of `ready`, `error`, `disabled`, or `loading`. |
| `windows` | array of window entries | no | Usage windows for this provider/account, in source order. |
| `balance` | number | yes | Structured balance for this same provider/account, or `null`. |
| `currency` | string | yes | Currency code associated with structured financial data, or `null`. |
| `serviceIndicator` | string | yes | Normalized service-status indicator when available, or `null`. |
| `warningKinds` | array of strings | no | Warning kind identifiers. Unknown future identifiers should be ignored. |
| `error` | string | yes | Shared-redactor-filtered diagnostic text, or `null`. |

Disabled, loading, and error entries remain visible in `providers`; without an owned ready
provider snapshot they have an empty `windows` array and `null` structured financial fields.
CodexBar copies usage and financial data only when the snapshot provider matches the entry's
provider, preventing data from crossing provider boundaries.

The public snapshot intentionally has no API key, cookie header, credential issue, raw credential
error, provider source payload, or encrypted credential field. Diagnostic errors pass through the
shared CodexBar redactor before serialization. Consumers must still treat `error` as untrusted
display text and escape it for their output context.

## Window entry

| Field | JSON type | Nullable | Meaning |
| --- | --- | --- | --- |
| `id` | string | no | Provider-scoped stable window identifier. |
| `title` | string | no | User-visible window title. |
| `usedPercent` | number | no | Usage percentage clamped to the inclusive range `0.0` through `100.0`. |
| `resetsAt` | string | yes | UTC RFC 3339 reset timestamp, or `null` when unknown. |

`usedPercent` is always a finite JSON number. If in-process provider data contains a non-finite
floating-point value, CodexBar normalizes `NaN` and negative infinity to `0.0`, and positive
infinity to `100.0`, before serialization.

Window ids are meaningful only within their provider/account entry. Consumers must not combine
windows, balances, labels, status, warnings, or errors across provider/account entries.

## Complete example

This example uses a fictitious account label and contains no credentials:

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-07-15T10:00:00Z",
  "providers": [
    {
      "provider": "openrouter",
      "accountId": "acc_work",
      "accountLabel": "Work",
      "status": "ready",
      "windows": [
        {
          "id": "weekly",
          "title": "Weekly",
          "usedPercent": 20.0,
          "resetsAt": "2026-07-22T10:00:00Z"
        }
      ],
      "balance": 12.5,
      "currency": "USD",
      "serviceIndicator": null,
      "warningKinds": [],
      "error": null
    }
  ]
}
```
