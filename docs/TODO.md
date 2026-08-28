---
summary: "Completed maintenance items for CodexBar."
read_when:
  - Reviewing completed parser maintenance
---

## Completed

- 2026-08-13: removed the retired Claude Opus tertiary-limit fallback from the Windows web and
  CLI usage parsers. The provider now reports the standard session, weekly, Sonnet, and explicitly
  scoped additional limits only. Historical Opus model pricing remains intentionally available for
  local cost-log calculation.
