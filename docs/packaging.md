---
summary: "Windows packaging and CI notes."
read_when:
  - Building the Windows app
  - Updating Windows CI or bundle configuration
---

# Packaging

## Local build

```powershell
npm ci
npm run build
.\node_modules\.bin\tauri.cmd build --bundles nsis
```

The local NSIS bundle is unsigned and is intended for development verification only.

## CI

The public workflow runs frontend checks, provider parity validation, Rust formatting, tests, Clippy,
and the TypeScript/Vite build on `windows-latest`. It does not publish installers or handle signing
credentials.

Official releases and automatic updates will be designed separately with a dedicated signing key.
