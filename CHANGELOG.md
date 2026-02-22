# Changelog

All notable changes to this project will be documented in this file.

## 2026-02-21 — Phase 7: Touch ID / macOS Keychain Integration

### Added
- **`swift_enclave.swift`** — Minimal native Swift binary that displays the macOS Touch ID / passcode prompt via `LAContext` and prints `AUTH_SUCCESS` or `AUTH_CANCELLED` to stdout.
- **`build_swift_enclave.sh`** — Compiles and signs the Swift binary using an Apple Development certificate. Run once to set up Touch ID support.
- **Settings → Enable Touch ID** — After unlocking the vault, users can save their master password to the macOS Keychain. Storage uses Apple's `/usr/bin/security add-generic-password` (no entitlements required).
- **Lock screen → Unlock with Touch ID** button — Shown only when `dist/swift_enclave` is present. Triggers the native biometric prompt, then retrieves the password from Keychain via `/usr/bin/security find-generic-password`.
- **Settings button on unlocked list screen** — ⚙️ gear icon next to the Lock button so Settings are always reachable without locking first.
- **`test/sync.test.mjs`** — Architecture sync test ensuring `host.mjs` and `server.mjs` share identical `VaultSession` and request-handler logic.

### Architecture
The Touch ID flow is split into two independent processes to bypass macOS child-process Keychain session restrictions:
1. **Swift binary** (`dist/swift_enclave prompt <reason>`) — shows the native biometric dialog.
2. **`/usr/bin/security`** (Apple pre-authorized CLI) — stores and retrieves the password from the user's login Keychain.

This means no code-signing entitlements are needed beyond a basic Apple Development certificate, and the vault password is encrypted at rest in the system Keychain.

## 2026-02-21 — Phase 6: UI/UX Improvements

### Added
- **Configurable Settings**: New Settings UI (accessible from the lock screen and, now, the unlocked list screen) to configure the Vault Path and Auto-lock timeout. Persists non-sensitive data via `browser.storage.local`.
- **Item Details View**: Clicking an item navigates to a rich Details view — username, passwords with 👁️ visibility toggle, clickable URLs, raw notes, and individual copy-to-clipboard with temporary "Copied" toast.
- **Domain Highlighting**: Queries the active browser tab to surface matching items under a "Suggested" banner.
- **Hotkey Support**: `Cmd+Shift+L` (macOS) / `Ctrl+Shift+L` (Windows/Linux) via `_execute_browser_action` in `manifest.json`.

## 2026-02-21 — Architecture: Native Messaging → Local HTTP Server

### Changed
- **`native-host/server.mjs`** [NEW] — Local HTTP server on `localhost:8737`, replaces native messaging host
  - Same `VaultSession` logic, CORS restricted to `moz-extension://` origins, binds only to `127.0.0.1`
- **`extension/background.js`** — Switched from `connectNative` to `fetch('http://127.0.0.1:8737/api')`
- **`extension/manifest.json`** — Removed `nativeMessaging` permission, added CSP `connect-src http://127.0.0.1:8737`
- **`test/extension.test.mjs`** — Updated tests for new architecture (116 total tests, all passing)

### Why
Firefox native messaging silently refused to launch the host process on macOS — `connectNative` returned successfully but the host immediately disconnected with no error. Extensive debugging (shebang scripts, CJS wrappers, launch scripts with logging) confirmed Firefox never actually spawned the process. The local HTTP server approach maintains the same security model (separate process, keys never in browser memory) while being simpler and more reliable.

## 2026-02-21 — Phase 3: Firefox Extension

### Added
- `extension/manifest.json` — MV2 manifest with minimal permissions (`nativeMessaging`, `activeTab`, `clipboardWrite`)
- `extension/background.js` — Message routing between popup, content script, and native host
- `extension/content.js` — Login form detection + framework-compatible auto-fill (React/Angular/Vue)
- `extension/popup/` — Dark theme popup UI (lock/unlock screens, search, copy, fill, toast notifications)
- `extension/icons/` — SVG lock icons (16px, 48px)
- `test/extension.test.mjs` — 42 tests (manifest validation, permissions security, file structure, HTML/XSS safety)

### Security
- No dangerous permissions (`tabs`, `history`, etc.)
- HTML escaping prevents XSS in popup
- Password input cleared immediately after unlock
- Content Security Policy enforced
- No credentials stored in browser storage

## 2026-02-21 — Phase 2: Native Messaging Host

### Added
- `native-host/host.mjs` — Native messaging host process
  - `VaultSession` class with unlock/lock lifecycle
  - stdio protocol (length-prefixed JSON) per Firefox native messaging spec
  - Auto-lock timer (5 min idle timeout, keys zeroed)
  - URL matching for `get_logins` (domain + subdomain matching)
  - `copy` action for clipboard support
  - Graceful shutdown (SIGTERM/SIGINT/exit handlers)
- `native-host/com.opvault.extension.json` — Firefox native messaging manifest
- `test/host.test.mjs` — 45 tests (session lifecycle, URL matching, protocol, all actions, security)

## 2026-02-21 — Phase 1: OPVault Decryption Library

### Added
- `src/opvault.mjs` — Core opvault decryption library using Node.js `crypto` module
  - PBKDF2-HMAC-SHA512 key derivation
  - opdata01 envelope parsing with Encrypt-then-MAC (HMAC-SHA256 + AES-256-CBC)
  - Full key hierarchy: derived keys → master/overview keys → item keys → item details
  - High-level API: `getItems()`, `getLogins()`, `unlockVault()`
  - `zeroBuffer()` for secure key material cleanup
- `test/opvault.test.mjs` — 30 tests covering:
  - JS wrapper parsing, PBKDF2 key derivation, opdata01 validation
  - HMAC tamper rejection, wrong password rejection
  - Full vault unlock, item decryption, error handling
- `src/demo.mjs` — CLI demo to unlock vault and display decrypted items
- `TECH.md` — Technical architecture documentation
- `package.json` — Project configuration (ESM, Node.js >= 18)

### Security
- HMAC verified before decryption at every level (Encrypt-then-MAC)
- All key material zeroed after use via `zeroBuffer()`
- No secrets logged or written to disk
