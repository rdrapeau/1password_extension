# Changelog

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
