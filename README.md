# 🔐 1Password OPVault Firefox Extension

A Firefox browser extension that reads passwords from 1Password `.opvault` vaults and auto-fills login forms.

All decryption happens in a **separate Node.js process** — your master password and vault keys never enter browser memory.

## Features

- 🔑 **Vault unlock** — PBKDF2 key derivation + AES-256-CBC decryption
- 🔍 **Search** — Find items by title, username, or URL
- ✏️ **Auto-fill** — Detect login forms and fill credentials (React/Angular/Vue compatible)
- 📋 **Clipboard** — Copy username or password with one click
- 🔒 **Auto-lock** — Keys zeroed from memory after 5 min idle
- 🛡️ **Minimal permissions** — Only `activeTab` + `clipboardWrite`

## Quick Start

### Prerequisites
- Node.js ≥ 18
- Firefox

### 1. Start the server
```bash
node native-host/server.mjs
# 🔐 OPVault server running at http://127.0.0.1:8737
```

### 2. Load the extension
1. Open `about:debugging#/runtime/this-firefox`
2. Click **"Load Temporary Add-on"**
3. Select `extension/manifest.json`

### 3. Use it
Click the extension icon → enter your vault path and master password → search, copy, or auto-fill.

## Architecture

```
Firefox Extension ──fetch──▶ Local HTTP Server (localhost:8737) ──decrypt──▶ .opvault files
   (popup + content script)       (Node.js, separate process)
```

The extension communicates with a local Node.js server via HTTP POST. The server handles all cryptographic operations, keeping keys isolated from the browser.

## Tests

```bash
# Run all 116 tests
node --test test/opvault.test.mjs test/host.test.mjs test/extension.test.mjs
```

| Suite | Tests | Coverage |
|-------|-------|----------|
| `opvault.test.mjs` | 30 | Crypto library (PBKDF2, HMAC, AES-CBC) |
| `host.test.mjs` | 45 | Server session, URL matching, security |
| `extension.test.mjs` | 41 | Manifest, permissions, XSS prevention |

## Security

- **Separate process** — Keys never in browser memory
- **Localhost only** — Server binds to `127.0.0.1`, CORS restricted to `moz-extension://`
- **Encrypt-then-MAC** — HMAC-SHA256 verified before any decryption
- **Key zeroing** — Sensitive material wiped from memory after use
- **No storage** — Nothing saved to browser localStorage/sessionStorage

## Project Structure

```
├── src/opvault.mjs              # Core decryption library
├── native-host/server.mjs       # Local HTTP server
├── extension/
│   ├── manifest.json            # MV2 manifest
│   ├── background.js            # Server communication
│   ├── content.js               # Form detection + auto-fill
│   └── popup/                   # Dark theme UI
├── test/                        # 116 tests
├── TECH.md                      # Technical architecture
└── CHANGELOG.md
```

## License

MIT
