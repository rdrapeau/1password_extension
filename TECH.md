# 1Password OPVault Firefox Extension — Technical Architecture

## Overview

A Firefox browser extension that reads passwords from 1Password `.opvault` vaults and auto-fills login forms. Uses a **local HTTP server** architecture where all cryptographic operations happen in a separate Node.js process — the master password and vault keys never enter browser memory.

## Project Structure

```
1password_extension/
├── src/
│   ├── opvault.mjs          # Core opvault decryption library
│   └── demo.mjs             # CLI demo script
├── test/
│   ├── opvault.test.mjs     # Decryption tests (30 tests)
│   ├── host.test.mjs        # Native host logic tests (45 tests)
│   ├── extension.test.mjs   # Extension static tests (41 tests)
│   └── sync.test.mjs        # Architecture sync tests (1 test)
├── native-host/
│   ├── server.mjs           # Local HTTP server (localhost:8737)
│   ├── host.mjs             # Native messaging host (length-prefixed stdio)
│   └── com.opvault.extension.json  # Native messaging manifest
├── extension/
│   ├── manifest.json        # MV2 manifest (minimal permissions)
│   ├── background.js        # Message routing via fetch to local server
│   ├── content.js           # Form detection + auto-fill
│   ├── icons/               # SVG extension icons
│   └── popup/
│       ├── popup.html       # All screens: lock, list, details, settings
│       ├── popup.css        # Dark theme UI
│       └── popup.js         # UI logic (search, fill, copy, settings, Touch ID)
├── swift_enclave.swift      # Native Swift binary source (Touch ID prompt)
├── build_swift_enclave.sh   # Compiles & signs swift_enclave
├── dist/
│   └── swift_enclave        # Compiled signed native binary (git-ignored)
├── Test Vault.opvault/      # Test vault (password: "test")
├── package.json
├── TECH.md                  # This file
└── CHANGELOG.md
```

## How to Run

### Prerequisites
- Node.js >= 18.0.0
- Firefox (for extension)
- Xcode Command Line Tools (for Touch ID support, macOS only)

### Run Tests
```bash
npm test
# 124 tests total
```

### Run Demo
```bash
node src/demo.mjs [vault_path] [password]
# Defaults: ./Test Vault.opvault, password "test"
```

### Run the Extension

1. **Start the local server:**
   ```bash
   node native-host/server.mjs
   # 🔐 OPVault server running at http://127.0.0.1:8737
   ```

2. **Load extension in Firefox:**
   - Open `about:debugging#/runtime/this-firefox`
   - Click "Load Temporary Add-on"
   - Select `extension/manifest.json`

3. **Use the extension:**
   - Click the extension icon in the toolbar
   - Enter vault path and master password
   - Search, copy, or auto-fill credentials

### Enable Touch ID (macOS)

1. **Build the native prompt binary** (one-time setup):
   ```bash
   ./build_swift_enclave.sh
   ```
   Requires an Apple Development certificate in Keychain (free via Xcode).

2. **Enable Touch ID in the extension:**
   - Unlock your vault, open **Settings**, click **Enable Touch ID**
   - Your master password is stored encrypted in the macOS Keychain

3. **Using Touch ID to unlock:**
   - On the lock screen, click **Unlock with Touch ID**
   - Authenticate with your fingerprint or device password

**Architecture:** The `swift_enclave` binary shows the native macOS biometric prompt and outputs `AUTH_SUCCESS` or `AUTH_CANCELLED` to stdout. The password is stored/retrieved via Apple's own `/usr/bin/security` CLI tool (no entitlements required). This two-step split cleanly bypasses macOS child-process Keychain session restrictions.

## OPVault Format

### Key Hierarchy
```
Master Password + Salt
        │
        ▼ (PBKDF2-HMAC-SHA512, 100k iterations)
  64-byte Derived Key
  ├── 32-byte Encryption Key
  └── 32-byte HMAC Key
        │
        ▼ (decrypt profile.masterKey / overviewKey via opdata01)
  Master Keys (for item details)
  Overview Keys (for item overviews/metadata)
        │
        ▼ (decrypt per-item keys from band files)
  Item Keys → Item Details (passwords, etc.)
```

### opdata01 Envelope
| Offset | Size | Content |
|--------|------|---------|
| 0 | 8 | Magic: `opdata01` |
| 8 | 8 | Plaintext length (LE uint64) |
| 16 | 16 | AES-CBC IV |
| 32 | N | Ciphertext (random padding + plaintext) |
| 32+N | 32 | HMAC-SHA256 over bytes [0..32+N) |

**Security**: HMAC is verified BEFORE decryption (Encrypt-then-MAC).

### Vault Files
- `profile.js`: Salt, iterations, encrypted master/overview keys
- `band_[0-F].js`: Encrypted items, keyed by UUID

## Security Architecture

- **Separate process**: All decryption in a local HTTP server (Node.js), keys never in browser memory
- **Localhost only**: Server binds to `127.0.0.1`, CORS restricted to `moz-extension://` origins
- **Encrypt-then-MAC**: HMAC-SHA256 verified before any AES decryption
- **Key zeroing**: `zeroBuffer()` wipes sensitive key material after use
- **Auto-lock**: Keys cleared from memory after configurable idle timeout (default 5 min)
- **Minimal permissions**: Extension only needs `activeTab` + `clipboardWrite`
- **Touch ID**: Biometric prompt via native Swift binary; password stored in macOS Keychain via `/usr/bin/security`

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1. OPVault Library | ✅ Done | Node.js decryption library, 30 tests |
| 2. Native Host | ✅ Done | Local HTTP server + native messaging, 45 tests |
| 3. Extension | ✅ Done | Firefox popup, auto-fill, clipboard, 41 tests |
| 4. Documentation | ✅ Done | TECH.md, CHANGELOG.md, end-to-end verified |
| 5. Architecture Migration | ✅ Done | Migrated to local HTTP server |
| 6. UI/UX Improvements | ✅ Done | Settings, item details, domain highlighting, hotkeys |
| 7. Touch ID (macOS) | ✅ Done | Swift CLI bridge + macOS Keychain via `security` CLI |
