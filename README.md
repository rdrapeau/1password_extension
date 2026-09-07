# 1Password Classic Manifest V3 Extension

This repository contains a Manifest V3 (MV3) compatible port of the classic **1Password extension (v4.7.x)** designed to work with **1Password 6 Desktop App** on macOS and Windows.

As modern browsers deprecate Manifest V2 (MV2), this project provides a compatibility bridge that allows the classic extension to run securely and permanently under the new Manifest V3 specification.

---

## Architecture Overview

The extension bridge consists of the original minified source code combined with modern polyfills and communication drivers to bridge the gap between MV2 APIs and MV3 requirements.

```
+-----------------------------------------------------------+
|                  1Password Classic MV3                    |
|                                                                                                                       |
|  +---------------------+        +----------------------+  |
|  |  Content Scripts    |        |  Background Scripts  |  |
|  |  (injected.min.js)  |        |  (global.min.js)     |  |
|  +----------+----------+        +----------+-----------+  |
|             |                              |              |
|             v                              v              |
|  +---------------------+        +----------------------+  |
|  |  content-polyfill   |        |  browseraction-poly  |  |
|  |  Keyboard Simulation|        |  polyfill.js         |  |
|  +---------------------+        +----------+-----------+  |
|                                            |              |
+--------------------------------------------|--------------+
                                             |
                                  (Native Messaging Pipe)
                                             |
                                             v
                              +-----------------------------+
                              | 1Password Desktop 6 Helper  |
                              +-----------------------------+
```

### Key Components

1. **Compatibility Layer (`browseraction-polyfill.js` & `polyfill.js`)**
   * **API Mapping**: Maps deprecated MV2 calls (like `chrome.browserAction`) dynamically to the modern MV3 `chrome.action` equivalents.
   * **Event & Port Management**: Emulates active background channel states since MV3 service workers / event pages do not support persistent background persistence in the same way.
   * **Tab Targeting Fallbacks**: Patches active window/tab query interfaces so that commands are routed correctly even when browser popups steal UI focus.

2. **Native Messaging Driver**
   * Communicates with the desktop application through a local stdin/stdout pipe managed by the OS.
   * This is the primary and most secure channel as it does not expose any network ports or loopback listeners.

3. **Legacy WebSocket Client (`websocket-connection.js`)**
   * Legacy loopback driver connecting over local port `6258` (`ws://127.0.0.1:6258/1password`).
   * *Note*: 1Password 6.8.9+ Desktop Helper intentionally drops WebSocket connections initiated by Firefox clients (`"Stopping connection since no we no longer accept connections over websockets for this type of client."`). Native Messaging is therefore the only supported communication path on modern macOS.

---

## Security Model & Identity Constraints

### Extension ID Requirement: `onepassword4@agilebits.com`
The extension **must** use the official Gecko extension ID `onepassword4@agilebits.com` in [manifest.json](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/manifest.json). Custom extension IDs (such as `onepassword4-mv3-local@agilebits.com`) will fail due to a dual-constraint integrity check:

1. **Firefox Native Messaging Enforcement**: Firefox consults `~/Library/Application Support/Mozilla/NativeMessagingHosts/2bua8c4s2c.com.agilebits.1password.json` and verifies that the calling extension's Gecko ID is listed in `allowed_extensions`. If not present, Firefox blocks the connection with:
   `[CHROME:NM] Port <...> disconnected: No such native application 2bua8c4s2c.com.agilebits.1password`
2. **1Password Desktop Helper Integrity Verification**: When `OnePasswordNativeMessageHost` runs, the helper (`2BUA8C4S2C.com.agilebits.onepassword-osx-helper`) invokes `-[OP4NativeMessageJSONMaintainer isValidOnDiskForBrowser:]`. It parses the on-disk manifest at `~/Library/Application Support/Mozilla/NativeMessagingHosts/2bua8c4s2c.com.agilebits.1password.json` and compares it directly against its internal hardcoded template via `compareOnDiskJSON:generatedJSON:`.
   * The expected template strictly requires `allowed_extensions` to contain **only** `["onepassword4@agilebits.com"]`.
   * If any other ID is present in the file, verification fails, 1Password Helper triggers `showFailedVerificationAlert` (which crashes internally in 1Password 6 due to an unhandled `nil` string argument in its alert formatter), and immediately drops the connection (`No disconnect message`).

Because both Firefox and 1Password Helper must agree on the manifest, **the only valid ID is `onepassword4@agilebits.com`**, and the host manifest must remain in its clean, stock format.

---

## Installation & Deployment Guide

### Step 1: Verify the Native Messaging Host Configuration

Verify that the Firefox Native Messaging Host file on macOS is in its default state:
* **Path**: `~/Library/Application Support/Mozilla/NativeMessagingHosts/2bua8c4s2c.com.agilebits.1password.json`

Ensure it matches the default template:
```json
{
  "path" : "/Applications/1Password.app/Contents/Library/LoginItems/2BUA8C4S2C.com.agilebits.onepassword-osx-helper.app/Contents/MacOS/OnePasswordNativeMessageHost",
  "allowed_extensions" : [
    "onepassword4@agilebits.com"
  ],
  "name" : "2bua8c4s2c.com.agilebits.1password",
  "type" : "stdio",
  "description" : "1Password Extension"
}
```

To prevent 1Password or browser updates from accidentally altering permissions:
```bash
chmod 444 ~/Library/Application\ Support/Mozilla/NativeMessagingHosts/2bua8c4s2c.com.agilebits.1password.json
```

### Step 2: Load the Extension in Firefox

Because Mozilla AMO does not permit third-party developer accounts to sign extensions under the `@agilebits.com` domain, the extension cannot be signed via AMO with the required `onepassword4@agilebits.com` ID.

#### Option A: Temporary Loading (All Firefox Channels)
1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click **"Load Temporary Add-on..."**.
3. Select [manifest.json](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/manifest.json) in this repository directory.
4. The extension will load with ID `onepassword4@agilebits.com` and connect immediately to 1Password Desktop.

#### Option B: Permanent Installation (Firefox Developer Edition / Nightly / ESR)
1. Open `about:config` and set `xpinstall.signatures.required` to `false`.
2. Package the extension:
   ```bash
   zip -r 1password-classic-mv3.xpi * -x "*.DS_Store" "*.git*"
   ```
3. Drag and drop `1password-classic-mv3.xpi` into Firefox to install permanently.

---

## Troubleshooting & Important Fixes

* **Desktop Verification Failure (`No disconnect message`)**: Occurs if `2bua8c4s2c.com.agilebits.1password.json` contains any extension IDs other than `onepassword4@agilebits.com`. 1Password Helper's `isValidOnDiskForBrowser:` rejects modified manifests. Restore the file to the stock configuration shown above.
* **`No such native application` Error**: Occurs when the loaded extension ID is not in `allowed_extensions` in the native host JSON file. Ensure the extension is running with ID `onepassword4@agilebits.com`.
* **Keyboard Event Simulation**: Replaced the obsolete, Firefox-specific `initKeyEvent` API inside [injected.min.js](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/injected.min.js) with standard `new KeyboardEvent` constructor calls to prevent filling scripts from crashing.
* **Focus & Tab Fallbacks**: Enhanced active window lookups inside [global.min.js](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/global.min.js) to resolve target tabs correctly even when system context menus or focus shifts away from browser windows.
* **Data Consent Manifest Property**: Added `data_collection_permissions` under `browser_specific_settings.gecko` in [manifest.json](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/manifest.json) declaring no data collection, satisfying current Mozilla Add-on Store validation requirements.
