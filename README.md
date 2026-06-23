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

3. **WebSocket Fallback Driver (`websocket-connection.js`)**
   * Remains as a legacy fallback client that communicates over local port `6258` (`ws://127.0.0.1:6258/1password`) in environments where Native Messaging is unavailable.

---

## Security Model & Risk Mitigation

Using this extension with **Native Messaging** significantly mitigates communication risks compared to the legacy loopback WebSocket protocol:

* **No Open Ports**: Unlike WebSockets, Native Messaging does not expose a local port (`6258`). Other apps, malicious local processes, or browser scripts cannot access the 1Password communications via network scanning.
* **OS-Level Isolation**: The operating system strictly handles process isolation and pipes, transmitting data entirely in-memory.
* **No Network Sniffing**: Loopback network traffic can sometimes be sniffed locally by unprivileged processes. Stdin/Stdout communication is immune to local packet capturing.
* **Extension ID Access Control**: Firefox verifies the Extension ID against a system-level JSON configuration file before allowing the connection to be established.

---

## Installation & Deployment Guide

Since standard Firefox Release channels enforce signature verification, the extension must be signed using your own credentials for private distribution.

### Step 1: Set Up Native Messaging Access

You must register the extension's Gecko ID with the local 1Password desktop helper app:

1. Open the Firefox Native Messaging Host file on your Mac:
   * **Path**: `~/Library/Application Support/Mozilla/NativeMessagingHosts/2bua8c4s2c.com.agilebits.1password.json`
2. Add the custom extension ID (`onepassword4-mv3-local@agilebits.com`) to the `allowed_extensions` list:
   ```json
   "allowed_extensions": [
     "onepassword4@agilebits.com",
     "onepassword4-mv3-local@agilebits.com"
   ]
   ```

### Step 2: Build & Package the Extension

Compress the source files into a standard `.xpi` (zip) file:
```bash
zip -r ../1password-classic-mv3.xpi * -x "*.DS_Store" "*web-ext-artifacts*"
```

### Step 3: Self-Sign via Mozilla AMO

To install it permanently on a standard build of Firefox, submit it as an **unlisted** add-on to get it signed:

1. Go to the [Mozilla Add-on Developer Hub Credentials Page](https://addons.mozilla.org/en-US/developers/addon/api/key/).
2. Generate your **JWT Issuer** and **JWT Secret**.
3. Sign the extension using `web-ext`:
   ```bash
   npx --yes web-ext sign --api-key="YOUR_JWT_ISSUER" --api-secret="YOUR_JWT_SECRET" --channel=unlisted
   ```
4. Download the signed `.xpi` file generated in the `web-ext-artifacts/` directory and drag-and-drop it into Firefox to install permanently.

---

## Troubleshooting & Important Fixes

This project includes key fixes targeting crashes and compatibility blockers on modern web engines:

* **Keyboard Event Simulation**: Replaced the obsolete, Firefox-specific `initKeyEvent` API inside [injected.min.js](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/injected.min.js) with standard `new KeyboardEvent` constructor calls to prevent filling scripts from crashing.
* **Focus & Tab Fallbacks**: Enhanced active window lookups inside [global.min.js](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/global.min.js) to resolve target tabs correctly even when system context menus or focus shifts away from browser windows.
* **Data Consent Manifest Property**: Added `data_collection_permissions` under `browser_specific_settings.gecko` in [manifest.json](file:///Users/drapeau/Documents/Developer/1password-7-mv3-source/manifest.json) declaring no data collection, satisfying current Mozilla Add-on Store validation requirements.
