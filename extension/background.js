/**
 * Background script — mediates between popup, content script, and local server.
 *
 * Communicates with the OPVault server running on localhost:8737 via fetch.
 * All vault operations go through the server; no sensitive data stored here.
 */

/* global browser */

const SERVER_URL = 'http://127.0.0.1:8737/api';
let isUnlocked = false;

// ─── Server Communication ──────────────────────────────────────────────

async function sendToServer(message) {
    try {
        const response = await fetch(SERVER_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(message),
        });
        return await response.json();
    } catch (err) {
        return {
            ok: false,
            error: 'Cannot connect to OPVault server. Make sure it is running:\n  node native-host/server.mjs',
        };
    }
}

// ─── Badge ─────────────────────────────────────────────────────────────

function updateBadge() {
    const text = isUnlocked ? '🔓' : '';
    const color = isUnlocked ? '#2ecc71' : '#95a5a6';
    browser.browserAction.setBadgeText({ text });
    browser.browserAction.setBadgeBackgroundColor({ color });
}

// ─── Message Handling ──────────────────────────────────────────────────

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleRuntimeMessage(message, sender).then(sendResponse);
    return true;
});

async function handleRuntimeMessage(message, sender) {
    switch (message.type) {
        case 'unlock': {
            const response = await sendToServer({
                action: 'unlock',
                vaultPath: message.vaultPath,
                password: message.password,
                autoLockMs: message.autoLockMs,
            });
            if (response.ok) {
                isUnlocked = true;
                updateBadge();
            }
            return response;
        }

        case 'lock': {
            const response = await sendToServer({ action: 'lock' });
            isUnlocked = false;
            updateBadge();
            return response;
        }

        case 'status': {
            const response = await sendToServer({ action: 'status' });
            if (response.ok) {
                isUnlocked = !response.locked;
                updateBadge();
            }
            return response;
        }

        case 'list': {
            return sendToServer({ action: 'list' });
        }

        case 'enable_biometrics': {
            return sendToServer({
                action: 'enable_biometrics',
                vaultPath: message.vaultPath,
                password: message.password,
            });
        }

        case 'biometric_unlock': {
            const resp = await sendToServer({
                action: 'biometric_unlock',
                vaultPath: message.vaultPath,
                autoLockMs: message.autoLockMs,
            });
            updateBadge();
            return resp;
        }

        case 'get_item': {
            return sendToServer({ action: 'get_item', uuid: message.uuid });
        }

        case 'get_logins': {
            return sendToServer({ action: 'get_logins', url: message.url });
        }

        case 'fill': {
            const creds = await sendToServer({ action: 'fill', uuid: message.uuid });
            if (!creds.ok) return creds;

            const tabs = await browser.tabs.query({ active: true, currentWindow: true });
            if (tabs.length === 0) {
                return { ok: false, error: 'No active tab' };
            }

            try {
                await browser.tabs.sendMessage(tabs[0].id, {
                    type: 'fill_credentials',
                    username: creds.username,
                    password: creds.password,
                });
                return { ok: true };
            } catch (err) {
                return { ok: false, error: 'Could not fill: ' + (err.message || 'content script not loaded') };
            }
        }

        case 'copy': {
            return sendToServer({
                action: 'copy',
                uuid: message.uuid,
                field: message.field,
            });
        }

        default:
            return { ok: false, error: `Unknown message type: ${message.type}` };
    }
}

// Initialize
updateBadge();
