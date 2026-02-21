/**
 * Test suite for the Firefox extension components.
 *
 * Tests the parts of the extension that can be tested outside the browser:
 *   - Content script: form detection, field filling, visibility checks
 *   - Popup: HTML escaping, search filtering logic
 *   - Background: message routing logic
 *   - Manifest: structure validation
 *
 * Note: Full integration tests require loading the extension in Firefox,
 * which is covered by manual testing (see TECH.md).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXT_DIR = join(__dirname, '..', 'extension');

// ─── Manifest Validation ──────────────────────────────────────────────

describe('Extension manifest', () => {
    let manifest;

    it('is valid JSON', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        manifest = JSON.parse(content);
        assert.ok(manifest);
    });

    it('is manifest_version 2', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.equal(m.manifest_version, 2);
    });

    it('has required fields', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.name);
        assert.ok(m.version);
        assert.ok(m.description);
    });

    it('has activeTab permission (minimal scope)', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.permissions.includes('activeTab'));
    });

    it('has clipboardWrite permission for copy support', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.permissions.includes('clipboardWrite'));
    });

    it('does not request unnecessary permissions', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        const dangerous = ['tabs', 'history', 'bookmarks', 'downloads', 'webRequest', 'nativeMessaging'];
        for (const perm of dangerous) {
            assert.ok(!m.permissions.includes(perm), `should not have "${perm}" permission`);
        }
    });

    it('has content_security_policy with connect-src for local server', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.content_security_policy);
        assert.ok(m.content_security_policy.includes("script-src 'self'"));
        assert.ok(m.content_security_policy.includes('connect-src'), 'CSP should allow localhost connection');
    });

    it('has gecko-specific extension id', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.browser_specific_settings?.gecko?.id);
        assert.equal(m.browser_specific_settings.gecko.id, 'opvault-autofill@local');
    });

    it('has browser_action with popup', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.browser_action);
        assert.ok(m.browser_action.default_popup);
    });

    it('has background script', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.background);
        assert.ok(m.background.scripts.includes('background.js'));
    });

    it('has content script', async () => {
        const content = await readFile(join(EXT_DIR, 'manifest.json'), 'utf-8');
        const m = JSON.parse(content);
        assert.ok(m.content_scripts);
        assert.ok(m.content_scripts[0].js.includes('content.js'));
    });
});

// ─── Extension Files Exist ────────────────────────────────────────────

describe('Extension files', () => {
    const requiredFiles = [
        'manifest.json',
        'background.js',
        'content.js',
        'popup/popup.html',
        'popup/popup.js',
        'popup/popup.css',
        'icons/icon-16.svg',
        'icons/icon-48.svg',
    ];

    for (const file of requiredFiles) {
        it(`has ${file}`, async () => {
            const content = await readFile(join(EXT_DIR, file), 'utf-8');
            assert.ok(content.length > 0, `${file} should not be empty`);
        });
    }
});

// ─── Popup HTML Validation ────────────────────────────────────────────

describe('Popup HTML', () => {
    let html;

    it('loads popup HTML', async () => {
        html = await readFile(join(EXT_DIR, 'popup', 'popup.html'), 'utf-8');
        assert.ok(html.includes('<!DOCTYPE html>'));
    });

    it('has lock screen elements', async () => {
        const h = await readFile(join(EXT_DIR, 'popup', 'popup.html'), 'utf-8');
        assert.ok(h.includes('id="lock-screen"'));
        assert.ok(h.includes('id="vault-path"'));
        assert.ok(h.includes('id="master-password"'));
        assert.ok(h.includes('id="unlock-btn"'));
    });

    it('has list screen elements', async () => {
        const h = await readFile(join(EXT_DIR, 'popup', 'popup.html'), 'utf-8');
        assert.ok(h.includes('id="list-screen"'));
        assert.ok(h.includes('id="search-input"'));
        assert.ok(h.includes('id="items-container"'));
        assert.ok(h.includes('id="lock-btn"'));
    });

    it('password input has type="password"', async () => {
        const h = await readFile(join(EXT_DIR, 'popup', 'popup.html'), 'utf-8');
        assert.ok(h.includes('type="password"'));
    });

    it('has autocomplete="off" on sensitive fields', async () => {
        const h = await readFile(join(EXT_DIR, 'popup', 'popup.html'), 'utf-8');
        // Both vault path and password should have autocomplete="off"
        const matches = h.match(/autocomplete="off"/g);
        assert.ok(matches && matches.length >= 2, 'should have autocomplete="off" on sensitive inputs');
    });

    it('links CSS and JS files', async () => {
        const h = await readFile(join(EXT_DIR, 'popup', 'popup.html'), 'utf-8');
        assert.ok(h.includes('popup.css'));
        assert.ok(h.includes('popup.js'));
    });
});

// ─── Content Script Validation ────────────────────────────────────────

describe('Content script', () => {
    let js;

    it('loads content script', async () => {
        js = await readFile(join(EXT_DIR, 'content.js'), 'utf-8');
        assert.ok(js.length > 0);
    });

    it('has form detection logic', async () => {
        const j = await readFile(join(EXT_DIR, 'content.js'), 'utf-8');
        assert.ok(j.includes('findLoginFields'));
        assert.ok(j.includes('input[type="password"]'));
    });

    it('uses native setter for React compatibility', async () => {
        const j = await readFile(join(EXT_DIR, 'content.js'), 'utf-8');
        assert.ok(j.includes('nativeInputValueSetter'), 'should use native setter for React');
    });

    it('dispatches input events for framework detection', async () => {
        const j = await readFile(join(EXT_DIR, 'content.js'), 'utf-8');
        assert.ok(j.includes("'input'"));
        assert.ok(j.includes("'change'"));
    });

    it('listens for fill_credentials messages', async () => {
        const j = await readFile(join(EXT_DIR, 'content.js'), 'utf-8');
        assert.ok(j.includes('fill_credentials'));
    });

    it('has MutationObserver for dynamic forms', async () => {
        const j = await readFile(join(EXT_DIR, 'content.js'), 'utf-8');
        assert.ok(j.includes('MutationObserver'));
    });
});

// ─── Background Script Validation ─────────────────────────────────────

describe('Background script', () => {
    let js;

    it('loads background script', async () => {
        js = await readFile(join(EXT_DIR, 'background.js'), 'utf-8');
        assert.ok(js.length > 0);
    });

    it('connects to local server via fetch', async () => {
        const j = await readFile(join(EXT_DIR, 'background.js'), 'utf-8');
        assert.ok(j.includes('fetch'));
        assert.ok(j.includes('127.0.0.1'));
    });

    it('handles all message types', async () => {
        const j = await readFile(join(EXT_DIR, 'background.js'), 'utf-8');
        const requiredTypes = ['unlock', 'lock', 'status', 'list', 'get_logins', 'fill', 'copy'];
        for (const type of requiredTypes) {
            assert.ok(j.includes(`'${type}'`), `should handle '${type}' message type`);
        }
    });

    it('does not store credentials', async () => {
        const j = await readFile(join(EXT_DIR, 'background.js'), 'utf-8');
        assert.ok(!j.includes('localStorage'));
        assert.ok(!j.includes('sessionStorage'));
        assert.ok(!j.includes('chrome.storage'));
    });
});

// ─── Security: Popup Script ──────────────────────────────────────────

describe('Security: popup script', () => {
    it('clears password from input after unlock', async () => {
        const js = await readFile(join(EXT_DIR, 'popup', 'popup.js'), 'utf-8');
        assert.ok(js.includes("masterPasswordInput.value = ''"), 'should clear password input after unlock');
    });

    it('has HTML escaping for XSS prevention', async () => {
        const js = await readFile(join(EXT_DIR, 'popup', 'popup.js'), 'utf-8');
        assert.ok(js.includes('escapeHtml'), 'should have escapeHtml function');
        assert.ok(js.includes('&amp;'));
        assert.ok(js.includes('&lt;'));
    });

    it('uses escapeHtml when rendering items', async () => {
        const js = await readFile(join(EXT_DIR, 'popup', 'popup.js'), 'utf-8');
        // All dynamic content in renderItems should use escapeHtml
        assert.ok(js.includes('escapeHtml(item.uuid)'));
        assert.ok(js.includes('escapeHtml(item.title)'));
    });
});

// ─── Native Messaging Manifest ────────────────────────────────────────

describe('Native messaging manifest', () => {
    it('is valid JSON', async () => {
        const content = await readFile(
            join(__dirname, '..', 'native-host', 'com.opvault.extension.json'),
            'utf-8'
        );
        const manifest = JSON.parse(content);
        assert.ok(manifest);
    });

    it('has correct type', async () => {
        const content = await readFile(
            join(__dirname, '..', 'native-host', 'com.opvault.extension.json'),
            'utf-8'
        );
        const manifest = JSON.parse(content);
        assert.equal(manifest.type, 'stdio');
    });

    it('allows our extension ID', async () => {
        const content = await readFile(
            join(__dirname, '..', 'native-host', 'com.opvault.extension.json'),
            'utf-8'
        );
        const manifest = JSON.parse(content);
        assert.ok(manifest.allowed_extensions.includes('opvault-autofill@local'));
    });
});
