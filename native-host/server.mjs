#!/opt/homebrew/bin/node
/**
 * Local HTTP server for OPVault Firefox Extension
 *
 * Replaces the native messaging host with a simple HTTP server on localhost.
 * This avoids Firefox native messaging issues while maintaining the same
 * security model: all decryption happens in this separate process.
 *
 * Usage:
 *   node native-host/server.mjs
 *   # or: ./native-host/server.mjs
 *
 * The server listens on http://localhost:8737 and accepts JSON POST requests.
 */

import { createServer } from 'node:http';
import {
    unlockVault,
    loadBandItems,
    decryptItemOverview,
    decryptItemDetails,
    zeroBuffer,
    CATEGORY,
} from '../src/opvault.mjs';

// ─── Configuration ─────────────────────────────────────────────────────

const PORT = 8737;
const HOST = '127.0.0.1'; // Only localhost — never expose to network
const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes

// ─── CORS origin whitelist (only our extension & dev harness) ──────

function isAllowedOrigin(origin) {
    // Allow null origin (for local file testing)
    if (!origin || origin === 'null') return true;
    // Allow extension origins
    if (origin.startsWith('moz-extension://')) return true;
    if (origin.startsWith('chrome-extension://')) return true;
    // Allow local dev harness (e.g. http://localhost:3000)
    if (origin.startsWith('http://localhost:')) return true;
    if (origin.startsWith('http://127.0.0.1:')) return true;
    return false;
}

// ─── Vault Session (same as native host) ───────────────────────────────

class VaultSession {
    constructor() {
        this._masterKeys = null;
        this._overviewKeys = null;
        this._items = null;
        this._overviews = null;
        this._vaultPath = null;
        this._lockTimer = null;
    }

    get isUnlocked() { return this._masterKeys !== null; }
    get vaultPath() { return this._vaultPath; }
    get itemCount() { return this._items ? this._items.length : 0; }

    async unlock(vaultPath, masterPassword) {
        this.lock();
        const { masterKeys, overviewKeys } = await unlockVault(vaultPath, masterPassword);
        this._masterKeys = masterKeys;
        this._overviewKeys = overviewKeys;
        this._vaultPath = vaultPath;

        this._items = await loadBandItems(vaultPath);
        this._overviews = new Map();

        for (const item of this._items) {
            try {
                const overview = decryptItemOverview(
                    item,
                    this._overviewKeys.encKey,
                    this._overviewKeys.macKey
                );
                this._overviews.set(item.uuid, overview);
            } catch {
                this._overviews.set(item.uuid, {});
            }
        }
        this._resetLockTimer();
    }

    lock() {
        if (this._masterKeys) {
            zeroBuffer(this._masterKeys.encKey);
            zeroBuffer(this._masterKeys.macKey);
            this._masterKeys = null;
        }
        if (this._overviewKeys) {
            zeroBuffer(this._overviewKeys.encKey);
            zeroBuffer(this._overviewKeys.macKey);
            this._overviewKeys = null;
        }
        this._items = null;
        this._overviews = null;
        this._vaultPath = null;
        if (this._lockTimer) {
            clearTimeout(this._lockTimer);
            this._lockTimer = null;
        }
    }

    _resetLockTimer() {
        if (this._lockTimer) clearTimeout(this._lockTimer);
        this._lockTimer = setTimeout(() => this.lock(), AUTO_LOCK_MS);
    }

    findByUrl(url) {
        this._assertUnlocked();
        this._resetLockTimer();
        const results = [];
        for (const item of this._items) {
            const overview = this._overviews.get(item.uuid) || {};
            const itemUrl = overview.url || '';
            if (itemUrl && urlMatches(itemUrl, url)) {
                results.push({
                    uuid: item.uuid,
                    title: overview.title || '(untitled)',
                    username: overview.ainfo || '',
                    url: itemUrl,
                    categoryName: CATEGORY[item.category] || 'Unknown',
                });
            }
        }
        return results;
    }

    listAll() {
        this._assertUnlocked();
        this._resetLockTimer();
        return this._items.map(item => {
            const overview = this._overviews.get(item.uuid) || {};
            return {
                uuid: item.uuid,
                title: overview.title || '(untitled)',
                categoryName: CATEGORY[item.category] || 'Unknown',
                url: overview.url || '',
                username: overview.ainfo || '',
            };
        });
    }

    getCredentials(uuid) {
        this._assertUnlocked();
        this._resetLockTimer();
        const item = this._items.find(i => i.uuid === uuid);
        if (!item) throw new Error(`Item not found: ${uuid}`);

        const details = decryptItemDetails(
            item,
            this._masterKeys.encKey,
            this._masterKeys.macKey
        );
        const overview = this._overviews.get(uuid) || {};

        let username = overview.ainfo || '';
        let password = details.password || '';
        if (details.fields) {
            for (const field of details.fields) {
                if (field.designation === 'username' && field.value) username = field.value;
                if (field.designation === 'password' && field.value) password = field.value;
            }
        }
        return { username, password, title: overview.title || '' };
    }

    _assertUnlocked() {
        if (!this.isUnlocked) throw new Error('Vault is locked');
    }
}

// ─── URL Matching ──────────────────────────────────────────────────────

function urlMatches(itemUrl, requestUrl) {
    try {
        const item = normalizeUrl(itemUrl);
        const request = normalizeUrl(requestUrl);
        if (!item || !request) return false;
        return request.hostname === item.hostname ||
            request.hostname.endsWith('.' + item.hostname) ||
            item.hostname.endsWith('.' + request.hostname);
    } catch {
        return requestUrl.toLowerCase().includes(itemUrl.toLowerCase()) ||
            itemUrl.toLowerCase().includes(requestUrl.toLowerCase());
    }
}

function normalizeUrl(urlStr) {
    if (!urlStr) return null;
    try {
        if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
            urlStr = 'https://' + urlStr;
        }
        return new URL(urlStr);
    } catch {
        return null;
    }
}

// ─── Request Handler ───────────────────────────────────────────────────

const session = new VaultSession();

async function handleRequest(msg) {
    try {
        switch (msg.action) {
            case 'unlock': {
                if (!msg.vaultPath || !msg.password) {
                    return { ok: false, error: 'Missing vaultPath or password' };
                }
                await session.unlock(msg.vaultPath, msg.password);
                return { ok: true, itemCount: session.itemCount };
            }
            case 'lock': {
                session.lock();
                return { ok: true };
            }
            case 'status': {
                return {
                    ok: true,
                    locked: !session.isUnlocked,
                    itemCount: session.itemCount,
                    vaultPath: session.vaultPath || null,
                };
            }
            case 'get_logins': {
                if (!msg.url) return { ok: false, error: 'Missing url' };
                return { ok: true, items: session.findByUrl(msg.url) };
            }
            case 'fill': {
                if (!msg.uuid) return { ok: false, error: 'Missing uuid' };
                const creds = session.getCredentials(msg.uuid);
                return { ok: true, username: creds.username, password: creds.password };
            }
            case 'copy': {
                if (!msg.uuid) return { ok: false, error: 'Missing uuid' };
                const field = msg.field || 'password';
                if (!['username', 'password'].includes(field)) {
                    return { ok: false, error: `Invalid field: ${field}` };
                }
                const credentials = session.getCredentials(msg.uuid);
                return { ok: true, value: credentials[field] };
            }
            case 'list': {
                return { ok: true, items: session.listAll() };
            }
            default:
                return { ok: false, error: `Unknown action: ${msg.action}` };
        }
    } catch (err) {
        return { ok: false, error: err.message || 'Internal error' };
    }
}

// ─── HTTP Server ───────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
    const origin = req.headers.origin || '';

    // CORS preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': isAllowedOrigin(origin) ? origin : '',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '86400',
        });
        res.end();
        return;
    }

    // Only accept POST to /api
    if (req.method !== 'POST' || req.url !== '/api') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Not found' }));
        return;
    }

    // Check origin
    if (!isAllowedOrigin(origin)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Forbidden origin' }));
        return;
    }

    // Read body
    const chunks = [];
    for await (const chunk of req) {
        chunks.push(chunk);
    }
    const body = Buffer.concat(chunks).toString('utf-8');

    let msg;
    try {
        msg = JSON.parse(body);
    } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Invalid JSON' }));
        return;
    }

    const result = await handleRequest(msg);

    res.writeHead(200, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': isAllowedOrigin(origin) ? origin : '',
    });
    res.end(JSON.stringify(result));
});

// Handle graceful shutdown
process.on('SIGTERM', () => { session.lock(); server.close(); process.exit(0); });
process.on('SIGINT', () => { session.lock(); server.close(); process.exit(0); });

server.listen(PORT, HOST, () => {
    console.log(`🔐 OPVault server running at http://${HOST}:${PORT}`);
    console.log('   Press Ctrl+C to stop');
});
