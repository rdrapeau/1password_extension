#!/opt/homebrew/bin/node
/**
 * Native Messaging Host for OPVault Firefox Extension
 *
 * This process runs outside the browser and handles all vault operations.
 * It communicates with the Firefox extension via stdin/stdout using the
 * native messaging protocol (length-prefixed JSON).
 *
 * Security model:
 *   - Master password received once, used for key derivation, then discarded
 *   - Decrypted vault keys held in memory only, never written to disk
 *   - Auto-lock: keys cleared after configurable idle timeout
 *   - Only sends credentials on explicit request (fill/copy)
 *   - No secrets in logs
 *
 * Protocol (stdin/stdout, length-prefixed JSON):
 *   → { action: "unlock", vaultPath: "...", password: "..." }
 *   ← { ok: true, itemCount: N }
 *
 *   → { action: "lock" }
 *   ← { ok: true }
 *
 *   → { action: "status" }
 *   ← { ok: true, locked: bool, itemCount: N, vaultPath: "..." }
 *
 *   → { action: "get_logins", url: "https://..." }
 *   ← { ok: true, items: [{ uuid, title, username }] }
 *
 *   → { action: "fill", uuid: "..." }
 *   ← { ok: true, username: "...", password: "..." }
 *
 *   → { action: "copy", uuid: "...", field: "password"|"username" }
 *   ← { ok: true, value: "..." }
 *
 *   → { action: "list" }
 *   ← { ok: true, items: [{ uuid, title, categoryName, url, username }] }
 *
 * All errors: ← { ok: false, error: "message" }
 */

import {
    unlockVault,
    loadBandItems,
    decryptItemOverview,
    decryptItemDetails,
    zeroBuffer,
    CATEGORY,
} from '../src/opvault.mjs';

// ─── Configuration ─────────────────────────────────────────────────────

const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes default

// ─── Vault State ───────────────────────────────────────────────────────

/**
 * VaultSession holds decrypted key material in memory.
 * All sensitive data is cleared on lock.
 */
class VaultSession {
    constructor() {
        this._masterKeys = null;
        this._overviewKeys = null;
        this._items = null;       // raw band items
        this._overviews = null;   // Map<uuid, decrypted overview>
        this._vaultPath = null;
        this._lockTimer = null;
    }

    get isUnlocked() {
        return this._masterKeys !== null;
    }

    get vaultPath() {
        return this._vaultPath;
    }

    get itemCount() {
        return this._items ? this._items.length : 0;
    }

    /**
     * Unlock vault: derive keys, decrypt master/overview keys, load items.
     */
    async unlock(vaultPath, masterPassword) {
        // Lock any existing session first
        this.lock();

        const { masterKeys, overviewKeys } = await unlockVault(vaultPath, masterPassword);
        this._masterKeys = masterKeys;
        this._overviewKeys = overviewKeys;
        this._vaultPath = vaultPath;

        // Load and decrypt all item overviews (lightweight metadata)
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
                // Skip items that fail to decrypt (e.g. tombstones)
                this._overviews.set(item.uuid, {});
            }
        }

        // Start auto-lock timer
        this._resetLockTimer();
    }

    /**
     * Lock vault: zero all key material and clear items from memory.
     */
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

    /**
     * Reset the auto-lock idle timer.
     */
    _resetLockTimer() {
        if (this._lockTimer) {
            clearTimeout(this._lockTimer);
        }
        this._lockTimer = setTimeout(() => {
            this.lock();
        }, AUTO_LOCK_MS);
        // Don't let the timer keep the process alive
        if (this._lockTimer.unref) {
            this._lockTimer.unref();
        }
    }

    /**
     * Find items matching a URL.
     * Returns lightweight overview data (no passwords).
     */
    findByUrl(url) {
        this._assertUnlocked();
        this._resetLockTimer();

        const results = [];
        for (const item of this._items) {
            const overview = this._overviews.get(item.uuid) || {};
            const categoryName = CATEGORY[item.category] || 'Unknown';

            // Match by URL in overview
            const itemUrl = overview.url || '';
            if (itemUrl && urlMatches(itemUrl, url)) {
                results.push({
                    uuid: item.uuid,
                    title: overview.title || '(untitled)',
                    username: overview.ainfo || '',
                    url: itemUrl,
                    categoryName,
                });
            }
        }

        return results;
    }

    /**
     * List all items (overview only, no passwords).
     */
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

    /**
     * Get full credentials for a specific item (on-demand only).
     */
    getCredentials(uuid) {
        this._assertUnlocked();
        this._resetLockTimer();

        const item = this._items.find(i => i.uuid === uuid);
        if (!item) {
            throw new Error(`Item not found: ${uuid}`);
        }

        const details = decryptItemDetails(
            item,
            this._masterKeys.encKey,
            this._masterKeys.macKey
        );

        const overview = this._overviews.get(uuid) || {};

        // Extract username/password from fields
        let username = overview.ainfo || '';
        let password = details.password || '';

        if (details.fields) {
            for (const field of details.fields) {
                if (field.designation === 'username' && field.value) {
                    username = field.value;
                }
                if (field.designation === 'password' && field.value) {
                    password = field.value;
                }
            }
        }

        return { username, password, title: overview.title || '' };
    }

    _assertUnlocked() {
        if (!this.isUnlocked) {
            throw new Error('Vault is locked');
        }
    }
}

// ─── URL Matching ──────────────────────────────────────────────────────

/**
 * Check if an item URL matches the requested URL.
 * Uses domain-level matching for flexibility.
 */
function urlMatches(itemUrl, requestUrl) {
    try {
        const item = normalizeUrl(itemUrl);
        const request = normalizeUrl(requestUrl);
        if (!item || !request) return false;

        // Exact hostname match or subdomain match
        return request.hostname === item.hostname ||
            request.hostname.endsWith('.' + item.hostname) ||
            item.hostname.endsWith('.' + request.hostname);
    } catch {
        // Fallback: simple string containment
        return requestUrl.toLowerCase().includes(itemUrl.toLowerCase()) ||
            itemUrl.toLowerCase().includes(requestUrl.toLowerCase());
    }
}

/**
 * Normalize a URL string to a URL object, handling missing protocols.
 */
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

// ─── Native Messaging Protocol ────────────────────────────────────────

/**
 * Read exactly `n` bytes from a readable stream.
 * Returns a Buffer of length `n`, or null on EOF.
 */
function readExact(stream, n) {
    return new Promise((resolve) => {
        const tryRead = () => {
            const data = stream.read(n);
            if (data !== null) {
                resolve(data);
                return;
            }
            // Not enough data — wait for more
            const onReadable = () => {
                cleanup();
                tryRead();
            };
            const onEnd = () => {
                cleanup();
                resolve(null);
            };
            const onError = () => {
                cleanup();
                resolve(null);
            };
            const cleanup = () => {
                stream.removeListener('readable', onReadable);
                stream.removeListener('end', onEnd);
                stream.removeListener('error', onError);
            };
            stream.once('readable', onReadable);
            stream.once('end', onEnd);
            stream.once('error', onError);
        };
        tryRead();
    });
}

/**
 * Read a native messaging message from stdin.
 * Format: 4-byte little-endian length prefix + JSON payload.
 * Returns null on EOF.
 */
async function readMessage(stream) {
    const header = await readExact(stream, 4);
    if (header === null) return null;

    const len = header.readUInt32LE(0);
    if (len === 0) return {};
    if (len > 1024 * 1024) throw new Error(`Message too large: ${len} bytes`);

    const payload = await readExact(stream, len);
    if (payload === null) return null;

    return JSON.parse(payload.toString('utf-8'));
}

/**
 * Write a native messaging message to stdout.
 * Format: 4-byte little-endian length prefix + JSON payload.
 */
function writeMessage(stream, obj) {
    const json = JSON.stringify(obj);
    const payload = Buffer.from(json, 'utf-8');
    const header = Buffer.alloc(4);
    header.writeUInt32LE(payload.length, 0);
    stream.write(header);
    stream.write(payload);
}

// ─── Message Handler ──────────────────────────────────────────────────

const session = new VaultSession();

/**
 * Handle a single incoming message and return the response.
 */
async function handleMessage(msg) {
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
                if (!msg.url) {
                    return { ok: false, error: 'Missing url' };
                }
                const items = session.findByUrl(msg.url);
                return { ok: true, items };
            }

            case 'fill': {
                if (!msg.uuid) {
                    return { ok: false, error: 'Missing uuid' };
                }
                const creds = session.getCredentials(msg.uuid);
                return { ok: true, username: creds.username, password: creds.password };
            }

            case 'copy': {
                if (!msg.uuid) {
                    return { ok: false, error: 'Missing uuid' };
                }
                const field = msg.field || 'password';
                if (!['username', 'password'].includes(field)) {
                    return { ok: false, error: `Invalid field: ${field}` };
                }
                const credentials = session.getCredentials(msg.uuid);
                return { ok: true, value: credentials[field] };
            }

            case 'list': {
                const allItems = session.listAll();
                return { ok: true, items: allItems };
            }

            default:
                return { ok: false, error: `Unknown action: ${msg.action}` };
        }
    } catch (err) {
        // Never leak internal error details — redact stack traces
        const safeMessage = err.message || 'Internal error';
        return { ok: false, error: safeMessage };
    }
}

// ─── Main Loop ─────────────────────────────────────────────────────────

/**
 * Start the native messaging host.
 * Reads length-prefixed JSON from stdin, processes, writes to stdout.
 */
async function main() {
    const stdin = process.stdin;
    const stdout = process.stdout;

    while (true) {
        const msg = await readMessage(stdin);
        if (msg === null) break; // EOF — Firefox closed the connection

        const response = await handleMessage(msg);
        writeMessage(stdout, response);
    }

    // Clean up on exit
    session.lock();
}

// Handle graceful shutdown
process.on('SIGTERM', () => { session.lock(); process.exit(0); });
process.on('SIGINT', () => { session.lock(); process.exit(0); });
process.on('exit', () => { session.lock(); });

// Export for testing
export { VaultSession, urlMatches, normalizeUrl, readMessage, writeMessage, handleMessage, session };

// Run main loop if this is the entry point
if (process.argv[1] && process.argv[1].includes('host.mjs')) {
    main().catch(() => {
        process.exit(1);
    });
}
