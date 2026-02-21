/**
 * OPVault Decryption Library
 *
 * Implements the 1Password OPVault format specification for reading
 * encrypted vault data. Uses Node.js built-in crypto module only.
 *
 * Format reference:
 *   - Key derivation: PBKDF2-HMAC-SHA512 (iterations from profile)
 *   - Encryption: AES-256-CBC with Encrypt-then-MAC (HMAC-SHA256)
 *   - Data envelope: opdata01 (8-byte magic + 8-byte plaintext len + 16-byte IV + ciphertext + 32-byte HMAC)
 *   - Key hierarchy: master password → derived keys → masterKey/overviewKey → item data
 *
 * Security notes:
 *   - All crypto uses Node.js built-in `crypto` module (OpenSSL-backed)
 *   - HMAC is verified BEFORE decryption (Encrypt-then-MAC)
 *   - Derived keys should be zeroed when no longer needed (see zeroBuffer)
 */

import { createHmac, pbkdf2, createDecipheriv, createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, basename } from 'node:path';

// ─── Constants ──────────────────────────────────────────────────────────

const OPDATA01_MAGIC = Buffer.from('opdata01');
const OPDATA01_HEADER_LEN = 8 + 8 + 16; // magic(8) + plaintext_len(8) + IV(16)
const HMAC_LEN = 32;
const AES_KEY_LEN = 32;
const HMAC_KEY_LEN = 32;
const DERIVED_KEY_LEN = AES_KEY_LEN + HMAC_KEY_LEN; // 64 bytes

// OPVault item categories
const CATEGORY = Object.freeze({
    '001': 'Login',
    '002': 'Credit Card',
    '003': 'Secure Note',
    '004': 'Identity',
    '005': 'Password',
    '099': 'Tombstone',
    '100': 'Software License',
    '101': 'Bank Account',
    '102': 'Database',
    '103': 'Driver License',
    '104': 'Outdoor License',
    '105': 'Membership',
    '106': 'Passport',
    '107': 'Rewards',
    '108': 'SSN',
    '109': 'Router',
    '110': 'Server',
    '111': 'Email',
});

// ─── Utility ────────────────────────────────────────────────────────────

/**
 * Zero out a Buffer's memory to prevent secrets from lingering.
 * @param {Buffer} buf
 */
export function zeroBuffer(buf) {
    if (Buffer.isBuffer(buf)) {
        buf.fill(0);
    }
}

/**
 * Parse a .js file that wraps JSON in a function call.
 * profile.js: "var profile={...};"
 * band_X.js:  "ld({...});"
 * @param {string} content - raw file content
 * @returns {object}
 */
export function parseJsWrapper(content) {
    const trimmed = content.trim();

    // profile.js: var profile={...};
    if (trimmed.startsWith('var profile=')) {
        let json = trimmed.slice('var profile='.length);
        if (json.endsWith(';')) json = json.slice(0, -1);
        return JSON.parse(json);
    }

    // band_X.js: ld({...});
    if (trimmed.startsWith('ld(')) {
        let json = trimmed.slice('ld('.length);
        if (json.endsWith(');')) json = json.slice(0, -2);
        return JSON.parse(json);
    }

    throw new Error('Unknown JS wrapper format');
}

// ─── Key Derivation ────────────────────────────────────────────────────

/**
 * Derive encryption and HMAC keys from master password using PBKDF2.
 *
 * @param {string} masterPassword
 * @param {Buffer} salt - from profile.salt (base64-decoded)
 * @param {number} iterations - from profile.iterations
 * @returns {Promise<{encKey: Buffer, macKey: Buffer}>}
 */
export function deriveKeys(masterPassword, salt, iterations) {
    return new Promise((resolve, reject) => {
        pbkdf2(
            masterPassword,
            salt,
            iterations,
            DERIVED_KEY_LEN,
            'sha512',
            (err, derivedKey) => {
                if (err) return reject(err);
                const encKey = derivedKey.subarray(0, AES_KEY_LEN);
                const macKey = derivedKey.subarray(AES_KEY_LEN, DERIVED_KEY_LEN);
                resolve({ encKey, macKey });
            }
        );
    });
}

// ─── opdata01 Decryption ───────────────────────────────────────────────

/**
 * Verify HMAC-SHA256 and decrypt an opdata01 blob.
 *
 * Format:
 *   [0..8)    "opdata01" magic
 *   [8..16)   plaintext length (little-endian uint64)
 *   [16..32)  IV (16 bytes for AES-CBC)
 *   [32..N-32) ciphertext (AES-256-CBC, PKCS7 padded)
 *   [N-32..N) HMAC-SHA256 over bytes [0..N-32)
 *
 * Security: HMAC is checked BEFORE decryption (Encrypt-then-MAC).
 *
 * @param {Buffer} data - raw opdata01 bytes
 * @param {Buffer} encKey - 32-byte AES key
 * @param {Buffer} macKey - 32-byte HMAC key
 * @returns {Buffer} decrypted plaintext
 */
export function decryptOpdata(data, encKey, macKey) {
    if (!Buffer.isBuffer(data)) {
        throw new Error('opdata01: expected Buffer');
    }

    if (data.length < OPDATA01_HEADER_LEN + HMAC_LEN) {
        throw new Error(`opdata01: data too short (${data.length} bytes)`);
    }

    // 1. Verify magic bytes
    const magic = data.subarray(0, 8);
    if (!magic.equals(OPDATA01_MAGIC)) {
        throw new Error(`opdata01: invalid magic (got ${magic.toString('hex')})`);
    }

    // 2. Read plaintext length (little-endian uint64, but we only use 32 bits)
    const plaintextLen = data.readUInt32LE(8);
    // bytes 12-15 are the high 32 bits, should be 0 for reasonable sizes

    // 3. Extract components
    const iv = data.subarray(16, 32);
    const ciphertext = data.subarray(32, data.length - HMAC_LEN);
    const storedHmac = data.subarray(data.length - HMAC_LEN);

    // 4. Verify HMAC BEFORE decryption (Encrypt-then-MAC)
    const hmac = createHmac('sha256', macKey);
    hmac.update(data.subarray(0, data.length - HMAC_LEN));
    const computedHmac = hmac.digest();

    if (!computedHmac.equals(storedHmac)) {
        throw new Error('opdata01: HMAC verification failed — wrong password or corrupted data');
    }

    // 5. Decrypt AES-256-CBC
    //    opdata01 uses custom padding (random bytes prepended), NOT PKCS7.
    //    We must disable auto-padding to avoid "bad decrypt" errors.
    const decipher = createDecipheriv('aes-256-cbc', encKey, iv);
    decipher.setAutoPadding(false);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // 6. Strip padding — the plaintext is the LAST plaintextLen bytes
    //    (opdata01 prepends random padding to fill block alignment)
    if (plaintextLen > decrypted.length) {
        throw new Error(`opdata01: plaintext length ${plaintextLen} > decrypted length ${decrypted.length}`);
    }

    return decrypted.subarray(decrypted.length - plaintextLen);
}

// ─── Key Unwrapping ────────────────────────────────────────────────────

/**
 * Decrypt a key stored in opdata01 format (e.g. masterKey, overviewKey).
 * The decrypted result is hashed with SHA-512 to produce the final
 * 64-byte key (split into 32-byte enc + 32-byte mac).
 *
 * @param {string} base64Data - base64-encoded opdata01 blob
 * @param {Buffer} encKey - derived encryption key
 * @param {Buffer} macKey - derived HMAC key
 * @returns {{encKey: Buffer, macKey: Buffer}}
 */
export function decryptKeyData(base64Data, encKey, macKey) {
    const data = Buffer.from(base64Data, 'base64');
    const plaintext = decryptOpdata(data, encKey, macKey);

    // Hash the decrypted key material with SHA-512 → 64 bytes
    const hashed = createHash('sha512').update(plaintext).digest();

    return {
        encKey: hashed.subarray(0, AES_KEY_LEN),
        macKey: hashed.subarray(AES_KEY_LEN, DERIVED_KEY_LEN),
    };
}

// ─── Item Key Decryption ───────────────────────────────────────────────

/**
 * Decrypt an item's key (`k` field in band data).
 * Item keys are encrypted with the vault's master encryption key using AES-256-CBC.
 *
 * Format of item key data (base64-decoded):
 *   [0..16)   IV
 *   [16..N-32) ciphertext (the 64-byte item key, AES-CBC encrypted)
 *   [N-32..N)  HMAC-SHA256 over IV+ciphertext
 *
 * @param {string} base64Key - base64-encoded item key data
 * @param {Buffer} masterEncKey - vault master encryption key
 * @param {Buffer} masterMacKey - vault master HMAC key
 * @returns {{encKey: Buffer, macKey: Buffer}} - item-level keys
 */
export function decryptItemKey(base64Key, masterEncKey, masterMacKey) {
    const data = Buffer.from(base64Key, 'base64');

    if (data.length < 16 + 32) {
        throw new Error(`Item key data too short (${data.length} bytes)`);
    }

    const iv = data.subarray(0, 16);
    const ciphertext = data.subarray(16, data.length - HMAC_LEN);
    const storedHmac = data.subarray(data.length - HMAC_LEN);

    // Verify HMAC first
    const hmac = createHmac('sha256', masterMacKey);
    hmac.update(data.subarray(0, data.length - HMAC_LEN));
    const computedHmac = hmac.digest();

    if (!computedHmac.equals(storedHmac)) {
        throw new Error('Item key: HMAC verification failed');
    }

    // Decrypt
    const decipher = createDecipheriv('aes-256-cbc', masterEncKey, iv);
    decipher.setAutoPadding(false); // item keys are exactly 64 bytes, no PKCS7 padding
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return {
        encKey: decrypted.subarray(0, AES_KEY_LEN),
        macKey: decrypted.subarray(AES_KEY_LEN, DERIVED_KEY_LEN),
    };
}

// ─── Profile Parsing ───────────────────────────────────────────────────

/**
 * Parse profile.js from a vault directory.
 *
 * @param {string} vaultPath - path to the .opvault directory
 * @returns {Promise<object>} parsed profile data
 */
export async function parseProfile(vaultPath) {
    const profilePath = join(vaultPath, 'default', 'profile.js');
    const content = await readFile(profilePath, 'utf-8');
    const profile = parseJsWrapper(content);

    // Validate required fields
    const required = ['salt', 'iterations', 'masterKey', 'overviewKey'];
    for (const field of required) {
        if (!profile[field]) {
            throw new Error(`profile.js missing required field: ${field}`);
        }
    }

    return profile;
}

// ─── Vault Unlock ──────────────────────────────────────────────────────

/**
 * Unlock a vault: derive keys from master password, decrypt master and
 * overview keys.
 *
 * @param {string} vaultPath - path to the .opvault directory
 * @param {string} masterPassword - the vault master password
 * @returns {Promise<{profile: object, masterKeys: {encKey: Buffer, macKey: Buffer}, overviewKeys: {encKey: Buffer, macKey: Buffer}}>}
 */
export async function unlockVault(vaultPath, masterPassword) {
    const profile = await parseProfile(vaultPath);

    const salt = Buffer.from(profile.salt, 'base64');
    const iterations = profile.iterations;

    // Derive keys from master password
    const derivedKeys = await deriveKeys(masterPassword, salt, iterations);

    // Decrypt master key (used for item details)
    const masterKeys = decryptKeyData(profile.masterKey, derivedKeys.encKey, derivedKeys.macKey);

    // Decrypt overview key (used for item overviews)
    const overviewKeys = decryptKeyData(profile.overviewKey, derivedKeys.encKey, derivedKeys.macKey);

    // Zero derived keys — no longer needed
    zeroBuffer(derivedKeys.encKey);
    zeroBuffer(derivedKeys.macKey);

    return { profile, masterKeys, overviewKeys };
}

// ─── Band File Parsing ─────────────────────────────────────────────────

/**
 * Load all items from band_*.js files.
 *
 * @param {string} vaultPath
 * @returns {Promise<object[]>} array of raw item objects
 */
export async function loadBandItems(vaultPath) {
    const defaultDir = join(vaultPath, 'default');
    const files = await readdir(defaultDir);
    const bandFiles = files.filter(f => /^band_[0-9A-F]\.js$/i.test(f));

    const items = [];
    for (const file of bandFiles) {
        const content = await readFile(join(defaultDir, file), 'utf-8');
        const bandData = parseJsWrapper(content);
        for (const [uuid, item] of Object.entries(bandData)) {
            items.push({ ...item, uuid });
        }
    }

    return items;
}

/**
 * Decrypt an item's overview (title, URL, tags, etc.)
 *
 * @param {object} item - raw band item
 * @param {Buffer} overviewEncKey
 * @param {Buffer} overviewMacKey
 * @returns {object} parsed overview
 */
export function decryptItemOverview(item, overviewEncKey, overviewMacKey) {
    if (!item.o) return {};
    const data = Buffer.from(item.o, 'base64');
    const plaintext = decryptOpdata(data, overviewEncKey, overviewMacKey);
    return JSON.parse(plaintext.toString('utf-8'));
}

/**
 * Decrypt an item's details (password, notes, fields, etc.)
 *
 * @param {object} item - raw band item with `k` (item key) and `d` (encrypted details)
 * @param {Buffer} masterEncKey
 * @param {Buffer} masterMacKey
 * @returns {object} parsed details
 */
export function decryptItemDetails(item, masterEncKey, masterMacKey) {
    if (!item.d || !item.k) return {};

    // First decrypt the item-specific key
    const itemKeys = decryptItemKey(item.k, masterEncKey, masterMacKey);

    // Then decrypt the details using the item key
    const data = Buffer.from(item.d, 'base64');
    const plaintext = decryptOpdata(data, itemKeys.encKey, itemKeys.macKey);

    // Zero item keys
    zeroBuffer(itemKeys.encKey);
    zeroBuffer(itemKeys.macKey);

    return JSON.parse(plaintext.toString('utf-8'));
}

// ─── High-Level API ────────────────────────────────────────────────────

/**
 * Load all items from a vault, decrypting overviews and optionally details.
 *
 * @param {string} vaultPath
 * @param {string} masterPassword
 * @param {object} [options]
 * @param {boolean} [options.includeDetails=false] - whether to decrypt item details
 * @param {string[]} [options.categories] - filter by category codes (e.g. ['001'] for logins)
 * @returns {Promise<object[]>} array of decrypted items
 */
export async function getItems(vaultPath, masterPassword, options = {}) {
    const { includeDetails = false, categories } = options;

    const { masterKeys, overviewKeys } = await unlockVault(vaultPath, masterPassword);

    const rawItems = await loadBandItems(vaultPath);

    const items = [];
    for (const rawItem of rawItems) {
        // Filter by category if specified
        if (categories && !categories.includes(rawItem.category)) {
            continue;
        }

        const overview = decryptItemOverview(rawItem, overviewKeys.encKey, overviewKeys.macKey);

        const item = {
            uuid: rawItem.uuid,
            category: rawItem.category,
            categoryName: CATEGORY[rawItem.category] || 'Unknown',
            overview,
            created: rawItem.created,
            updated: rawItem.updated,
        };

        if (includeDetails) {
            item.details = decryptItemDetails(rawItem, masterKeys.encKey, masterKeys.macKey);
        }

        items.push(item);
    }

    // Zero vault keys when done
    zeroBuffer(masterKeys.encKey);
    zeroBuffer(masterKeys.macKey);
    zeroBuffer(overviewKeys.encKey);
    zeroBuffer(overviewKeys.macKey);

    return items;
}

/**
 * Get all login items from a vault.
 *
 * @param {string} vaultPath
 * @param {string} masterPassword
 * @returns {Promise<object[]>} array of login items with full details
 */
export async function getLogins(vaultPath, masterPassword) {
    return getItems(vaultPath, masterPassword, {
        includeDetails: true,
        categories: ['001'],
    });
}

export { CATEGORY };
