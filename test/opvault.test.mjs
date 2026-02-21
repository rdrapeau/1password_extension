/**
 * Extensive test suite for the OPVault decryption library.
 *
 * Tests cover:
 *   - JS wrapper parsing (profile.js, band_*.js formats)
 *   - PBKDF2 key derivation (correct output length, determinism)
 *   - opdata01 structure validation (magic bytes, HMAC verification)
 *   - Security: HMAC rejects tampered data
 *   - Security: wrong password fails with clear error
 *   - Full vault unlock with real test vault
 *   - Item listing and detail decryption
 *   - Key zeroing after use
 *   - Error handling for missing/corrupt files
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    parseJsWrapper,
    deriveKeys,
    decryptOpdata,
    decryptKeyData,
    decryptItemKey,
    decryptItemOverview,
    decryptItemDetails,
    parseProfile,
    unlockVault,
    loadBandItems,
    getItems,
    getLogins,
    zeroBuffer,
    CATEGORY,
} from '../src/opvault.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VAULT_PATH = join(__dirname, '..', 'Test Vault.opvault');
const MASTER_PASSWORD = 'test';

// ─── parseJsWrapper ────────────────────────────────────────────────────

describe('parseJsWrapper', () => {
    it('parses profile.js format (var profile={...};)', () => {
        const input = 'var profile={"uuid":"ABC","iterations":100000};';
        const result = parseJsWrapper(input);
        assert.equal(result.uuid, 'ABC');
        assert.equal(result.iterations, 100000);
    });

    it('parses band_X.js format (ld({...});)', () => {
        const input = 'ld({"ABC123":{"uuid":"ABC123","category":"001"}});';
        const result = parseJsWrapper(input);
        assert.ok(result.ABC123);
        assert.equal(result.ABC123.category, '001');
    });

    it('throws on unknown format', () => {
        assert.throws(() => parseJsWrapper('unknown format'), /Unknown JS wrapper format/);
    });

    it('handles whitespace around content', () => {
        const input = '  var profile={"uuid":"ABC"};  ';
        const result = parseJsWrapper(input);
        assert.equal(result.uuid, 'ABC');
    });
});

// ─── Key Derivation ────────────────────────────────────────────────────

describe('deriveKeys (PBKDF2)', () => {
    it('produces 32-byte encryption key and 32-byte HMAC key', async () => {
        const salt = Buffer.from('bZ2lp8HaUjEJJ2/SPhsX0A==', 'base64');
        const result = await deriveKeys('test', salt, 100000);
        assert.equal(result.encKey.length, 32, 'encryption key should be 32 bytes');
        assert.equal(result.macKey.length, 32, 'HMAC key should be 32 bytes');
    });

    it('is deterministic (same inputs → same output)', async () => {
        const salt = Buffer.from('bZ2lp8HaUjEJJ2/SPhsX0A==', 'base64');
        const r1 = await deriveKeys('test', salt, 100000);
        const r2 = await deriveKeys('test', salt, 100000);
        assert.ok(r1.encKey.equals(r2.encKey), 'encryption keys should match');
        assert.ok(r1.macKey.equals(r2.macKey), 'HMAC keys should match');
    });

    it('different passwords produce different keys', async () => {
        const salt = Buffer.from('bZ2lp8HaUjEJJ2/SPhsX0A==', 'base64');
        const r1 = await deriveKeys('test', salt, 100000);
        const r2 = await deriveKeys('wrong', salt, 100000);
        assert.ok(!r1.encKey.equals(r2.encKey), 'different passwords should produce different keys');
    });

    it('different salts produce different keys', async () => {
        const salt1 = Buffer.alloc(16, 1);
        const salt2 = Buffer.alloc(16, 2);
        const r1 = await deriveKeys('test', salt1, 1000);
        const r2 = await deriveKeys('test', salt2, 1000);
        assert.ok(!r1.encKey.equals(r2.encKey));
    });
});

// ─── opdata01 Decryption ───────────────────────────────────────────────

describe('decryptOpdata', () => {
    it('rejects non-Buffer input', () => {
        assert.throws(
            () => decryptOpdata('not a buffer', Buffer.alloc(32), Buffer.alloc(32)),
            /expected Buffer/
        );
    });

    it('rejects data that is too short', () => {
        assert.throws(
            () => decryptOpdata(Buffer.alloc(10), Buffer.alloc(32), Buffer.alloc(32)),
            /data too short/
        );
    });

    it('rejects data with wrong magic bytes', () => {
        const data = Buffer.alloc(100);
        data.write('NOTMAGIC', 0);
        assert.throws(
            () => decryptOpdata(data, Buffer.alloc(32), Buffer.alloc(32)),
            /invalid magic/
        );
    });

    it('rejects data with invalid HMAC (tampered data)', () => {
        // Create a buffer that has correct magic but bad HMAC
        const data = Buffer.alloc(100);
        Buffer.from('opdata01').copy(data, 0);
        // Everything else is zeros — HMAC will not match
        assert.throws(
            () => decryptOpdata(data, Buffer.alloc(32), Buffer.alloc(32)),
            /HMAC verification failed/
        );
    });
});

// ─── Security Tests ────────────────────────────────────────────────────

describe('Security: HMAC verification', () => {
    let profile;

    before(async () => {
        profile = await parseProfile(VAULT_PATH);
    });

    it('rejects decryption with wrong password', async () => {
        const salt = Buffer.from(profile.salt, 'base64');
        const wrongKeys = await deriveKeys('WRONG_PASSWORD', salt, profile.iterations);

        assert.throws(
            () => decryptKeyData(profile.masterKey, wrongKeys.encKey, wrongKeys.macKey),
            /HMAC verification failed/,
            'wrong password should fail HMAC check before any decryption'
        );
    });

    it('rejects tampered masterKey data', async () => {
        const salt = Buffer.from(profile.salt, 'base64');
        const keys = await deriveKeys(MASTER_PASSWORD, salt, profile.iterations);

        // Tamper with the masterKey data
        const tamperedData = Buffer.from(profile.masterKey, 'base64');
        tamperedData[40] ^= 0xff; // Flip a byte in the middle
        const tamperedBase64 = tamperedData.toString('base64');

        assert.throws(
            () => decryptKeyData(tamperedBase64, keys.encKey, keys.macKey),
            /HMAC verification failed/,
            'tampered data should fail HMAC check'
        );
    });
});

describe('Security: zeroBuffer', () => {
    it('zeros out buffer contents', () => {
        const buf = Buffer.from([1, 2, 3, 4, 5]);
        zeroBuffer(buf);
        assert.ok(buf.every(b => b === 0), 'all bytes should be zero');
    });

    it('handles non-Buffer gracefully', () => {
        assert.doesNotThrow(() => zeroBuffer(null));
        assert.doesNotThrow(() => zeroBuffer(undefined));
        assert.doesNotThrow(() => zeroBuffer('string'));
    });
});

// ─── Profile Parsing ───────────────────────────────────────────────────

describe('parseProfile', () => {
    it('parses the test vault profile', async () => {
        const profile = await parseProfile(VAULT_PATH);

        assert.ok(profile.uuid, 'should have uuid');
        assert.ok(profile.salt, 'should have salt');
        assert.equal(profile.iterations, 100000, 'should have 100000 iterations');
        assert.ok(profile.masterKey, 'should have masterKey');
        assert.ok(profile.overviewKey, 'should have overviewKey');
        assert.equal(profile.profileName, 'Test Vault');
    });

    it('rejects non-existent vault path', async () => {
        await assert.rejects(
            () => parseProfile('/nonexistent/vault.opvault'),
            { code: 'ENOENT' }
        );
    });
});

// ─── Full Vault Unlock ─────────────────────────────────────────────────

describe('unlockVault', () => {
    it('successfully unlocks with correct password', async () => {
        const result = await unlockVault(VAULT_PATH, MASTER_PASSWORD);

        assert.ok(result.profile, 'should return profile');
        assert.ok(result.masterKeys, 'should return masterKeys');
        assert.ok(result.masterKeys.encKey, 'should have master encryption key');
        assert.ok(result.masterKeys.macKey, 'should have master HMAC key');
        assert.equal(result.masterKeys.encKey.length, 32);
        assert.equal(result.masterKeys.macKey.length, 32);

        assert.ok(result.overviewKeys, 'should return overviewKeys');
        assert.ok(result.overviewKeys.encKey, 'should have overview encryption key');
        assert.ok(result.overviewKeys.macKey, 'should have overview HMAC key');
        assert.equal(result.overviewKeys.encKey.length, 32);
        assert.equal(result.overviewKeys.macKey.length, 32);
    });

    it('fails with wrong password', async () => {
        await assert.rejects(
            () => unlockVault(VAULT_PATH, 'WRONG_PASSWORD'),
            /HMAC verification failed/
        );
    });
});

// ─── Band Items ────────────────────────────────────────────────────────

describe('loadBandItems', () => {
    it('loads items from band files', async () => {
        const items = await loadBandItems(VAULT_PATH);
        assert.ok(items.length > 0, 'should find at least one item');
        assert.ok(items[0].uuid, 'items should have uuid');
        assert.ok(items[0].category, 'items should have category');
    });
});

// ─── Item Decryption ───────────────────────────────────────────────────

describe('Item decryption', () => {
    let masterKeys, overviewKeys, rawItems;

    before(async () => {
        const result = await unlockVault(VAULT_PATH, MASTER_PASSWORD);
        masterKeys = result.masterKeys;
        overviewKeys = result.overviewKeys;
        rawItems = await loadBandItems(VAULT_PATH);
    });

    it('decrypts item overview', () => {
        const item = rawItems[0];
        const overview = decryptItemOverview(item, overviewKeys.encKey, overviewKeys.macKey);
        assert.ok(typeof overview === 'object', 'overview should be an object');
        // Overview typically includes title and/or url
        assert.ok(
            overview.title || overview.url || Object.keys(overview).length > 0,
            'overview should have some content'
        );
    });

    it('decrypts item details', () => {
        const item = rawItems[0];
        const details = decryptItemDetails(item, masterKeys.encKey, masterKeys.macKey);
        assert.ok(typeof details === 'object', 'details should be an object');
    });

    it('item has expected category', () => {
        const item = rawItems[0];
        assert.ok(CATEGORY[item.category], `category ${item.category} should be recognized`);
    });
});

// ─── High-Level API ────────────────────────────────────────────────────

describe('getItems', () => {
    it('returns all items with overviews', async () => {
        const items = await getItems(VAULT_PATH, MASTER_PASSWORD);
        assert.ok(items.length > 0, 'should return items');

        for (const item of items) {
            assert.ok(item.uuid, 'item should have uuid');
            assert.ok(item.category, 'item should have category');
            assert.ok(item.categoryName, 'item should have categoryName');
            assert.ok(item.overview, 'item should have overview');
        }
    });

    it('returns items with details when requested', async () => {
        const items = await getItems(VAULT_PATH, MASTER_PASSWORD, { includeDetails: true });
        assert.ok(items.length > 0);

        for (const item of items) {
            assert.ok(item.details, 'item should have details when includeDetails=true');
        }
    });

    it('filters by category', async () => {
        const items = await getItems(VAULT_PATH, MASTER_PASSWORD, { categories: ['001'] });
        for (const item of items) {
            assert.equal(item.category, '001', 'should only include login items');
        }
    });

    it('fails with wrong password', async () => {
        await assert.rejects(
            () => getItems(VAULT_PATH, 'WRONG'),
            /HMAC verification failed/
        );
    });
});

// ─── Category Map ──────────────────────────────────────────────────────

describe('CATEGORY', () => {
    it('maps known category codes', () => {
        assert.equal(CATEGORY['001'], 'Login');
        assert.equal(CATEGORY['002'], 'Credit Card');
        assert.equal(CATEGORY['003'], 'Secure Note');
        assert.equal(CATEGORY['005'], 'Password');
    });

    it('is frozen (immutable)', () => {
        assert.ok(Object.isFrozen(CATEGORY));
    });
});
