import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('Architecture Sync', () => {
    it('ensures host.mjs and server.mjs share identical core logic', () => {
        const hostCode = readFileSync(join(__dirname, '..', 'native-host', 'host.mjs'), 'utf8');
        const serverCode = readFileSync(join(__dirname, '..', 'native-host', 'server.mjs'), 'utf8');

        // Extract class VaultSession
        const extractClass = (code) => {
            const start = code.indexOf('class VaultSession');
            const end = code.indexOf('// ───', start);
            return code.substring(start, end).trim();
        };

        const hostSession = extractClass(hostCode);
        const serverSession = extractClass(serverCode);

        // Strip all whitespace for a resilient structural comparison
        const normalizeCode = (str) => str.replace(/\s+/g, '');

        assert.equal(
            normalizeCode(hostSession),
            normalizeCode(serverSession),
            'VaultSession implementation differs between host.mjs and server.mjs! Any changes made to one must be copied to the other.'
        );

        // Extract urlMatches
        const extractUrlMatches = (code) => {
            const start = code.indexOf('function urlMatches');
            const end = code.indexOf('function normalizeUrl', start);
            return code.substring(start, end).trim();
        };

        assert.equal(
            normalizeCode(extractUrlMatches(hostCode)),
            normalizeCode(extractUrlMatches(serverCode)),
            'urlMatches implementation differs between host.mjs and server.mjs!'
        );

        const extractNormalizeUrl = (code) => {
            const start = code.indexOf('function normalizeUrl');
            const end = code.indexOf('// ───', start);
            return code.substring(start, end).trim();
        };

        assert.equal(
            normalizeCode(extractNormalizeUrl(hostCode)),
            normalizeCode(extractNormalizeUrl(serverCode)),
            'normalizeUrl implementation differs between host.mjs and server.mjs!'
        );

        // Extract action switch
        const extractSwitch = (code) => {
            const start = code.indexOf('switch (msg.action)');
            const end = code.indexOf('} catch', start);
            return code.substring(start, end).trim();
        };

        const hostSwitch = extractSwitch(hostCode);
        const serverSwitch = extractSwitch(serverCode);

        assert.ok(hostSwitch.length > 100, 'Could not cleanly extract message switch from host.mjs');
        assert.ok(serverSwitch.length > 100, 'Could not cleanly extract message switch from server.mjs');

        assert.equal(
            normalizeCode(hostSwitch),
            normalizeCode(serverSwitch),
            'The core switch(msg.action) handling differs between host.mjs and server.mjs! Ensure get_item, get_logins, copy, unlock, etc behave identically in both files.'
        );
    });
});
