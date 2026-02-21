/**
 * Demo script — demonstrates unlocking a test vault and reading credentials.
 *
 * Usage: node src/demo.mjs [vault_path] [password]
 *
 * Security note: This prints credentials to stdout for demo purposes only.
 * In production, credentials should never be logged or printed.
 */

import { getItems } from './opvault.mjs';
import { argv } from 'node:process';

const vaultPath = argv[2] || './Test Vault.opvault';
const password = argv[3] || 'test';

console.log('═══════════════════════════════════════════════════════');
console.log('  OPVault Decryption Demo');
console.log('═══════════════════════════════════════════════════════');
console.log(`Vault: ${vaultPath}`);
console.log(`Password: ${'*'.repeat(password.length)}`);
console.log('');

try {
    console.log('🔐 Unlocking vault...');
    const startTime = performance.now();

    const items = await getItems(vaultPath, password, { includeDetails: true });

    const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
    console.log(`✅ Vault unlocked in ${elapsed}s`);
    console.log(`📦 Found ${items.length} item(s)`);
    console.log('');

    for (const item of items) {
        console.log('───────────────────────────────────────────────────────');
        console.log(`  ${item.categoryName}: ${item.overview.title || '(untitled)'}`);
        console.log('───────────────────────────────────────────────────────');

        if (item.overview.url) {
            console.log(`  URL:      ${item.overview.url}`);
        }
        if (item.overview.ainfo) {
            console.log(`  Username: ${item.overview.ainfo}`);
        }

        if (item.details) {
            if (item.details.fields) {
                for (const field of item.details.fields) {
                    if (field.designation === 'username') {
                        console.log(`  Username: ${field.value}`);
                    } else if (field.designation === 'password') {
                        console.log(`  Password: ${field.value}`);
                    }
                }
            }
            if (item.details.password) {
                console.log(`  Password: ${item.details.password}`);
            }
            if (item.details.notesPlain) {
                console.log(`  Notes:    ${item.details.notesPlain}`);
            }
        }

        console.log('');
    }

    console.log('═══════════════════════════════════════════════════════');
    console.log('✅ Demo complete. Keys have been zeroed from memory.');
    console.log('═══════════════════════════════════════════════════════');
} catch (err) {
    console.error(`❌ Error: ${err.message}`);
    process.exit(1);
}
