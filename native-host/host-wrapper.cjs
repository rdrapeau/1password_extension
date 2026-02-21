#!/opt/homebrew/bin/node
// CJS wrapper to launch the ESM native host
// Firefox native messaging requires a directly executable file
const { execFileSync } = require('child_process');
const { join } = require('path');

// Import and run the ESM host by spawning node with the correct flags
const hostPath = join(__dirname, 'host.mjs');

// Instead of importing ESM, we re-exec with node in ESM mode
// But we need to pass through stdin/stdout for native messaging
const { spawn } = require('child_process');
const child = spawn(process.execPath, [hostPath], {
    stdio: 'inherit'
});
child.on('exit', (code) => process.exit(code || 0));
