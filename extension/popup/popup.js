/**
 * Popup UI logic — manages lock/unlock screens, item list, search,
 * fill and copy actions.
 *
 * Communicates with the background script via browser.runtime.sendMessage.
 * Never directly accesses vault data.
 */

/* global browser */

// ─── DOM Elements ──────────────────────────────────────────────────────

const lockScreen = document.getElementById('lock-screen');
const listScreen = document.getElementById('list-screen');
const settingsScreen = document.getElementById('settings-screen');

const vaultPathInput = document.getElementById('vault-path');
const masterPasswordInput = document.getElementById('master-password');
const unlockBtn = document.getElementById('unlock-btn');
const unlockError = document.getElementById('unlock-error');

const lockBtn = document.getElementById('lock-btn');
const searchInput = document.getElementById('search-input');
const itemsContainer = document.getElementById('items-container');
const itemCount = document.getElementById('item-count');

// Biometrics Elements
const biometricContainer = document.getElementById('biometric-container');
const biometricUnlockBtn = document.getElementById('biometric-unlock-btn');
const biometricSettingsContainer = document.getElementById('biometric-settings-container');
const biometricPassword = document.getElementById('biometric-password');
const enableBiometricBtn = document.getElementById('enable-biometric-btn');
const biometricMsg = document.getElementById('biometric-msg');
const biometricError = document.getElementById('biometric-error');

// Details Elements
const detailsScreen = document.getElementById('details-screen');
const detailsBackBtn = document.getElementById('details-back-btn');
const detailsTitle = document.getElementById('details-title');
const detailsSubtitle = document.getElementById('details-subtitle');
const detailsLoading = document.getElementById('details-loading');
const detailsFields = document.getElementById('details-fields');
const detailsNotesContainer = document.getElementById('details-notes-container');
const detailsNotes = document.getElementById('details-notes');

// Settings Elements
const lockSettingsBtn = document.getElementById('lock-settings-btn');
const listSettingsBtn = document.getElementById('list-settings-btn');
const settingsBackBtn = document.getElementById('settings-back-btn');
const settingsVaultPath = document.getElementById('settings-vault-path');
const settingsAutoLock = document.getElementById('settings-auto-lock');
const settingsSaveBtn = document.getElementById('settings-save-btn');
const settingsMsg = document.getElementById('settings-msg');

let settingsReturnScreen = null;

let allItems = [];

// ─── Screen Management ─────────────────────────────────────────────────

function showScreen(screen) {
    lockScreen.classList.remove('active');
    listScreen.classList.remove('active');
    settingsScreen.classList.remove('active');
    detailsScreen.classList.remove('active');
    screen.classList.add('active');
}

// ─── Settings ──────────────────────────────────────────────────────────

async function openSettings(returnScreen) {
    settingsReturnScreen = returnScreen;
    try {
        const data = await browser.storage.local.get(['vaultPath', 'autoLockMinutes']);
        if (data.vaultPath) settingsVaultPath.value = data.vaultPath;
        if (data.autoLockMinutes !== undefined) settingsAutoLock.value = data.autoLockMinutes;
    } catch (e) {
        // Dev harness mock might fail
    }
    showScreen(settingsScreen);
}

lockSettingsBtn.addEventListener('click', () => openSettings(lockScreen));
listSettingsBtn.addEventListener('click', () => openSettings(listScreen));

settingsBackBtn.addEventListener('click', () => {
    showScreen(settingsReturnScreen || lockScreen);
});

settingsSaveBtn.addEventListener('click', async () => {
    const path = settingsVaultPath.value.trim();
    const mins = parseInt(settingsAutoLock.value, 10);
    const autoLockMinutes = isNaN(mins) ? 5 : mins;

    try {
        await browser.storage.local.set({ vaultPath: path, autoLockMinutes });

        if (path) vaultPathInput.value = path;

        settingsMsg.classList.remove('hidden');
        setTimeout(() => settingsMsg.classList.add('hidden'), 2000);
    } catch (e) {
        // Dev harness mock might fail
    }
});

enableBiometricBtn.addEventListener('click', async () => {
    const vaultPath = settingsVaultPath.value.trim() || vaultPathInput.value.trim();
    const password = biometricPassword.value;

    if (!vaultPath || !password) {
        biometricError.textContent = 'Vault path and Master Password required';
        biometricError.classList.remove('hidden');
        return;
    }

    biometricError.classList.add('hidden');
    enableBiometricBtn.disabled = true;
    enableBiometricBtn.textContent = 'Enabling...';

    try {
        const response = await browser.runtime.sendMessage({
            type: 'enable_biometrics',
            vaultPath,
            password,
        });

        if (response.ok) {
            biometricPassword.value = '';
            biometricMsg.classList.remove('hidden');
            setTimeout(() => biometricMsg.classList.add('hidden'), 3000);
        } else {
            biometricError.textContent = response.error || 'Failed to enable Touch ID';
            biometricError.classList.remove('hidden');
        }
    } catch (err) {
        biometricError.textContent = 'Connection error';
        biometricError.classList.remove('hidden');
    } finally {
        enableBiometricBtn.disabled = false;
        enableBiometricBtn.textContent = 'Enable Touch ID';
    }
});

// ─── Unlock ────────────────────────────────────────────────────────────

unlockBtn.addEventListener('click', handleUnlock);
masterPasswordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleUnlock();
});

async function handleUnlock() {
    const vaultPath = vaultPathInput.value.trim();
    const password = masterPasswordInput.value;

    if (!vaultPath || !password) {
        showError('Please enter vault path and password');
        return;
    }

    // Show loading
    unlockBtn.disabled = true;
    unlockBtn.querySelector('.btn-text').classList.add('hidden');
    unlockBtn.querySelector('.btn-loading').classList.remove('hidden');
    hideError();

    let autoLockMs = 5 * 60 * 1000;
    try {
        const data = await browser.storage.local.get(['autoLockMinutes']);
        if (data.autoLockMinutes !== undefined) {
            autoLockMs = data.autoLockMinutes * 60 * 1000;
        }
    } catch (e) { }

    try {
        const response = await browser.runtime.sendMessage({
            type: 'unlock',
            vaultPath,
            password,
            autoLockMs,
        });

        if (response.ok) {
            // Clear password from input immediately
            masterPasswordInput.value = '';
            await loadItems();
            showScreen(listScreen);
            searchInput.focus();
        } else {
            const msg = response.error?.includes('HMAC')
                ? 'Wrong password'
                : (response.error || 'Failed to unlock');
            showError(msg);
        }
    } catch (err) {
        showError('Connection error: ' + (err.message || 'server may not be running'));
    } finally {
        unlockBtn.disabled = false;
        unlockBtn.querySelector('.btn-text').classList.remove('hidden');
        unlockBtn.querySelector('.btn-loading').classList.add('hidden');
    }
}

biometricUnlockBtn.addEventListener('click', async () => {
    const vaultPath = vaultPathInput.value.trim();
    if (!vaultPath) {
        showError('Please enter vault path');
        return;
    }

    hideError();
    biometricUnlockBtn.disabled = true;
    biometricUnlockBtn.innerHTML = 'Waiting for Touch ID...';

    let autoLockMs = 5 * 60 * 1000;
    try {
        const data = await browser.storage.local.get(['autoLockMinutes']);
        if (data.autoLockMinutes !== undefined) {
            autoLockMs = data.autoLockMinutes * 60 * 1000;
        }
    } catch (e) { }

    try {
        // This call will block until the macOS Touch ID prompt resolves
        const response = await browser.runtime.sendMessage({
            type: 'biometric_unlock',
            vaultPath,
            autoLockMs,
        });

        if (response.ok) {
            masterPasswordInput.value = '';
            await loadItems();
            showScreen(listScreen);
            searchInput.focus();
        } else {
            showError(response.error || 'Failed to unlock with Touch ID');
        }
    } catch (err) {
        showError('Connection error: ' + (err.message || 'server disconnected'));
    } finally {
        biometricUnlockBtn.disabled = false;
        biometricUnlockBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
              <path d="M12 2v20M17 5c0 0-3-3-5-3S7 5 7 5M19 10c0 0-4-5-7-5S5 10 5 10M21 15c0 0-5-6-9-6s-9 6-9 6M22 20c0 0-6-7-10-7s-10 7-10 7" stroke-linecap="round"/>
            </svg>
            Unlock with Touch ID`;
    }
});

// ─── Lock ──────────────────────────────────────────────────────────────

lockBtn.addEventListener('click', async () => {
    await browser.runtime.sendMessage({ type: 'lock' });
    allItems = [];
    showScreen(lockScreen);
    masterPasswordInput.focus();
});

// ─── Item Loading ──────────────────────────────────────────────────────

let suggestedItems = [];

async function loadItems() {
    try {
        // Try to get the active tab's URL to show suggested logins
        const tabs = await browser.tabs.query({ active: true, currentWindow: true }).catch(() => []);
        const currentUrl = tabs[0]?.url;

        let suggResp = null;
        if (currentUrl && currentUrl.startsWith('http')) {
            suggResp = await browser.runtime.sendMessage({ type: 'get_logins', url: currentUrl }).catch(() => null);
        }

        const response = await browser.runtime.sendMessage({ type: 'list' });

        if (response.ok) {
            allItems = response.items;
            itemCount.textContent = `${allItems.length} item${allItems.length !== 1 ? 's' : ''}`;

            suggestedItems = (suggResp && suggResp.ok && suggResp.items) ? suggResp.items : [];

            renderItems(allItems, suggestedItems);
        }
    } catch {
        renderItems([], []);
    }
}

// ─── Search ────────────────────────────────────────────────────────────

searchInput.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase().trim();
    if (!query) {
        renderItems(allItems, suggestedItems);
        return;
    }

    const filtered = allItems.filter(item =>
        (item.title || '').toLowerCase().includes(query) ||
        (item.username || '').toLowerCase().includes(query) ||
        (item.url || '').toLowerCase().includes(query) ||
        (item.categoryName || '').toLowerCase().includes(query)
    );
    // When searching, don't show the suggested group separately to avoid confusion
    renderItems(filtered, []);
});

// ─── Item Rendering ────────────────────────────────────────────────────

const CATEGORY_ICONS = {
    'Login': '🔑',
    'Password': '🔒',
    'Credit Card': '💳',
    'Secure Note': '📝',
    'Identity': '👤',
    'Bank Account': '🏦',
    'Email': '📧',
    'Server': '🖥️',
    'Software License': '📀',
};

function renderItemCard(item) {
    return `
    <div class="item-card" data-uuid="${escapeHtml(item.uuid)}">
      <div class="item-icon">${CATEGORY_ICONS[item.categoryName] || '🔐'}</div>
      <div class="item-info">
        <div class="item-title">${escapeHtml(item.title)}</div>
        <div class="item-subtitle">${escapeHtml(item.username || item.url || item.categoryName)}</div>
      </div>
      <div class="item-actions">
        <button class="action-btn" data-action="copy-user" data-uuid="${escapeHtml(item.uuid)}" title="Copy username">
          👤
        </button>
        <button class="action-btn" data-action="copy-pass" data-uuid="${escapeHtml(item.uuid)}" title="Copy password">
          📋
        </button>
        <button class="action-btn" data-action="fill" data-uuid="${escapeHtml(item.uuid)}" title="Auto-fill">
          ✏️
        </button>
      </div>
    </div>
    `;
}

function renderItems(items, suggested = []) {
    if (items.length === 0 && suggested.length === 0) {
        itemsContainer.innerHTML = '<div class="empty-state">No items found</div>';
        return;
    }

    let html = '';

    // De-duplicate suggested items from the main list
    const suggestedUuids = new Set(suggested.map(i => i.uuid));
    const otherItems = items.filter(i => !suggestedUuids.has(i.uuid));

    if (suggested.length > 0) {
        html += '<div class="list-header" style="padding: 4px 12px 8px 12px; font-size: 11px; color: var(--accent); font-weight: 600; text-transform: uppercase;">Suggested</div>';
        html += suggested.map(item => renderItemCard(item)).join('');

        if (otherItems.length > 0) {
            html += '<div class="list-header" style="border-top: 1px solid var(--border); margin-top: 8px; padding: 12px 12px 8px 12px; font-size: 11px; color: var(--text-secondary); font-weight: 600; text-transform: uppercase;">All Items</div>';
        }
    }

    html += otherItems.map(item => renderItemCard(item)).join('');

    itemsContainer.innerHTML = html;

    // Attach event listeners
    itemsContainer.querySelectorAll('.action-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            handleAction(btn);
        });
    });

    // Click on card = show details
    itemsContainer.querySelectorAll('.item-card').forEach(card => {
        card.addEventListener('click', () => {
            const uuid = card.dataset.uuid;
            showDetails(uuid);
        });
    });
}

// ─── Details View ──────────────────────────────────────────────────────

detailsBackBtn.addEventListener('click', () => {
    showScreen(listScreen);
});

async function showDetails(uuid) {
    showScreen(detailsScreen);

    // Reset state
    detailsTitle.textContent = 'Loading...';
    detailsSubtitle.textContent = '';
    detailsFields.innerHTML = '';
    detailsNotes.textContent = '';
    detailsNotesContainer.classList.add('hidden');
    detailsFields.classList.add('hidden');
    detailsLoading.classList.remove('hidden');

    try {
        const response = await browser.runtime.sendMessage({
            type: 'get_item',
            uuid,
        });

        if (response.ok && response.item) {
            renderDetails(response.item);
        } else {
            detailsTitle.textContent = 'Error loading details';
            detailsLoading.textContent = response.error || 'Failed to decrypt item';
        }
    } catch (err) {
        detailsTitle.textContent = 'Connection error';
        detailsLoading.textContent = err.message || 'Server disconnected';
    }
}

function renderDetails(item) {
    detailsLoading.classList.add('hidden');
    detailsFields.classList.remove('hidden');

    detailsTitle.textContent = item.title;
    detailsSubtitle.textContent = `${CATEGORY_ICONS[item.categoryName] || '🔐'} ${item.categoryName}`;

    let html = '';

    // Standard fields (from overview/details)
    const fieldsToRender = [];

    // Username
    if (item.username) fieldsToRender.push({ label: 'username', value: item.username, type: 'text' });

    // Top-level Password
    if (item.password) fieldsToRender.push({ label: 'password', value: item.password, type: 'password' });

    // Extracted Fields (including password)
    if (item.fields) {
        for (const f of item.fields) {
            if (!f.value) continue;
            // Skip username if we already added it and it matches
            if (f.designation === 'username' && f.value === item.username) continue;
            // Skip top-level password if it matches
            if (f.designation === 'password' && f.value === item.password) continue;

            const isPassword = f.type === 'P' || f.designation === 'password';
            fieldsToRender.push({
                label: f.name || f.designation || 'field',
                value: f.value,
                type: isPassword ? 'password' : 'text'
            });
        }
    }

    // URLs
    if (item.url) {
        html += `
        <div class="detail-row">
          <span class="detail-label">website</span>
          <div style="padding: 6px 0;">
            <a href="${escapeHtml(item.url)}" class="detail-link" target="_blank" rel="noopener noreferrer">${escapeHtml(item.url)}</a>
          </div>
        </div>`;
    }

    // Render Fields
    for (let i = 0; i < fieldsToRender.length; i++) {
        const field = fieldsToRender[i];
        const inputType = field.type === 'password' ? 'password' : 'text';
        const toggleBtn = field.type === 'password'
            ? `<button class="detail-action toggle-btn" title="Toggle visibility" data-index="${i}">👁️</button>`
            : '';

        html += `
        <div class="detail-row">
          <span class="detail-label">${escapeHtml(field.label)}</span>
          <div class="detail-value-group">
            <input type="${inputType}" class="detail-value" value="${escapeHtml(field.value)}" readonly id="detail-input-${i}">
            ${toggleBtn}
            <button class="detail-action copy-btn" title="Copy" data-value="${escapeHtml(field.value)}">📋</button>
          </div>
        </div>`;
    }

    detailsFields.innerHTML = html;

    // Attach toggle listeners
    detailsFields.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const input = document.getElementById(`detail-input-${btn.dataset.index}`);
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🔒';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        });
    });

    // Attach copy listeners
    detailsFields.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            await navigator.clipboard.writeText(btn.dataset.value);
            btn.classList.add('copied');
            const original = btn.textContent;
            btn.textContent = '✓';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.textContent = original;
            }, 1500);
            showToast('Copied');
        });
    });

    // Notes
    if (item.notes) {
        detailsNotes.textContent = item.notes; // textContent escapes HTML safely
        detailsNotesContainer.classList.remove('hidden');
    }
}

// ─── Actions ───────────────────────────────────────────────────────────

async function handleAction(btn) {
    const action = btn.dataset.action;
    const uuid = btn.dataset.uuid;

    switch (action) {
        case 'copy-user':
            await handleCopy(uuid, 'username', btn);
            break;
        case 'copy-pass':
            await handleCopy(uuid, 'password', btn);
            break;
        case 'fill':
            await handleFill(uuid);
            break;
    }
}

async function handleFill(uuid) {
    try {
        const response = await browser.runtime.sendMessage({
            type: 'fill',
            uuid,
        });

        if (response.ok) {
            showToast('Credentials filled ✓');
            // Close popup after a short delay
            setTimeout(() => window.close(), 600);
        } else {
            showToast(response.error || 'Fill failed');
        }
    } catch {
        showToast('Fill failed — try refreshing the page');
    }
}

async function handleCopy(uuid, field, btn) {
    try {
        const response = await browser.runtime.sendMessage({
            type: 'copy',
            uuid,
            field,
        });

        if (response.ok && response.value) {
            await navigator.clipboard.writeText(response.value);

            // Visual feedback
            btn.classList.add('copied');
            const original = btn.textContent;
            btn.textContent = '✓';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.textContent = original;
            }, 1500);

            showToast(`${field === 'password' ? 'Password' : 'Username'} copied`);
        } else {
            showToast(response.error || 'Copy failed');
        }
    } catch {
        showToast('Copy failed');
    }
}

// ─── Toast ─────────────────────────────────────────────────────────────

function showToast(message) {
    let toast = document.querySelector('.toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('visible');
    setTimeout(() => toast.classList.remove('visible'), 2000);
}

// ─── Error Display ─────────────────────────────────────────────────────

function showError(msg) {
    unlockError.textContent = msg;
    unlockError.classList.remove('hidden');
}

function hideError() {
    unlockError.classList.add('hidden');
}

// ─── Utilities ─────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);
}

// ─── Init ──────────────────────────────────────────────────────────────

(async () => {
    // Check if already unlocked
    try {
        const status = await browser.runtime.sendMessage({ type: 'status' });

        // Show biometrics UI if available on the system
        if (status.biometricsAvailable) {
            biometricContainer.classList.remove('hidden');
            biometricSettingsContainer.classList.remove('hidden');
        }

        if (status.ok && !status.locked) {
            await loadItems();
            showScreen(listScreen);

            // Restore vault path if we have it
            if (status.vaultPath) {
                vaultPathInput.value = status.vaultPath;
            }
            return;
        }
    } catch {
        // Server not running, show lock screen
    }

    showScreen(lockScreen);

    // Check if we have a saved default vault path
    try {
        const data = await browser.storage.local.get(['vaultPath']);
        if (data.vaultPath && !vaultPathInput.value) {
            vaultPathInput.value = data.vaultPath;
        }
    } catch (e) { }

    masterPasswordInput.focus();
})();
