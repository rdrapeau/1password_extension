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

const vaultPathInput = document.getElementById('vault-path');
const masterPasswordInput = document.getElementById('master-password');
const unlockBtn = document.getElementById('unlock-btn');
const unlockError = document.getElementById('unlock-error');

const lockBtn = document.getElementById('lock-btn');
const searchInput = document.getElementById('search-input');
const itemsContainer = document.getElementById('items-container');
const itemCount = document.getElementById('item-count');

let allItems = [];

// ─── Screen Management ─────────────────────────────────────────────────

function showScreen(screen) {
    lockScreen.classList.remove('active');
    listScreen.classList.remove('active');
    screen.classList.add('active');
}

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

    try {
        const response = await browser.runtime.sendMessage({
            type: 'unlock',
            vaultPath,
            password,
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

// ─── Lock ──────────────────────────────────────────────────────────────

lockBtn.addEventListener('click', async () => {
    await browser.runtime.sendMessage({ type: 'lock' });
    allItems = [];
    showScreen(lockScreen);
    masterPasswordInput.focus();
});

// ─── Item Loading ──────────────────────────────────────────────────────

async function loadItems() {
    try {
        const response = await browser.runtime.sendMessage({ type: 'list' });
        if (response.ok) {
            allItems = response.items;
            itemCount.textContent = `${allItems.length} item${allItems.length !== 1 ? 's' : ''}`;
            renderItems(allItems);
        }
    } catch {
        renderItems([]);
    }
}

// ─── Search ────────────────────────────────────────────────────────────

searchInput.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase().trim();
    if (!query) {
        renderItems(allItems);
        return;
    }

    const filtered = allItems.filter(item =>
        (item.title || '').toLowerCase().includes(query) ||
        (item.username || '').toLowerCase().includes(query) ||
        (item.url || '').toLowerCase().includes(query) ||
        (item.categoryName || '').toLowerCase().includes(query)
    );
    renderItems(filtered);
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

function renderItems(items) {
    if (items.length === 0) {
        itemsContainer.innerHTML = '<div class="empty-state">No items found</div>';
        return;
    }

    itemsContainer.innerHTML = items.map(item => `
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
  `).join('');

    // Attach event listeners
    itemsContainer.querySelectorAll('.action-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            handleAction(btn);
        });
    });

    // Click on card = fill
    itemsContainer.querySelectorAll('.item-card').forEach(card => {
        card.addEventListener('click', () => {
            const uuid = card.dataset.uuid;
            handleFill(uuid);
        });
    });
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
    masterPasswordInput.focus();
})();
