/**
 * Content script — detects login forms and fills credentials.
 *
 * Injected into all web pages. Only receives fill commands from the
 * background script — never has access to vault data.
 *
 * Security:
 *   - Only receives specific username/password for the current fill
 *   - Never requests or stores vault data
 *   - Credentials are injected directly into form fields
 */

/* global browser */

// ─── Form Detection ────────────────────────────────────────────────────

/**
 * Find login form fields on the page.
 * Returns { usernameField, passwordField } or null if not found.
 */
function findLoginFields() {
    const passwordFields = document.querySelectorAll(
        'input[type="password"]:not([aria-hidden="true"]):not([hidden])'
    );

    if (passwordFields.length === 0) return null;

    // Use the first visible password field
    const passwordField = Array.from(passwordFields).find(isVisible) || passwordFields[0];

    // Find the username field: look for inputs near the password field
    const usernameField = findUsernameField(passwordField);

    return { usernameField, passwordField };
}

/**
 * Find the username/email field associated with a password field.
 * Walks backwards through preceding inputs in the same form or DOM.
 */
function findUsernameField(passwordField) {
    const form = passwordField.closest('form');
    const candidates = form
        ? form.querySelectorAll('input')
        : document.querySelectorAll('input');

    // Username field heuristics
    const usernameSelectors = [
        'input[type="email"]',
        'input[type="text"][autocomplete="username"]',
        'input[type="text"][autocomplete="email"]',
        'input[name*="user" i]',
        'input[name*="email" i]',
        'input[name*="login" i]',
        'input[id*="user" i]',
        'input[id*="email" i]',
        'input[id*="login" i]',
        'input[placeholder*="email" i]',
        'input[placeholder*="user" i]',
        'input[type="text"]',
    ];

    // Try specific selectors first
    const scope = form || document;
    for (const selector of usernameSelectors) {
        const field = scope.querySelector(selector);
        if (field && field !== passwordField && isVisible(field)) {
            return field;
        }
    }

    // Fallback: find the text/email input immediately before the password field
    const inputList = Array.from(candidates);
    const pwIdx = inputList.indexOf(passwordField);
    for (let i = pwIdx - 1; i >= 0; i--) {
        const input = inputList[i];
        if (
            (input.type === 'text' || input.type === 'email' || input.type === '') &&
            isVisible(input)
        ) {
            return input;
        }
    }

    return null;
}

/**
 * Check if an element is visible.
 */
function isVisible(el) {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    return (
        style.display !== 'none' &&
        style.visibility !== 'hidden' &&
        style.opacity !== '0' &&
        el.offsetWidth > 0 &&
        el.offsetHeight > 0
    );
}

// ─── Credential Filling ────────────────────────────────────────────────

/**
 * Fill a form field with a value, dispatching proper events
 * so that frameworks (React, Angular, Vue) detect the change.
 */
function fillField(field, value) {
    if (!field || !value) return;

    // Focus the field
    field.focus();
    field.dispatchEvent(new Event('focus', { bubbles: true }));

    // Set the value using the native setter to bypass React etc.
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(field),
        'value'
    )?.set;

    if (nativeInputValueSetter) {
        nativeInputValueSetter.call(field, value);
    } else {
        field.value = value;
    }

    // Dispatch events that frameworks listen to
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
}

/**
 * Fill login credentials into the page.
 */
function fillCredentials(username, password) {
    const fields = findLoginFields();
    if (!fields) {
        return { ok: false, error: 'No login form found on this page' };
    }

    if (fields.usernameField && username) {
        fillField(fields.usernameField, username);
    }
    if (fields.passwordField && password) {
        fillField(fields.passwordField, password);
    }

    return { ok: true };
}

// ─── Message Listener ──────────────────────────────────────────────────

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'fill_credentials') {
        const result = fillCredentials(message.username, message.password);
        sendResponse(result);
    }

    if (message.type === 'detect_login') {
        const fields = findLoginFields();
        sendResponse({ hasLoginForm: fields !== null });
    }
});

// ─── Visual Indicator ──────────────────────────────────────────────────

/**
 * Add a small indicator icon near detected password fields.
 * This is a subtle visual cue that the extension can auto-fill.
 */
function addFieldIndicators() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    for (const field of passwordFields) {
        if (field.dataset.opvaultIndicator) continue;
        field.dataset.opvaultIndicator = 'true';

        // Style the field to make room for the indicator
        field.style.backgroundImage = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%234a9eff'%3E%3Cpath d='M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z'/%3E%3C/svg%3E")`;
        field.style.backgroundRepeat = 'no-repeat';
        field.style.backgroundPosition = 'right 8px center';
        field.style.backgroundSize = '16px 16px';
        field.style.paddingRight = '32px';
    }
}

// Run indicator detection after page load and on DOM changes
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addFieldIndicators);
} else {
    addFieldIndicators();
}

// Watch for dynamically added forms
const observer = new MutationObserver(() => {
    addFieldIndicators();
});
observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
});
