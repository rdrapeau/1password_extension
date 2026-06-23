// Content Script Polyfill for Manifest V3
// Ensures compatibility with the injected scripts

(function() {
  'use strict';
  
  // Ensure chrome namespace exists in content scripts
  if (typeof chrome === 'undefined' && typeof browser !== 'undefined') {
    window.chrome = browser;
  }
  
  // Make sure runtime messaging works
  if (chrome && chrome.runtime) {
    // Wrap sendMessage to ensure compatibility
    const originalSendMessage = chrome.runtime.sendMessage;
    chrome.runtime.sendMessage = function() {
      try {
        return originalSendMessage.apply(this, arguments);
      } catch (e) {
        console.warn('[1Password Content] Message send error:', e);
      }
    };
  }
  
  console.log('[1Password Content Polyfill] Loaded');
})();
