// Background script for 1Password Extension (Manifest V3 - Firefox)
// Firefox MV3 uses regular scripts loaded via script tags, not importScripts

console.log('[1Password] Background script loading...');

// The scripts are loaded in order via manifest.json background.scripts array
// This file loads after ext/sjcl.js and global.min.js

// Listen for extension icon clicks
if (browser && browser.action) {
  browser.action.onClicked.addListener((tab) => {
    console.log('[1Password] Extension icon clicked');
  });
}

// Context menu setup (if needed)
if (browser && browser.runtime) {
  browser.runtime.onInstalled.addListener(() => {
    console.log('[1Password] Extension installed/updated');
  });
  
  // Message handling from content scripts
  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('[1Password] Message received:', message);
    // Handle messages from content scripts
    return false; // or true if async response
  });
}

console.log('[1Password] Background script loaded');
