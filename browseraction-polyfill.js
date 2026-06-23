// Polyfill for MV3: browserAction -> action compatibility
// This fixes MV2 API usage in legacy global.min.js

if (typeof chrome !== 'undefined' && chrome.action && !chrome.browserAction) {
  console.log('[NoLegacy] Polyfilling browserAction with action API');
  
  // Map browserAction to action for MV3 compatibility
  chrome.browserAction = {
    onClicked: chrome.action.onClicked,
    enable: function(tabId) {
      return chrome.action.enable(tabId);
    },
    disable: function(tabId) {
      return chrome.action.disable(tabId);
    },
    setIcon: function(details, callback) {
      return chrome.action.setIcon(details, callback);
    },
    setTitle: function(details, callback) {
      return chrome.action.setTitle(details, callback);
    },
    setBadgeText: function(details, callback) {
      return chrome.action.setBadgeText(details, callback);
    },
    setBadgeBackgroundColor: function(details, callback) {
      return chrome.action.setBadgeBackgroundColor(details, callback);
    }
  };
}
