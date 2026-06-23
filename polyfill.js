// Polyfill for Manifest V2 -> V3 compatibility
// Maps old MV2 APIs to new MV3 APIs

(function() {
  'use strict';
  
  // Map browserAction (MV2) to action (MV3)
  if (typeof chrome !== 'undefined' && chrome.action && !chrome.browserAction) {
    chrome.browserAction = chrome.action;
  }
  
  // Also for browser namespace (Firefox)
  if (typeof browser !== 'undefined' && browser.action && !browser.browserAction) {
    browser.browserAction = browser.action;
  }
  
  // Ensure chrome namespace exists
  if (typeof chrome === 'undefined' && typeof browser !== 'undefined') {
    window.chrome = browser;
  }
  
  // Wrap contextMenus.create to handle 'onclick' -> 'onClicked' migration
  if (chrome && chrome.contextMenus && chrome.contextMenus.create) {
    const originalCreate = chrome.contextMenus.create;
    chrome.contextMenus.create = function(createProperties, callback) {
      // Convert onclick to onClicked event listener
      if (createProperties.onclick) {
        const onclickHandler = createProperties.onclick;
        delete createProperties.onclick;
        
        // Add the click listener after creation
        const menuId = originalCreate.call(this, createProperties, callback);
        
        if (chrome.contextMenus.onClicked) {
          chrome.contextMenus.onClicked.addListener((info, tab) => {
            if (info.menuItemId === menuId || info.menuItemId === createProperties.id) {
              onclickHandler(info, tab);
            }
          });
        }
        
        return menuId;
      }
      
      return originalCreate.call(this, createProperties, callback);
    };
  }
  
  // Wrap chrome.tabs.query to handle potential undefined results
  if (chrome && chrome.tabs && chrome.tabs.query) {
    const originalQuery = chrome.tabs.query;
    chrome.tabs.query = function(queryInfo, callback) {
      const promise = originalQuery.call(this, queryInfo, function(tabs) {
        // Ensure tabs is always an array and tabs have expected properties
        const safeTabs = (tabs || []).map(tab => {
          return {
            ...tab,
            focused: tab.focused !== undefined ? tab.focused : false,
            active: tab.active !== undefined ? tab.active : false
          };
        });
        if (callback) {
          try {
            callback(safeTabs);
          } catch (e) {
            console.warn('[1Password Polyfill] Error in tabs.query callback:', e);
          }
        }
      });
      return promise;
    };
  }
  
  // Wrap chrome.tabs.get as well
  if (chrome && chrome.tabs && chrome.tabs.get) {
    const originalGet = chrome.tabs.get;
    chrome.tabs.get = function(tabId, callback) {
      return originalGet.call(this, tabId, function(tab) {
        if (tab) {
          const safeTab = {
            ...tab,
            focused: tab.focused !== undefined ? tab.focused : false,
            active: tab.active !== undefined ? tab.active : false
          };
          if (callback) {
            try {
              callback(safeTab);
            } catch (e) {
              console.warn('[1Password Polyfill] Error in tabs.get callback:', e);
            }
          }
        } else if (callback) {
          callback(tab);
        }
      });
    };
  }
  
  // Add global error handler to catch remaining issues
  if (typeof window !== 'undefined') {
    const originalErrorHandler = window.onerror;
    window.onerror = function(message, source, lineno, colno, error) {
      if (message && message.includes("can't access property \"focused\"")) {
        console.warn('[1Password Polyfill] Suppressed focused property error');
        return true; // Suppress the error
      }
      if (originalErrorHandler) {
        return originalErrorHandler(message, source, lineno, colno, error);
      }
      return false;
    };
  }
  
  console.log('[1Password Polyfill] MV2->MV3 compatibility layer loaded');
})();
