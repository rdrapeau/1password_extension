// websocket-connection.js
// Fallback connection for 1Password 6 (WebSockets)

(function() {
  'use strict';

  // Spoof the Origin header for the local WebSocket handshake.
  // This bypasses the local 1Password Agent's origin whitelist check by pretending
  // the request is coming from the official whitelisted Chrome Extension.
  // Note: Match patterns do not support port numbers, so we match 127.0.0.1/localhost
  // and check the port dynamically in the listener.
  if (typeof chrome !== 'undefined' && chrome.webRequest && chrome.webRequest.onBeforeSendHeaders) {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      function(details) {
        if (!details.url.includes(':6258')) {
          return; // Only intercept 1Password Agent port
        }
        console.log('[1Password WebSocket Connection] Spoofing Origin header for request:', details.url);
        let originHeaderExists = false;
        for (let i = 0; i < details.requestHeaders.length; ++i) {
          if (details.requestHeaders[i].name.toLowerCase() === 'origin') {
            details.requestHeaders[i].value = 'chrome-extension://aodmelocbcadldecgiahgplhmifhfael';
            originHeaderExists = true;
            break;
          }
        }
        if (!originHeaderExists) {
          details.requestHeaders.push({
            name: 'Origin',
            value: 'chrome-extension://aodmelocbcadldecgiahgplhmifhfael'
          });
        }
        return { requestHeaders: details.requestHeaders };
      },
      { 
        urls: ["<all_urls>"] 
      },
      ["blocking", "requestHeaders"]
    );
  }

  function createWebSocketPort(wsUrl) {
    const ws = new WebSocket(wsUrl);
    const messageListeners = [];
    const disconnectListeners = [];
    const queue = [];
    let isClosed = false;

    ws.onopen = function() {
      console.log('[1Password WebSocketPort] Connection established, flushing queue:', queue.length);
      while (queue.length > 0) {
        const msg = queue.shift();
        console.log('[1Password WebSocketPort] Sending queued message:', msg);
        ws.send(JSON.stringify(msg));
      }
    };

    ws.onmessage = function(event) {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch (e) {
        console.error('[1Password WebSocketPort] Failed to parse message:', event.data, e);
        return;
      }
      console.log('[1Password WebSocketPort] Received message:', data);
      for (const listener of messageListeners) {
        try {
          listener(data);
        } catch (e) {
          console.error('[1Password WebSocketPort] Error in message listener:', e);
        }
      }
    };

    ws.onclose = function(event) {
      if (isClosed) return;
      isClosed = true;
      console.log('[1Password WebSocketPort] Connection closed:', event.reason);
      for (const listener of disconnectListeners) {
        try {
          listener({ error: null });
        } catch (e) {
          console.error('[1Password WebSocketPort] Error in disconnect listener:', e);
        }
      }
    };

    ws.onerror = function(err) {
      console.error('[1Password WebSocketPort] Error:', err);
      if (isClosed) return;
      isClosed = true;
      for (const listener of disconnectListeners) {
        try {
          listener({ error: new Error('WebSocket connection error') });
        } catch (e) {
          console.error('[1Password WebSocketPort] Error in disconnect listener:', e);
        }
      }
    };

    return {
      postMessage(msg) {
        console.log('[1Password WebSocketPort] postMessage called:', msg);
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify(msg));
        } else if (ws.readyState === WebSocket.CONNECTING) {
          queue.push(msg);
        } else {
          console.warn('[1Password WebSocketPort] Attempted to send message while socket is closed:', msg);
        }
      },
      onMessage: {
        addListener(cb) {
          if (!messageListeners.includes(cb)) {
            messageListeners.push(cb);
          }
        }
      },
      onDisconnect: {
        addListener(cb) {
          if (!disconnectListeners.includes(cb)) {
            disconnectListeners.push(cb);
          }
        }
      },
      disconnect() {
        isClosed = true;
        ws.close();
      }
    };
  }

  function WebSocketConnection(bundleId, agent) {
    this.bundleId = bundleId;
    this.agent = agent;
  }

  WebSocketConnection.prototype.connect = function() {
    const wsUrl = 'ws://127.0.0.1:6258/1password';
    console.info('[1Password WebSocketConnection] Connecting to ' + wsUrl);

    let port = null;
    const portFactory = function(onMessageCallback) {
      if (!port) {
        port = createWebSocketPort(wsUrl);
      }
      port.onMessage.addListener(onMessageCallback);
      return port;
    };

    const NativeMessagingConnection = window.NativeMessagingConnection || (typeof C !== 'undefined' ? C : null);
    if (!NativeMessagingConnection) {
      console.error('[1Password WebSocketConnection] NativeMessagingConnection constructor not found.');
      return;
    }

    const conn = new NativeMessagingConnection(portFactory, portFactory, this.bundleId, this.agent);
    conn.connect();
  };

  window.WebSocketConnection = WebSocketConnection;
  console.log('[1Password WebSocketConnection] Fallback driver registered.');
})();
