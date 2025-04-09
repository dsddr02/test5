// ====================== 配置部分 ======================
const PROXY_PATH = '/proxy';          // WebSocket 代理路径
const PROXY_TRIGGER = ':443';        // 触发代理的标记
const UUID = 'YOUR-UUID-HERE';       // 替换为你的UUID
const AUTH_KEY = 'your_password';    // 可选认证密钥

// ====================== WebSocket 处理 ======================
async function handleWebSocket(request) {
  // 认证检查（可选）
  const url = new URL(request.url);
  if (AUTH_KEY && url.searchParams.get('key') !== AUTH_KEY) {
    return new Response('Forbidden', { status: 403 });
  }

  const [client, worker] = Object.values(new WebSocketPair());
  
  client.addEventListener('message', event => {
    try {
      // 这里可以添加解密逻辑
      worker.send(event.data);
    } catch (err) {
      console.error('Client message error:', err);
      client.close(1011, 'Error');
    }
  });

  worker.addEventListener('message', event => {
    try {
      // 这里可以添加加密逻辑
      client.send(event.data);
    } catch (err) {
      console.error('Worker message error:', err);
      worker.close(1011, 'Error');
    }
  });

  client.addEventListener('close', () => worker.close());
  worker.addEventListener('close', () => client.close());

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: {
      'X-Proxy': 'Cloudflare-Worker'
    }
  });
}

// ====================== HTTP 代理处理 ======================
async function handleProxyRequest(request, realHost) {
  const url = new URL(request.url);
  
  // 构造真实URL
  const proxyUrl = new URL(url.pathname + url.search, `https://${realHost}`);
  
  // 修改请求头
  const newHeaders = new Headers(request.headers);
  newHeaders.set('Host', realHost);
  newHeaders.delete('X-Forwarded-For');
  newHeaders.set('X-Real-IP', request.headers.get('CF-Connecting-IP'));
  
  // 转发请求
  try {
    const response = await fetch(proxyUrl, {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: 'manual'
    });
    
    // 复制响应并移除敏感头
    const responseHeaders = new Headers(response.headers);
    responseHeaders.delete('set-cookie');
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  } catch (err) {
    return new Response(`Proxy error: ${err.message}`, { status: 502 });
  }
}

// ====================== 主请求处理 ======================
async function handleRequest(request) {
  const url = new URL(request.url);
  
  // WebSocket 代理 (V2RayN使用)
  if (request.headers.get('Upgrade') === 'websocket') {
    if (url.pathname === PROXY_PATH) {
      return handleWebSocket(request);
    }
    return new Response('WebSocket endpoint not found', { status: 404 });
  }

  // HTTP 代理触发方式1: example.com:443
  if (url.hostname.includes(PROXY_TRIGGER)) {
    const realHost = url.hostname.split(PROXY_TRIGGER)[0];
    return handleProxyRequest(request, realHost);
  }

  // HTTP 代理触发方式2: /http-proxy/example.com/path
  if (url.pathname.startsWith('/http-proxy/')) {
    const pathParts = url.pathname.split('/');
    if (pathParts.length >= 3) {
      const realHost = pathParts[2];
      const newPath = '/' + pathParts.slice(3).join('/');
      url.pathname = newPath;
      return handleProxyRequest(request, realHost);
    }
  }

  // 默认响应
  return new Response(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Cloudflare Worker Proxy</title>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }
        code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
      </style>
    </head>
    <body>
      <h1>Worker Proxy Service</h1>
      <p><strong>WebSocket Proxy (V2RayN):</strong> <code>wss://${url.hostname}${PROXY_PATH}</code></p>
      <p><strong>UUID:</strong> ${UUID}</p>
      
      <h2>HTTP Proxy Usage:</h2>
      <h3>Format 1 (URL suffix):</h3>
      <p><code>https://<i>target-domain</i>:443/<i>path</i></code></p>
      <p>Example: <code>https://example.com:443/api/data</code></p>
      
      <h3>Format 2 (Path prefix):</h3>
      <p><code>https://${url.hostname}/http-proxy/<i>target-domain</i>/<i>path</i></code></p>
      <p>Example: <code>https://${url.hostname}/http-proxy/example.com/api/data</code></p>
      
      ${AUTH_KEY ? `<p><strong>Authentication Key:</strong> <code>?key=${AUTH_KEY}</code></p>` : ''}
    </body>
    </html>
  `, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// ====================== Worker 入口 ======================
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
