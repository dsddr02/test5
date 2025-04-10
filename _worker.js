// src/worker.js
import { connect } from "cloudflare:sockets";

// 配置管理
const config = {
  sha224Password: '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88',
  proxyIP: "",
  timeout: 30000,
  maxConnections: 100,
  debug: false
};

// 连接池管理
const connectionPool = new Map();

// 日志系统
const logger = {
  debug(...args) {
    if (config.debug) console.debug(`[DEBUG][${new Date().toISOString()}]`, ...args);
  },
  info(...args) {
    console.log(`[INFO][${new Date().toISOString()}]`, ...args);
  },
  error(...args) {
    console.error(`[ERROR][${new Date().toISOString()}]`, ...args);
  }
};

// 错误处理类
class ProxyError extends Error {
  constructor(message, type = 'INTERNAL') {
    super(message);
    this.type = type;
    this.timestamp = new Date().toISOString();
  }
}

// 主Worker逻辑
const worker_default = {
  async fetch(request, env, ctx) {
    try {
      // 初始化配置
      initConfig(env);
      
      const upgradeHeader = request.headers.get("Upgrade");
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        return handleHttpRequest(request);
      } else {
        return await trojanOverWSHandler(request);
      }
    } catch (err) {
      logger.error('Main handler error:', err);
      return new Response(err.toString(), { 
        status: err.type === 'AUTH' ? 403 : 500 
      });
    }
  }
};

// 初始化配置
function initConfig(env) {
  config.proxyIP = env.PROXYIP || config.proxyIP;
  config.debug = env.DEBUG === 'true' || config.debug;
  logger.debug('Configuration loaded:', config);
}

// HTTP请求处理
async function handleHttpRequest(request) {
  const url = new URL(request.url);
  switch (url.pathname) {
    case "/link":
      return generateTrojanLink(request);
    case "/health":
      return healthCheck();
    default:
      return new Response("404 Not found", { status: 404 });
  }
}

// 生成Trojan链接
function generateTrojanLink(request) {
  const host = request.headers.get('Host');
  return new Response(
    `trojan://${config.sha224Password}@${host}:443/?type=ws&host=${host}&security=tls`, 
    {
      status: 200,
      headers: { "Content-Type": "text/plain;charset=utf-8" }
    }
  );
}

// 健康检查
function healthCheck() {
  return new Response(
    JSON.stringify({
      status: 'ok',
      connections: connectionPool.size,
      memoryUsage: process.memoryUsage().rss
    }), 
    {
      headers: { 'Content-Type': 'application/json' }
    }
  );
}

// Trojan over WebSocket处理
async function trojanOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let address = "";
  let portWithRandomLog = "";

  const log = (info, event) => {
    logger.info(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };

  try {
    await readableWebSocketStream.pipeTo(new WritableStream({
      async write(chunk) {
        if (remoteSocketWrapper.value) {
          return writeToSocket(remoteSocketWrapper.value, chunk);
        }

        const { hasError, message, portRemote, addressRemote, rawClientData } = 
          await parseTrojanHeader(chunk);
        
        if (hasError) {
          throw new ProxyError(message, 'AUTH');
        }

        address = addressRemote;
        portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
        
        await handleTCPOutBound(
          remoteSocketWrapper, 
          addressRemote, 
          portRemote, 
          rawClientData, 
          webSocket, 
          log
        );
      },
      close() { log('WebSocket stream closed'); },
      abort(reason) { log('WebSocket stream aborted', reason); }
    }));
  } catch (err) {
    logger.error('WebSocket pipe error:', err);
    safeCloseWebSocket(webSocket);
  }

  return new Response(null, { status: 101, webSocket: client });
}

// 获取或创建连接
async function getOrCreateConnection(address, port) {
  const key = `${address}:${port}`;
  
  if (connectionPool.has(key)) {
    const conn = connectionPool.get(key);
    if (conn.readyState === 'open') return conn;
    connectionPool.delete(key);
  }

  if (connectionPool.size >= config.maxConnections) {
    throw new ProxyError('Connection pool exhausted', 'CAPACITY');
  }

  logger.debug(`Creating new connection to ${key}`);
  const newConn = await connect({ hostname: address, port });
  newConn.on('close', () => connectionPool.delete(key));
  connectionPool.set(key, newConn);
  return newConn;
}

// 写入socket数据
async function writeToSocket(socket, chunk) {
  const writer = socket.writable.getWriter();
  try {
    await writer.write(chunk);
  } finally {
    writer.releaseLock();
  }
}

// 处理TCP出站连接
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = await getOrCreateConnection(address, port);
    remoteSocket.value = tcpSocket;
    log(`Connected to ${address}:${port}`);
    await writeToSocket(tcpSocket, rawClientData);
    return tcpSocket;
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, log);
}

// 远程socket转WebSocket
async function remoteSocketToWS(remoteSocket, webSocket, log) {
  try {
    await remoteSocket.readable.pipeTo(new WritableStream({
      write(chunk) {
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          webSocket.send(chunk);
        }
      },
      close() { log('Remote socket closed'); },
      abort(reason) { log('Remote socket aborted', reason); }
    }));
  } catch (error) {
    logger.error('Remote to WS error:', error);
  } finally {
    safeCloseWebSocket(webSocket);
  }
}

// 以下辅助函数保持不变（与原始代码相同）
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  /* 原实现保持不变 */
}

async function parseTrojanHeader(buffer) {
  /* 原实现保持不变 */
}

function isValidSHA224(hash) {
  /* 原实现保持不变 */
}

function base64ToArrayBuffer(base64Str) {
  /* 原实现保持不变 */
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  /* 原实现保持不变 */
}

export default worker_default;
