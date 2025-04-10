// src/worker.js
import { connect } from "cloudflare:sockets";

// Configuration settings
const settings = {
  hashedKey: '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88',
  serverAddress: "",
  requestTimeout: 30000,
  maxActiveConnections: 100,
  enableDebug: false
};

// Connection manager
const activeConnections = new Map();

// Logger utility
const logUtil = {
  debug(...args) {
    if (settings.enableDebug) console.debug(`[DEBUG][${new Date().toISOString()}]`, ...args);
  },
  info(...args) {
    console.log(`[INFO][${new Date().toISOString()}]`, ...args);
  },
  error(...args) {
    console.error(`[ERROR][${new Date().toISOString()}]`, ...args);
  }
};

// Custom error class
class AppError extends Error {
  constructor(message, category = 'INTERNAL') {
    super(message);
    this.category = category;
    this.timestamp = new Date().toISOString();
  }
}

const mainWorker = {
  async fetch(request, env, ctx) {
    try {
      initializeSettings(env);
      
      if (request.headers.get("Upgrade") !== "websocket") {
        return handleHttpRequest(request);
      } else {
        return await processWebSocketRequest(request);
      }
    } catch (err) {
      logUtil.error('Request processing error:', err);
      return new Response(err.toString(), { 
        status: err.category === 'AUTH' ? 403 : 500 
      });
    }
  }
};

function initializeSettings(env) {
  settings.serverAddress = env.SERVER_ADDRESS || settings.serverAddress;
  settings.enableDebug = env.DEBUG === 'true' || settings.enableDebug;
  logUtil.debug('Loaded configuration:', settings);
}

async function handleHttpRequest(request) {
  const url = new URL(request.url);
  switch (url.pathname) {
    case "/generate-link":
      return generateProxyLink(request);
    case "/status":
      return checkServiceHealth();
    default:
      return new Response("404 Not found", { status: 404 });
  }
}

function generateProxyLink(request) {
  const host = request.headers.get('Host');
  return new Response(
    `trojan://${settings.hashedKey}@${host}:443/?type=ws&host=${host}&security=tls`, 
    {
      status: 200,
      headers: { "Content-Type": "text/plain;charset=utf-8" }
    }
  );
}
// 将 WebSocket 的 readable 部分转换为可读流
function createSocketReadableStream(webSocket) {
  return new ReadableStream({
    start(controller) {
      webSocket.onmessage = (event) => {
        if (event.data) {
          controller.enqueue(event.data);
        }
      };

      webSocket.onerror = (err) => {
        controller.error(new Error('WebSocket error: ' + err.message));
      };

      webSocket.onclose = () => {
        controller.close();
      };
    },
    cancel() {
      webSocket.close();
    }
  });
}

function checkServiceHealth() {
  return new Response(
    JSON.stringify({
      status: 'operational',
      activeConnections: activeConnections.size
    }), 
    {
      headers: { 'Content-Type': 'application/json' }
    }
  );
}

async function processWebSocketRequest(request) {
  const socketPair = new WebSocketPair();
  const [clientSocket, serverSocket] = Object.values(socketPair);
  serverSocket.accept();

  try {
    await handleClientSocket(serverSocket, request);
  } catch (err) {
    logUtil.error('WebSocket processing error:', err);
    closeWebSocketSafely(serverSocket);
  }

  return new Response(null, { status: 101, webSocket: clientSocket });
}

async function handleClientSocket(socket, request) {
  const readableStream = createSocketReadableStream(socket);

  let remoteConnection = { instance: null };
  let remoteAddress = "";
  let remotePort = "";

  await readableStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (remoteConnection.instance) {
        return sendDataToSocket(remoteConnection.instance, chunk);
      }

      const { error, message, targetPort, targetAddress, initialPayload } = await extractConnectionData(chunk);
      if (error) {
        throw new AppError(message, 'AUTH');
      }

      remoteAddress = targetAddress;
      remotePort = targetPort;

      await establishOutboundConnection(remoteConnection, targetAddress, targetPort, initialPayload, socket);
    },
    close() { logUtil.info('Client socket closed'); },
    abort(reason) { logUtil.info('Client socket aborted', reason); }
  }));
}

async function establishOutboundConnection(remoteConn, address, port, payload, clientSocket) {
  remoteConn.instance = await getOrCreateRemoteConnection(address, port);
  logUtil.info(`Connected to ${address}:${port}`);
  await sendDataToSocket(remoteConn.instance, payload);
  relayDataBetweenSockets(remoteConn.instance, clientSocket);
}

async function getOrCreateRemoteConnection(address, port) {
  const connKey = `${address}:${port}`;
  if (activeConnections.has(connKey)) {
    const existingConn = activeConnections.get(connKey);
    if (existingConn.readyState === 'open') return existingConn;
    activeConnections.delete(connKey);
  }

  if (activeConnections.size >= settings.maxActiveConnections) {
    throw new AppError('Max connections reached', 'CAPACITY');
  }

  logUtil.debug(`Opening new connection to ${connKey}`);
  const newConnection = await connect({ hostname: address, port });
  newConnection.on('close', () => activeConnections.delete(connKey));
  activeConnections.set(connKey, newConnection);
  return newConnection;
}

async function sendDataToSocket(socket, data) {
  const writer = socket.writable.getWriter();
  try {
    await writer.write(data);
  } finally {
    writer.releaseLock();
  }
}

async function relayDataBetweenSockets(sourceSocket, destinationSocket) {
  try {
    await sourceSocket.readable.pipeTo(new WritableStream({
      write(chunk) {
        if (destinationSocket.readyState === 1) {
          destinationSocket.send(chunk);
        }
      },
      close() { logUtil.info('Remote connection closed'); },
      abort(reason) { logUtil.info('Remote connection aborted', reason); }
    })).catch(error => {
      logUtil.error('Data relay failed:', error);
      closeWebSocketSafely(destinationSocket);
    });
  } catch (err) {
    logUtil.error('Relay error:', err);
  }
}

function closeWebSocketSafely(socket) {
  if (socket.readyState < 2) {
    socket.close();
  }
}

export default mainWorker;
