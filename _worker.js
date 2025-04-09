import { connect } from "cloudflare:sockets";

// 配置默认值
const DEFAULT_CONFIG = {
  uuid: "550e8400-e29b-41d4-a716-446655440000",
  fallbackIp: "ts.hpc.tw:443",
  fakeWebsite: "www.baidu.com"
};

export default {
  async fetch(request, env) {
    const config = {
      uuid: env.SUB_UUID || DEFAULT_CONFIG.uuid,
      fallbackIp: env.PROXY_IP || DEFAULT_CONFIG.fallbackIp,
      fakeWebsite: env.FAKE_WEB || DEFAULT_CONFIG.fakeWebsite
    };

    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      // 非WebSocket请求处理
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
        if (config.fakeWebsite) {
          url.hostname = config.fakeWebsite;
          return fetch(new Request(url, request));
        }
        return new Response("", { status: 200 });
      }

      // WebSocket升级处理
      return await handleWebSocketUpgrade(request, config);
    } catch (error) {
      console.error(`Processing Error: ${error.stack}`);
      return new Response(error.message, { status: 500 });
    }
  }
};

async function handleWebSocketUpgrade(request, config) {
  const wsPair = new WebSocketPair();
  const [client, server] = Object.values(wsPair);
  server.accept();

  try {
    // 严格协议检查
    const protocolHeader = request.headers.get("Sec-WebSocket-Protocol");
    if (!protocolHeader) {
      throw new Error("必须包含 Sec-WebSocket-Protocol 头部");
    }

    // 验证协议数据
    const vlessData = validateProtocol(protocolHeader, config.uuid);
    const target = parseVlessAddress(vlessData);
    
    // 建立连接
    const tcpSocket = await establishConnection(target, config.fallbackIp);
    setupStreaming(server, tcpSocket, vlessData.remaining);
    
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: {
        "Sec-WebSocket-Protocol": protocolHeader  // 回显协议头
      }
    });
  } catch (error) {
    server.close(1008, error.message);
    console.error(`WebSocket Error: ${error.stack}`);
    return new Response(error.message, { status: 400 });
  }
}

// 协议验证函数
function validateProtocol(header, expectedUuid) {
  try {
    const buffer = base64Decode(header);
    const view = new DataView(buffer);
    
    // 验证版本
    if (view.getUint8(0) !== 0) {
      throw new Error("无效的VLESS版本");
    }
    
    // 验证UUID
    const uuidBytes = new Uint8Array(buffer.slice(1, 17));
    if (uuidToHex(uuidBytes) !== expectedUuid.toLowerCase()) {
      throw new Error("UUID验证失败");
    }
    
    return {
      addressType: view.getUint8(17),
      addressStart: 18,
      buffer: buffer
    };
  } catch (e) {
    throw new Error(`协议验证失败: ${e.message}`);
  }
}

// 连接建立函数
async function establishConnection(target, fallback) {
  const primaryOptions = {
    hostname: target.address,
    port: target.port,
    allowHalfOpen: false
  };

  try {
    const socket = await connect(primaryOptions);
    await socket.opened;
    return socket;
  } catch (primaryError) {
    if (!fallback) throw primaryError;
    
    const [host, port] = fallback.includes(":") ? 
      fallback.split(":") : 
      [fallback, 443];
    
    try {
      const socket = await connect({
        hostname: host,
        port: Number(port) || 443
      });
      await socket.opened;
      return socket;
    } catch (fallbackError) {
      throw new Error(`所有连接尝试失败:\n主连接: ${primaryError.message}\n备用连接: ${fallbackError.message}`);
    }
  }
}

// 工具函数
function base64Decode(str) {
  const sanitized = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(str.length + (4 - str.length % 4) % 4, '=');
  
  return Uint8Array.from(atob(sanitized), c => c.charCodeAt(0)).buffer;
}

function uuidToHex(bytes) {
  return [...bytes]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
}
