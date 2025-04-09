import { connect } from "cloudflare:sockets";

// 配置默认值
const DEFAULT_CONFIG = {
  uuid: "550e8400-e29b-41d4-a716-446655440000",
  fallbackIp: "ts.hpc.tw:443",
  fakeWebsite: "www.baidu.com",
  // 新增默认协议头配置
  defaultProtocols: [
    "eyJ2IjoiIiwiaWQiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJhZGRyIjoiZHN0LmFkZHIiLCJwb3J0Ijo0NDN9" // 示例base64数据
  ]
};

export default {
  async fetch(request, env) {
    const config = {
      uuid: env.SUB_UUID || DEFAULT_CONFIG.uuid,
      fallbackIp: env.PROXY_IP || DEFAULT_CONFIG.fallbackIp,
      fakeWebsite: env.FAKE_WEB || DEFAULT_CONFIG.fakeWebsite,
      defaultProtocols: env.DEFAULT_PROTOCOLS 
        ? JSON.parse(env.DEFAULT_PROTOCOLS) 
        : DEFAULT_CONFIG.defaultProtocols
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
    // 头部处理增强：尝试多个可能的头部字段
    let protocolHeader = [
      request.headers.get("Sec-WebSocket-Protocol"),
      request.headers.get("X-Protocol"),
      request.headers.get("Proxy-Authorization")
    ].find(Boolean);

    // 如果头部不存在，使用默认值（开发环境调试用）
    if (!protocolHeader && config.defaultProtocols?.length > 0) {
      console.warn("Using fallback protocol header");
      protocolHeader = config.defaultProtocols[0];
    }

    if (!protocolHeader) {
      throw new Error("Missing required protocol header. 需要以下任一头部: Sec-WebSocket-Protocol, X-Protocol");
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

// 协议验证增强版
// 增强版协议验证
function validateProtocol(header, expectedUuid) {
  try {
    // 调试日志
    console.log("Received protocol header:", header);
    
    // 解码Base64
    let buffer;
    try {
      buffer = base64Decode(header);
    } catch (e) {
      throw new Error(`Base64解码失败: ${e.message}`);
    }

    // 调试解码后数据
    console.log("Decoded data length:", buffer.byteLength);
    if (buffer.byteLength > 0) {
      console.log("First 3 bytes:", 
        new Uint8Array(buffer.slice(0, 3)).join(','));
    }

    // 验证最小长度
    const MIN_VLESS_LENGTH = 18;
    if (buffer.byteLength < MIN_VLESS_LENGTH) {
      throw new Error(`数据过短 (${buffer.byteLength} < ${MIN_VLESS_LENGTH})`);
    }

    const view = new DataView(buffer);
    
    // 验证版本号 (必须为0x00)
    const version = view.getUint8(0);
    if (version !== 0) {
      throw new Error(`无效版本号: ${version} (应为0)`);
    }
    
    // 提取并验证UUID
    const uuidBytes = new Uint8Array(buffer.slice(1, 17));
    const receivedUuid = uuidToHex(uuidBytes);
    if (receivedUuid !== expectedUuid.toLowerCase()) {
      console.error("UUID不匹配:", {
        received: receivedUuid,
        expected: expectedUuid.toLowerCase()
      });
      throw new Error("UUID验证失败");
    }

    // 返回解析结果
    return {
      addressType: view.getUint8(17),
      buffer: buffer,
      offset: 18,
      raw: new Uint8Array(buffer)
    };
  } catch (e) {
    throw new Error(`协议验证失败: ${e.message}`);
  }
}

// 增强版Base64解码
function base64Decode(str) {
  try {
    // 处理URL安全的Base64
    let sanitized = String(str)
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/\s/g, '');
    
    // 补全padding
    const padLength = 4 - (sanitized.length % 4);
    if (padLength < 4) {
      sanitized += '='.repeat(padLength);
    }
    
    // 解码
    const decoded = atob(sanitized);
    return Uint8Array.from(decoded, c => c.charCodeAt(0)).buffer;
  } catch (e) {
    throw new Error(`Base64解码错误: ${e.message}`);
  }
}
// 地址解析增强版
function parseVlessAddress({ addressType, buffer, offset = 0 }) {
  const view = new DataView(buffer);
  let addressLength = 0;
  let addressValue = "";
  let newOffset = offset;

  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      addressValue = Array.from(new Uint8Array(buffer, newOffset, 4))
        .join(".");
      newOffset += 4;
      break;
      
    case 2: // Domain
      addressLength = view.getUint8(newOffset);
      newOffset += 1;
      addressValue = new TextDecoder()
        .decode(new Uint8Array(buffer, newOffset, addressLength));
      newOffset += addressLength;
      break;
      
    case 3: // IPv6
      addressLength = 16;
      const ipv6Parts = [];
      for (let i = 0; i < 8; i++) {
        ipv6Parts.push(view.getUint16(newOffset + i * 2).toString(16));
      }
      addressValue = ipv6Parts.join(":");
      newOffset += 16;
      break;
      
    default:
      throw new Error(`Unsupported address type: ${addressType}`);
  }

  // 解析端口
  const port = view.getUint16(newOffset);
  newOffset += 2;

  return {
    address: addressValue,
    port: port,
    remaining: buffer.slice(newOffset),
    raw: new Uint8Array(buffer)
  };
}

// 连接建立增强版
async function establishConnection(target, fallback) {
  const primaryOptions = {
    hostname: target.address,
    port: target.port,
    allowHalfOpen: false
  };

  const connectionAttempts = [
    { type: "primary", options: primaryOptions }
  ];

  // 添加备用连接配置
  if (fallback) {
    const [host, port] = fallback.includes(":") 
      ? fallback.split(":") 
      : [fallback, 443];
    connectionAttempts.push({
      type: "fallback",
      options: {
        hostname: host,
        port: Number(port) || 443
      }
    });
  }

  // 尝试所有可用连接
  const errors = [];
  for (const attempt of connectionAttempts) {
    try {
      console.log(`Attempting ${attempt.type} connection to ${attempt.options.hostname}:${attempt.options.port}`);
      const socket = await connect(attempt.options);
      await socket.opened;
      return socket;
    } catch (error) {
      errors.push(`${attempt.type} failed: ${error.message}`);
      console.error(`Connection ${attempt.type} failed:`, error);
    }
  }

  throw new Error(`All connection attempts failed:\n${errors.join("\n")}`);
}

// 流处理增强版
function setupStreaming(webSocket, tcpSocket, initialData) {
  const tcpWriter = tcpSocket.writable.getWriter();
  
  // 发送初始握手数据
  webSocket.send(new Uint8Array([0, 0])).catch(console.error);
// 注意右括号的位置变化
  // TCP → WebSocket
  tcpSocket.readable.pipeTo(new WritableStream({
    write(chunk) {
      webSocket.send(chunk).catch(err => {
        console.error("TCP→WS write error:", err);
        tcpWriter.abort(err).catch(() => {});
      });
    },
    close() {
      webSocket.close(1000, "TCP stream ended");
    },
    abort(err) {
      console.error("TCP→WS stream aborted:", err);
      webSocket.close(1011, err.message);
    }
  }));

  // WebSocket → TCP
  const wsStream = new ReadableStream({
    start(controller) {
      if (initialData && initialData.byteLength > 0) {
        controller.enqueue(initialData);
      }
      
      webSocket.addEventListener("message", ({ data }) => {
        controller.enqueue(data);
      });
      
      webSocket.addEventListener("close", () => {
        controller.close();
        tcpWriter.close().catch(() => {});
      });
      
      webSocket.addEventListener("error", (err) => {
        controller.error(err);
        tcpWriter.abort(err).catch(() => {});
      });
    }
  });

  wsStream.pipeTo(new WritableStream({
    write(chunk) {
      return tcpWriter.write(chunk).catch(err => {
        console.error("WS→TCP write error:", err);
        webSocket.close(1011, err.message);
        throw err;
      });
    },
    close() {
      return tcpWriter.close().catch(console.error);
    },
    abort(err) {
      tcpWriter.abort(err).catch(() => {});
    }
  }));
}

// 工具函数
function base64Decode(str) {
  const sanitized = String(str)
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(str.length + (4 - str.length % 4) % 4, '=');
  
  try {
    return Uint8Array.from(atob(sanitized), c => c.charCodeAt(0)).buffer;
  } catch (e) {
    throw new Error(`Base64 decode failed: ${e.message}`);
  }
}

function uuidToHex(bytes) {
  if (!bytes || bytes.length !== 16) return "";
  return [...bytes]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
}
