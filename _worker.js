import { connect } from "cloudflare:sockets";

// Configuration
let configUuid = "550e8400-e29b-41d4-a716-446655440000";
let fallbackIp = "ts.hpc.tw";
let fakeWebsite = "www.baidu.com";

// Entry point
export default {
  async fetch(request, env) {
    // Apply environment variables
    configUuid = env.SUB_UUID || configUuid;
    fallbackIp = env.PROXY_IP || fallbackIp;
    fakeWebsite = env.FAKE_WEB || fakeWebsite;

    try {
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);

      // Handle non-WebSocket requests
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
        if (fakeWebsite) {
          url.hostname = fakeWebsite;
          url.protocol = "https:";
          const proxiedRequest = new Request(url, request);
          return fetch(proxiedRequest);
        }
        return new Response("", { status: 200 });
      }

      // Handle WebSocket upgrade
      return await handleWebSocketUpgrade(request);
    } catch (error) {
      console.error("Error processing request:", error);
      return new Response("Internal Server Error", { status: 500 });
    }
  },
};

// Handles the WebSocket upgrade request
async function handleWebSocketUpgrade(request) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  server.accept();

  try {
    // Verify required headers
    const protocolHeader = request.headers.get("sec-websocket-protocol");
    if (!protocolHeader) {
      throw new Error("Missing Sec-WebSocket-Protocol header");
    }

    // Decode and parse VLESS data
    const decryptedData = base64Decode(protocolHeader);
    const { tcpSocket, initialWriteData } = await parseVlessHeader(decryptedData);
    
    // Establish proxying pipeline
    establishPipeline(server, tcpSocket, initialWriteData);
    return new Response(null, { 
      status: 101, 
      webSocket: client,
      headers: {
        "Sec-WebSocket-Protocol": protocolHeader
      }
    });
  } catch (error) {
    console.error("WebSocket upgrade failed:", error);
    server.close(1011, error.message);
    return new Response(`WebSocket Error: ${error.message}`, { status: 400 });
  }
}

// Base64 decoding with validation
function base64Decode(encodedString) {
  if (!encodedString) {
    throw new Error("Empty encoded string");
  }

  try {
    // URL-safe base64 conversion
    const sanitized = encodedString
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .replace(/\s/g, "");
    
    // Add padding if needed
    const padLength = 4 - (sanitized.length % 4);
    const padded = padLength < 4 ? sanitized + "=".repeat(padLength) : sanitized;
    
    const decoded = atob(padded);
    return Uint8Array.from(decoded, (c) => c.charCodeAt(0)).buffer;
  } catch (error) {
    throw new Error(`Base64 decode failed: ${error.message}`);
  }
}

// Parses VLESS header and establishes TCP connection
async function parseVlessHeader(vlessData) {
  if (!vlessData || vlessData.byteLength < 18) {
    throw new Error("Invalid VLESS data");
  }

  const view = new DataView(vlessData);
  const uuidBytes = new Uint8Array(vlessData.slice(1, 17));
  
  // Validate UUID
  if (validateVlessKey(uuidBytes) !== configUuid) {
    throw new Error("UUID authentication failed");
  }

  const addressType = view.getUint8(17);
  let addressLength = 0;
  let addressIndex = 18;
  let targetAddress = "";

  // Parse address
  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      targetAddress = new Uint8Array(vlessData.slice(addressIndex, addressIndex + 4)).join(".");
      break;
    case 2: // Domain
      addressLength = view.getUint8(addressIndex);
      addressIndex += 1;
      targetAddress = new TextDecoder().decode(
        vlessData.slice(addressIndex, addressIndex + addressLength)
      );
      break;
    case 3: // IPv6
      addressLength = 16;
      const ipv6Parts = [];
      for (let i = 0; i < 8; i++) {
        ipv6Parts.push(view.getUint16(addressIndex + i * 2).toString(16));
      }
      targetAddress = ipv6Parts.join(":");
      break;
    default:
      throw new Error(`Unsupported address type: ${addressType}`);
  }

  // Parse port
  const portIndex = addressIndex + addressLength;
  const targetPort = view.getUint16(portIndex);

  // Remaining data
  const initialWriteData = vlessData.slice(portIndex + 2);

  // Establish TCP connection
  try {
    const tcpSocket = await connect({
      hostname: targetAddress,
      port: targetPort,
    });
    await tcpSocket.opened;
    return { tcpSocket, initialWriteData };
  } catch (primaryError) {
    console.error("Primary connection failed:", primaryError);
    
    if (!fallbackIp) throw primaryError;
    
    try {
      const [host, port] = fallbackIp.includes(":") 
        ? fallbackIp.split(":") 
        : [fallbackIp, 443];
      
      const tcpSocket = await connect({
        hostname: host,
        port: Number(port) || 443,
      });
      await tcpSocket.opened;
      return { tcpSocket, initialWriteData };
    } catch (fallbackError) {
      console.error("Fallback connection failed:", fallbackError);
      throw new Error(`All connection attempts failed. Last error: ${fallbackError.message}`);
    }
  }
}

// UUID validation helper
function validateVlessKey(bytes) {
  if (!bytes || bytes.length !== 16) return "";
  
  const keyFormat = Array.from({ length: 256 }, (_, i) => 
    (i + 256).toString(16).slice(1)
  );
  
  return [
    keyFormat[bytes[0]], keyFormat[bytes[1]], 
    keyFormat[bytes[2]], keyFormat[bytes[3]], "-",
    keyFormat[bytes[4]], keyFormat[bytes[5]], "-",
    keyFormat[bytes[6]], keyFormat[bytes[7]], "-",
    keyFormat[bytes[8]], keyFormat[bytes[9]], "-",
    keyFormat[bytes[10]], keyFormat[bytes[11]], 
    keyFormat[bytes[12]], keyFormat[bytes[13]], 
    keyFormat[bytes[14]], keyFormat[bytes[15]]
  ].join("").toLowerCase();
}

// Creates data pipeline between WebSocket and TCP
async function establishPipeline(webSocket, tcpSocket, initialData) {
  const tcpWriter = tcpSocket.writable.getWriter();
  
  // Send handshake confirmation
  await webSocket.send(new Uint8Array([0, 0]).buffer);

  // TCP → WebSocket
  tcpSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      try {
        await webSocket.send(chunk);
      } catch (error) {
        console.error("TCP→WS write error:", error);
        tcpWriter.abort(error);
      }
    },
    close() {
      console.log("TCP→WS stream closed");
      webSocket.close(1000);
    },
    abort(error) {
      console.error("TCP→WS stream aborted:", error);
      webSocket.close(1011, error.message);
    }
  }));

  // WebSocket → TCP
  const wsStream = new ReadableStream({
    start(controller) {
      if (initialData) {
        controller.enqueue(initialData);
      }
      
      webSocket.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });
      
      webSocket.addEventListener("close", () => {
        controller.close();
        tcpWriter.close().catch(console.error);
      });
      
      webSocket.addEventListener("error", (error) => {
        controller.error(error);
        tcpWriter.abort(error).catch(console.error);
      });
    }
  });

  wsStream.pipeTo(new WritableStream({
    async write(chunk) {
      try {
        await tcpWriter.write(chunk);
      } catch (error) {
        console.error("WS→TCP write error:", error);
        webSocket.close(1011, error.message);
      }
    },
    close() {
      tcpWriter.close().catch(console.error);
    },
    abort(error) {
      tcpWriter.abort(error).catch(console.error);
    }
  }));
}
