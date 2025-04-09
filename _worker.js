import { connect } from "cloudflare:sockets";

// Configuration
let configUuid = "550e8400-e29b-41d4-a716-446655440000";
let fallbackIp = "yx1.pp876.dpdns.org";
let fakeWebsite = "www.baidu.com";

// Entry point
export default {
  async fetch(requestObject, environment) {
    configUuid = environment.SUB_UUID ?? configUuid;
    fallbackIp = environment.PROXY_IP ?? fallbackIp;
    fakeWebsite = environment.FAKE_WEB ?? fakeWebsite;

    const upgradeHeader = requestObject.headers.get("Upgrade");
    const requestUrl = new URL(requestObject.url);
    if (!upgradeHeader || upgradeHeader !== "websocket") {
      if (fakeWebsite) {
        requestUrl.hostname = fakeWebsite;
        requestUrl.protocol = "https:";
        const proxiedRequest = new Request(requestUrl, requestObject);
        return fetch(proxiedRequest);
      } else {
        return new Response("", { status: 200 }); // Return an empty response instead of the project page
      }
    } else if (upgradeHeader === "websocket") {
      return await handleWebSocketUpgrade(requestObject);
    }
  },
};

// Handles the WebSocket upgrade request
async function handleWebSocketUpgrade(requestObject) {
  const webSocketPair = new WebSocketPair();
  const [clientWebSocket, workerWebSocket] = Object.values(webSocketPair);
  workerWebSocket.accept();

  const encryptedDataHeader = requestObject.headers.get("sec-websocket-protocol");
  const decryptedData = base64Decode(encryptedDataHeader); // Decrypt target access data, passed to TCP handshake
  const { tcpSocket, initialWriteData } = await parseVlessHeader(decryptedData); // Parse VLESS data and perform TCP handshake
  establishPipeline(workerWebSocket, tcpSocket, initialWriteData);
  return new Response(null, { status: 101, webSocket: clientWebSocket });
}

// Uses base64 decoding
function base64Decode(encodedString) {
  encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");
  const decodedData = atob(encodedString);
  const decodedBuffer = Uint8Array.from(decodedData, (char) => char.charCodeAt(0));
  return decodedBuffer.buffer;
}

// Parses the VLESS header and creates the TCP handshake
async function parseVlessHeader(vlessData, tcpSocket) {
  if (validateVlessKey(new Uint8Array(vlessData.slice(1, 17))) !== configUuid) {
    return null;
  }

  const dataLocation = new Uint8Array(vlessData)[17];
  const portIndex = 18 + dataLocation + 1;
  const portBuffer = vlessData.slice(portIndex, portIndex + 2);
  const targetPort = new DataView(portBuffer).getUint16(0);

  const addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessData.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];

  let addressLength = 0;
  let targetAddress = "";
  let addressInfoIndex = addressIndex + 1;

  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      targetAddress = new Uint8Array(vlessData.slice(addressInfoIndex, addressInfoIndex + addressLength)).join(".");
      break;
    case 2: // Domain
      addressLength = new Uint8Array(vlessData.slice(addressInfoIndex, addressInfoIndex + 1))[0];
      addressInfoIndex += 1;
      targetAddress = new TextDecoder().decode(vlessData.slice(addressInfoIndex, addressInfoIndex + addressLength));
      break;
    case 3: // IPv6
      addressLength = 16;
      const dataView = new DataView(vlessData.slice(addressInfoIndex, addressInfoIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      targetAddress = ipv6.join(":");
      break;
  }

  const initialWriteData = vlessData.slice(addressInfoIndex + addressLength);
  try {
    tcpSocket = await connect({ hostname: targetAddress, port: targetPort });
    await tcpSocket.opened;
  } catch {
    if (fallbackIp) {
      let [fallbackIpAddress, fallbackIpPort] = fallbackIp.split(":");
      tcpSocket = await connect({
        hostname: fallbackIpAddress,
        port: Number(fallbackIpPort) || 443,
      });
    }
  }
  return { tcpSocket, initialWriteData };
}

// Validates the VLESS key
function validateVlessKey(byteArray, offset = 0) {
  const uuid = (
    keyFormat[byteArray[offset + 0]] +
    keyFormat[byteArray[offset + 1]] +
    keyFormat[byteArray[offset + 2]] +
    keyFormat[byteArray[offset + 3]] +
    "-" +
    keyFormat[byteArray[offset + 4]] +
    keyFormat[byteArray[offset + 5]] +
    "-" +
    keyFormat[byteArray[offset + 6]] +
    keyFormat[byteArray[offset + 7]] +
    "-" +
    keyFormat[byteArray[offset + 8]] +
    keyFormat[byteArray[offset + 9]] +
    "-" +
    keyFormat[byteArray[offset + 10]] +
    keyFormat[byteArray[offset + 11]] +
    keyFormat[byteArray[offset + 12]] +
    keyFormat[byteArray[offset + 13]] +
    keyFormat[byteArray[offset + 14]] +
    keyFormat[byteArray[offset + 15]]
  ).toLowerCase();
  return uuid;
}

const keyFormat = [];
for (let i = 0; i < 256; ++i) {
  keyFormat.push((i + 256).toString(16).slice(1));
}

// Creates the transmission pipeline between client WebSocket, Cloudflare, and the target
async function establishPipeline(clientWebSocket, tcpSocket, initialWriteData) {
  const tcpWriter = tcpSocket.writable.getWriter();
  await clientWebSocket.send(new Uint8Array([0, 0]).buffer); // Send WS handshake authentication information to the client

  tcpSocket.readable.pipeTo(
    new WritableStream({
      // Send data returned by the TCP interface back to the client via the WS interface
      async write(vlessData) {
        await clientWebSocket.send(vlessData);
      },
    })
  );

  const dataStream = new ReadableStream({
    // Listen for WS interface data and send it to the data stream
    async start(controller) {
      if (initialWriteData) {
        controller.enqueue(initialWriteData);
        initialWriteData = null;
      }
      clientWebSocket.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      }); // Listen for client WS interface messages and push them to the data stream
      clientWebSocket.addEventListener("close", () => {
        controller.close();
      }); // Listen for client WS interface close information and end the stream transmission
      clientWebSocket.addEventListener("error", () => {
        controller.close();
      }); // Listen for client WS interface error information and end the stream transmission
    },
  });

  dataStream.pipeTo(
    new WritableStream({
      // Send WS data received from the client to the TCP interface
      async write(vlessData) {
        await tcpWriter.write(vlessData);
      },
    })
  );
}
