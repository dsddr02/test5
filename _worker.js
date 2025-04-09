import { connect } from "cloudflare:sockets";

// Configuration block
let subscriptionPath = "sub";
let myUUID = "550e8400-e29b-41d4-a716-446655440000";
let defaultNodeName = "节点";
let proxyIP = "yx1.pp876.dpdns.org";
let fakeWebsite = "";

// Web entry point
export default {
  async fetch(request, env) {
    subscriptionPath = env.SUB_PATH ?? subscriptionPath;
    myUUID = env.SUB_UUID ?? myUUID;
    defaultNodeName = env.SUB_NAME ?? defaultNodeName;
    proxyIP = env.PROXY_IP ?? proxyIP;
    fakeWebsite = env.FAKE_WEB ?? fakeWebsite;

    const upgradeHeader = request.headers.get("Upgrade");
    const url = new URL(request.url);

    if (!upgradeHeader || upgradeHeader !== "websocket") {
      const encodedSubscriptionPath = encodeURIComponent(subscriptionPath);
      switch (url.pathname) {
        case `/${encodedSubscriptionPath}`:
          const userAgent = request.headers.get("User-Agent")?.toLowerCase() || "";
          const configGenerators = {
            v2ray: v2rayConfig,
            default: generateHintPage,
          };
          const tool = Object.keys(configGenerators).find((tool) => userAgent.includes(tool));
          const generateConfig = configGenerators[tool || "default"];
          return generateConfig(request.headers.get("Host"));
        default:
          if (fakeWebsite) {
            url.hostname = fakeWebsite;
            url.protocol = "https:";
            const fakeRequest = new Request(url, request);
            return fetch(fakeRequest);
          } else {
            return generateProjectInfoPage();
          }
      }
    } else if (upgradeHeader === "websocket") {
      return await upgradeWSRequest(request);
    }
  },
};

// Core script architecture
async function upgradeWSRequest(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  const secWebSocketProtocol = request.headers.get("sec-websocket-protocol");

  if (!secWebSocketProtocol) {
    return new Response("WebSocket protocol header missing", { status: 400 });
  }

  const decodedData = decodeBase64(secWebSocketProtocol);
  const { tcpSocket, initialWriteData } = await parseVLHeader(decodedData);
  if (!tcpSocket) {
    return new Response("Invalid VL header or UUID", { status: 400 });
  }
  establishTunnel(webSocket, tcpSocket, initialWriteData);
  return new Response(null, { status: 101, webSocket: client });
}

function decodeBase64(encodedString) {
  const base64 = encodedString.replace(/-/g, "+").replace(/_/g, "/");
  const decodedString = atob(base64);
  return Uint8Array.from(decodedString, (c) => c.charCodeAt(0)).buffer;
}

async function parseVLHeader(vlData) {
  const keyBytes = new Uint8Array(vlData.slice(1, 17));
  if (validateVLKey(keyBytes) !== myUUID) {
    return null;
  }

  const dataOffset = new Uint8Array(vlData)[17];
  const portStartIndex = 18 + dataOffset + 1;
  const portBuffer = vlData.slice(portStartIndex, portStartIndex + 2);
  const targetPort = new DataView(portBuffer).getUint16(0);

  const addressStartIndex = portStartIndex + 2;
  const addressTypeBuffer = new Uint8Array(vlData.slice(addressStartIndex, addressStartIndex + 1));
  const addressType = addressTypeBuffer[0];
  let addressLength = 0;
  let targetAddress = "";
  let addressInfoIndex = addressStartIndex + 1;

  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      targetAddress = new Uint8Array(vlData.slice(addressInfoIndex, addressInfoIndex + addressLength)).join(".");
      break;
    case 2: // Domain
      addressLength = new Uint8Array(vlData.slice(addressInfoIndex, addressInfoIndex + 1))[0];
      addressInfoIndex += 1;
      targetAddress = new TextDecoder().decode(vlData.slice(addressInfoIndex, addressInfoIndex + addressLength));
      break;
    case 3: // IPv6
      addressLength = 16;
      const dataView = new DataView(vlData.slice(addressInfoIndex, addressInfoIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      targetAddress = ipv6.join(":");
      break;
  }

  const initialWriteData = vlData.slice(addressInfoIndex + addressLength);

  const [proxyHost, proxyPortStr] = proxyIP.split(":");
  const proxyPort = Number(proxyPortStr) || 443;

  try {
    const tcpSocket = await connect({
      hostname: proxyHost,
      port: proxyPort,
    });
    return { tcpSocket, initialWriteData };
  } catch (error) {
    console.error("Error connecting to proxy:", error);
    return { tcpSocket: null, initialWriteData: null };
  }
}

function validateVLKey(arr, offset = 0) {
  let uuid = "";
  for (let i = 0; i < 16; i++) {
    uuid += byteToHex[arr[offset + i]];
    if ([3, 5, 7, 9].includes(i)) {
      uuid += "-";
    }
  }
  return uuid.toLowerCase();
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i < 16 ? "0" : "") + i.toString(16));

async function establishTunnel(webSocket, tcpSocket, initialWriteData) {
  const tcpWriter = tcpSocket.writable.getWriter();
  await webSocket.send(new Uint8Array([0, 0]).buffer);

  tcpSocket.readable.pipeTo(
    new WritableStream({
      async write(chunk) {
        try {
          await webSocket.send(chunk);
        } catch (error) {
          console.error("Error sending data to WebSocket:", error);
          tcpSocket.close();
        }
      },
      close() {
        webSocket.close();
      },
      abort(reason) {
        console.error("TCP readable stream aborted:", reason);
        webSocket.close();
      },
    })
  );

  const webSocketStream = new ReadableStream({
    start(controller) {
      if (initialWriteData) {
        controller.enqueue(initialWriteData);
        initialWriteData = null;
      }
      webSocket.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });
      webSocket.addEventListener("close", () => {
        controller.close();
        tcpSocket.close();
      });
      webSocket.addEventListener("error", (error) => {
        console.error("WebSocket error:", error);
        controller.error(error);
        tcpSocket.close();
      });
    },
  });

  webSocketStream.pipeTo(
    new WritableStream({
      async write(chunk) {
        try {
          await tcpWriter.write(chunk);
        } catch (error) {
          console.error("Error writing to TCP socket:", error);
          webSocket.close();
          tcpSocket.close();
        }
      },
      close() {
        tcpWriter.close();
        tcpSocket.close();
      },
      abort(reason) {
        console.error("WebSocket readable stream aborted:", reason);
        tcpWriter.close();
        tcpSocket.close();
      },
    })
  );
}

function generateProjectInfoPage() {
  const projectInfo = `
<title>项目介绍</title>
<style>
  body {
    font-size: 25px;
  }
</style>
<pre>
<strong>edge-tunnel</strong>

这是一个基于CF平台的VLESS代理服务
默认使用 ip.sb 作为代理地址

vless://${myUUID}@ip.sb:443?encryption=none&security=tls&sni=your-hostname&fp=chrome&type=ws&host=your-hostname&path=/?ed=9999#默认节点
</pre>
`;

  return new Response(projectInfo, {
    status: 200,
    headers: { "Content-Type": "text/html;charset=utf-8" },
  });
}

function generateHintPage() {
  const hintPage = `
<title>订阅-${subscriptionPath}</title>
<style>
  body {
    font-size: 25px;
  }
</style>
<strong>请把链接导入v2ray客户端</strong>
`;
  return new Response(hintPage, {
    status: 200,
    headers: { "Content-Type": "text/html;charset=utf-8" },
  });
}

function v2rayConfig(hostName) {
  const path = encodeURIComponent("/?ed=9999");
  const configContent = `vless://${myUUID}@${proxyIP.split(":")[0]}:443?encryption=none&security=tls&sni=${hostName}&fp=chrome&type=ws&host=${hostName}&path=${path}#${defaultNodeName}`;

  return new Response(configContent, {
    status: 200,
    headers: { "Content-Type": "text/plain;charset=utf-8" },
  });
}
