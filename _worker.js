import { connect } from "cloudflare:sockets";

const mainWorker = {
    async handleRequest(request, environment, context) {
        try {
            const authToken = environment.AUTH_SECRET || '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';
            const fallbackProxy = environment.FALLBACK_PROXY || '';
            
            if (!/^[0-9a-f]{56}$/i.test(authToken)) {
                throw new Error('Invalid authentication token');
            }

            if (request.headers.get("Upgrade") === "websocket") {
                return establishWebSocketConnection(request, authToken, fallbackProxy);
            }

            const requestUrl = new URL(request.url);
            if (requestUrl.pathname === "/connection-info") {
                const domain = request.headers.get('Host');
                return new Response(`trojan://server-auth@${domain}:443/?type=ws&host=${domain}&security=tls`, {
                    headers: {"Content-Type": "text/plain;charset=utf-8"}
                });
            }
            
            return new Response("404 Not found", { status: 404 });
        } catch (error) {
            return new Response(error.toString());
        }
    }
};

async function establishWebSocketConnection(request, authToken, fallbackProxy) {
    const [clientSide, serverSide] = Object.values(new WebSocketPair());
    serverSide.accept();
    
    let destinationSocket = null;
    const initialData = extractInitialData(request.headers.get("sec-websocket-protocol") || "");
    
    const dataStream = new ReadableStream({
        start(controller) {
            serverSide.addEventListener("message", (event) => controller.enqueue(event.data));
            serverSide.addEventListener("close", () => controller.close());
            serverSide.addEventListener("error", (error) => controller.error(error));
            if (initialData) controller.enqueue(initialData);
        },
        cancel() { serverSide.close(); }
    });
    
    await dataStream.pipeTo(new WritableStream({
        async write(dataChunk) {
            if (!destinationSocket) {
                const { targetHost, targetPort, payload, error } = validateProtocolHeader(dataChunk, authToken);
                if (error) throw new Error(error);
                
                destinationSocket = await createRemoteConnection(targetHost, targetPort, fallbackProxy, payload, serverSide);
            } else {
                const dataWriter = destinationSocket.writable.getWriter();
                await dataWriter.write(dataChunk);
                dataWriter.releaseLock();
            }
        }
    })).catch(error => console.error("Data stream error:", error));
    
    return new Response(null, { status: 101, webSocket: clientSide });
}

function extractInitialData(protocolHeader) {
    try {
        return Uint8Array.from(atob(protocolHeader.replace(/-/g, "+").replace(/_/g, "/")), char => char.charCodeAt(0)).buffer;
    } catch {
        return null;
    }
}

async function validateProtocolHeader(dataBuffer, expectedToken) {
    if (dataBuffer.byteLength < 56) return { error: "invalid data length" };
    if (new Uint8Array(dataBuffer.slice(56, 58)).join() !== "13,10") return { error: "invalid header format" };
    
    if (new TextDecoder().decode(dataBuffer.slice(0, 56)) !== expectedToken) {
        return { error: "authentication failed" };
    }

    const protocolData = dataBuffer.slice(58);
    if (protocolData.byteLength < 6) return { error: "insufficient protocol data" };
    
    const commandType = new DataView(protocolData).getUint8(0);
    if (commandType !== 1) return { error: "only direct connections supported" };

    const addressFormat = new DataView(protocolData).getUint8(1);
    let position = 2, hostAddress = "";
    
    if (addressFormat === 1) { // IPv4
        hostAddress = Array.from(new Uint8Array(protocolData.slice(position, position + 4))).join(".");
        position += 4;
    } else if (addressFormat === 3) { // Domain
        const length = new Uint8Array(protocolData.slice(position, position + 1))[0];
        hostAddress = new TextDecoder().decode(protocolData.slice(position + 1, position + 1 + length));
        position += 1 + length;
    } else if (addressFormat === 4) { // IPv6
        const rawData = new DataView(protocolData.slice(position, position + 16));
        hostAddress = Array.from({length: 8}, (_, i) => rawData.getUint16(i * 2).toString(16)).join(":");
        position += 16;
    } else {
        return { error: `unsupported address format ${addressFormat}` };
    }

    const connectionPort = new DataView(protocolData.slice(position, position + 2)).getUint16(0);
    return { 
        targetHost: hostAddress, 
        targetPort: connectionPort, 
        payload: protocolData.slice(position + 4) 
    };
}

async function createRemoteConnection(host, port, proxy, initialPayload, webSocket) {
    const connectionTarget = proxy || host;
    const networkSocket = connect({ hostname: connectionTarget, port });
    
    const outputWriter = networkSocket.writable.getWriter();
    await outputWriter.write(initialPayload);
    outputWriter.releaseLock();
    
    networkSocket.readable.pipeTo(new WritableStream({
        write(data) { webSocket.send(data); },
        close() { webSocket.close(); }
    })).catch(() => webSocket.close());
    
    return networkSocket;
}

export default mainWorker;
