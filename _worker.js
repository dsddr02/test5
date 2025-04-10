import { connect } from "cloudflare:sockets";

const trojanWorker = {
    async fetch(request, env) {
        try {
            // Configuration
            const authToken = env.AUTH_SECRET || '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';
            const proxyServer = env.FALLBACK_PROXY || '';
            
            // Validate authentication token
            if (!/^[0-9a-f]{56}$/i.test(authToken)) {
                return new Response('Invalid authentication configuration', { status: 500 });
            }

            // Handle WebSocket connections
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader === 'websocket') {
                return handleWebSocketConnection(request, authToken, proxyServer);
            }

            // Handle HTTP requests
            const requestUrl = new URL(request.url);
            if (requestUrl.pathname === '/connection-details') {
                const hostname = request.headers.get('Host');
                return new Response(
                    `trojan://${authToken}@${hostname}:443/?type=ws&host=${hostname}&security=tls`,
                    { headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
                );
            }

            return new Response('Endpoint not found', { status: 404 });

        } catch (error) {
            return new Response(`Server error: ${error.message}`, { status: 500 });
        }
    }
};

async function handleWebSocketConnection(request, authToken, proxyServer) {
    try {
        const [clientSocket, serverSocket] = Object.values(new WebSocketPair());
        serverSocket.accept();

        let remoteConnection = null;
        const earlyData = processEarlyData(request.headers.get('Sec-WebSocket-Protocol') || '');

        const messageStream = new ReadableStream({
            start(controller) {
                serverSocket.addEventListener('message', (event) => {
                    controller.enqueue(event.data);
                });
                serverSocket.addEventListener('close', () => controller.close());
                serverSocket.addEventListener('error', (err) => controller.error(err));
                if (earlyData) controller.enqueue(earlyData);
            },
            cancel() { serverSocket.close(); }
        });

        await messageStream.pipeTo(new WritableStream({
            async write(dataChunk) {
                if (!remoteConnection) {
                    const connectionDetails = validateTrojanHeader(dataChunk, authToken);
                    if (connectionDetails.error) {
                        throw new Error(connectionDetails.error);
                    }
                    remoteConnection = await establishRemoteConnection(
                        connectionDetails.targetHost,
                        connectionDetails.targetPort,
                        proxyServer,
                        connectionDetails.payload,
                        serverSocket
                    );
                } else {
                    const writer = remoteConnection.writable.getWriter();
                    await writer.write(dataChunk);
                    writer.releaseLock();
                }
            }
        }));

        return new Response(null, {
            status: 101,
            webSocket: clientSocket
        });

    } catch (error) {
        return new Response(`WebSocket error: ${error.message}`, { status: 500 });
    }
}

function processEarlyData(protocolHeader) {
    try {
        const base64Data = protocolHeader.replace(/-/g, '+').replace(/_/g, '/');
        return Uint8Array.from(atob(base64Data), c => c.charCodeAt(0)).buffer;
    } catch {
        return null;
    }
}

function validateTrojanHeader(dataBuffer, expectedToken) {
    // Minimum header length check
    if (dataBuffer.byteLength < 56) {
        return { error: 'Invalid data length' };
    }

    // CRLF check (0x0D 0x0A)
    if (new Uint8Array(dataBuffer.slice(56, 58)).join() !== '13,10') {
        return { error: 'Invalid protocol header' };
    }

    // Password verification
    const receivedToken = new TextDecoder().decode(dataBuffer.slice(0, 56));
    if (receivedToken !== expectedToken) {
        return { error: 'Authentication failed' };
    }

    const protocolData = dataBuffer.slice(58);
    if (protocolData.byteLength < 6) {
        return { error: 'Incomplete protocol data' };
    }

    const dataView = new DataView(protocolData);
    if (dataView.getUint8(0) !== 1) {
        return { error: 'Only TCP connections supported' };
    }

    const addressType = dataView.getUint8(1);
    let position = 2;
    let hostAddress = '';

    switch (addressType) {
        case 1: // IPv4
            hostAddress = Array.from(new Uint8Array(protocolData.slice(position, position + 4))).join('.');
            position += 4;
            break;
        case 3: // Domain
            const domainLength = new Uint8Array(protocolData.slice(position, position + 1))[0];
            hostAddress = new TextDecoder().decode(protocolData.slice(position + 1, position + 1 + domainLength));
            position += 1 + domainLength;
            break;
        case 4: // IPv6
            const rawData = new DataView(protocolData.slice(position, position + 16));
            hostAddress = Array.from({length: 8}, (_, i) => rawData.getUint16(i * 2).toString(16)).join(':');
            position += 16;
            break;
        default:
            return { error: `Unsupported address type: ${addressType}` };
    }

    const portNumber = dataView.getUint16(position);
    return {
        targetHost: hostAddress,
        targetPort: portNumber,
        payload: protocolData.slice(position + 4)
    };
}

async function establishRemoteConnection(host, port, proxyServer, initialData, webSocket) {
    const connectionTarget = proxyServer || host;
    const socket = connect({
        hostname: connectionTarget,
        port: port
    });

    try {
        const writer = socket.writable.getWriter();
        await writer.write(initialData);
        writer.releaseLock();

        socket.readable.pipeTo(new WritableStream({
            write(chunk) {
                if (webSocket.readyState === 1) { // OPEN state
                    webSocket.send(chunk);
                }
            },
            close() {
                webSocket.close();
            },
            abort(err) {
                console.error('Remote connection error:', err);
                webSocket.close();
            }
        }));

        return socket;
    } catch (error) {
        webSocket.close();
        throw error;
    }
}

export default trojanWorker;
