// src/worker.js
import { connect as establishConnection } from "cloudflare:sockets";
let secretPhraseHash = '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';
let gatewayAddress = "";

if (!validateSecretPhraseHash(secretPhraseHash)) {
    throw new Error('secretPhraseHash is not valid');
}

const serviceWorker = {

    async fetch(incomingRequest, environmentVariables, context) {
        try {
            gatewayAddress = environmentVariables.PROXYIP || gatewayAddress;
            secretPhraseHash = environmentVariables.SHA224PASS || secretPhraseHash;
            const upgradeHeaderValue = incomingRequest.headers.get("Upgrade");
            if (!upgradeHeaderValue || upgradeHeaderValue !== "websocket") {
                const requestURL = new URL(incomingRequest.url);
                switch (requestURL.pathname) {
                    case "/link":
                        const currentHost = incomingRequest.headers.get('Host');
                        return new Response(`trojan://ca110us@${currentHost}:443/?type=ws&host=${currentHost}&security=tls`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    default:
                        return new Response("404 Resource Not Found", { status: 404 });
                }
            } else {
                return await handleTrojanOverWebSocket(incomingRequest);
            }
        } catch (error) {
            let errorDetail = error;
            return new Response(errorDetail.toString());
        }
    }
};

async function handleTrojanOverWebSocket(requestObject) {
    const webSocketConnection = new WebSocketPair();
    const [clientSocket, serverSocket] = Object.values(webSocketConnection);
    serverSocket.accept();
    let targetAddress = "";
    let targetPortWithIdentifier = "";
    const logEvent = (information, details) => {
        console.log(`[${targetAddress}:${targetPortWithIdentifier}] ${information}`, details || "");
    };
    const earlyDataProtocol = requestObject.headers.get("sec-websocket-protocol") || "";
    const readableClientStream = createReadableWebSocketStream(serverSocket, earlyDataProtocol, logEvent);
    let remoteConnectionWrapper = {
        value: null
    };
    let udpWriteStream = null;
    readableClientStream.pipeTo(new WritableStream({
        async write(dataChunk, streamController) {
            if (udpWriteStream) {
                return udpWriteStream(dataChunk);
            }
            if (remoteConnectionWrapper.value) {
                if (remoteConnectionWrapper.type === 'tcp') {
                    const writer = remoteConnectionWrapper.value.writable.getWriter();
                    await writer.write(dataChunk);
                    writer.releaseLock();
                    return;
                } else if (remoteConnectionWrapper.type === 'udp') {
                    // Handle UDP data forwarding here if needed.
                    // This part requires more context on how UDP should be handled over WebSocket.
                    // Typically, UDP over WebSocket involves encapsulating UDP packets within WebSocket messages.
                    // You'd need to define a specific format for this encapsulation.
                    logEvent("Received data for UDP, but UDP handling is not fully implemented in the write stream.");
                    return;
                }
            }
            const {
                hasProblem,
                errorMessage,
                remotePort = 443,
                remoteHostname = "",
                initialClientData,
                isUdp
            } = await parseTrojanHeaderData(dataChunk);
            targetAddress = remoteHostname;
            targetPortWithIdentifier = `${remotePort}--${Math.random()} ${isUdp ? 'udp' : 'tcp'}`;
            if (hasProblem) {
                throw new Error(errorMessage);
                return;
            }
            if (isUdp) {
                logEvent("Received UDP request, handling not fully implemented.");
                // Implement UDP handling logic here. This might involve:
                // 1. Establishing a UDP socket.
                // 2. Forwarding encapsulated UDP packets.
                // 3. Potentially using a separate mechanism for the UDP connection.
                // For now, we'll just log that a UDP request was received.
                streamController.error("UDP support is not fully implemented.");
            } else {
                manageTCPOutboundConnection(remoteConnectionWrapper, remoteHostname, remotePort, initialClientData, serverSocket, logEvent);
            }
        },
        close() {
            logEvent(`readableClientStream has closed`);
        },
        abort(reason) {
            logEvent(`readableClientStream was aborted`, JSON.stringify(reason));
        }
    })).catch((err) => {
        logEvent("readableClientStream pipeTo encountered an error", err);
    });
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: clientSocket
    });
}

async function parseTrojanHeaderData(bufferData) {
    if (bufferData.byteLength < 56) {
        return {
            hasProblem: true,
            errorMessage: "received insufficient data"
        };
    }
    let crLfPosition = 56;
    if (new Uint8Array(bufferData.slice(56, 57))[0] !== 0x0d || new Uint8Array(bufferData.slice(57, 58))[0] !== 0x0a) {
        return {
            hasProblem: true,
            errorMessage: "invalid header format (missing CRLF)"
        };
    }
    const clientPassword = new TextDecoder().decode(bufferData.slice(0, crLfPosition));
    if (clientPassword !== secretPhraseHash) {
        return {
            hasProblem: true,
            errorMessage: "incorrect password"
        };
    }

    const socks5Payload = bufferData.slice(crLfPosition + 2);
    if (socks5Payload.byteLength < 6) {
        return {
            hasProblem: true,
            errorMessage: "invalid SOCKS5 request payload"
        };
    }

    const dataView = new DataView(socks5Payload);
    const command = dataView.getUint8(0);
    const isUdp = command === 3; // 0x03 for UDP ASSOCIATE

    if (command !== 1 && command !== 3) {
        return {
            hasProblem: true,
            errorMessage: "unsupported SOCKS5 command, only CONNECT (TCP) and UDP ASSOCIATE are permitted",
            isUdp: false
        };
    }

    const addressType = dataView.getUint8(1);
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    let addressLengthValue = 0;
    let addressStartIndex = 2;
    let destinationAddress = "";
    switch (addressType) {
        case 1:
            addressLengthValue = 4;
            destinationAddress = new Uint8Array(
                socks5Payload.slice(addressStartIndex, addressStartIndex + addressLengthValue)
            ).join(".");
            break;
        case 3:
            addressLengthValue = new Uint8Array(
                socks5Payload.slice(addressStartIndex, addressStartIndex + 1)
            )[0];
            addressStartIndex += 1;
            destinationAddress = new TextDecoder().decode(
                socks5Payload.slice(addressStartIndex, addressStartIndex + addressLengthValue)
            );
            break;
        case 4:
            addressLengthValue = 16;
            const ipv6DataView = new DataView(socks5Payload.slice(addressStartIndex, addressStartIndex + addressLengthValue));
            const ipv6Parts = [];
            for (let i = 0; i < 8; i++) {
                ipv6Parts.push(ipv6DataView.getUint16(i * 2).toString(16));
            }
            destinationAddress = ipv6Parts.join(":");
            break;
        default:
            return {
                hasProblem: true,
                errorMessage: `unrecognized address type: ${addressType}`,
                isUdp: isUdp
            };
    }

    if (!destinationAddress) {
        return {
            hasProblem: true,
            errorMessage: `destination address is empty, address type: ${addressType}`,
            isUdp: isUdp
        };
    }

    const portStartIndex = addressStartIndex + addressLengthValue;
    const portBufferData = socks5Payload.slice(portStartIndex, portStartIndex + 2);
    const destinationPort = new DataView(portBufferData).getUint16(0);

    const initialDataStartIndex = portStartIndex + 2;
    const initialClientData = socks5Payload.slice(initialDataStartIndex);

    return {
        hasProblem: false,
        remoteHostname: destinationAddress,
        remotePort: destinationPort,
        initialClientData: initialClientData,
        isUdp: isUdp
    };
}

async function manageTCPOutboundConnection(remoteEndpoint, targetHostname, targetPort, initialData, clientWebSocket, logger) {
    async function initiateConnectionAndSend(hostname, port) {
        const remoteTCPSocket = establishConnection({
            hostname: hostname,
            port: port
        });
        remoteEndpoint.value = remoteTCPSocket;
        remoteEndpoint.type = 'tcp';
        logger(`established TCP connection to ${hostname}:${port}`);
        const writer = remoteTCPSocket.writable.getWriter();
        await writer.write(initialData);
        writer.releaseLock();
        return remoteTCPSocket;
    }
    async function attemptRetry() {
        const remoteTCPSocket = await initiateConnectionAndSend(gatewayAddress || targetHostname, targetPort);
        remoteTCPSocket.closed.catch((error) => {
            console.log("retry tcpSocket closure error", error);
        }).finally(() => {
            secureCloseWebSocket(clientWebSocket);
        });
        pipeRemoteToWebSocket(remoteTCPSocket, clientWebSocket, attemptRetry, logger);
    }
    const tcpSocket = await initiateConnectionAndSend(targetHostname, targetPort);
    pipeRemoteToWebSocket(tcpSocket, clientWebSocket, attemptRetry, logger);
}

function createReadableWebSocketStream(webSocketConnection, initialProtocol, loggingFunction) {
    let streamCancelled = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketConnection.addEventListener("message", (event) => {
                if (streamCancelled) {
                    return;
                }
                const messageData = event.data;
                controller.enqueue(messageData);
            });
            webSocketConnection.addEventListener("close", () => {
                secureCloseWebSocket(webSocketConnection);
                if (streamCancelled) {
                    return;
                }
                controller.close();
            });
            webSocketConnection.addEventListener("error", (err) => {
                loggingFunction("webSocketConnection encountered an error");
                controller.error(err);
            });
            const { earlyData, error } = decodeBase64ToArrayBuffer(initialProtocol);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            if (streamCancelled) {
                return;
            }
            loggingFunction(`readableStream was cancelled due to: ${reason}`);
            streamCancelled = true;
            secureCloseWebSocket(webSocketConnection);
        }
    });
    return stream;
}

async function pipeRemoteToWebSocket(remoteSocketConnection, webSocketConnection, retryFunction, loggerFunction) {
    let receivedInitialData = false;
    if (!remoteSocketConnection || !remoteSocketConnection.readable) {
        loggerFunction("pipeRemoteToWebSocket received an invalid remote socket.");
        secureCloseWebSocket(webSocketConnection);
        return;
    }
    await remoteSocketConnection.readable.pipeTo(
        new WritableStream({
            start() {},
            /**
             *
             * @param {Uint8Array} chunkData
             * @param {*} controller
             */
            async write(chunkData, controller) {
                receivedInitialData = true;
                if (webSocketConnection.readyState !== WEBSOCKET_OPEN_STATE) {
                    controller.error(
                        "webSocket connection is not currently open"
                    );
                }
                webSocketConnection.send(chunkData);
            },
            close() {
                loggerFunction(`remoteSocketConnection.readable has closed, receivedInitialData: ${receivedInitialData}`);
            },
            abort(reason) {
                console.error("remoteSocketConnection.readable was aborted", reason);
            }
        })
    ).catch((error) => {
        console.error(
            `pipeRemoteToWebSocket encountered an error:`,
            error.stack || error
        );
        secureCloseWebSocket(webSocketConnection);
    });
    if (receivedInitialData === false && retryFunction) {
        loggerFunction(`attempting retry`);
        retryFunction();
    }
}

function validateSecretPhraseHash(hashValue) {
    const sha224Pattern = /^[0-9a-f]{56}$/i;
    return sha224Pattern.test(hashValue);
}

function decodeBase64ToArrayBuffer(base64String) {
    if (!base64String) {
        return { error: null };
    }
    try {
        base64String = base64String.replace(/-/g, "+").replace(/_/g, "/");
        const decodedString = atob(base64String);
        const byteArray = Uint8Array.from(decodedString, (char) => char.charCodeAt(0));
        return { earlyData: byteArray.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

let WEBSOCKET_OPEN_STATE = 1;
let WEBSOCKET_CLOSING_STATE = 2;

function secureCloseWebSocket(socketObject) {
    try {
        if (socketObject.readyState === WEBSOCKET_OPEN_STATE || socketObject.readyState === WEBSOCKET_CLOSING_STATE) {
            socketObject.close();
        }
    } catch (error) {
        console.error("secureCloseWebSocket error occurred", error);
    }
}
export {
    serviceWorker as
    default
};
//# sourceMappingURL=worker.js.map
