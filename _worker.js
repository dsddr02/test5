import { connect } from "cloudflare:sockets";

const worker = {
    async fetch(request, env) {
        try {
            const authToken = env.AUTH_SECRET || 'default_token_here';
            const fallbackProxy = env.FALLBACK_PROXY || '';
            
            if (!/^[0-9a-f]{56}$/i.test(authToken)) {
                return new Response('Invalid authentication token', { status: 401 });
            }

            // Handle WebSocket upgrade
            if (request.headers.get('Upgrade') === 'websocket') {
                return handleWebSocket(request, authToken, fallbackProxy);
            }

            // Handle HTTP requests
            const url = new URL(request.url);
            if (url.pathname === '/connection-info') {
                return new Response(
                    `trojan://${authToken}@${request.headers.get('Host')}:443`,
                    { headers: { 'Content-Type': 'text/plain' } }
                );
            }

            return new Response('Not found', { status: 404 });
        } catch (error) {
            return new Response(error.message, { status: 500 });
        }
    }
};

async function handleWebSocket(request, authToken, fallbackProxy) {
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    
    // ... rest of your WebSocket handling logic ...
    
    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

// Export the worker as default
export default worker;
