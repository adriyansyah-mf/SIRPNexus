/**
 * Custom HTTP server: Next.js + WebSocket proxy to API gateway (same-origin WS; cookie auth).
 */
const http = require('http');
const next = require('next');
const httpProxy = require('http-proxy');

const dev = process.env.NODE_ENV !== 'production';
const hostname = process.env.HOSTNAME || '0.0.0.0';
const port = parseInt(process.env.PORT || '3000', 10);
const gw = (process.env.API_GATEWAY_URL || 'http://api-gateway:8000').replace(/\/$/, '');

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();
const proxy = httpProxy.createProxyServer({ ws: true, xfwd: true });

proxy.on('error', (err, req, res) => {
  console.error('[sirp] stream proxy error', err?.message || err);
  if (res && !res.headersSent && typeof res.writeHead === 'function') {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
  }
  try {
    res?.end?.('Bad gateway');
  } catch (_) {
    /* ignore */
  }
});

function isStreamPath(urlPath) {
  return urlPath === '/stream/events' || urlPath.startsWith('/stream/events/');
}

app.prepare().then(() => {
  const server = http.createServer((req, res) => {
    try {
      const pathOnly = (req.url || '').split('?')[0];
      if (isStreamPath(pathOnly)) {
        proxy.web(req, res, { target: gw, changeOrigin: true });
        return;
      }
      void handle(req, res);
    } catch (e) {
      console.error(e);
      res.statusCode = 500;
      res.end('internal error');
    }
  });

  server.on('upgrade', (req, socket, head) => {
    const pathOnly = (req.url || '').split('?')[0];
    if (isStreamPath(pathOnly)) {
      proxy.ws(req, socket, head, { target: gw, changeOrigin: true });
    } else {
      socket.destroy();
    }
  });

  server.listen(port, hostname, () => {
    console.log(`[sirp] ready on http://${hostname}:${port} (WS /stream/events → ${gw})`);
  });
});
