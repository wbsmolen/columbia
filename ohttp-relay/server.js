// Columbia — OHTTP relay (RFC 9458)
//
// The relay is the split-trust counterpart to the gateway. It sees the client's
// IP and an OPAQUE ciphertext (message/ohttp-req) — never the plaintext, never
// the target. It forwards the ciphertext to the gateway, stripping every
// identifying header, and returns the encapsulated response. The gateway sees
// the relay's IP + plaintext but NOT the client's IP. Neither party ever holds
// identity + content together — that's the operator-blind property.
//
// NON-COLLUSION CAVEAT: for the security guarantee, relay and gateway MUST be
// run by different, non-colluding operators. Running both on one host validates
// the flow but provides no protection against the single operator. See
// ../SELFHOSTING.md. Logs are RED-only — no IP, no content, no headers.

const http = require('http');
const https = require('https');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '8080', 10);
const GATEWAY = process.env.GATEWAY_URL; // e.g. https://<gateway-host>/gateway

// DoS bounds: cap how much we buffer in either direction so a single connection
// can't exhaust relay memory. Both are overridable via env.
const MAX_BODY = parseInt(process.env.MAX_BODY_BYTES || '65536', 10);
const MAX_RESP_BYTES = parseInt(process.env.MAX_RESP_BYTES || '1000000', 10);
const GW_TIMEOUT_MS = parseInt(process.env.GW_TIMEOUT_MS || '15000', 10);

function log(fields) {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...fields }) + '\n');
}

// Validate GATEWAY_URL ONCE at startup. Parsing per-request both wasted work and
// hid a misconfiguration until the first relay attempt. Require https so the
// relay→gateway hop is always encrypted.
let gw;
try {
  gw = new URL(GATEWAY);
} catch {
  log({ event: 'fatal', reason: 'gateway_url_invalid' });
  process.exit(1);
}
if (gw.protocol !== 'https:') {
  log({ event: 'fatal', reason: 'gateway_not_https' });
  process.exit(1);
}
const GW_PORT = gw.port || 443; // honor a non-default port instead of hardcoding 443

const server = http.createServer((req, res) => {
  const start = Date.now();

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    log({ route: '/health', status: 200, durationMs: Date.now() - start });
    return;
  }
  // Only POST /relay is a relay request. Everything else → 404 (no probing other
  // paths, no relaying non-POST methods).
  if (!(req.method === 'POST' && req.url === '/relay')) {
    res.writeHead(404); res.end(); return;
  }

  const chunks = [];
  let received = 0;
  let aborted = false;
  req.on('data', (c) => {
    if (aborted) return;
    received += c.length;
    if (received > MAX_BODY) {
      // Request body too large: refuse, tear down, and stop buffering.
      aborted = true;
      res.writeHead(413); res.end();
      log({ route: '/relay', status: 413, durationMs: Date.now() - start });
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => {
    if (aborted) return;
    const body = Buffer.concat(chunks);

    // Forward ONLY the opaque ciphertext + its content type. Deliberately send a
    // fresh request with NO client headers, NO X-Forwarded-For — the gateway must
    // not learn who the client is.
    const opts = {
      hostname: gw.hostname,
      port: GW_PORT,
      path: gw.pathname,
      method: 'POST',
      timeout: GW_TIMEOUT_MS,
      headers: { 'Content-Type': 'message/ohttp-req', 'Content-Length': body.length },
    };
    const greq = https.request(opts, (gres) => {
      const rc = [];
      let rcLen = 0;
      let respAborted = false;
      gres.on('data', (d) => {
        if (respAborted) return;
        rcLen += d.length;
        if (rcLen > MAX_RESP_BYTES) {
          // Gateway response too large: drop it and fail closed.
          respAborted = true;
          gres.destroy();
          if (!res.headersSent) { res.writeHead(502); res.end(); }
          log({ route: '/relay', status: 502, durationMs: Date.now() - start });
          return;
        }
        rc.push(d);
      });
      gres.on('end', () => {
        if (respAborted) return;
        const rb = Buffer.concat(rc);
        // Pin the response content-type — never echo the gateway's header back.
        res.writeHead(gres.statusCode || 502, { 'Content-Type': 'message/ohttp-res' });
        res.end(rb);
        log({ route: '/relay', status: gres.statusCode || 502, durationMs: Date.now() - start });
      });
    });
    greq.on('timeout', () => {
      greq.destroy(new Error('gw timeout'));
    });
    greq.on('error', () => {
      if (!res.headersSent) { res.writeHead(502); res.end(); }
      log({ route: '/relay', status: 502, durationMs: Date.now() - start });
    });
    greq.write(body);
    greq.end();
  });
});

// Connection-level timeouts so slow-loris style clients can't pin sockets open.
server.requestTimeout = 20000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;

server.listen(PORT, () => log({ event: 'listen', port: PORT, role: 'ohttp-relay' }));
