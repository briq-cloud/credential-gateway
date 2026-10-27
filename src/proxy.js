// The proxy. A briq points HTTPS_PROXY at it. For a CONNECT to a host one of the team's secrets
// allows, the gateway answers the TLS handshake itself with a certificate from its CA, reads the
// requests, swaps each placeholder for the real value where the secret allows (headers, body),
// sends them on over its own TLS connection, and rewrites the real value back to the placeholder
// in what comes back. Any other host is tunnelled byte for byte: the gateway sees nothing of it.
// Only the secrets the calling briq named in its env are put in: the API says which briq, by
// address, named which.
// Plain HTTP through the proxy is forwarded as it is, never injected: a real value in clear is
// not something we send.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';

/** Hop-by-hop headers, never forwarded. */
const HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/**
 * @param {object} deps
 * @param {import('./config.js').Config} deps.config
 * @param {import('./ca.js').LeafCerts} deps.leafs
 * @param {import('./config.js').Events} deps.events
 * @param {(line: object) => void} deps.log
 * @param {{ maxBody?: number, upstreamCa?: string, upstreamPort?: (host: string, port: number) => number }} [opts]
 */
export function createProxy({ config, leafs, events, log }, opts = {}) {
  const maxBody = opts.maxBody ?? 8 * 1024 * 1024;

  const server = http.createServer((req, res) => {
    // Health, for the briq's healthcheck.
    if (req.url === '/healthz' && !req.headers.host?.includes(':')) {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok\n');
      return;
    }
    if (req.url === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok\n');
      return;
    }
    // Plain HTTP through the proxy: forwarded, never injected.
    let target;
    try {
      target = new URL(req.url);
    } catch {
      res.writeHead(400);
      res.end('a proxy request needs an absolute URL\n');
      return;
    }
    if (target.protocol !== 'http:') {
      res.writeHead(400);
      res.end('plain HTTP only here; use CONNECT for TLS\n');
      return;
    }
    const up = http.request(
      {
        host: target.hostname,
        port: target.port || 80,
        method: req.method,
        path: `${target.pathname}${target.search}`,
        headers: forwardHeaders(req.rawHeaders, target.host),
      },
      (upRes) => {
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        upRes.pipe(res);
      },
    );
    up.on('error', (err) => {
      log({
        level: 'warn',
        message: 'http forward failed',
        host: target.hostname,
        err: String(err),
      });
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(up);
  });

  server.on('connect', (req, socket, head) => {
    const [host, portText] = splitHostPort(req.url ?? '');
    const port = Number(portText || 443);
    if (!host || !Number.isInteger(port)) {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }
    socket.on('error', () => socket.destroy());
    (async () => {
      const briqId = await config.resolveBriq(socket.remoteAddress ?? '');
      // Every briq that goes through the gateway is in its config; an address none has is
      // tunnelled without secrets, and says so.
      if (!briqId)
        log({
          level: 'warn',
          message: 'request from an unknown address, tunnelled without secrets',
          address: socket.remoteAddress,
          host,
        });
      const secrets = port === 443 ? config.forHost(host, briqId) : [];
      if (!secrets.length) {
        tunnel(host, port, socket, head, log);
        return;
      }
      await mitm(host, port, socket, head, secrets, briqId);
    })().catch((err) => {
      log({ level: 'warn', message: 'intercept failed', host, err: String(err) });
      socket.destroy();
    });
  });

  /** A host the gateway has nothing to inject for: a tunnel. */
  function tunnel(host, port, socket, head, log) {
    const up = net.connect(port, host, () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);
    });
    up.on('error', (err) => {
      log({ level: 'debug', message: 'tunnel failed', host, port, err: String(err) });
      socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    });
    socket.on('close', () => up.destroy());
  }

  /** A host with secrets: the gateway is the TLS server the client talks to. */
  async function mitm(host, port, socket, head, secrets, briqId) {
    const leaf = await leafs.for(host);
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    const tlsSocket = new tls.TLSSocket(socket, {
      isServer: true,
      secureContext: tls.createSecureContext({ key: leaf.key, cert: leaf.cert }),
      ALPNProtocols: ['http/1.1'],
    });
    tlsSocket.on('error', () => tlsSocket.destroy());
    if (head?.length) tlsSocket.unshift(head);
    const inner = http.createServer((req, res) => {
      handle(req, res, host, port, secrets, briqId).catch((err) => {
        log({ level: 'warn', message: 'request failed', host, err: String(err) });
        if (!res.headersSent) res.writeHead(502);
        res.end();
      });
    });
    inner.on('clientError', (_err, s) => s.destroy());
    inner.emit('connection', tlsSocket);
  }

  /** One request to an intercepted host. */
  async function handle(req, res, host, port, secrets, briqId) {
    // The request must address the CONNECT host: a Host naming another site on the same address
    // (a shared CDN) would carry the real value there. An absolute-form target is refused too.
    const reqHost = (req.headers.host ?? '').replace(/:\d+$/, '').toLowerCase();
    if (
      (reqHost && reqHost !== host.toLowerCase()) ||
      /^[a-z][a-z0-9+.-]*:\/\//i.test(req.url ?? '')
    ) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end(`briq credential gateway: the request must address ${host}\n`);
      return;
    }
    let headers = forwardHeaders(req.rawHeaders, host);
    // Scrubbing reads the response as text: ask for it uncompressed.
    headers = without(headers, ['accept-encoding']);
    headers['accept-encoding'] = 'identity';
    const used = new Set();
    // Headers: every secret that allows them.
    for (const [name, value] of Object.entries(headers)) {
      let v = value;
      for (const s of secrets) {
        if (!s.locations.includes('header') || !v.includes(s.placeholder)) continue;
        v = v.split(s.placeholder).join(s.value);
        used.add(s.name);
      }
      headers[name] = v;
    }
    // The body, when it fits: substituted for the secrets that allow it; otherwise streamed.
    const bodySecrets = secrets.filter((s) => s.locations.includes('body'));
    const { buffer, overflow } = await readBody(req, maxBody);
    let body = buffer;
    if (buffer && !overflow && bodySecrets.length) {
      let text = buffer.toString('utf8');
      for (const s of bodySecrets) {
        if (!text.includes(s.placeholder)) continue;
        text = text.split(s.placeholder).join(s.value);
        used.add(s.name);
      }
      body = Buffer.from(text, 'utf8');
    }
    if (body && !overflow) {
      headers = without(headers, ['transfer-encoding']);
      headers['content-length'] = String(body.length);
    }
    const upstream = https.request({
      host,
      port: opts.upstreamPort ? opts.upstreamPort(host, port) : port,
      servername: host,
      method: req.method,
      path: req.url,
      headers,
      ...(opts.upstreamCa ? { ca: opts.upstreamCa } : {}),
    });
    const upRes = await new Promise((resolve, reject) => {
      upstream.on('response', resolve);
      upstream.on('error', reject);
      if (overflow) {
        upstream.write(buffer);
        req.pipe(upstream);
      } else upstream.end(body);
    });
    const status = upRes.statusCode ?? 502;
    events.record({ briqId, host, method: req.method ?? '', status, secrets: used });
    // What comes back: the real value, if the destination echoes it, becomes the placeholder
    // again. Headers always; the body when it fits.
    const scrub = (text) => {
      let t = text;
      for (const s of secrets)
        if (used.has(s.name) && t.includes(s.value)) t = t.split(s.value).join(s.placeholder);
      return t;
    };
    const resHeaders = {};
    for (let i = 0; i < upRes.rawHeaders.length; i += 2) {
      const n = upRes.rawHeaders[i];
      if (HOP.has(n.toLowerCase())) continue;
      const v = scrub(upRes.rawHeaders[i + 1]);
      resHeaders[n] = resHeaders[n] ? [].concat(resHeaders[n], v) : v;
    }
    const out = await readBody(upRes, maxBody);
    if (out.overflow) {
      // Too big to hold: on its way as it is.
      res.writeHead(status, resHeaders);
      res.write(out.buffer);
      upRes.pipe(res);
      return;
    }
    let resBody = out.buffer ?? Buffer.alloc(0);
    let finalHeaders = without(resHeaders, ['content-length']);
    const encoding = String(upRes.headers['content-encoding'] ?? 'identity').toLowerCase();
    if (used.size && resBody.length && encoding !== 'identity') {
      // Asked for none, got a compressed body: read it to scrub it, or refuse it. A real value
      // never goes on unread.
      try {
        resBody = decompress(encoding, resBody);
        finalHeaders = without(finalHeaders, ['content-encoding']);
      } catch {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end(
          `briq credential gateway: a ${encoding} response from ${host} could not be read to scrub it\n`,
        );
        return;
      }
    }
    const scrubbed = used.size ? Buffer.from(scrub(resBody.toString('latin1')), 'latin1') : resBody;
    finalHeaders['content-length'] = String(scrubbed.length);
    res.writeHead(status, finalHeaders);
    res.end(scrubbed);
  }

  return server;
}

/** A compressed body, readable: one encoding, the ones Node knows. */
function decompress(encoding, buf) {
  switch (encoding) {
    case 'gzip':
    case 'x-gzip':
      return zlib.gunzipSync(buf);
    case 'deflate':
      try {
        return zlib.inflateSync(buf);
      } catch {
        return zlib.inflateRawSync(buf);
      }
    case 'br':
      return zlib.brotliDecompressSync(buf);
    case 'zstd':
      if (typeof zlib.zstdDecompressSync === 'function') return zlib.zstdDecompressSync(buf);
      throw new Error('zstd is not available');
    default:
      throw new Error(`unknown content-encoding ${encoding}`);
  }
}

/** `obj` without the keys named, compared without case: header names come in either. */
function without(obj, keys) {
  const drop = new Set(keys.map((k) => k.toLowerCase()));
  return Object.fromEntries(Object.entries(obj).filter(([k]) => !drop.has(k.toLowerCase())));
}

/** The headers to send on: not the hop-by-hop ones, with `host` set, names as they were. */
function forwardHeaders(rawHeaders, host) {
  const out = {};
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i];
    const lower = name.toLowerCase();
    if (HOP.has(lower) || lower === 'host') continue;
    out[name] = out[name] ? `${out[name]}, ${rawHeaders[i + 1]}` : rawHeaders[i + 1];
  }
  out.host = host;
  return out;
}

/** The whole body up to `max` bytes; past it, what was read and `overflow`. */
function readBody(stream, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const onData = (c) => {
      chunks.push(c);
      size += c.length;
      if (size > max) {
        stream.off('data', onData);
        stream.off('end', onEnd);
        stream.pause();
        resolve({ buffer: Buffer.concat(chunks), overflow: true });
      }
    };
    const onEnd = () =>
      resolve({ buffer: chunks.length ? Buffer.concat(chunks) : null, overflow: false });
    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', reject);
  });
}

function splitHostPort(s) {
  const m = /^\[?([^\]]+?)\]?(?::(\d+))?$/.exec(s);
  return m ? [m[1], m[2]] : [null, null];
}
