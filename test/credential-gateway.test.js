// The gateway against a fake API and a fake destination, with curl as the client, as a briq's
// tools would be: the destination gets the real value, the client never does.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { promisify } from 'node:util';
import { gzipSync } from 'node:zlib';
import { LeafCerts, loadOrCreateCa } from '../src/ca.js';
import { Api, Config, Events, hostMatches, normalizeIp } from '../src/config.js';
import { createProxy } from '../src/proxy.js';

const SECRET = 'real-secret-VALUE-0123456789';
const PLACEHOLDER = 'briq_secret_a1b2c3d4e5f6a7b8';
const BODY_SECRET = 'body-secret-VALUE-9876543210';
const BODY_PLACEHOLDER = 'briq_secret_ffffffffeeeeeeee';
const OTHER_PLACEHOLDER = 'briq_secret_0000000011111111';
const OWN_SECRET = 'own-secret-VALUE-5555555555';
const OWN_PLACEHOLDER = 'briq_secret_abcdefabcdefabcd';

describe('hostMatches', () => {
  it('matches exact hosts and wildcard subdomains', () => {
    assert.equal(hostMatches('api.github.com', 'api.github.com'), true);
    assert.equal(hostMatches('api.github.com', 'github.com'), false);
    assert.equal(hostMatches('*.example.com', 'a.example.com'), true);
    assert.equal(hostMatches('*.example.com', 'a.b.example.com'), true);
    assert.equal(hostMatches('*.example.com', 'example.com'), false);
    assert.equal(hostMatches('*.example.com', 'notexample.com'), false);
    assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
    assert.equal(normalizeIp('fdaa::1%eth0'), 'fdaa::1');
  });
});

describe('the gateway', () => {
  const dir = mkdtempSync(join(tmpdir(), 'briq-gw-'));
  /** @type {any} */ let destination;
  /** @type {any} */ let fakeApi;
  /** @type {any} */ let proxy;
  let destPort = 0;
  let proxyPort = 0;
  let caRegistered = '';
  const received = [];
  const posted = [];
  let config;
  let events;

  before(async () => {
    // The destination: an HTTPS server with a CA of its own, echoing what it got.
    const destCa = await loadOrCreateCa(join(dir, 'dest-ca'), 'destination');
    const destLeaf = await new LeafCerts(destCa).for('localhost');
    destination = https.createServer({ key: destLeaf.key, cert: destLeaf.cert }, (req, res) => {
      let body = '';
      req.on('data', (c) => {
        body += c;
      });
      req.on('end', () => {
        received.push({ method: req.method, url: req.url, headers: req.headers, body });
        res.setHeader('x-echo-auth', req.headers.authorization ?? '');
        res.setHeader('content-type', 'application/json');
        const payload = JSON.stringify({ auth: req.headers.authorization ?? null, body });
        // A server that compresses whatever the client asked for.
        if (req.headers['x-test-gzip']) {
          res.setHeader('content-encoding', 'gzip');
          res.end(gzipSync(payload));
        } else res.end(payload);
      });
    });
    await new Promise((r) => destination.listen(0, '127.0.0.1', r));
    destPort = destination.address().port;
    writeFileSync(join(dir, 'dest-ca.pem'), destCa.certPem);

    // The API the gateway reports to.
    fakeApi = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => {
        body += c;
      });
      req.on('end', () => {
        if (req.headers.authorization !== 'Bearer gw-token') {
          res.writeHead(401);
          res.end();
          return;
        }
        if (req.method === 'PUT' && req.url === '/internal/credential-gateway/ca') {
          caRegistered = JSON.parse(body).cert;
          res.writeHead(204);
          res.end();
        } else if (req.method === 'GET' && req.url === '/internal/credential-gateway/config') {
          res.setHeader('content-type', 'application/json');
          res.end(
            JSON.stringify({
              secrets: [
                {
                  name: 'TOKEN',
                  placeholder: PLACEHOLDER,
                  value: SECRET,
                  hosts: ['localhost'],
                  locations: ['header'],
                },
                {
                  name: 'BODY',
                  placeholder: BODY_PLACEHOLDER,
                  value: BODY_SECRET,
                  hosts: ['localhost'],
                  locations: ['header', 'body'],
                },
                // A team secret for the same host that the test briq did not name.
                {
                  name: 'OTHER',
                  placeholder: OTHER_PLACEHOLDER,
                  value: 'other-secret-VALUE',
                  hosts: ['localhost'],
                  locations: ['header'],
                },
              ],
              briqs: [
                {
                  id: 'bq_test',
                  host: 'localhost',
                  secrets: ['TOKEN', 'BODY'],
                  // The briq's own secret with hosts: its value, for it alone.
                  own: [
                    {
                      name: 'OWN',
                      placeholder: OWN_PLACEHOLDER,
                      value: OWN_SECRET,
                      hosts: ['localhost'],
                      locations: ['header'],
                    },
                  ],
                },
              ],
            }),
          );
        } else if (req.method === 'POST' && req.url === '/internal/credential-gateway/events') {
          posted.push(...JSON.parse(body).events);
          res.writeHead(204);
          res.end();
        } else {
          res.writeHead(404);
          res.end();
        }
      });
    });
    await new Promise((r) => fakeApi.listen(0, '127.0.0.1', r));
    const apiUrl = `http://127.0.0.1:${fakeApi.address().port}`;

    // The gateway, composed as index.js composes it.
    const api = new Api({ url: apiUrl, token: 'gw-token' });
    const ca = await loadOrCreateCa(join(dir, 'ca'), 'test team');
    await api.registerCa(ca.certPem);
    writeFileSync(join(dir, 'ca.pem'), ca.certPem);
    config = new Config(api, { refreshMs: 60_000, resolve6: async () => ['::1', '127.0.0.1'] });
    await config.start();
    events = new Events(api, { flushMs: 60_000 });
    proxy = createProxy(
      { config, leafs: new LeafCerts(ca), events, log: () => {} },
      { upstreamCa: destCa.certPem, upstreamPort: () => destPort, maxBody: 1024 },
    );
    await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
    proxyPort = proxy.address().port;
  });

  after(async () => {
    proxy.close();
    fakeApi.close();
    destination.close();
    config.stop();
    await events.stop();
  });

  // Async: a blocking curl would wait on the proxy, which runs in this very event loop.
  const run = promisify(execFile);
  const curl = async (args) =>
    (
      await run('curl', ['-sS', '-x', `http://127.0.0.1:${proxyPort}`, ...args], {
        encoding: 'utf8',
      })
    ).stdout;

  it('registers its CA with the API', () => {
    assert.match(caRegistered, /BEGIN CERTIFICATE/);
  });

  it('swaps the placeholder for the real value in a header, and back in the response', async () => {
    received.length = 0;
    const out = await curl([
      '--cacert',
      join(dir, 'ca.pem'),
      '-H',
      `Authorization: Bearer ${PLACEHOLDER}`,
      '-D',
      '-',
      'https://localhost:443/echo?x=1',
    ]);
    assert.equal(received.length, 1);
    assert.equal(received[0].headers.authorization, `Bearer ${SECRET}`);
    assert.equal(received[0].url, '/echo?x=1');
    // The client sees the placeholder, in the header and in the body the destination echoed.
    assert.ok(out.includes(`x-echo-auth: Bearer ${PLACEHOLDER}`), out);
    assert.ok(out.includes(`"auth":"Bearer ${PLACEHOLDER}"`), out);
    assert.ok(!out.includes(SECRET), 'the real value reached the client');
  });

  it('puts in only the secrets the briq named: another placeholder passes through as text', async () => {
    received.length = 0;
    await curl([
      '--cacert',
      join(dir, 'ca.pem'),
      '-H',
      `Authorization: Bearer ${OTHER_PLACEHOLDER}`,
      'https://localhost:443/other',
    ]);
    assert.equal(received.length, 1);
    assert.equal(received[0].headers.authorization, `Bearer ${OTHER_PLACEHOLDER}`);
  });

  it("puts in the briq's own secret with hosts, and scrubs it from the response", async () => {
    received.length = 0;
    const out = await curl([
      '--cacert',
      join(dir, 'ca.pem'),
      '-H',
      `Authorization: Bearer ${OWN_PLACEHOLDER}`,
      '-D',
      '-',
      'https://localhost:443/own',
    ]);
    assert.equal(received[0].headers.authorization, `Bearer ${OWN_SECRET}`);
    assert.ok(out.includes(`x-echo-auth: Bearer ${OWN_PLACEHOLDER}`), out);
    assert.ok(!out.includes(OWN_SECRET), 'the real value reached the client');
  });

  it('substitutes in the body only for a secret that allows it', async () => {
    received.length = 0;
    await curl([
      '--cacert',
      join(dir, 'ca.pem'),
      '-X',
      'POST',
      '-H',
      'content-type: application/json',
      '--data',
      JSON.stringify({ a: PLACEHOLDER, b: BODY_PLACEHOLDER }),
      'https://localhost:443/post',
    ]);
    assert.equal(received.length, 1);
    const body = JSON.parse(received[0].body);
    assert.equal(body.a, PLACEHOLDER, 'a header-only secret is never put in a body');
    assert.equal(body.b, BODY_SECRET);
    assert.equal(received[0].headers['content-length'], String(received[0].body.length));
  });

  it('asks for an uncompressed response, and reads one that comes compressed anyway', async () => {
    received.length = 0;
    const out = await curl([
      '--cacert',
      join(dir, 'ca.pem'),
      '--compressed',
      '-H',
      `Authorization: Bearer ${PLACEHOLDER}`,
      '-H',
      'x-test-gzip: 1',
      '-D',
      '-',
      'https://localhost:443/gz',
    ]);
    assert.equal(received[0].headers['accept-encoding'], 'identity');
    // Decompressed, scrubbed, sent on plain.
    assert.ok(out.includes(`"auth":"Bearer ${PLACEHOLDER}"`), out);
    assert.ok(!out.includes(SECRET), 'the real value reached the client in a compressed body');
    assert.ok(!/content-encoding/i.test(out), out);
  });

  it('refuses a request whose Host is not the CONNECT host', async () => {
    received.length = 0;
    const out = await curl([
      '--cacert',
      join(dir, 'ca.pem'),
      '-H',
      'Host: other.example',
      '-H',
      `Authorization: Bearer ${PLACEHOLDER}`,
      '-o',
      '/dev/null',
      '-w',
      '%{http_code}',
      'https://localhost:443/x',
    ]);
    assert.equal(out, '400');
    assert.equal(received.length, 0, 'the destination was reached');
  });

  it('tunnels a host no secret allows, without touching the bytes', async () => {
    received.length = 0;
    // The destination's own CA, since the gateway did not terminate anything.
    const out = await curl([
      '--cacert',
      join(dir, 'dest-ca.pem'),
      '-H',
      `Authorization: Bearer ${PLACEHOLDER}`,
      `https://localhost:${destPort}/tunnel`,
    ]);
    assert.equal(received.length, 1);
    assert.equal(
      received[0].headers.authorization,
      `Bearer ${PLACEHOLDER}`,
      'no injection off the allow-list',
    );
    assert.ok(out.includes(PLACEHOLDER));
  });

  it('answers its health check', async () => {
    const out = (
      await run('curl', ['-sS', `http://127.0.0.1:${proxyPort}/healthz`], { encoding: 'utf8' })
    ).stdout;
    assert.equal(out.trim(), 'ok');
  });

  it('reports which briq used which secret against which host', async () => {
    await events.flush();
    const e = posted.find((x) => x.secrets.includes('TOKEN'));
    assert.ok(e, JSON.stringify(posted));
    assert.equal(e.briqId, 'bq_test');
    assert.equal(e.host, 'localhost');
    assert.ok(e.count >= 1);
  });
});
