// The briq credential gateway, as a briq runs it: one per team, on the team's private network.
//   BRIQ_API_URL        the API that holds the team's secrets (https://api.briq.cloud)
//   BRIQ_GATEWAY_TOKEN  this gateway's bearer token for the API's /internal/credential-gateway/* endpoints
//   GATEWAY_PORT        3128 unless set
//   GATEWAY_STATE_DIR   where the CA lives, a volume (/data)
//   GATEWAY_REFRESH_MS  how often the config is read again (15000)
import { promises as dns } from 'node:dns';
import { LeafCerts, loadOrCreateCa } from './ca.js';
import { Api, Config, Events } from './config.js';
import { createProxy } from './proxy.js';

const env = process.env;
const log = (line) =>
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), ...line })}\n`);

const apiUrl = env.BRIQ_API_URL;
const token = env.BRIQ_GATEWAY_TOKEN;
if (!apiUrl || !token) {
  log({ level: 'error', message: 'BRIQ_API_URL and BRIQ_GATEWAY_TOKEN are required' });
  process.exit(2);
}
const port = Number(env.GATEWAY_PORT ?? 3128);
const stateDir = env.GATEWAY_STATE_DIR ?? '/data';

const api = new Api({ url: apiUrl, token });
const ca = await loadOrCreateCa(stateDir, env.BRIQ_TEAM ?? 'team');
await api.registerCa(ca.certPem);
log({ level: 'info', message: 'ca registered', subject: ca.cert.subject });

const config = new Config(api, {
  refreshMs: Number(env.GATEWAY_REFRESH_MS ?? 15_000),
  // Every address of a briq's name, either family: Fly's private network is IPv6, a briqyard
  // tenant's is IPv4.
  resolve: async (host) => (await dns.lookup(host, { all: true })).map((a) => a.address),
  log,
});
await config.start();
const events = new Events(api, { log });
const server = createProxy({ config, leafs: new LeafCerts(ca), events, log });

server.listen(port, '::', () => log({ level: 'info', message: 'listening', port }));

const stop = async () => {
  server.close();
  config.stop();
  await events.stop();
  process.exit(0);
};
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
