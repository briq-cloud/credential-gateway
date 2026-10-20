// What the gateway knows, from the API: the team's secrets (placeholder, value, hosts, where to
// put them) and the team's briqs (to name the one a request came from). Fetched at boot and
// every few seconds, so a rotation or a new secret applies without a restart; events (which
// briq used which secret against which host) go back the same way, batched.

/** A host pattern against a host: exact, or `*.example.com` for subdomains only. */
export function hostMatches(pattern, host) {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p.startsWith('*.')) return h.endsWith(p.slice(1)) && h.length > p.length - 1;
  return p === h;
}

export class Api {
  /** @param {{ url: string, token: string, fetch?: typeof fetch }} opts */
  constructor({ url, token, fetch: f = fetch }) {
    this.url = url.replace(/\/$/, '');
    this.token = token;
    this.fetch = f;
  }

  async call(method, path, body) {
    const r = await this.fetch(`${this.url}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${(await r.text()).slice(0, 200)}`);
    return r.status === 204 ? null : r.json();
  }

  /** Tell the API which certificate this gateway's CA has, so the team's briqs can trust it. */
  registerCa(certPem) {
    return this.call('PUT', '/internal/credential-gateway/ca', { cert: certPem });
  }

  /**
   * @returns {Promise<{ secrets: Array<{ name: string, placeholder: string, value: string, hosts: string[], locations: string[] }>, briqs: Array<{ id: string, host: string }> }>}
   */
  config() {
    return this.call('GET', '/internal/credential-gateway/config');
  }

  events(events) {
    return this.call('POST', '/internal/credential-gateway/events', { events });
  }
}

/** The live config, refreshed on a timer; the last good one stays when a fetch fails. */
export class Config {
  /** @param {Api} api @param {{ refreshMs?: number, resolve6?: (host: string) => Promise<string[]>, log?: (line: object) => void }} opts */
  constructor(api, { refreshMs = 15_000, resolve6, log = () => {} } = {}) {
    this.api = api;
    this.refreshMs = refreshMs;
    this.resolve6 = resolve6;
    this.log = log;
    this.secrets = [];
    /** @type {Map<string, string>} IPv6 address → briq id */
    this.briqByIp = new Map();
    /** @type {Map<string, Set<string>>} briq id → the names of the team secrets its env names */
    this.secretsByBriq = new Map();
    /** @type {Map<string, any[]>} briq id → its own secrets with hosts (same shape as a team's) */
    this.ownByBriq = new Map();
    this.lastRefreshAt = 0;
    this.timer = null;
  }

  async refresh() {
    const c = await this.api.config();
    this.secrets = c.secrets ?? [];
    this.secretsByBriq = new Map((c.briqs ?? []).map((b) => [b.id, new Set(b.secrets ?? [])]));
    this.ownByBriq = new Map((c.briqs ?? []).map((b) => [b.id, b.own ?? []]));
    this.lastRefreshAt = Date.now();
    if (this.resolve6) {
      const byIp = new Map();
      await Promise.all(
        (c.briqs ?? []).map(async (b) => {
          try {
            for (const ip of await this.resolve6(b.host)) byIp.set(normalizeIp(ip), b.id);
          } catch {
            // A briq that is not running has no address; it is not sending requests either.
          }
        }),
      );
      this.briqByIp = byIp;
    }
    this.log({
      level: 'debug',
      message: 'config refreshed',
      secrets: this.secrets.length,
      briqs: this.briqByIp.size,
    });
  }

  start() {
    const tick = async () => {
      try {
        await this.refresh();
      } catch (err) {
        this.log({ level: 'warn', message: 'config refresh failed', err: String(err) });
      }
    };
    this.timer = setInterval(tick, this.refreshMs);
    this.timer.unref();
    return tick();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }

  /**
   * The secrets that apply to a request from `briqId` to `host`: the ones that briq named in its
   * env, for that host. Naming a secret at run is the grant; a request from no known briq gets
   * none, and another briq's placeholder passes through as text.
   */
  forHost(host, briqId) {
    const named = briqId ? this.secretsByBriq.get(briqId) : undefined;
    if (!named) return [];
    const forThisHost = (s) => (s.hosts ?? []).some((p) => hostMatches(p, host));
    return [
      ...this.secrets.filter((s) => named.has(s.name) && forThisHost(s)),
      ...(this.ownByBriq.get(briqId) ?? []).filter(forThisHost),
    ];
  }

  /** Which briq an address belongs to, when the API told us about it. */
  briqOf(address) {
    return this.briqByIp.get(normalizeIp(address)) ?? null;
  }

  /**
   * `briqOf`, asking the API again first when the address is new to us (at most every two
   * seconds): a briq that just booted is making its first requests before the next refresh.
   */
  async resolveBriq(address) {
    const known = this.briqOf(address);
    if (known || Date.now() - this.lastRefreshAt < 2_000) return known;
    try {
      await this.refresh();
    } catch (err) {
      this.log({ level: 'warn', message: 'config refresh failed', err: String(err) });
    }
    return this.briqOf(address);
  }
}

/** An IPv6 address as Node reports it, without an IPv4-mapped prefix or a zone. */
export function normalizeIp(ip) {
  return ip
    .replace(/^::ffff:/, '')
    .replace(/%.*$/, '')
    .toLowerCase();
}

/** Usage, batched per (briq, host, secrets, status class) and flushed on a timer. */
export class Events {
  /** @param {Api} api @param {{ flushMs?: number, log?: (line: object) => void }} opts */
  constructor(api, { flushMs = 30_000, log = () => {} } = {}) {
    this.api = api;
    this.log = log;
    /** @type {Map<string, { briqId: string | null, host: string, method: string, status: number, secrets: string[], count: number, firstAt: string, lastAt: string }>} */
    this.pending = new Map();
    this.timer = setInterval(() => this.flush(), flushMs);
    this.timer.unref();
  }

  record({ briqId, host, method, status, secrets }) {
    const names = [...secrets].sort();
    const key = `${briqId}|${host}|${method}|${Math.floor(status / 100)}|${names.join(',')}`;
    const now = new Date().toISOString();
    const e = this.pending.get(key);
    if (e) {
      e.count += 1;
      e.lastAt = now;
      e.status = status;
    } else
      this.pending.set(key, {
        briqId,
        host,
        method,
        status,
        secrets: names,
        count: 1,
        firstAt: now,
        lastAt: now,
      });
  }

  async flush() {
    if (!this.pending.size) return;
    const events = [...this.pending.values()];
    this.pending = new Map();
    try {
      await this.api.events(events);
    } catch (err) {
      this.log({
        level: 'warn',
        message: 'events not delivered',
        err: String(err),
        count: events.length,
      });
    }
  }

  async stop() {
    clearInterval(this.timer);
    await this.flush();
  }
}
