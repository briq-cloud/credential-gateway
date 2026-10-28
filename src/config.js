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
  /** @param {Api} api @param {{ refreshMs?: number, unknownWaitMs?: number, resolve?: (host: string) => Promise<string[]>, log?: (line: object) => void }} opts */
  constructor(api, { refreshMs = 15_000, unknownWaitMs = 10_000, resolve, log = () => {} } = {}) {
    this.api = api;
    this.refreshMs = refreshMs;
    this.unknownWaitMs = unknownWaitMs;
    this.resolve = resolve;
    this.log = log;
    this.secrets = [];
    /** @type {Map<string, string>} address → briq id */
    this.briqByIp = new Map();
    /** @type {Map<string, Set<string>>} briq id → the names of the team secrets its env names */
    this.secretsByBriq = new Map();
    /** @type {Map<string, any[]>} briq id → its own secrets with hosts (same shape as a team's) */
    this.ownByBriq = new Map();
    this.lastRefreshAt = 0;
    /** When `refreshSoon` last asked, whatever the answer. */
    this.lastAskedAt = 0;
    /** @type {Promise<void> | null} */
    this.asking = null;
    this.timer = null;
  }

  async refresh() {
    const c = await this.api.config();
    this.secrets = c.secrets ?? [];
    this.secretsByBriq = new Map((c.briqs ?? []).map((b) => [b.id, new Set(b.secrets ?? [])]));
    this.ownByBriq = new Map((c.briqs ?? []).map((b) => [b.id, b.own ?? []]));
    this.lastRefreshAt = Date.now();
    if (this.resolve) {
      const byIp = new Map();
      await Promise.all(
        (c.briqs ?? []).map(async (b) => {
          try {
            for (const ip of await this.resolve(b.host)) byIp.set(normalizeIp(ip), b.id);
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
   * `briqOf`, asking the API again while the address is new to us, for up to `unknownWaitMs`: a
   * briq that just booted makes its first requests before the next refresh, and its name can take
   * a few seconds more to resolve on the private network. A request from an address still unknown
   * after that is tunnelled without secrets.
   */
  async resolveBriq(address) {
    const deadline = Date.now() + this.unknownWaitMs;
    for (;;) {
      const known = this.briqOf(address);
      if (known || Date.now() >= deadline) return known;
      await this.refreshSoon();
    }
  }

  /** A refresh shared by every connection waiting on one, at most one a second. */
  refreshSoon() {
    this.asking ??= (async () => {
      const wait = this.lastAskedAt + 1_000 - Date.now();
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      this.lastAskedAt = Date.now();
      try {
        await this.refresh();
      } catch (err) {
        this.log({ level: 'warn', message: 'config refresh failed', err: String(err) });
      }
    })().finally(() => {
      this.asking = null;
    });
    return this.asking;
  }
}

/** An address as Node reports it, without an IPv4-mapped prefix or a zone. */
export function normalizeIp(ip) {
  return ip
    .replace(/^::ffff:/, '')
    .replace(/%.*$/, '')
    .toLowerCase();
}

/**
 * Usage, batched per (briq, host, secrets, status class) and flushed on a timer. A batch the API
 * did not take is kept for the next flush, up to `maxPending` entries.
 */
export class Events {
  /** @param {Api} api @param {{ flushMs?: number, maxPending?: number, log?: (line: object) => void }} opts */
  constructor(api, { flushMs = 30_000, maxPending = 1_000, log = () => {} } = {}) {
    this.api = api;
    this.log = log;
    this.maxPending = maxPending;
    /** @type {Map<string, { briqId: string | null, host: string, method: string, status: number, secrets: string[], count: number, firstAt: string, lastAt: string }>} */
    this.pending = new Map();
    this.timer = setInterval(() => this.flush(), flushMs);
    this.timer.unref();
  }

  record({ briqId, host, method, status, secrets }) {
    const names = [...secrets].sort();
    const key = Events.key({ briqId, host, method, status, secrets: names });
    const now = new Date().toISOString();
    const e = this.pending.get(key);
    if (e) {
      e.count += 1;
      e.lastAt = now;
      e.status = status;
    } else if (this.pending.size < this.maxPending)
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

  static key({ briqId, host, method, status, secrets }) {
    return `${briqId}|${host}|${method}|${Math.floor(status / 100)}|${secrets.join(',')}`;
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
        message: 'events not delivered, kept for the next flush',
        err: String(err),
        count: events.length,
      });
      for (const e of events) {
        const key = Events.key(e);
        const later = this.pending.get(key);
        if (later) {
          later.count += e.count;
          later.firstAt = e.firstAt;
        } else if (this.pending.size < this.maxPending) this.pending.set(key, e);
      }
    }
  }

  async stop() {
    clearInterval(this.timer);
    await this.flush();
  }
}
