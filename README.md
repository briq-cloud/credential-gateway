# briq credential gateway

The credential gateway of [briq](https://briq.cloud): the proxy a team's briqs reach the internet
through. A briq holds a placeholder instead of a secret; on the way out, to the hosts the secret
allows, the gateway puts the real value in. The real value is never in the briq's environment,
and a response that echoes it as it is gets the placeholder back instead (see Limits for what
that does not cover).

```
ghcr.io/briq-cloud/credential-gateway:<commit sha>
```

briq runs one per team, on the team's private network, and points the team's briqs at it
(`HTTPS_PROXY`, and the gateway's CA certificate as a boot file). Nothing to install on your side;
this repo is here so you can read what sits between your sandbox and the internet.

One static binary (Rust: tokio, hyper, rustls), a few MB of memory.

## What it does

- **CONNECT to a host one of the calling briq's secrets allows** (port 443): the API tells the
  gateway which briq, by address, named which team secrets in its env, and which secrets of its
  own (given at run with `hosts`) it holds; only those are put in, and only for that briq, read
  again for each request (a revoked or rotated secret stops at the next one). The
  gateway answers the TLS handshake with a certificate from its own CA, reads each request,
  replaces each of those placeholders with the real value where the secret allows it (request
  headers; the body too when the secret says so), and sends the request on over its own TLS
  connection to the real host, asking for an uncompressed answer. In the response, a real value
  that applies to the request, if the host echoes it, becomes the placeholder again, in headers
  and body; a compressed answer is decompressed first, or refused. The request must address the
  CONNECT host: a `Host` naming another site is refused.
- **Both directions stream.** A response goes on as the host writes it (server-sent events
  included); the gateway only keeps back a tail that could be the start of a real value, until
  the next bytes say. A request body with a secret allowed in it is held up to 8 MB to keep its
  `Content-Length` (eight such bodies at a time); a larger one, or one past those eight, is
  rewritten as it streams and sent chunked.
- **CONNECT to any other host**: a tunnel, byte for byte. The gateway sees nothing of it.
- **Plain HTTP through the proxy**: forwarded as it is, never injected. A real value in clear is
  not something it sends.
- **A briq that just started**: the gateway knows a briq by its address on the private network.
  A request from an address it does not know yet waits up to 10 seconds while it asks the API
  again (at most once a second, shared by every waiting connection); still unknown after that, it
  is tunnelled without secrets. An address two briqs claim gets no secrets either.
- **Reports** to the briq API which briq used which secret against which host and method,
  batched and sent every 30 seconds and on shutdown: that is the team's audit log. A batch the
  API does not take is sent again with the next. A report of a secret put in is never dropped
  for room.

The CA is made on the gateway's first boot and kept on its volume; its private key never leaves
the machine. The API only ever gets the certificate. A CA that is on the volume but cannot be read
stops the gateway rather than being replaced: the team's briqs trust the one they were given.

## Limits

- HTTPS only, HTTP/1.1 only (the gateway offers no HTTP/2 in the handshake; clients fall back).
- No WebSocket through an intercepted host: the upgrade is not passed on. A host with no secret
  is a tunnel, where anything works.
- Substitution is textual: a secret used to compute a signature (AWS SigV4, an HMAC) does not
  work, and a client that validates a key's format at startup may reject the placeholder.
- A token exchange (OAuth client credentials) returns the new token into the briq unredacted:
  exchange outside, store the result.
- A response from an intercepted host loses its `Content-Length` (what is replaced changes the
  length): it is sent chunked. Its trailers are dropped.
- Scrubbing replaces the real value as bytes. An echo that changes it (escaped, encoded, cut,
  compressed without saying so) is not caught, and neither is a value the briq stores on an
  allowed host (an issue body, a gist) and reads back changed. The gateway keeps a value out of
  the briq's environment and out of plain echoes; a host that the briq can make return what it
  sent is a host that can return the value.
- A briq can bypass the proxy; it then carries only placeholders, which are worthless without it.

## Configuration

| Variable | What |
| --- | --- |
| `BRIQ_API_URL` | The API that holds the team's secrets |
| `BRIQ_GATEWAY_TOKEN` | This gateway's bearer token for `/internal/credential-gateway/*` |
| `BRIQ_TEAM` | What a new CA says it is for |
| `GATEWAY_PORT` | 3128 |
| `GATEWAY_STATE_DIR` | Where the CA lives: `/data`, a volume |
| `GATEWAY_REFRESH_MS` | How often the config is read again: 15000 |
| `GATEWAY_HELD_BODIES` | Maximum request bodies buffered at once: 8; 0 streams every body |
| `GATEWAY_MAX_BODY_MB` | Buffer threshold for input and rewritten request bytes in MiB: 8; positive integer |
| `GATEWAY_MAX_CONNECTIONS` | Maximum proxy sockets: 1024; positive integer |
| `GATEWAY_MAX_CONFIG_MB` | Maximum control-API response body in MiB: 8; positive integer |
| `GATEWAY_LOG_LEVEL` | `debug`, `info` (default), `warn`, `error` |

`credential-gateway health` asks the running gateway's `/healthz` and exits 0 when it answers
(the image's `HEALTHCHECK`). Logs are one JSON line per event: `ts`, `level`, `message`, fields.

The body limits control buffering, not the maximum accepted request size. A body over the
threshold, or arriving while all buffer slots are occupied, is rewritten as a stream and
sent chunked. Allow memory for TLS connections, rewriting and the runtime in addition to
`GATEWAY_HELD_BODIES × GATEWAY_MAX_BODY_MB`; that product is not a process memory limit.
Invalid limits stop startup. The threshold applies to rewritten output as well as input;
an expanding body that exceeds it streams chunked. Streaming rewriting emits at most
64 KiB per output frame, including when one replacement is larger than that.

The connection limit includes clients still sending headers, intercepted TLS connections and
raw tunnels, until their sockets close. At capacity, additional remote sockets are closed.
Two extra slots serve only loopback `GET /healthz` requests, each with a two-second deadline
and no keep-alive. They keep the local health command available without admitting more proxy
traffic. Other requests using these slots receive 503. The default connection count is a
generic ceiling, not a recommendation for a particular VM size.

HTTP parsing uses a 64 KiB read-buffer limit. Rewritten header fields (names, values and
separators) have a separate 64 KiB aggregate budget. Oversized rewritten request fields
are refused with 431; oversized response fields fail closed with 502.

After CONNECT, a client has 10 seconds to complete its TLS handshake. Incomplete handshakes
are closed so abandoned clients do not hold their TLS state indefinitely. Streamed responses
remain open for their full duration.

Control-API response collection is bounded for both fixed-length and chunked bodies. An
oversized or malformed config leaves the last good config in use. The API client retains
at most two idle connections to its fixed origin.

## The API it talks to

Every call carries `Authorization: Bearer <BRIQ_GATEWAY_TOKEN>`; a call gets 15 seconds.

| Call | When | Body |
| --- | --- | --- |
| `PUT /internal/credential-gateway/ca` | at boot; the gateway does not start without it | `{ "cert": "<CA PEM>" }` |
| `GET /internal/credential-gateway/config` | at boot, every `GATEWAY_REFRESH_MS`, and while an address is unknown | answer below |
| `POST /internal/credential-gateway/events` | every 30 seconds and on shutdown, when there is usage | `{ "events": [...] }` |

The config:

```json
{
  "secrets": [
    { "name": "GITHUB_TOKEN", "placeholder": "briq_secret_…", "value": "…",
      "hosts": ["api.github.com", "*.githubusercontent.com"], "locations": ["header"] }
  ],
  "briqs": [
    { "id": "bq_…", "host": "<a name that resolves to the briq's addresses>",
      "secrets": ["GITHUB_TOKEN"],
      "own": [ { "name": "…", "placeholder": "…", "value": "…", "hosts": ["…"], "locations": ["header", "body"] } ] }
  ]
}
```

`secrets` are the team's; a briq gets those its `secrets` names, plus its `own`. A host is exact
or `*.example.com` (subdomains only). `locations` is `header`, plus `body` when allowed.

An event, one per (briq, host, method, status class, secrets):

```json
{ "briqId": "bq_…", "host": "api.github.com", "method": "GET", "status": 200,
  "secrets": ["GITHUB_TOKEN"], "count": 3, "firstAt": "<RFC 3339>", "lastAt": "<RFC 3339>" }
```

## Develop

```bash
cargo test      # a fake API, a fake HTTPS destination, curl as the client
cargo clippy --all-targets -- -D warnings
docker build -t credential-gateway .
```

The optional Rust SSE load generator is built separately from the gateway:

```bash
cargo build --release --locked --example stress
./target/release/examples/stress streams 1000 "$GATEWAY_IP" 8 proxy 16 50 ./gateway-ca.pem
./target/release/examples/stress streams 1000 unused 8 direct 16 50 ./bench-ca.pem
```

Set `GATEWAY_IP` to the benchmark gateway. This example requires the synthetic SSE fixture
at `bench.internal:443`, its registered client identity, and the corresponding CA files;
it is not a load generator for arbitrary upstream services. The arguments after `streams`
are connection count, gateway address, an unused body-size argument retained for compatibility
with the Python fixture client, route, concurrent connection setups, arrival rate per second,
and an optional CA file. Zero setup limit removes the setup concurrency bound; zero arrival
rate disables pacing.
`BENCH_DIRECT_ADDR` can override the direct fixture address; TLS still verifies `bench.internal`.

Each worker must receive exactly 30 validated data events; fixture waiting heartbeats are
accepted while its stream group forms. Every requested stream must overlap for at least five
seconds. JSON output reports completion, overlap, timing and errors; any failed worker or
insufficient overlap exits nonzero. Network operations have a ten-second deadline and workers
a hundred-second deadline. Compare direct and proxied runs with the same fixture resources
before drawing conclusions about gateway capacity. The example belongs only in benchmark
images, never the production gateway image.

Every push to `main` builds and pushes `latest` and the commit's short sha; briq runs a sha tag,
pinned in its API, so a merge here reaches briq only with that pin's change. MIT licensed. The
briq service is operated by Uplab SAS under its [terms](https://briq.cloud/legal/terms).
