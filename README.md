# briq credential gateway

The credential gateway of [briq](https://briq.cloud): the proxy a team's briqs reach the internet
through. A briq holds a placeholder instead of a secret; on the way out, to the hosts the secret
allows, the gateway puts the real value in. The real value never enters the briq, not in its
environment, not in a response.

```
ghcr.io/briq-cloud/credential-gateway:latest
```

briq runs one per team, on the team's private network, and points the team's briqs at it
(`HTTPS_PROXY`, and the gateway's CA certificate as a boot file). Nothing to install on your side;
this repo is here so you can read what sits between your sandbox and the internet.

## What it does

- **CONNECT to a host one of the calling briq's secrets allows** (port 443): the API tells the
  gateway which briq, by address, named which team secrets in its env, and which secrets of its
  own (given at run with `hosts`) it holds; only those are put in, and only for that briq. The gateway answers the TLS handshake with a certificate from its own
  CA, reads each request, replaces each of those placeholders with the real value where the
  secret allows it (request headers; the body too when the secret
  says so), and sends the request on over its own TLS connection to the real host, asking for an
  uncompressed answer. In the response, the real value, if the host echoes it, becomes the
  placeholder again, in headers and body; a compressed answer is decompressed first, or refused.
  The request must address the CONNECT host: a `Host` naming another site is refused.
- **CONNECT to any other host**: a tunnel, byte for byte. The gateway sees nothing of it.
- **Plain HTTP through the proxy**: forwarded as it is, never injected. A real value in clear is
  not something it sends.
- **Reports** to the briq API which briq used which secret against which host and method,
  batched per minute: that is the team's audit log.

The CA is made on the gateway's first boot and kept on its volume; its private key never leaves
the machine. The API only ever gets the certificate.

## Limits

- HTTPS only, HTTP/1.1 only (the gateway offers no HTTP/2 in the handshake; clients fall back).
- Substitution is textual: a secret used to compute a signature (AWS SigV4, an HMAC) does not
  work, and a client that validates a key's format at startup may reject the placeholder.
- A token exchange (OAuth client credentials) returns the new token into the briq unredacted:
  exchange outside, store the result.
- Bodies and responses over 8 MB are passed through as they are.
- A briq can bypass the proxy; it then carries only placeholders, which are worthless without it.

## Configuration

| Variable | What |
| --- | --- |
| `BRIQ_API_URL` | The API that holds the team's secrets |
| `BRIQ_GATEWAY_TOKEN` | This gateway's bearer token for `/internal/credential-gateway/*` |
| `GATEWAY_PORT` | 3128 |
| `GATEWAY_STATE_DIR` | Where the CA lives: `/data`, a volume |
| `GATEWAY_REFRESH_MS` | How often the config is read again: 15000 |

## Develop

```bash
npm install
npm test        # a fake API, a fake destination, curl as the client
docker build -t credential-gateway .
```

This repo is written by each release from briq's source tree; changes are made there and land
here with the image. MIT licensed. The briq service is operated by Uplab SAS under its
[terms](https://briq.cloud/legal/terms).
