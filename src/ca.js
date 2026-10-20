import { webcrypto } from 'node:crypto';
// The gateway's certificate authority: one per team, made on first boot and kept on the
// gateway's own disk. Its key never leaves the machine; the API gets the certificate, which it
// hands to the team's briqs as a boot file. Leaf certificates for the hosts the gateway
// terminates TLS for are minted from it on demand and cached.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto);

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const DAY = 24 * 60 * 60 * 1000;

const pem = (buf, label) => x509.PemConverter.encode(buf, label);

async function exportKey(key) {
  return pem(await webcrypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY');
}
async function importKey(pemText) {
  const der = x509.PemConverter.decode(pemText)[0];
  return webcrypto.subtle.importKey('pkcs8', der, ALG, true, ['sign']);
}

/**
 * Load the CA from `dir`, or make one. Returns PEM strings and the live keys.
 * @param {string} dir
 * @param {string} name what the certificate says it is for (the team)
 */
export async function loadOrCreateCa(dir, name) {
  mkdirSync(dir, { recursive: true });
  const certPath = join(dir, 'ca.crt');
  const keyPath = join(dir, 'ca.key');
  try {
    const certPem = readFileSync(certPath, 'utf8');
    const keyPem = readFileSync(keyPath, 'utf8');
    const cert = new x509.X509Certificate(certPem);
    const privateKey = await importKey(keyPem);
    return { certPem, keyPem, cert, privateKey };
  } catch {
    // A new one, when there is none or it cannot be read.
  }
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: `CN=briq gateway (${name}), O=briq`,
    notBefore: new Date(now - DAY),
    notAfter: new Date(now + 10 * 365 * DAY),
    signingAlgorithm: ALG,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  const certPem = cert.toString('pem');
  const keyPem = await exportKey(keys.privateKey);
  writeFileSync(keyPath, keyPem, { mode: 0o600 });
  writeFileSync(certPath, certPem);
  return { certPem, keyPem, cert, privateKey: keys.privateKey };
}

/** Leaf certificates by host, minted from the CA; one key pair for all of them. */
export class LeafCerts {
  /** @param {{ cert: x509.X509Certificate, privateKey: CryptoKey }} ca */
  constructor(ca) {
    this.ca = ca;
    /** @type {Map<string, { key: string, cert: string, expires: number }>} */
    this.cache = new Map();
    this.keys = null;
  }

  /** @param {string} host */
  async for(host) {
    const hit = this.cache.get(host);
    if (hit && hit.expires > Date.now() + DAY) return hit;
    this.keys ??= await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
    const now = Date.now();
    const notAfter = new Date(now + 30 * DAY);
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial(),
      subject: `CN=${host}`,
      issuer: this.ca.cert.subject,
      notBefore: new Date(now - DAY),
      notAfter,
      signingAlgorithm: ALG,
      publicKey: this.keys.publicKey,
      signingKey: this.ca.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
          true,
        ),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth], true),
        new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: host }]),
        await x509.AuthorityKeyIdentifierExtension.create(this.ca.cert),
      ],
    });
    const made = {
      key: await exportKey(this.keys.privateKey),
      cert: `${cert.toString('pem')}\n${this.ca.cert.toString('pem')}`,
      expires: notAfter.getTime(),
    };
    this.cache.set(host, made);
    return made;
  }
}

function serial() {
  const b = webcrypto.getRandomValues(new Uint8Array(12));
  b[0] &= 0x7f; // positive
  return Buffer.from(b).toString('hex');
}
