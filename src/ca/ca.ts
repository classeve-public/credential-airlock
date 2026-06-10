/**
 * Local Certificate Authority for TLS interception of allowlisted hosts.
 *
 * The agent trusts this CA (via NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE wired in
 * by the launcher, or by importing airlock-ca.crt). The proxy then terminates TLS
 * for allowlisted hosts to inject credentials and enforce policy, and re-encrypts
 * to the real upstream. Non-allowlisted hosts are never intercepted — they are
 * denied outright (deny-by-default egress).
 *
 * The CA private key lives only inside the sealed vault. Per-host leaf certs are
 * minted on demand and cached, all sharing ONE leaf keypair so minting is cheap
 * (no per-host RSA keygen).
 */
import * as tls from 'tls';
import * as forge from 'node-forge';

const pki = forge.pki;

export interface CaMaterial {
  certPem: string;
  keyPem: string;
}

function randomSerial(): string {
  // Positive hex serial.
  const bytes = forge.random.getBytesSync(16);
  let hex = forge.util.bytesToHex(bytes);
  // Ensure positive (high bit clear) per RFC 5280 best practice.
  if (parseInt(hex[0], 16) >= 8) hex = '0' + hex.slice(1);
  return hex;
}

/** Generate a fresh self-signed CA (RSA-2048, ~10 year validity). */
export function generateCA(): CaMaterial {
  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
  const attrs = [
    { name: 'commonName', value: 'Credential Airlock Local CA' },
    { name: 'organizationName', value: 'Credential Airlock' },
    { shortName: 'OU', value: 'Local TLS Interception (this machine only)' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    certPem: pki.certificateToPem(cert),
    keyPem: pki.privateKeyToPem(keys.privateKey),
  };
}

export class CertAuthority {
  private caCert: forge.pki.Certificate;
  private caKey: forge.pki.PrivateKey;
  private leafKeys: forge.pki.rsa.KeyPair;
  private leafPublicPem: string;
  private leafPrivatePem: string;
  private cache = new Map<string, tls.SecureContext>();

  constructor(material: CaMaterial) {
    this.caCert = pki.certificateFromPem(material.certPem);
    this.caKey = pki.privateKeyFromPem(material.keyPem);
    // One shared leaf keypair for all intercepted hosts -> cheap per-host minting.
    this.leafKeys = pki.rsa.generateKeyPair(2048);
    this.leafPublicPem = pki.publicKeyToPem(this.leafKeys.publicKey);
    this.leafPrivatePem = pki.privateKeyToPem(this.leafKeys.privateKey);
  }

  private mintCertPem(host: string): string {
    const cert = pki.createCertificate();
    cert.publicKey = this.leafKeys.publicKey;
    cert.serialNumber = randomSerial();
    cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
    cert.validity.notAfter = new Date(Date.now() + 2 * 365 * 24 * 3600 * 1000);
    cert.setSubject([{ name: 'commonName', value: host }]);
    cert.setIssuer((this.caCert.subject.attributes as forge.pki.CertificateField[]));
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      {
        name: 'subjectAltName',
        altNames: [isIp ? { type: 7, ip: host } : { type: 2, value: host }],
      },
    ]);
    cert.sign(this.caKey, forge.md.sha256.create());
    return pki.certificateToPem(cert);
  }

  /** Get (cached) a TLS SecureContext presenting a valid cert for `host`. */
  contextFor(host: string): tls.SecureContext {
    const hit = this.cache.get(host);
    if (hit) return hit;
    const certPem = this.mintCertPem(host);
    const ctx = tls.createSecureContext({
      key: this.leafPrivatePem,
      cert: certPem,
    });
    this.cache.set(host, ctx);
    return ctx;
  }
}
