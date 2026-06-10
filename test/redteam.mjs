/**
 * Red-team integration tests — actively try to break the trust boundary.
 *
 * Self-re-execs with NODE_EXTRA_CA_CERTS = a throwaway upstream CA so the proxy
 * trusts the fake upstreams (as it would real providers). The client trusts the
 * airlock CA explicitly. Covers attacks the unit/e2e suites don't:
 *   - key exfiltration via CONNECT-target vs Host-header confusion
 *   - cross-secret isolation (secret A must never leak when talking to B's host)
 *   - placeholder not injected toward a non-allowed host
 *   - connection reuse: target/injection stays correct across pipelined requests
 *   - egress deny-by-default on CONNECT
 *   - admin plane: no reveal endpoint, token required, DNS-rebinding Host rejected
 *
 * Run: node test/redteam.mjs   (after `npm run build`)
 */
import { createRequire } from 'module';
import http from 'http';
import https from 'https';
import tls from 'tls';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';
import forge from 'node-forge';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const D = (p) => require(path.join(here, '..', 'dist', p));

const PROXY_PORT = 17760;
const ADMIN_PORT = 17761;
const UP_PORT = 18460;
const SECRET_SVC = 'REALSECRET_svc_AAAA';
const SECRET_OTHER = 'REALSECRET_other_BBBB';

// ---- parent: trust the upstream CA, then re-exec ----
if (!process.env.AIRLOCK_RT_CHILD) {
  const { generateCA } = D('ca/ca.js');
  const up = generateCA();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-rt-'));
  fs.writeFileSync(path.join(tmp, 'upstream-ca.pem'), up.certPem);
  fs.writeFileSync(path.join(tmp, 'upstream-ca.json'), JSON.stringify(up));
  const res = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
    stdio: 'inherit',
    env: { ...process.env, AIRLOCK_RT_CHILD: '1', NODE_EXTRA_CA_CERTS: path.join(tmp, 'upstream-ca.pem'), AIRLOCK_HOME: path.join(tmp, 'home'), AIRLOCK_PROXY_PORT: String(PROXY_PORT), AIRLOCK_ADMIN_PORT: String(ADMIN_PORT), E2E_TMP: tmp },
  });
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  process.exit(res.status ?? 1);
}

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => { if (cond) pass++; else { fail++; console.log(`  FAIL  ${name}  ${extra}`); } };

function parseOne(buf, off) {
  const sep = buf.indexOf('\r\n\r\n', off);
  const head = buf.slice(off, sep).toString('utf8');
  const lines = head.split('\r\n');
  const status = parseInt(lines[0].split(' ')[1], 10);
  const headers = {};
  for (let i = 1; i < lines.length; i++) { const c = lines[i].indexOf(':'); if (c > 0) headers[lines[i].slice(0, c).trim().toLowerCase()] = lines[i].slice(c + 1).trim(); }
  const len = parseInt(headers['content-length'] || '0', 10);
  const bodyStart = sep + 4;
  const body = buf.slice(bodyStart, bodyStart + len).toString('utf8');
  return { status, headers, body, next: bodyStart + len };
}

// One request per connection (Connection: close). hostHeader overrides the Host line.
function viaProxy({ connectHost, port, method = 'GET', pathName = '/', headers = {}, body = null, hostHeader, airlockCa }) {
  return new Promise((resolve, reject) => {
    const cr = http.request({ host: '127.0.0.1', port: PROXY_PORT, method: 'CONNECT', path: `${connectHost}:${port}` });
    cr.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return resolve({ connectStatus: res.statusCode }); }
      const t = tls.connect({ socket, servername: connectHost, ca: [airlockCa] }, () => {
        const lines = [`${method} ${pathName} HTTP/1.1`, `Host: ${hostHeader || connectHost}`, 'Connection: close', ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`)];
        if (body != null) lines.push(`Content-Length: ${Buffer.byteLength(body)}`);
        t.write(lines.join('\r\n') + '\r\n\r\n' + (body || ''));
      });
      const chunks = [];
      t.on('data', (d) => chunks.push(d));
      t.on('end', () => { try { resolve(parseOne(Buffer.concat(chunks), 0)); } catch (e) { reject(e); } });
      t.on('error', reject);
    });
    cr.on('error', reject);
    cr.end();
  });
}

// Two pipelined requests on ONE intercepted TLS connection (keep-alive reuse).
function viaProxyReuse({ connectHost, port, airlockCa }) {
  return new Promise((resolve, reject) => {
    const cr = http.request({ host: '127.0.0.1', port: PROXY_PORT, method: 'CONNECT', path: `${connectHost}:${port}` });
    cr.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return resolve({ connectStatus: res.statusCode }); }
      const t = tls.connect({ socket, servername: connectHost, ca: [airlockCa] }, () => {
        const r1 = `GET /one HTTP/1.1\r\nHost: ${connectHost}\r\nConnection: keep-alive\r\n\r\n`;
        const r2 = `GET /two HTTP/1.1\r\nHost: ${connectHost}\r\nConnection: close\r\n\r\n`;
        t.write(r1 + r2);
      });
      const chunks = [];
      t.on('data', (d) => chunks.push(d));
      t.on('end', () => {
        try { const buf = Buffer.concat(chunks); const a = parseOne(buf, 0); const b = parseOne(buf, a.next); resolve([a, b]); } catch (e) { reject(e); }
      });
      t.on('error', reject);
    });
    cr.on('error', reject);
    cr.end();
  });
}

async function main() {
  const tmp = process.env.E2E_TMP;
  const { Runtime } = D('runtime.js');
  const { paths } = D('config.js');
  const { AdminServer } = D('admin/server.js');
  const { CertAuthority } = D('ca/ca.js');
  const P = paths();

  const up = JSON.parse(fs.readFileSync(path.join(tmp, 'upstream-ca.json'), 'utf8'));
  void CertAuthority;
  // Default leaf covering BOTH localhost (SNI) and 127.0.0.1 (no-SNI/IP), signed by the upstream CA.
  const upLeaf = (() => {
    const caCert = forge.pki.certificateFromPem(up.certPem);
    const caKey = forge.pki.privateKeyFromPem(up.keyPem);
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date(Date.now() - 86400000);
    cert.validity.notAfter = new Date(Date.now() + 86400000 * 365);
    cert.setSubject([{ name: 'commonName', value: 'localhost' }]);
    cert.setIssuer(caCert.subject.attributes);
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] },
    ]);
    cert.sign(caKey, forge.md.sha256.create());
    return { key: forge.pki.privateKeyToPem(keys.privateKey), cert: forge.pki.certificateToPem(cert) };
  })();
  const receivedAll = [];
  const upstream = https.createServer({ key: upLeaf.key, cert: upLeaf.cert }, (req, res) => {
    const c = [];
    req.on('data', (x) => c.push(x));
    req.on('end', () => {
      receivedAll.push({ url: req.url, headers: req.headers });
      const payload = JSON.stringify({ url: req.url, headers: req.headers });
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
      res.end(payload);
    });
  });
  await new Promise((r) => upstream.listen(UP_PORT, '127.0.0.1', r));

  const rt = await Runtime.initNew(P);
  // svc -> only 'localhost'; other -> only '127.0.0.1'. Both resolve to 127.0.0.1.
  rt.addOrUpdateSecret({ name: 'svc', placeholder: '__SVC__', allowedHosts: ['localhost'], injection: { mode: 'header', header: 'authorization', valueTemplate: 'Bearer {{secret}}' }, value: SECRET_SVC });
  rt.addOrUpdateSecret({ name: 'other', placeholder: '__OTHER__', allowedHosts: ['127.0.0.1'], injection: { mode: 'header', header: 'x-other', valueTemplate: '{{secret}}' }, value: SECRET_OTHER });
  // An allowlisted PRIVATE IP — the SSRF guard must still refuse egress to it.
  rt.addOrUpdateSecret({ name: 'internal', placeholder: '__INT__', allowedHosts: ['10.0.0.1'], injection: { mode: 'header', header: 'x-int', valueTemplate: '{{secret}}' }, value: 'REALSECRET_internal_CCCC' });
  await rt.startProxy();
  const ca = rt.vault.caCertPem;

  // 1. CONNECT-target keying: CONNECT localhost but spoof Host: 127.0.0.1.
  //    Injection must follow the CONNECT target (localhost -> svc), NOT the Host header,
  //    and 'other' (bound to 127.0.0.1) must NOT leak.
  {
    const r = await viaProxy({ connectHost: 'localhost', port: UP_PORT, pathName: '/echo', hostHeader: '127.0.0.1', airlockCa: ca });
    const got = receivedAll[receivedAll.length - 1];
    ok('exfil: injection keyed on CONNECT target, not spoofed Host header', got.headers.authorization === `Bearer ${SECRET_SVC}`, got.headers.authorization);
    ok("exfil: other-host secret does NOT leak via Host spoof", got.headers['x-other'] === undefined && !JSON.stringify(got).includes(SECRET_OTHER));
    ok('exfil: response body does not reflect svc secret unscrubbed', !r.body.includes(SECRET_SVC));
  }

  // 2. Cross-secret isolation the other direction: CONNECT 127.0.0.1 -> only 'other'.
  {
    await viaProxy({ connectHost: '127.0.0.1', port: UP_PORT, pathName: '/echo', hostHeader: 'localhost', airlockCa: ca });
    const got = receivedAll[receivedAll.length - 1];
    ok('isolation: CONNECT 127.0.0.1 injects only its own secret', got.headers['x-other'] === SECRET_OTHER && got.headers.authorization === undefined, JSON.stringify(got.headers));
    ok('isolation: svc secret does not leak to the other host', !JSON.stringify(got).includes(SECRET_SVC));
  }

  // 3. Placeholder for svc sent toward 127.0.0.1 (where svc is not allowed) must NOT be swapped.
  {
    await viaProxy({ connectHost: '127.0.0.1', port: UP_PORT, pathName: '/p', headers: { 'x-try': '__SVC__' }, airlockCa: ca });
    const got = receivedAll[receivedAll.length - 1];
    ok('host-binding: svc placeholder not injected toward a non-allowed host', got.headers['x-try'] === '__SVC__' && !JSON.stringify(got).includes(SECRET_SVC), got.headers['x-try']);
  }

  // 4. Connection reuse: two pipelined requests on one intercepted socket both get svc.
  {
    const out = await viaProxyReuse({ connectHost: 'localhost', port: UP_PORT, airlockCa: ca });
    const r1 = receivedAll[receivedAll.length - 2];
    const r2 = receivedAll[receivedAll.length - 1];
    ok('reuse: both pipelined requests reached upstream', Array.isArray(out) && out.length === 2 && out[0].status === 200 && out[1].status === 200, JSON.stringify(out));
    ok('reuse: target+injection stays correct across reused connection', r1 && r2 && r1.headers.authorization === `Bearer ${SECRET_SVC}` && r2.headers.authorization === `Bearer ${SECRET_SVC}`, JSON.stringify([r1 && r1.headers.authorization, r2 && r2.headers.authorization]));
  }

  // 5. Egress deny-by-default on CONNECT.
  {
    const r = await viaProxy({ connectHost: 'blocked.invalid', port: 443, airlockCa: ca });
    ok('egress: CONNECT to non-allowlisted host -> 403', r.connectStatus === 403, JSON.stringify(r));
  }

  // 5b. SSRF guard: even an allowlisted private IP is refused at egress (never inject inward).
  {
    const r = await viaProxy({ connectHost: '10.0.0.1', port: 443, airlockCa: ca });
    ok('SSRF: CONNECT to allowlisted private IP (10.0.0.1) refused (403)', r.connectStatus === 403, JSON.stringify(r));
  }

  // ---- Admin control-plane red-team ----
  const admin = new AdminServer(rt);
  await admin.start();
  const token = admin.token;
  const adminReq = (opts, headers = {}) => new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: ADMIN_PORT, ...opts, headers }, (res) => {
      const c = []; res.on('data', (x) => c.push(x)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString('utf8') }));
    });
    req.on('error', () => resolve({ status: 0, body: '' }));
    req.end();
  });

  // 6. No-reveal: listing returns metadata with NO value field.
  {
    const r = await adminReq({ method: 'GET', path: '/api/secrets' }, { 'x-airlock-token': token });
    let arr = []; try { arr = JSON.parse(r.body); } catch {}
    const anyValue = arr.some((s) => 'value' in s) || r.body.includes(SECRET_SVC) || r.body.includes(SECRET_OTHER);
    ok('admin: GET /api/secrets returns no secret values', r.status === 200 && Array.isArray(arr) && !anyValue, r.body.slice(0, 120));
  }
  // 7. Token required.
  {
    const r = await adminReq({ method: 'GET', path: '/api/status' });
    ok('admin: API without token -> 401', r.status === 401, `status=${r.status}`);
  }
  // 8. No reveal route exists.
  {
    const r = await adminReq({ method: 'GET', path: '/api/secrets/svc/reveal' }, { 'x-airlock-token': token });
    ok('admin: there is no /reveal route (404)', r.status === 404, `status=${r.status}`);
  }
  // 9. DNS-rebinding: a non-loopback Host header is rejected even with a valid token.
  {
    const r = await adminReq({ method: 'GET', path: '/api/status' }, { 'x-airlock-token': token, host: 'evil.attacker.com' });
    ok('admin: non-loopback Host header rejected (DNS-rebind guard)', r.status === 403, `status=${r.status}`);
  }
  // 10. Path traversal on static serving.
  {
    const r = await adminReq({ method: 'GET', path: '/../../package.json' });
    ok('admin: path traversal does not serve files', r.status === 404 || r.status === 403 || !r.body.includes('"dependencies"'), `status=${r.status}`);
  }

  await admin.stop();
  await rt.stopProxy();
  rt.close();
  await new Promise((r) => upstream.close(r));
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error('redteam crashed:', e); process.exit(1); });
