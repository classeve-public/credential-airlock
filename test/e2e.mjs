/**
 * End-to-end test of the real HTTPS interception path.
 *
 * Self-re-execs once with NODE_EXTRA_CA_CERTS pointing at a throwaway "upstream"
 * CA, so the proxy (running in-process) trusts our fake upstream's TLS cert just
 * as it would a real provider. The client trusts the airlock CA explicitly.
 *
 * Asserts: header injection, placeholder-in-body injection, deny-by-default
 * egress, amount cap, human-approval hold (approve + deny), audit chain
 * integrity, and that the real secret never touches disk or the audit log.
 */
import { createRequire } from 'module';
import http from 'http';
import https from 'https';
import tls from 'tls';
import net from 'net';
import zlib from 'zlib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const dist = (p) => require(path.join(here, '..', 'dist', p));

const PROXY_PORT = 17799;
const UP_PORT = 18444;
const HEADER_SECRET = 'REALSECRET_header_4242';
const PH_SECRET = 'REALSECRET_ph_9999';

// ---- parent: set up trust + re-exec ---------------------------------------
if (!process.env.AIRLOCK_E2E_CHILD) {
  const { generateCA } = dist('ca/ca.js');
  const up = generateCA();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-e2e-'));
  const caFile = path.join(tmp, 'upstream-ca.pem');
  fs.writeFileSync(caFile, up.certPem);
  fs.writeFileSync(path.join(tmp, 'upstream-ca.json'), JSON.stringify(up));
  const res = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
    stdio: 'inherit',
    env: {
      ...process.env,
      AIRLOCK_E2E_CHILD: '1',
      NODE_EXTRA_CA_CERTS: caFile,
      AIRLOCK_HOME: path.join(tmp, 'home'),
      AIRLOCK_PROXY_PORT: String(PROXY_PORT),
      E2E_TMP: tmp,
    },
  });
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {}
  process.exit(res.status ?? 1);
}

// ---- child: the actual test ------------------------------------------------
let passed = 0;
let failed = 0;
const ok = (name, cond, extra = '') => {
  if (cond) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name}  ${extra}`);
  }
};

function parseResponse(buf) {
  const sep = buf.indexOf('\r\n\r\n');
  const head = buf.slice(0, sep).toString('utf8');
  const body = buf.slice(sep + 4).toString('utf8');
  const lines = head.split('\r\n');
  const status = parseInt(lines[0].split(' ')[1], 10);
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx > 0) headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
  }
  return { status, body, headers };
}

// Make an HTTPS request through the proxy via CONNECT; client trusts airlockCa.
function viaProxy({ host, port, method = 'GET', pathName = '/', headers = {}, body = null, airlockCa }) {
  return new Promise((resolve, reject) => {
    const connreq = http.request({ host: '127.0.0.1', port: PROXY_PORT, method: 'CONNECT', path: `${host}:${port}` });
    connreq.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        resolve({ connectStatus: res.statusCode });
        return;
      }
      const tlsSock = tls.connect({ socket, servername: host, ca: [airlockCa] }, () => {
        const lines = [
          `${method} ${pathName} HTTP/1.1`,
          `Host: ${host}`,
          'Connection: close',
          ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
        ];
        if (body != null) lines.push(`Content-Length: ${Buffer.byteLength(body)}`);
        tlsSock.write(lines.join('\r\n') + '\r\n\r\n' + (body || ''));
      });
      const chunks = [];
      tlsSock.on('data', (d) => chunks.push(d));
      tlsSock.on('end', () => resolve(parseResponse(Buffer.concat(chunks))));
      tlsSock.on('error', reject);
    });
    connreq.on('error', reject);
    connreq.end();
  });
}

// Plain-HTTP forward-proxy request (absolute-form URL as the request target).
function viaPlainProxy(absoluteUrl) {
  return new Promise((resolve, reject) => {
    const u = new URL(absoluteUrl);
    const r = http.request(
      { host: '127.0.0.1', port: PROXY_PORT, method: 'GET', path: absoluteUrl, headers: { Host: u.host } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      }
    );
    r.on('error', reject);
    r.end();
  });
}

async function main() {
  const tmp = process.env.E2E_TMP;
  const { Runtime } = dist('runtime.js');
  const { paths } = dist('config.js');
  const { CertAuthority } = dist('ca/ca.js');
  const P = paths();

  // Fake upstream HTTPS server that echoes what it received.
  const up = JSON.parse(fs.readFileSync(path.join(tmp, 'upstream-ca.json'), 'utf8'));
  const upCa = new CertAuthority(up);
  let received = null; // what the upstream actually saw (responses are scrubbed, so we can't read it back)
  const upstream = https.createServer({ SNICallback: (sn, cb) => cb(null, upCa.contextFor(sn || 'localhost')) }, (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const bodyStr = Buffer.concat(chunks).toString('utf8');
      received = { url: req.url, headers: req.headers, body: bodyStr };
      // Deliberately REFLECT the auth back (body + header) to test response scrubbing.
      const payload = JSON.stringify({ url: req.url, headers: req.headers, body: bodyStr });
      if (req.url.startsWith('/gzipreflect')) {
        // Non-conforming: gzip despite the proxy stripping Accept-Encoding.
        const gz = zlib.gzipSync(Buffer.from(payload));
        res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': gz.length });
        res.end(gz);
        return;
      }
      if (req.url.startsWith('/bomb')) {
        // Small compressed body that inflates to 11MB (> MAX_BODY 10MB) — a zip bomb.
        const big = zlib.gzipSync(Buffer.alloc(11 * 1024 * 1024, 0x41));
        res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': big.length });
        res.end(big);
        return;
      }
      if (req.url.startsWith('/fakegzip')) {
        // Hostile: claim gzip but send PLAINTEXT echoing the injected secret. The proxy
        // can't decompress (to scrub) -> must FAIL CLOSED, never forward the raw bytes.
        const leak = 'PLAINTEXT-NOT-GZIP ' + String(req.headers.authorization || '') + ' end';
        res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': Buffer.byteLength(leak) });
        res.end(leak);
        return;
      }
      if (req.url.startsWith('/octet')) {
        res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': Buffer.byteLength(payload), 'x-echo-auth': String(req.headers.authorization || '') });
        res.end(payload);
        return;
      }
      if (req.url.startsWith('/resetmid')) {
        // Hostile/flaky upstream: send headers + a PARTIAL body, then ABRUPTLY reset
        // the TCP connection mid-body (no 'end'). The proxy must finalize the agent
        // response (no hang) and still write one audit line for the egress.
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100000' });
        res.write('{"partial":true,');
        setTimeout(() => {
          try {
            res.socket?.destroy();
          } catch {
            /* ignore */
          }
        }, 20);
        return;
      }
      if (req.url.startsWith('/reflectname')) {
        // Hostile: echo the RECEIVED credential back as a response HEADER NAME.
        const secretName = String(req.headers.authorization || 'x').replace(/^Bearer /, '');
        const h = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) };
        try {
          h[secretName] = '1';
        } catch {
          /* invalid name */
        }
        res.writeHead(200, h);
        res.end(payload);
        return;
      }
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-echo-auth': String(req.headers.authorization || ''),
      });
      res.end(payload);
    });
  });
  await new Promise((r) => upstream.listen(UP_PORT, '127.0.0.1', r));

  const rt = await Runtime.initNew(P);
  rt.addOrUpdateSecret({
    name: 'svc',
    placeholder: '__SVC__',
    allowedHosts: ['localhost'],
    injection: { mode: 'header', header: 'authorization', valueTemplate: 'Bearer {{secret}}' },
    value: HEADER_SECRET,
  });
  rt.addOrUpdateSecret({
    name: 'apikey',
    placeholder: '__APIKEY__',
    allowedHosts: ['localhost'],
    injection: { mode: 'placeholder', placeholder: '__APIKEY__', injectInBody: true },
    value: PH_SECRET,
  });
  // A secret bound to a NON-local host, to prove cleartext injection is refused.
  rt.addOrUpdateSecret({
    name: 'cleartextsvc',
    placeholder: '__CT__',
    allowedHosts: ['api.cleartext.test'],
    injection: { mode: 'header', header: 'authorization', valueTemplate: 'Bearer {{secret}}' },
    value: 'REALSECRET_cleartext_5555',
  });
  // Explicit policy: approval + amount rules BEFORE the broad allow (first match wins).
  rt.savePolicy({
    defaultAction: 'deny',
    egressAllowlist: ['localhost', 'api.cleartext.test'],
    rules: [
      { id: 'approval', match: { hosts: ['localhost'], paths: ['/needapproval'] }, action: 'require_approval' },
      { id: 'amount', match: { hosts: ['localhost'], paths: ['/charge'] }, action: 'allow', amountLimit: { field: 'amount', max: 1000 } },
      { id: 'allow-local', match: { hosts: ['localhost'] }, action: 'allow' },
      { id: 'allow-ct', match: { hosts: ['api.cleartext.test'] }, action: 'allow' },
    ],
  });
  await rt.startProxy();
  const airlockCa = rt.vault.caCertPem;

  // 1. header-mode injection reaches upstream + response is scrubbed
  {
    const r = await viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/echo', airlockCa });
    ok('header injection: upstream received real Bearer token', received && received.headers.authorization === `Bearer ${HEADER_SECRET}`, received && received.headers.authorization);
    ok('response scrub: secret redacted in reflected body', !r.body.includes(HEADER_SECRET) && r.body.includes('REDACTED'), r.body.slice(0, 100));
    ok('response scrub: secret redacted in reflected header', !(r.headers['x-echo-auth'] || '').includes(HEADER_SECRET), r.headers['x-echo-auth']);
  }

  // 1c. a reflective upstream echoing the secret as a response HEADER NAME must be dropped/scrubbed
  {
    const r = await viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/reflectname', airlockCa });
    const keys = Object.keys(r.headers).join('|').toLowerCase();
    ok('response scrub: secret reflected as a HEADER NAME is dropped', !keys.includes(HEADER_SECRET.toLowerCase()), keys);
  }

  // 1d. cleartext credential injection to a NON-local host is refused (key never leaves over plain HTTP)
  {
    const r = await viaPlainProxy('http://api.cleartext.test/x');
    ok('cleartext guard: plain-HTTP injection to a non-local host is refused (403)', r.status === 403 && /cleartext/i.test(r.body), `${r.status} ${r.body.slice(0, 80)}`);
  }

  // 1e. set-time validation: a control-char secret value is rejected at write time (not sealed then black-holed)
  {
    let threw = false;
    try {
      rt.addOrUpdateSecret({
        name: 'bad',
        placeholder: '__BAD__',
        allowedHosts: ['localhost'],
        injection: { mode: 'header', header: 'authorization', valueTemplate: 'Bearer {{secret}}' },
        value: 'tok\r\nInjected: 1',
      });
    } catch {
      threw = true;
    }
    ok('set-time validation: a CR/LF secret value is rejected at write time', threw && !rt.vault.hasSecret('bad'));
  }

  // 1b. gzip reflective response: decompressed, scrubbed, re-emitted identity (not corrupted)
  {
    const r = await viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/gzipreflect', airlockCa });
    let parsed = null;
    try {
      parsed = JSON.parse(r.body);
    } catch {
      /* leave null */
    }
    ok('gzip response: body is valid decompressed JSON (not corrupted)', parsed !== null, r.body.slice(0, 80));
    ok('gzip response: secret redacted', !r.body.includes(HEADER_SECRET) && r.body.includes('REDACTED'));
    ok('gzip response: content-encoding stripped', !('content-encoding' in r.headers));
  }

  // 1c. body scrubbed regardless of content-type (octet-stream reflective body)
  {
    const r = await viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/octet', airlockCa });
    ok('non-textual content-type: body still scrubbed', !r.body.includes(HEADER_SECRET) && r.body.includes('REDACTED'), r.body.slice(0, 80));
  }

  // 1d. a decompression bomb is contained: bounded output + FAIL CLOSED (502), no OOM/leak
  {
    const r = await viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/bomb', airlockCa });
    ok('decompression bomb contained (fails closed 502, no raw passthrough)', r.status === 502, `status=${r.status}`);
  }

  // 1e. fake Content-Encoding (plaintext labelled gzip) reflecting the secret: must FAIL CLOSED
  {
    const r = await viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/fakegzip', airlockCa });
    ok('fake content-encoding: fails closed (502)', r.status === 502, `status=${r.status}`);
    ok('fake content-encoding: injected secret is NOT leaked to the agent', !r.body.includes(HEADER_SECRET), r.body.slice(0, 80));
  }

  // 1f. HEAD response: content-length preserved (not rewritten to 0)
  {
    const r = await viaProxy({ host: 'localhost', port: UP_PORT, method: 'HEAD', pathName: '/echo', airlockCa });
    ok('HEAD: status 200 and content-length preserved (not zeroed)', r.status === 200 && Number(r.headers['content-length']) > 0, `cl=${r.headers['content-length']}`);
  }

  // 1g. LIFECYCLE: an upstream RST mid-body must finalize the agent response (no
  // permanent hang) AND still emit an audit line. (Regression: the old teardown
  // handlers released the byte counter but never ended res or called done.)
  {
    let r;
    try {
      r = await Promise.race([
        viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/resetmid', airlockCa }),
        new Promise((res) => setTimeout(() => res({ status: 'HANG_TIMEOUT' }), 8000)),
      ]);
    } catch (e) {
      r = { status: 'ERR', err: String(e) };
    }
    ok('lifecycle: upstream RST mid-body does NOT hang the agent', r.status !== 'HANG_TIMEOUT', JSON.stringify(r));
    ok('lifecycle: upstream RST mid-body fails closed (502)', r.status === 502, JSON.stringify(r));
  }

  // 1h. LIFECYCLE/AUDIT: an allowlisted host whose connection is REFUSED must 502
  // (no hang) and the audit must NOT over-claim the credential as delivered.
  {
    const closedPort = await new Promise((resolve) => {
      const s = net.createServer();
      s.listen(0, '127.0.0.1', () => {
        const p = s.address().port;
        s.close(() => resolve(p));
      });
    });
    let r;
    try {
      r = await Promise.race([
        viaProxy({ host: 'localhost', port: closedPort, pathName: '/echo', airlockCa }),
        new Promise((res) => setTimeout(() => res({ status: 'HANG_TIMEOUT' }), 8000)),
      ]);
    } catch (e) {
      r = { status: 'ERR', err: String(e) };
    }
    ok('lifecycle: connection-refused upstream fails closed without hang', r.status === 502 || r.status === 'ERR', JSON.stringify(r));
  }

  // 1i. DENY-BY-DEFAULT on the PLAIN-HTTP plane: a non-allowlisted host is refused
  // (403) — symmetric with CONNECT, and BEFORE any DNS lookup (no blind-DNS exfil).
  {
    const r = await viaPlainProxy('http://definitely-not-allowlisted.invalid/x');
    ok('deny-by-default (plain plane): non-allowlisted host refused (403)', r.status === 403, `${r.status} ${r.body.slice(0, 80)}`);
  }

  // 2. placeholder injection in header AND body (verified at the upstream)
  {
    await viaProxy({
      host: 'localhost',
      port: UP_PORT,
      method: 'POST',
      pathName: '/echo',
      headers: { 'x-api-key': '__APIKEY__', 'content-type': 'application/json' },
      body: JSON.stringify({ k: '__APIKEY__' }),
      airlockCa,
    });
    ok('placeholder injection: header swapped (upstream)', received && received.headers['x-api-key'] === PH_SECRET, received && received.headers['x-api-key']);
    ok('placeholder injection: body swapped (upstream)', received && received.body.includes(PH_SECRET) && !received.body.includes('__APIKEY__'), received && received.body);
  }

  // 3. deny-by-default egress
  {
    const r = await viaProxy({ host: 'blocked.invalid', port: 443, airlockCa });
    ok('egress deny: non-allowlisted host gets 403 on CONNECT', r.connectStatus === 403, JSON.stringify(r));
  }

  // 4. amount cap
  {
    const over = await viaProxy({
      host: 'localhost', port: UP_PORT, method: 'POST', pathName: '/charge',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ amount: 5000 }), airlockCa,
    });
    ok('amount cap: over-limit charge blocked (403)', over.status === 403, `status=${over.status}`);
    const under = await viaProxy({
      host: 'localhost', port: UP_PORT, method: 'POST', pathName: '/charge',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ amount: 500 }), airlockCa,
    });
    ok('amount cap: under-limit charge allowed (200)', under.status === 200, `status=${under.status}`);
  }

  // 4b. amount-cap bypass attempts now fail closed
  {
    const ws = await viaProxy({
      host: 'localhost', port: UP_PORT, method: 'POST', pathName: '/charge',
      headers: { 'content-type': 'text/plain' }, body: '   {"amount":5000}', airlockCa,
    });
    ok('amount bypass (leading-whitespace + text/plain) blocked', ws.status === 403, `status=${ws.status}`);
    const form = await viaProxy({
      host: 'localhost', port: UP_PORT, method: 'POST', pathName: '/charge',
      headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'amount=5000&currency=usd', airlockCa,
    });
    ok('amount bypass (urlencoded over-limit) blocked', form.status === 403, `status=${form.status}`);
    const mp = await viaProxy({
      host: 'localhost', port: UP_PORT, method: 'POST', pathName: '/charge',
      headers: { 'content-type': 'multipart/form-data; boundary=X' },
      body: '--X\r\nContent-Disposition: form-data; name="amount"\r\n\r\n5000\r\n--X--\r\n', airlockCa,
    });
    ok('amount cap (multipart, unparseable) fails closed', mp.status === 403, `status=${mp.status}`);
  }

  // 4c. JSON array / bare primitive / non-numeric amount cannot bypass the cap
  {
    const cases = [
      ['top-level array', JSON.stringify([{ amount: 99999 }])],
      ['bare number', '99999'],
      ['non-numeric string', JSON.stringify({ amount: '99999abc' })],
    ];
    for (const [label, body] of cases) {
      const r = await viaProxy({
        host: 'localhost', port: UP_PORT, method: 'POST', pathName: '/charge',
        headers: { 'content-type': 'application/json' }, body, airlockCa,
      });
      ok(`amount bypass (${label}) blocked`, r.status === 403, `status=${r.status}`);
    }
    // duplicate urlencoded keys: get() sees the first (under-cap), upstream uses the last
    const dup = await viaProxy({
      host: 'localhost', port: UP_PORT, method: 'POST', pathName: '/charge',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'amount=1&currency=usd&amount=99999', airlockCa,
    });
    ok('amount bypass (duplicate urlencoded key) blocked', dup.status === 403, `status=${dup.status}`);
  }

  // 5. human-approval hold — approve
  {
    const p = viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/needapproval', airlockCa });
    await new Promise((r) => setTimeout(r, 250));
    const pending = rt.approvals.listPending();
    ok('approval: request is held pending', pending.length === 1, `pending=${pending.length}`);
    if (pending.length) rt.approvals.approve(pending[0].id);
    const r = await p;
    ok('approval: approved request completes (200)', r.status === 200, `status=${r.status}`);
  }

  // 5b. human-approval hold — deny
  {
    const p = viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/needapproval', airlockCa });
    await new Promise((r) => setTimeout(r, 250));
    const pending = rt.approvals.listPending();
    if (pending.length) rt.approvals.deny(pending[0].id);
    const r = await p;
    ok('approval: denied request is blocked (403)', r.status === 403, `status=${r.status}`);
  }

  // 6. audit chain integrity
  {
    const v = rt.audit.verify();
    ok('audit: hash chain verifies', v.ok === true && v.entries > 0, JSON.stringify(v));
  }

  // 7. secret never on disk / in audit
  {
    const vaultBytes = fs.readFileSync(P.vaultEnc);
    ok('vault.enc does not contain the plaintext secret', !vaultBytes.includes(HEADER_SECRET) && !vaultBytes.includes(PH_SECRET));
    const auditTxt = fs.existsSync(P.audit) ? fs.readFileSync(P.audit, 'utf8') : '';
    ok('audit log does not contain any secret value', !auditTxt.includes(HEADER_SECRET) && !auditTxt.includes(PH_SECRET));
    const auditHasName = auditTxt.includes('"svc"') || auditTxt.includes('svc');
    ok('audit log records secret NAME (svc), not value', auditHasName);
    // The connection-refused request (1h) must be audited as a NON-delivered egress —
    // the credential never left, so the tamper-evident log must not over-claim it.
    ok('audit fidelity: a pre-egress failure is recorded delivered:false', auditTxt.includes('"delivered":false'), 'no delivered:false entry found');
  }

  await rt.stopProxy();
  rt.close();

  // 8. audit: a crash-torn trailing fragment recovers cleanly (truncate-on-open, no chain fork)
  {
    const { AuditLog } = dist('audit/audit.js');
    fs.appendFileSync(P.audit, '{"seq":999,"partial'); // torn write, no trailing newline
    const al = new AuditLog(P); // constructor must physically drop the torn bytes
    al.append({ event: 'system', reason: 'post-recovery' });
    const v = al.verify();
    ok('audit: recovers from a torn tail (verify ok after next append)', v.ok === true, JSON.stringify(v));
  }

  // 9. audit: tail truncation is detected AND stays detected after a later append
  {
    const { AuditLog } = dist('audit/audit.js');
    ok('audit: intact chain verifies', new AuditLog(P).verify().ok === true);
    const lines = fs.readFileSync(P.audit, 'utf8').split('\n').filter((l) => l.trim());
    fs.writeFileSync(P.audit, lines.slice(0, -1).join('\n') + '\n'); // delete the most recent entry
    const al = new AuditLog(P); // detects tip-ahead -> writes a sticky tamper marker
    ok('audit: tail truncation detected (tip mismatch)', al.verify().ok === false, JSON.stringify(al.verify()));
    al.append({ event: 'system', reason: 'post-truncation' }); // a later append must NOT launder it
    ok('audit: truncation stays detected after a later append', new AuditLog(P).verify().ok === false);
  }

  // 9. a vault is never clobbered
  {
    const { Vault } = dist('vault/vault.js');
    const { createSealer, autoSealerKind } = dist('crypto/sealer.js');
    let threw = false;
    try {
      await Vault.create(P, createSealer(autoSealerKind()));
    } catch {
      threw = true;
    }
    ok('vault: refuses to overwrite an existing vault', threw);
  }

  // 10. single-instance lock prevents concurrent writers
  {
    const a = await Runtime.open(P);
    a.acquireLock();
    const b = await Runtime.open(P);
    let locked = false;
    try {
      b.acquireLock();
    } catch {
      locked = true;
    }
    ok('lock: a second acquire is refused while held', locked);
    b.close();
    a.close();
  }

  await new Promise((r) => upstream.close(r));

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('e2e crashed:', e);
  process.exit(1);
});
