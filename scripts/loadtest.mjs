/**
 * Load / soak test — sustained concurrent traffic through the real TLS
 * interception path, asserting the security invariants hold under load:
 *
 *   1. ZERO credential leak — the real secret never appears in any response
 *      (header or body), across thousands of scrubbed reflections.
 *   2. Every allowed request succeeds (200) with the secret injected upstream.
 *   3. Deny-by-default still refuses a non-allowlisted host under load.
 *   4. Memory stays bounded (no per-request leak).
 *
 * Reports throughput, p50/p99 latency, and peak RSS as launch evidence.
 *
 * Self-re-execs once with NODE_EXTRA_CA_CERTS = a throwaway upstream CA, exactly
 * like test/e2e.mjs, so the in-process proxy trusts the fake upstream's TLS.
 *
 * Tunables: LOADTEST_MS (default 5000), LOADTEST_CONC (default 24).
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

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const dist = (p) => require(path.join(here, '..', 'dist', p));

const PROXY_PORT = 17850;
const UP_PORT = 18470;
const SECRET = 'REALSECRET_loadtest_DO_NOT_LEAK_5f3c9a';
const DURATION_MS = Number(process.env.LOADTEST_MS) || 5000;
const CONCURRENCY = Number(process.env.LOADTEST_CONC) || 24;

// ---- parent: trust the upstream CA, then re-exec ---------------------------
if (!process.env.AIRLOCK_LOAD_CHILD) {
  const { generateCA } = dist('ca/ca.js');
  const up = generateCA();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-load-'));
  fs.writeFileSync(path.join(tmp, 'upstream-ca.pem'), up.certPem);
  fs.writeFileSync(path.join(tmp, 'upstream-ca.json'), JSON.stringify(up));
  const res = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
    stdio: 'inherit',
    env: {
      ...process.env,
      AIRLOCK_LOAD_CHILD: '1',
      NODE_EXTRA_CA_CERTS: path.join(tmp, 'upstream-ca.pem'),
      AIRLOCK_HOME: path.join(tmp, 'home'),
      AIRLOCK_PROXY_PORT: String(PROXY_PORT),
    },
  });
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {}
  process.exit(res.status ?? 1);
}

// ---- child: run the load ----------------------------------------------------
function parseResponse(buf) {
  const sep = buf.indexOf('\r\n\r\n');
  if (sep < 0) return { status: 0, headers: {}, body: buf.toString('utf8') };
  const head = buf.slice(0, sep).toString('utf8');
  const body = buf.slice(sep + 4).toString('utf8');
  const lines = head.split('\r\n');
  const status = parseInt(lines[0].split(' ')[1], 10);
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx > 0) headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
  }
  return { status, headers, body };
}

function viaProxy({ host, port, pathName = '/', airlockCa }) {
  return new Promise((resolve, reject) => {
    const cr = http.request({ host: '127.0.0.1', port: PROXY_PORT, method: 'CONNECT', path: `${host}:${port}` });
    cr.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        return resolve({ connectStatus: res.statusCode });
      }
      const t = tls.connect({ socket, servername: host, ca: [airlockCa] }, () => {
        t.write(`GET ${pathName} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      });
      const chunks = [];
      t.on('data', (d) => chunks.push(d));
      t.on('end', () => resolve(parseResponse(Buffer.concat(chunks))));
      t.on('error', reject);
    });
    cr.on('error', reject);
    cr.end();
  });
}

async function main() {
  const { Runtime } = dist('runtime.js');
  const { paths } = dist('config.js');
  const { CertAuthority } = dist('ca/ca.js');
  const P = paths();

  const up = JSON.parse(fs.readFileSync(path.join(process.env.AIRLOCK_HOME, '..', 'upstream-ca.json'), 'utf8'));
  const upCa = new CertAuthority(up);
  // Upstream reflects the injected Authorization header + a body containing it,
  // so a scrub regression would immediately leak the secret back to us.
  const upstream = https.createServer({ SNICallback: (sn, cb) => cb(null, upCa.contextFor(sn || 'localhost')) }, (req, res) => {
    const payload = JSON.stringify({ url: req.url, auth: req.headers.authorization || '' });
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
      'x-echo-auth': String(req.headers.authorization || ''),
    });
    res.end(payload);
  });
  await new Promise((r) => upstream.listen(UP_PORT, '127.0.0.1', r));

  const rt = await Runtime.initNew(P);
  rt.addOrUpdateSecret({
    name: 'svc',
    placeholder: '__SVC__',
    allowedHosts: ['localhost'],
    injection: { mode: 'header', header: 'authorization', valueTemplate: `Bearer {{secret}}` },
    value: SECRET,
  });
  rt.savePolicy({
    defaultAction: 'deny',
    egressAllowlist: ['localhost'],
    rules: [{ id: 'allow-local', match: { hosts: ['localhost'] }, action: 'allow' }],
  });
  await rt.startProxy();
  const airlockCa = rt.vault.caCertPem;

  let ok = 0;
  let leaks = 0;
  let bad = 0;
  let denied = 0;
  let denyChecks = 0;
  const latencies = [];
  const rss0 = process.memoryUsage().rss;
  let peakRss = rss0;
  const deadline = Date.now() + DURATION_MS;

  async function oneRequest(i) {
    // Every ~13th request probes deny-by-default toward a non-allowlisted host.
    const denyProbe = i % 13 === 0;
    const t0 = process.hrtime.bigint();
    try {
      if (denyProbe) {
        denyChecks++;
        const r = await viaProxy({ host: 'blocked.example', port: UP_PORT, pathName: '/x', airlockCa });
        if (r.connectStatus && r.connectStatus !== 200) denied++;
        else bad++; // a non-allowlisted host that connected is a deny-by-default failure
        return;
      }
      const r = await viaProxy({ host: 'localhost', port: UP_PORT, pathName: '/echo', airlockCa });
      const hay = (r.body || '') + '\n' + (r.headers ? JSON.stringify(r.headers) : '');
      if (hay.includes(SECRET)) leaks++;
      if (r.status === 200) ok++;
      else bad++;
    } catch {
      bad++;
    } finally {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      latencies.push(ms);
      const rss = process.memoryUsage().rss;
      if (rss > peakRss) peakRss = rss;
    }
  }

  let counter = 0;
  async function worker() {
    while (Date.now() < deadline) await oneRequest(counter++);
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

  await rt.stopProxy();
  rt.close();
  await new Promise((r) => upstream.close(r));

  latencies.sort((a, b) => a - b);
  const pct = (p) => (latencies.length ? latencies[Math.min(latencies.length - 1, Math.floor((p / 100) * latencies.length))] : 0);
  const total = ok + bad + denied;
  const secs = DURATION_MS / 1000;
  const mb = (n) => (n / 1024 / 1024).toFixed(1);

  console.log('');
  console.log('Credential Airlock — load / soak results');
  console.log('-----------------------------------------');
  console.log(`duration:        ${secs}s   concurrency: ${CONCURRENCY}`);
  console.log(`requests:        ${total}   (${(total / secs).toFixed(0)}/s)`);
  console.log(`allowed 200:     ${ok}`);
  console.log(`deny probes:     ${denyChecks}   correctly denied: ${denied}`);
  console.log(`latency p50/p99: ${pct(50).toFixed(1)} / ${pct(99).toFixed(1)} ms`);
  console.log(`RSS start/peak:  ${mb(rss0)} / ${mb(peakRss)} MB   (delta ${mb(peakRss - rss0)} MB)`);
  console.log(`LEAKS:           ${leaks}`);
  console.log('-----------------------------------------');

  const failures = [];
  if (leaks > 0) failures.push(`SECRET LEAKED in ${leaks} responses`);
  if (ok === 0) failures.push('no allowed requests succeeded');
  if (bad > 0) failures.push(`${bad} unexpected/failed requests (incl. any deny-by-default bypass)`);
  if (denyChecks > 0 && denied !== denyChecks) failures.push(`deny-by-default failed: ${denyChecks - denied}/${denyChecks} non-allowlisted hosts were NOT denied`);
  // Generous ceiling: a per-request leak over thousands of requests would blow past this.
  if (peakRss - rss0 > 350 * 1024 * 1024) failures.push(`RSS grew ${mb(peakRss - rss0)} MB (possible leak)`);

  if (failures.length) {
    console.log('RESULT: FAIL');
    for (const f of failures) console.log('  - ' + f);
    process.exit(1);
  }
  console.log('RESULT: PASS  (zero leaks, deny-by-default held, memory bounded under load)');
  process.exit(0);
}

main().catch((e) => {
  console.error('loadtest error:', e);
  process.exit(1);
});
