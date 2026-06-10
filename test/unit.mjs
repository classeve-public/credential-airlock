/**
 * Deterministic unit + property tests for the pure-logic core.
 *
 * Strong, fast, reproducible evidence for the crypto, secret-sharing, policy,
 * audit-chain, migration-share, glob, and injection logic. Run: node test/unit.mjs
 * (after `npm run build`). Exits non-zero on any failure.
 */
import { createRequire } from 'module';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const D = (p) => require(path.join(here, '..', 'dist', p));

let pass = 0;
let fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) {
    pass++;
  } else {
    fail++;
    console.log(`  FAIL  ${name}  ${extra}`);
  }
};
const section = (s) => console.log(`\n— ${s}`);
const throws = (fn) => {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
};

// ---------------------------------------------------------------------------
section('shamir secret sharing (GF256) — property fuzz');
{
  const { split, combine } = D('crypto/shamir.js');
  let roundTrips = 0;
  let kMinus1Mismatch = 0;
  let kMinus1Trials = 0;
  for (let trial = 0; trial < 400; trial++) {
    const len = 1 + (crypto.randomBytes(1)[0] % 48);
    const secret = crypto.randomBytes(len);
    const n = 2 + (crypto.randomBytes(1)[0] % 8); // 2..9
    const k = 2 + (crypto.randomBytes(1)[0] % (n - 1)); // 2..n
    const shares = split(secret, k, n);
    // any k distinct shares reconstruct
    const idx = [...Array(n).keys()];
    for (let s = idx.length - 1; s > 0; s--) {
      const j = crypto.randomBytes(1)[0] % (s + 1);
      [idx[s], idx[j]] = [idx[j], idx[s]];
    }
    const pick = idx.slice(0, k).map((i) => shares[i]);
    const recon = combine(pick);
    if (recon.equals(secret)) roundTrips++;
    // k-1 shares must NOT reconstruct the secret
    if (k - 1 >= 2) {
      kMinus1Trials++;
      const less = idx.slice(0, k - 1).map((i) => shares[i]);
      const wrong = combine(less);
      if (!wrong.equals(secret)) kMinus1Mismatch++;
    }
  }
  ok('shamir: 400/400 random k-of-n round-trips reconstruct', roundTrips === 400, `got ${roundTrips}`);
  ok('shamir: (k-1) shares never reconstruct the secret', kMinus1Trials > 0 && kMinus1Mismatch === kMinus1Trials, `${kMinus1Mismatch}/${kMinus1Trials}`);

  // edge cases
  const zero = Buffer.alloc(32, 0);
  ok('shamir: all-zero secret round-trips', combine(split(zero, 2, 3).slice(0, 2)).equals(zero));
  const ff = Buffer.alloc(32, 0xff);
  ok('shamir: all-0xFF secret round-trips', combine(split(ff, 3, 5).slice(2, 5)).equals(ff));
  const sec = crypto.randomBytes(32);
  ok('shamir: k=n round-trips', combine(split(sec, 4, 4)).equals(sec));
  ok('shamir: duplicate share indices rejected', throws(() => combine([split(sec, 2, 3)[0], split(sec, 2, 3)[0]])));
  ok('shamir: k<2 rejected', throws(() => split(sec, 1, 3)));
  ok('shamir: n<k rejected', throws(() => split(sec, 3, 2)));
}

// ---------------------------------------------------------------------------
section('AES-256-GCM authenticated encryption');
{
  const { aesgcmEncrypt, aesgcmDecrypt, randomKey } = D('crypto/aesgcm.js');
  const key = randomKey();
  const aad = Buffer.from('ctx');
  for (let i = 0; i < 50; i++) {
    const pt = crypto.randomBytes(crypto.randomBytes(1)[0]);
    const blob = aesgcmEncrypt(key, pt, aad);
    if (!aesgcmDecrypt(key, blob, aad).equals(pt)) {
      ok('aesgcm: round-trip', false);
      break;
    }
  }
  ok('aesgcm: round-trip (50 random)', true);
  const blob = aesgcmEncrypt(key, Buffer.from('topsecret'), aad);
  ok('aesgcm: wrong key rejected', throws(() => aesgcmDecrypt(randomKey(), blob, aad)));
  ok('aesgcm: AAD mismatch rejected', throws(() => aesgcmDecrypt(key, blob, Buffer.from('other'))));
  const tampered = Buffer.from(blob);
  tampered[tampered.length - 1] ^= 0x01; // flip a ciphertext byte
  ok('aesgcm: ciphertext tamper rejected', throws(() => aesgcmDecrypt(key, tampered, aad)));
  const tagFlip = Buffer.from(blob);
  tagFlip[13] ^= 0x01; // flip a tag byte
  ok('aesgcm: tag tamper rejected', throws(() => aesgcmDecrypt(key, tagFlip, aad)));
  ok('aesgcm: 12-byte IVs are unique across encryptions', (() => {
    const ivs = new Set();
    for (let i = 0; i < 1000; i++) ivs.add(aesgcmEncrypt(key, Buffer.from('x'), aad).subarray(0, 12).toString('hex'));
    return ivs.size === 1000;
  })());
  ok('aesgcm: non-32-byte key rejected', throws(() => aesgcmEncrypt(crypto.randomBytes(16), Buffer.from('x'))));
}

// ---------------------------------------------------------------------------
section('HKDF / scrypt KDFs');
{
  const { hkdf, scryptKey } = D('crypto/hkdf.js');
  const ikm = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  ok('hkdf: deterministic + correct length', hkdf(ikm, salt, 'info', 32).equals(hkdf(ikm, salt, 'info', 32)) && hkdf(ikm, salt, 'info', 32).length === 32);
  ok('hkdf: different info -> different key', !hkdf(ikm, salt, 'a', 32).equals(hkdf(ikm, salt, 'b', 32)));
  ok('hkdf: different salt -> different key', !hkdf(ikm, salt, 'i', 32).equals(hkdf(ikm, crypto.randomBytes(16), 'i', 32)));
  const sa = crypto.randomBytes(16);
  ok('scrypt: deterministic', scryptKey('correct horse battery staple', sa).equals(scryptKey('correct horse battery staple', sa)));
  ok('scrypt: different passphrase -> different key', !scryptKey('a-very-long-passphrase', sa).equals(scryptKey('b-very-long-passphrase', sa)));
}

// ---------------------------------------------------------------------------
section('glob host/path matching (anti-bypass anchoring)');
{
  const { matchHost, matchPath, matchAnyHost, matchAnyPath } = D('util/glob.js');
  ok('glob: *.stripe.com matches api.stripe.com', matchHost('*.stripe.com', 'api.stripe.com'));
  ok('glob: *.stripe.com matches deep a.b.stripe.com', matchHost('*.stripe.com', 'a.b.stripe.com'));
  ok('glob: *.stripe.com does NOT match evil-stripe.com', !matchHost('*.stripe.com', 'evil-stripe.com'));
  ok('glob: *.stripe.com does NOT match stripe.com.evil.com', !matchHost('*.stripe.com', 'stripe.com.evil.com'));
  ok('glob: *.stripe.com does NOT match notstripe.com', !matchHost('*.stripe.com', 'notstripe.com'));
  ok('glob: exact host match', matchHost('api.openai.com', 'api.openai.com'));
  ok('glob: exact host rejects subdomain', !matchHost('api.openai.com', 'evil.api.openai.com'));
  ok('glob: host match is case-insensitive', matchHost('api.openai.com', 'API.OpenAI.COM'));
  ok('glob: no partial (anchored) match', !matchHost('openai.com', 'api.openai.com.evil'));
  ok('glob: path /v1/* matches /v1/chat', matchPath('/v1/*', '/v1/chat'));
  ok('glob: path /v1/* rejects /v2/x', !matchPath('/v1/*', '/v2/x'));
  ok('glob: empty host patterns never match', !matchAnyHost([], 'x'));
  ok('glob: empty path patterns match any (no constraint)', matchAnyPath(undefined, '/anything'));
}

// ---------------------------------------------------------------------------
section('policy engine: deny-by-default, allow, amount fail-closed, rate limit');
{
  const { PolicyEngine, extractAmount } = D('policy/policy.js');
  const ct = 'application/json';
  ok('extractAmount: json number', extractAmount(Buffer.from('{"amount":5000}'), ct, 'amount') === 5000);
  ok('extractAmount: leading whitespace + no ct', extractAmount(Buffer.from('   {"amount":5000}'), undefined, 'amount') === 5000);
  ok('extractAmount: dot-path nested', extractAmount(Buffer.from('{"a":{"b":7}}'), ct, 'a.b') === 7);
  ok('extractAmount: top-level array -> undefined', extractAmount(Buffer.from('[{"amount":9}]'), ct, 'amount') === undefined);
  ok('extractAmount: bare number -> undefined', extractAmount(Buffer.from('9'), ct, 'amount') === undefined);
  ok('extractAmount: non-numeric string -> undefined', extractAmount(Buffer.from('{"amount":"9abc"}'), ct, 'amount') === undefined);
  ok('extractAmount: urlencoded single', extractAmount(Buffer.from('amount=500'), 'application/x-www-form-urlencoded', 'amount') === 500);
  ok('extractAmount: urlencoded duplicate -> undefined (fail closed)', extractAmount(Buffer.from('amount=1&amount=9'), 'application/x-www-form-urlencoded', 'amount') === undefined);
  ok('extractAmount: multipart -> undefined', extractAmount(Buffer.from('--X\r\nContent-Disposition: form-data; name="amount"\r\n\r\n9\r\n--X--'), 'multipart/form-data; boundary=X', 'amount') === undefined);

  const eng = new PolicyEngine({
    defaultAction: 'deny',
    egressAllowlist: ['api.x.com'],
    rules: [
      { id: 'charge', match: { hosts: ['api.x.com'], paths: ['/charge'] }, action: 'allow', amountLimit: { field: 'amount', max: 1000 } },
      { id: 'rl', match: { hosts: ['api.x.com'], paths: ['/rl'] }, action: 'allow', rateLimit: { max: 2, windowSec: 60 } },
      { id: 'allow', match: { hosts: ['api.x.com'] }, action: 'allow' },
    ],
  });
  ok('policy: host off allowlist -> deny', eng.evaluate({ host: 'evil.com', method: 'GET', path: '/', body: null }).action === 'deny');
  ok('policy: allowed host+rule -> allow', eng.evaluate({ host: 'api.x.com', method: 'GET', path: '/ok', body: null }).action === 'allow');
  ok('policy: amount under cap -> allow', eng.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge', body: Buffer.from('{"amount":500}'), contentType: ct }).action === 'allow');
  ok('policy: amount over cap -> deny', eng.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge', body: Buffer.from('{"amount":5000}'), contentType: ct }).action === 'deny');
  ok('policy: amount unreadable (array) on capped rule -> deny', eng.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge', body: Buffer.from('[{"amount":5000}]'), contentType: ct }).action === 'deny');
  ok('policy: negative amount denied (lower bound)', eng.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge', body: Buffer.from('{"amount":-5}'), contentType: ct }).action === 'deny');
  ok('policy: over-cap amount in QUERY denied', eng.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge?amount=5000', body: null }).action === 'deny');
  ok('policy: under-cap amount in QUERY allowed', eng.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge?amount=500', body: null }).action === 'allow');
  ok('policy: capped mutating request with NO readable amount -> deny (fail closed)', eng.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge', body: null }).action === 'deny');
  const rl = () => eng.evaluate({ host: 'api.x.com', method: 'GET', path: '/rl', body: null }).action;
  ok('policy: rate limit allows up to max then denies', rl() === 'allow' && rl() === 'allow' && rl() === 'deny');
  // windowSec=0 must fail closed, not become unlimited
  const eng0 = new PolicyEngine({ defaultAction: 'deny', egressAllowlist: ['h'], rules: [{ id: 'z', match: { hosts: ['h'] }, action: 'allow', rateLimit: { max: 1, windowSec: 0 } }] });
  ok('policy: rateLimit windowSec=0 fails closed (deny)', eng0.evaluate({ host: 'h', method: 'GET', path: '/', body: null }).action === 'deny');
}

// ---------------------------------------------------------------------------
section('migration shares: offline encode/decode + VDK derivation');
{
  const { encodeOfflineShare, decodeOfflineShare, deriveVdk, generateMrk } = D('vault/mrk.js');
  for (let i = 0; i < 50; i++) {
    const share = crypto.randomBytes(33);
    const enc = encodeOfflineShare(share);
    if (!decodeOfflineShare(enc).equals(share)) {
      ok('offline share: round-trip', false);
      break;
    }
  }
  ok('offline share: round-trip (50 random)', true);
  const share = crypto.randomBytes(33);
  const enc = encodeOfflineShare(share);
  ok('offline share: format prefix CA1-', enc.startsWith('CA1-'));
  ok('offline share: corrupted checksum rejected', throws(() => decodeOfflineShare(enc.slice(0, -1) + (enc.slice(-1) === 'a' ? 'b' : 'a'))));
  ok('offline share: corrupted data rejected', throws(() => decodeOfflineShare('CA1-' + 'AAAA' + enc.slice(enc.indexOf('-', 4)))));
  ok('offline share: garbage rejected', throws(() => decodeOfflineShare('not-a-share')));
  const mrk = generateMrk();
  const salt = crypto.randomBytes(16);
  ok('deriveVdk: deterministic + 32 bytes', deriveVdk(mrk, salt).equals(deriveVdk(mrk, salt)) && deriveVdk(mrk, salt).length === 32);
  ok('deriveVdk: different salt -> different VDK', !deriveVdk(mrk, salt).equals(deriveVdk(mrk, crypto.randomBytes(16))));
}

// ---------------------------------------------------------------------------
section('credential injection: per-secret host binding');
{
  const { applyInjection } = D('proxy/inject.js');
  const inj = [{ name: 'k', value: 'REALKEY', allowedHosts: ['api.openai.com'], placeholder: '__K__', injection: { mode: 'header', header: 'authorization', valueTemplate: 'Bearer {{secret}}' } }];
  const allowed = applyInjection(inj, { host: 'api.openai.com', method: 'GET', path: '/', headers: {}, body: null });
  ok('inject: header set for allowed host', allowed.headers['authorization'] === 'Bearer REALKEY' && allowed.injected.includes('k'));
  const denied = applyInjection(inj, { host: 'evil.com', method: 'GET', path: '/', headers: {}, body: null });
  ok('inject: NOT injected toward a non-allowed host', denied.headers['authorization'] === undefined && denied.injected.length === 0);

  const ph = [{ name: 'p', value: 'REALVAL', allowedHosts: ['api.x.com'], placeholder: '__P__', injection: { mode: 'placeholder', placeholder: '__P__', injectInBody: true } }];
  const r = applyInjection(ph, { host: 'api.x.com', method: 'POST', path: '/', headers: { 'x-key': '__P__' }, body: Buffer.from('{"k":"__P__"}') });
  ok('inject: placeholder swapped in header', r.headers['x-key'] === 'REALVAL');
  ok('inject: placeholder swapped in body', r.body.toString().includes('REALVAL') && !r.body.toString().includes('__P__'));
  const r2 = applyInjection(ph, { host: 'evil.com', method: 'POST', path: '/', headers: { 'x-key': '__P__' }, body: Buffer.from('__P__') });
  ok('inject: placeholder NOT swapped toward non-allowed host', r2.headers['x-key'] === '__P__' && r2.body.toString() === '__P__');
}

// ---------------------------------------------------------------------------
section('audit chain: tamper-evidence');
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-unit-'));
  process.env.AIRLOCK_HOME = tmp;
  // require config AFTER setting AIRLOCK_HOME
  delete require.cache[require.resolve(path.join(here, '..', 'dist', 'config.js'))];
  const { paths } = D('config.js');
  const { AuditLog } = D('audit/audit.js');
  const P = paths();
  fs.mkdirSync(P.root, { recursive: true });
  const al = new AuditLog(P);
  for (let i = 0; i < 5; i++) al.append({ event: 'system', reason: 'e' + i });
  ok('audit: intact chain verifies', al.verify().ok === true && al.verify().entries === 5);
  // in-place tamper of an interior line
  const lines = fs.readFileSync(P.audit, 'utf8').split('\n').filter((l) => l.trim());
  const obj = JSON.parse(lines[2]);
  obj.reason = 'TAMPERED';
  lines[2] = JSON.stringify(obj);
  fs.writeFileSync(P.audit, lines.join('\n') + '\n');
  ok('audit: in-place tamper detected', new AuditLog(P).verify().ok === false);
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
