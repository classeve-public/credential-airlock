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
    // k-1 shares must NOT reconstruct the secret. Only assert on secrets long
    // enough that a coincidental (k-1)-point match is cryptographically impossible
    // (256^-16); for a 1-byte secret a chance ~1/256 collision is expected and
    // would make this a flaky assertion, not a real reconstruction.
    if (k - 1 >= 2 && secret.length >= 16) {
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

// ---------------------------------------------------------------------------
section('audit: read-only open (repair=false) never mutates the log');
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-unit-ro-'));
  process.env.AIRLOCK_HOME = tmp;
  delete require.cache[require.resolve(path.join(here, '..', 'dist', 'config.js'))];
  const { paths } = D('config.js');
  const { AuditLog } = D('audit/audit.js');
  const P = paths();
  fs.mkdirSync(P.root, { recursive: true });
  const w = new AuditLog(P, true); // repair-capable writer (the daemon)
  for (let i = 0; i < 3; i++) w.append({ event: 'system', reason: 'e' + i });
  fs.appendFileSync(P.audit, '{"seq":99,"torn'); // simulate a crash-torn trailing fragment
  const sizeBefore = fs.statSync(P.audit).size;
  const ro = new AuditLog(P, false); // read-only open MUST NOT truncate or write tip/tamper
  ok('audit(repair=false): leaves the torn file byte-for-byte unchanged', fs.statSync(P.audit).size === sizeBefore);
  ok('audit(repair=false): verify reports the torn line (not ok)', ro.verify().ok === false);
  ok('audit(repair=false): did NOT write a sticky tamper marker', !fs.existsSync(P.auditTamper));
  const rw = new AuditLog(P, true); // a repair open (daemon restart) DROPS the torn tail
  ok('audit(repair=true): truncates the torn tail on open', fs.statSync(P.audit).size < sizeBefore);
  ok('audit(repair=true): verify ok after repair', rw.verify().ok === true);
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
}

// ---------------------------------------------------------------------------
section('windows command-line quoting (DEP0190-safe spawn)');
{
  const { quoteWinArg, winCommandLine } = D('util/wincmd.js');
  ok('quote: simple token left unquoted', quoteWinArg('simple') === 'simple');
  ok('quote: empty string -> ""', quoteWinArg('') === '""');
  ok('quote: token with spaces is wrapped', quoteWinArg('a b') === '"a b"');
  ok('quote: embedded double-quote is escaped', quoteWinArg('a"b') === '"a\\"b"');
  ok('quote: trailing backslashes doubled before closing quote', quoteWinArg('a b\\') === '"a b\\\\"');
  ok('quote: backslashes before a quote doubled (+1)', quoteWinArg('a\\"b') === '"a\\\\\\"b"');
  ok(
    'cmdline: command + args joined with correct quoting',
    winCommandLine('C:\\my app\\node.exe', ['-e', 'x y']) === '"C:\\my app\\node.exe" -e "x y"'
  );
  // cmd.exe metacharacters in a bare token must be quoted so cmd treats them as
  // literal (else `?a=1&b=2` would split into a second command).
  ok('quote: url with & is quoted (cmd metachar neutralized)', quoteWinArg('https://h/p?a=1&b=2') === '"https://h/p?a=1&b=2"');
  ok('quote: pipe metachar forces quoting', quoteWinArg('a|b') === '"a|b"');
}

// ---------------------------------------------------------------------------
section('deep-audit regressions: byte-aware scrub / SSRF / host canon / policy');
{
  // #1 non-ASCII secret must be redacted in its on-the-wire latin1 form (headers).
  const { registerRedaction, clearRedactions, scrub, scrubLatin1 } = D('util/logger.js');
  clearRedactions();
  const secret = 'RSEC_' + String.fromCharCode(0xe9) + 'x' + String.fromCharCode(0xff) + '_END';
  registerRedaction(secret);
  const wire = Buffer.from(secret, 'utf8').toString('latin1'); // what Node hands us for a header value
  ok('scrubLatin1: redacts a non-ASCII secret in its latin1 wire form', !scrubLatin1('X-Echo: ' + wire).includes(wire) && scrubLatin1(wire).includes('***REDACTED***'));
  ok('scrub: also catches the wire form (registered as a redaction)', !scrub('hdr=' + wire).includes(wire));
  clearRedactions();
}
{
  // #7 isPrivateAddress must block IPv4-mapped IPv6 (incl. hex form) + standard ranges.
  const { isPrivateAddress, canonicalHost } = D('proxy/proxy.js');
  const priv = ['127.0.0.1', '10.1.2.3', '192.168.0.1', '172.16.0.1', '172.31.255.255', '169.254.169.254', '0.0.0.0', '::1', 'fc00::1', 'fd12::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe', '::ffff:c0a8:1',
    // fully-expanded IPv6 forms must also be classified (normalize-then-test, not string-shape)
    '0:0:0:0:0:ffff:7f00:1', '0:0:0:0:0:ffff:a9fe:a9fe', '0:0:0:0:0:ffff:0a00:0001', '0:0:0:0:0:0:0:1', '0:0:0:0:0:ffff:127.0.0.1',
    // RFC 4007 zone-id (%scope) forms — the OS still routes these to loopback/metadata
    '::ffff:127.0.0.1%lo', '::ffff:169.254.169.254%eth0', '::ffff:10.0.0.1%1', 'fe80::1%eth0', '::1%lo'];
  const pub = ['8.8.8.8', '1.1.1.1', '203.0.113.5', '172.32.0.1', '::ffff:8.8.8.8', '2606:4700:4700::1111',
    // a legitimately-zoned PUBLIC address must NOT be over-blocked
    '2606:4700:4700::1111%5'];
  ok('isPrivateAddress: private/loopback/metadata (incl. hex IPv4-mapped) all blocked', priv.every((a) => isPrivateAddress(a)), priv.filter((a) => !isPrivateAddress(a)).join(','));
  ok('isPrivateAddress: public addresses allowed', pub.every((a) => !isPrivateAddress(a)), pub.filter((a) => isPrivateAddress(a)).join(','));
  // #6 host canonicalization (trailing dot + case) so policy/injection/egress agree.
  ok('canonicalHost: lowercases + strips trailing dot on a DNS name', canonicalHost('API.Stripe.Com.') === 'api.stripe.com');
  ok('canonicalHost: strips multiple trailing dots', canonicalHost('api.x.com..') === 'api.x.com');
  ok('canonicalHost: leaves an IPv4 literal unchanged', canonicalHost('127.0.0.1') === '127.0.0.1');
}
{
  // #9 unrecognized rule action must fail closed (deny), not fall through to allow.
  const { PolicyEngine } = D('policy/policy.js');
  const e1 = new PolicyEngine({ defaultAction: 'deny', egressAllowlist: ['api.x.com'], rules: [{ id: 'bad', match: { hosts: ['api.x.com'] }, action: 'block' }] });
  ok('policy: unrecognized rule action coerced to deny', e1.evaluate({ host: 'api.x.com', method: 'GET', path: '/', body: null }).action === 'deny');
  // #3 amount cap must bind BOTH body and query: a within-cap body must not mask an over-cap query.
  const e2 = new PolicyEngine({ defaultAction: 'deny', egressAllowlist: ['api.x.com'], rules: [{ id: 'charge', match: { hosts: ['api.x.com'], paths: ['/charge'] }, action: 'allow', amountLimit: { field: 'amount', max: 1000 } }] });
  const overQuery = e2.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge?amount=999999', body: Buffer.from('{"amount":1}'), contentType: 'application/json' });
  ok('policy: over-cap QUERY amount denied even with within-cap body', overQuery.action === 'deny', JSON.stringify(overQuery));
  const bothOk = e2.evaluate({ host: 'api.x.com', method: 'POST', path: '/charge?amount=500', body: Buffer.from('{"amount":1}'), contentType: 'application/json' });
  ok('policy: both-location amounts within cap -> allow', bothOk.action === 'allow', JSON.stringify(bothOk));
}

// ---------------------------------------------------------------------------
section('round-7 regressions: env sanitize, encoded/lowercased scrub');
{
  // #3 launched agents must NOT inherit the vault-sealing passphrase / sealer / home.
  const { sanitizedEnv } = D('util/env.js');
  const fake = {
    PATH: '/x',
    HTTPS_PROXY: 'http://127.0.0.1:7788',
    AIRLOCK_PASSPHRASE: 'p',
    AIRLOCK_PASSPHRASE_FILE: '/f',
    AIRLOCK_SEALER: 'passphrase',
    AIRLOCK_HOME: '/h',
  };
  const clean = sanitizedEnv(fake);
  ok(
    'env: sanitizedEnv strips AIRLOCK passphrase/sealer/home',
    !('AIRLOCK_PASSPHRASE' in clean) && !('AIRLOCK_PASSPHRASE_FILE' in clean) && !('AIRLOCK_SEALER' in clean) && !('AIRLOCK_HOME' in clean)
  );
  ok('env: sanitizedEnv keeps non-sensitive vars (PATH, proxy)', clean.PATH === '/x' && clean.HTTPS_PROXY === 'http://127.0.0.1:7788');
}
{
  const { registerRedaction, clearRedactions, scrubBuffer, scrub } = D('util/logger.js');
  // #8 query-mode injection sends encodeURIComponent(value); a reflective upstream echoing that must be scrubbed.
  clearRedactions();
  const secret = 'sk live/AKIA+SECRET==';
  registerRedaction(secret);
  const enc = encodeURIComponent(secret); // sk%20live%2FAKIA%2BSECRET%3D%3D
  ok('scrub: percent-encoded (query-mode) secret reflection is redacted', !scrubBuffer(Buffer.from('echo=' + enc)).toString().includes(enc));
  clearRedactions();
  // #2 a mixed-case secret reflected as a lowercased header NAME must be redacted.
  registerRedaction('Sk-AbC123XyZ');
  ok('scrub: lowercased secret form is redacted (header-name case-fold)', !scrub('x-h: sk-abc123xyz').includes('sk-abc123xyz'));
  clearRedactions();
}

// ---------------------------------------------------------------------------
section('round-8 regressions: injectable-secret validation char-class');
{
  const { assertInjectableSecret } = D('util/secret-validate.js');
  const hdr = (header) => ({ mode: 'header', header, valueTemplate: 'Bearer {{secret}}' });

  // header mode: CR/LF rejected (header injection), >0xFF rejected (Node throws),
  // tab + high-Latin1 allowed (Node permits them in header values).
  ok('validate: header mode rejects CR/LF value', throws(() => assertInjectableSecret('tok\r\nX: 1', hdr('authorization'))));
  ok('validate: header mode rejects code unit >0xFF', throws(() => assertInjectableSecret('tokĀ', hdr('authorization'))));
  ok('validate: header mode allows tab and high-Latin1', !throws(() => assertInjectableSecret('tok\tvalÿ', hdr('authorization'))));
  ok('validate: header mode rejects an invalid header NAME', throws(() => assertInjectableSecret('tok', hdr('bad name'))));
  ok('validate: a clean token is accepted', !throws(() => assertInjectableSecret('sk-live-ABC123==', hdr('authorization'))));

  // placeholder mode: header-safe UNCONDITIONALLY (the placeholder can land in a
  // header even with injectInBody), so CR/LF is rejected regardless.
  ok(
    'validate: placeholder+injectInBody still rejects CR/LF (would smuggle headers)',
    throws(() => assertInjectableSecret('a\r\nb', { mode: 'placeholder', placeholder: '__K__', injectInBody: true }))
  );

  // query mode: the value is percent-encoded, so CR/LF is SAFE on the wire and
  // allowed; only a lone surrogate (encodeURIComponent throws) and a control-char
  // param name are rejected.
  ok('validate: query mode ALLOWS CR/LF value (percent-encoded)', !throws(() => assertInjectableSecret('a\r\nb', { mode: 'query', queryParam: 'api_key' })));
  ok('validate: query mode rejects a control-char param name', throws(() => assertInjectableSecret('tok', { mode: 'query', queryParam: 'a\nb' })));

  // lone surrogate rejected in every mode (would crash encodeURIComponent at inject time).
  ok('validate: lone surrogate value rejected (query)', throws(() => assertInjectableSecret('k\uD800ey', { mode: 'query', queryParam: 'q' })));
  ok('validate: lone surrogate value rejected (header)', throws(() => assertInjectableSecret('k\uD800ey', hdr('authorization'))));
  ok('validate: empty value rejected', throws(() => assertInjectableSecret('', hdr('authorization'))));
}

// ---------------------------------------------------------------------------
section('round-8 regressions: isLocalLiteral is IP-literal-anchored (no DNS-name match)');
{
  const { isLocalLiteral } = D('proxy/proxy.js');
  ok('isLocalLiteral: 127.0.0.1 is loopback', isLocalLiteral('127.0.0.1') === true);
  ok('isLocalLiteral: localhost is loopback', isLocalLiteral('localhost') === true);
  ok('isLocalLiteral: ::1 (bracketed) is loopback', isLocalLiteral('[::1]') === true);
  // The bug: an unanchored /^127\./ matched DNS names, exempting them from the
  // cleartext/SSRF/vetting guards. These must now be FALSE.
  ok('isLocalLiteral: 127.evil.com is NOT loopback', isLocalLiteral('127.evil.com') === false);
  ok('isLocalLiteral: 127.0.0.1.evil.com is NOT loopback', isLocalLiteral('127.0.0.1.evil.com') === false);
  ok('isLocalLiteral: a public host is NOT loopback', isLocalLiteral('api.openai.com') === false);
}

// ---------------------------------------------------------------------------
section('round-8 regressions: env sanitization strips the whole AIRLOCK_* namespace');
{
  const { sanitizedEnv } = D('util/env.js');
  const clean = sanitizedEnv({
    PATH: '/x',
    HTTPS_PROXY: 'http://127.0.0.1:7788',
    AIRLOCK_PASSPHRASE: 'p',
    AIRLOCK_SEALER: 'passphrase',
    AIRLOCK_HOME: '/h',
    AIRLOCK_PROXY_PORT: '7788',
    AIRLOCK_FUTURE_SECRET: 'leak', // a var nobody remembered to denylist
    AIRLOCK_ACTIVE: '1',
  });
  ok(
    'env: a future AIRLOCK_* var is stripped by the namespace sweep (no denylist drift)',
    !('AIRLOCK_FUTURE_SECRET' in clean) && !('AIRLOCK_PROXY_PORT' in clean) && !('AIRLOCK_ACTIVE' in clean)
  );
  ok('env: non-AIRLOCK vars survive', clean.PATH === '/x' && clean.HTTPS_PROXY === 'http://127.0.0.1:7788');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
