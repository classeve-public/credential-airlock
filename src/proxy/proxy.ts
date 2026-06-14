/**
 * The proxy — the trust boundary and the product.
 *
 * Data plane (loopback only):
 *   - Agent points HTTP(S)_PROXY here.
 *   - CONNECT to a host NOT on the egress allowlist  -> 403 (deny-by-default).
 *   - CONNECT to an allowlisted host -> TLS is intercepted with a cert minted by
 *     the local CA (the agent trusts it via NODE_EXTRA_CA_CERTS). The decrypted
 *     request is policy-checked, credentials are injected, and it is re-encrypted
 *     to the REAL upstream whose certificate IS verified (rejectUnauthorized).
 *   - Every request is audited. No endpoint ever reveals a key.
 */
import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import * as zlib from 'zlib';
import * as dns from 'dns';
import { Vault } from '../vault/vault';
import { PolicyEngine, extractAmount, extractAmountFromQuery } from '../policy/policy';
import { Approvals } from '../policy/approvals';
import { AuditLog } from '../audit/audit';
import { CertAuthority } from '../ca/ca';
import { applyInjection, Headers } from './inject';
import { log, scrub, scrubBuffer, scrubLatin1, maxRedactionLength } from '../util/logger';
import { HEADER_TOKEN_RE } from '../util/http-token';
import { AirlockConfig } from '../types';

const MAX_BODY = 10 * 1024 * 1024;
// Aggregate cap on bytes buffered across all in-flight requests (memory DoS guard).
const MAX_INFLIGHT_BYTES = 64 * 1024 * 1024;
let inFlightBytes = 0;

// DoS / robustness limits (overridable via env for unusual deployments).
const TLS_HANDSHAKE_TIMEOUT_MS = Number(process.env.AIRLOCK_TLS_HANDSHAKE_MS) || 10_000;
const TUNNEL_IDLE_TIMEOUT_MS = Number(process.env.AIRLOCK_TUNNEL_IDLE_MS) || 120_000;
const UPSTREAM_TIMEOUT_MS = Number(process.env.AIRLOCK_UPSTREAM_TIMEOUT_MS) || 60_000;
const MAX_CONNECT_TUNNELS = Number(process.env.AIRLOCK_MAX_TUNNELS) || 512;
let activeTunnels = 0;

/** True for hosts the operator can only have meant literally (loopback/localhost). */
export function isLocalLiteral(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === 'ip6-localhost' || h === '::1') return true;
  // Only a REAL IPv4 literal in 127/8 is loopback — NOT a DNS name that merely
  // starts with "127." (e.g. "127.evil.com", "127.0.0.1.attacker.test"). Treating
  // such names as loopback would exempt them from the cleartext-injection guard,
  // the SSRF/DNS-rebinding check, and connect-time IP vetting — leaking the real
  // key over plaintext to an attacker-controlled host. net.isIPv4 rejects names.
  return net.isIPv4(h) && h.startsWith('127.');
}

function isPrivateV4(o: number[]): boolean {
  if (o.length !== 4 || o.some((n) => !(n >= 0 && n <= 255))) return false;
  if (o[0] === 127 || o[0] === 0 || o[0] === 10) return true;
  if (o[0] === 169 && o[1] === 254) return true; // link-local (incl. cloud metadata 169.254.169.254)
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  return false;
}

/**
 * Expand ANY valid IPv6 literal — compressed (::), fully expanded, or
 * IPv4-embedded (dotted or hex) — to its 16 bytes, so classification does not
 * depend on the textual shape. Returns null if not a valid IPv6 literal.
 */
function ipv6ToBytes(addr: string): number[] | null {
  // Strip any RFC 4007 zone/scope id first (e.g. ::ffff:127.0.0.1%lo). net.isIPv6
  // accepts the zoned form and the OS still routes it (to loopback here), so the
  // guard MUST classify the same address the kernel will connect to.
  let s = addr.replace(/%.*$/, '');
  if (!net.isIPv6(s)) return null;
  // Fold an IPv4 dotted tail (e.g. ::ffff:127.0.0.1) into two hex hextets.
  const dm = s.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (dm) {
    const o = [dm[1], dm[2], dm[3], dm[4]].map(Number);
    if (o.some((n) => n > 255)) return null;
    s = s.slice(0, s.length - dm[0].length) + (((o[0] << 8) | o[1]).toString(16)) + ':' + (((o[2] << 8) | o[3]).toString(16));
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (part: string): number[] => (part === '' ? [] : part.split(':').map((h) => parseInt(h, 16)));
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 0 : missing !== 0) return null;
  const groups = halves.length === 2 ? [...head, ...new Array(missing).fill(0), ...tail] : head;
  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) return null;
  const bytes: number[] = [];
  for (const g of groups) bytes.push((g >> 8) & 0xff, g & 0xff);
  return bytes;
}

/** Private / loopback / link-local / unspecified address ranges (SSRF inward targets). */
export function isPrivateAddress(ip: string): boolean {
  const a = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIPv4(a)) return isPrivateV4(a.split('.').map(Number));
  if (net.isIPv6(a)) {
    const b = ipv6ToBytes(a);
    if (!b) return false;
    if (b.every((x) => x === 0)) return true; // :: unspecified
    if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true; // ::1 loopback
    if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
    if ((b[0] & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
    // IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d): first 10 bytes zero
    if (b.slice(0, 10).every((x) => x === 0) && ((b[10] === 0xff && b[11] === 0xff) || (b[10] === 0 && b[11] === 0))) {
      return isPrivateV4([b[12], b[13], b[14], b[15]]);
    }
    return false;
  }
  return false; // not an IP literal (callers pass IPs; hostnames are resolved separately)
}

/**
 * Canonicalize a request host once at ingestion so equivalent DNS forms cannot
 * diverge between the egress allowlist, the policy rules, injection host-binding,
 * and the upstream connection. Lowercases, and strips a trailing dot from a DNS
 * name (the FQDN form 'api.x.com.' is equivalent to 'api.x.com' for DNS but would
 * otherwise bypass exact host-scoped rules / per-secret injection binding).
 */
export function canonicalHost(host: string): string {
  const h = (host || '').trim().toLowerCase();
  const bare = h.replace(/^\[|\]$/g, '');
  if (net.isIP(bare)) return h; // IP literal: leave as-is (incl. any brackets)
  return h.replace(/\.+$/, '');
}

/**
 * Egress SSRF guard: refuse to inject credentials toward an internal/loopback
 * service that an allowlisted PUBLIC name resolves to (DNS rebinding / inward
 * redirect). A host the operator allowlisted as a literal loopback/localhost is
 * permitted (explicit opt-in). Returns null if allowed, or a deny reason.
 */
async function egressBlockReason(host: string): Promise<string | null> {
  if (process.env.AIRLOCK_ALLOW_INTERNAL_EGRESS === '1') return null;
  if (isLocalLiteral(host)) return null; // operator explicitly allowlisted a local host
  if (net.isIP(host)) return isPrivateAddress(host) ? `host ${host} is a private/loopback address` : null;
  try {
    const addrs = await dns.promises.lookup(host, { all: true });
    const bad = addrs.find((a) => isPrivateAddress(a.address));
    if (bad) return `host ${host} resolves to an internal address ${bad.address} (possible SSRF/DNS-rebinding)`;
  } catch {
    return null; // let the normal connection attempt fail/report
  }
  return null;
}

/**
 * A dns.lookup wrapper used for the UPSTREAM connection that fails CLOSED if the
 * host resolves to a private/loopback address at CONNECT time. This closes the
 * TOCTOU window between egressBlockReason()'s resolution (time-of-check) and the
 * actual connect (time-of-use): a name that resolves public at the guard but
 * rebinds to an internal/metadata IP at connect is refused, so the credential is
 * never delivered to an internal target. Used only for non-loopback hosts.
 */
const vettingLookup: net.LookupFunction = (hostname, options, callback) => {
  const cb = callback as (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => void;
  (dns.lookup as unknown as (h: string, o: object, c: typeof cb) => void)(hostname, options as object, (err, address, family) => {
    if (!err) {
      const list = Array.isArray(address)
        ? (address as Array<{ address: string }>)
        : [{ address: address as unknown as string }];
      const bad = list.find((a) => isPrivateAddress(a.address));
      if (bad) {
        cb(new Error(`refusing to connect: ${hostname} resolved to private address ${bad.address} (possible DNS rebinding)`), address, family);
        return;
      }
    }
    cb(err, address, family);
  });
};

function decompress(ce: string, buf: Buffer): Buffer {
  // Bound the OUTPUT size: a small compressed body can inflate to GBs (zip bomb).
  // Exceeding the cap throws ERR_BUFFER_TOO_LARGE, which the caller catches and
  // falls back to forwarding header-scrubbed only.
  const opts = { maxOutputLength: MAX_BODY };
  if (/\bbr\b/.test(ce)) return zlib.brotliDecompressSync(buf, opts);
  if (/gzip/.test(ce)) return zlib.gunzipSync(buf, opts);
  if (/\bdeflate\b/.test(ce)) {
    try {
      return zlib.inflateSync(buf, opts);
    } catch {
      return zlib.inflateRawSync(buf, opts);
    }
  }
  return buf;
}
const HOP_BY_HOP = new Set([
  'proxy-connection',
  'proxy-authorization',
  'connection',
  'keep-alive',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

class BodyError extends Error {
  constructor(readonly kind: 'too_large' | 'busy') {
    super(kind);
  }
}

/**
 * Scrub any injected/registered secret out of a response header value. Node hands
 * us header values as latin1, so we scrub the byte-accurate latin1 form first
 * (catches non-ASCII secrets) and then the contiguous code-point form as well.
 */
function scrubHeader(v: string | string[] | undefined): string | string[] | undefined {
  if (v == null) return v;
  const one = (x: unknown): string => scrub(scrubLatin1(String(x)));
  return Array.isArray(v) ? v.map(one) : one(v);
}

export interface ProxyDeps {
  vault: Vault;
  policy: PolicyEngine;
  approvals: Approvals;
  audit: AuditLog;
  config: AirlockConfig;
}

interface Target {
  host: string;
  port: number;
}

const targets = new WeakMap<object, Target>();

export class AirlockProxy {
  private readonly server: http.Server;
  private readonly mitm: http.Server;
  private readonly ca: CertAuthority;

  constructor(private readonly deps: ProxyDeps) {
    this.ca = new CertAuthority(deps.vault.getCA());

    // Parses decrypted HTTP from intercepted TLS sockets.
    this.mitm = http.createServer((req, res) => {
      this.handleRequest(req, res, 'https').catch((e) => this.failClosedUnexpected(res, e));
    });
    this.mitm.on('clientError', (_e, sock) => sock.destroy());

    // The proxy endpoint the agent talks to.
    this.server = http.createServer((req, res) => {
      this.handlePlainHttp(req, res).catch((e) => this.failClosedUnexpected(res, e));
    });
    this.server.on('connect', (req, sock, head) =>
      this.handleConnect(req, sock as net.Socket, head).catch((e) => {
        log.debug('CONNECT handler threw; closing tunnel', { err: String(e) });
        try {
          (sock as net.Socket).destroy();
        } catch {
          /* ignore */
        }
      })
    );
    this.server.on('clientError', (_e, sock) => {
      try {
        (sock as net.Socket).end('HTTP/1.1 400 Bad Request\r\n\r\n');
      } catch {
        /* ignore */
      }
    });
    // WebSocket/Upgrade is not supported (can't be policy-inspected/scrubbed the
    // same way). Reject deterministically instead of leaving the socket hanging.
    const rejectUpgrade = (_req: http.IncomingMessage, sock: net.Socket) => {
      try {
        sock.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      } catch {
        /* ignore */
      }
    };
    this.mitm.on('upgrade', rejectUpgrade);
    this.server.on('upgrade', rejectUpgrade);
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const onErr = (e: Error) => reject(e);
      this.server.once('error', onErr);
      this.server.listen(this.deps.config.proxyPort, this.deps.config.proxyHost, () => {
        this.server.removeListener('error', onErr);
        log.info(`proxy (data plane) listening on http://${this.deps.config.proxyHost}:${this.deps.config.proxyPort}`);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  // --- CONNECT (HTTPS) ----------------------------------------------------
  private async handleConnect(req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer): Promise<void> {
    const raw = req.url || '';
    const idx = raw.lastIndexOf(':');
    const host = canonicalHost(idx > 0 ? raw.slice(0, idx) : raw);
    const port = idx > 0 ? parseInt(raw.slice(idx + 1), 10) || 443 : 443;

    clientSocket.on('error', () => {});

    if (activeTunnels >= MAX_CONNECT_TUNNELS) {
      try {
        clientSocket.write('HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nProxy-Agent: credential-airlock\r\n\r\n');
        clientSocket.end();
      } catch {
        /* ignore */
      }
      return;
    }

    if (!host || !this.deps.policy.isHostAllowed(host)) {
      this.deps.audit.append({
        event: 'request',
        host,
        method: 'CONNECT',
        path: '',
        decision: 'denied',
        reason: 'host not on egress allowlist (deny-by-default)',
      });
      try {
        clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nProxy-Agent: credential-airlock\r\n\r\n');
        clientSocket.end();
      } catch {
        /* ignore */
      }
      return;
    }

    // SSRF guard: never inject credentials toward an internal/loopback service an
    // allowlisted PUBLIC name resolves to (DNS rebinding / inward redirect).
    const blocked = await egressBlockReason(host);
    if (blocked) {
      this.deps.audit.append({ event: 'request', host, method: 'CONNECT', path: '', decision: 'denied', reason: blocked });
      try {
        clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nProxy-Agent: credential-airlock\r\n\r\n');
        clientSocket.end();
      } catch {
        /* ignore */
      }
      return;
    }

    try {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: credential-airlock\r\n\r\n');
    } catch {
      return;
    }
    if (head && head.length) clientSocket.unshift(head);

    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      secureContext: this.ca.contextFor(host),
      SNICallback: (servername, cb) => {
        try {
          cb(null, this.ca.contextFor(servername || host));
        } catch (e) {
          cb(e as Error);
        }
      },
    });
    targets.set(tlsSocket, { host, port });
    activeTunnels++;
    let closed = false;
    const cleanup = () => {
      if (!closed) {
        closed = true;
        activeTunnels--;
      }
    };
    clientSocket.on('close', cleanup);
    tlsSocket.on('close', cleanup);
    // Fail a stalled TLS handshake so a slowloris client cannot pin sockets/fds.
    const hsTimer = setTimeout(() => {
      log.debug('CONNECT TLS handshake timeout', { host });
      try {
        tlsSocket.destroy();
      } catch {
        /* ignore */
      }
      try {
        clientSocket.destroy();
      } catch {
        /* ignore */
      }
    }, TLS_HANDSHAKE_TIMEOUT_MS);
    hsTimer.unref?.();
    tlsSocket.once('secure', () => clearTimeout(hsTimer));
    // Drop idle tunnels so they cannot pin sockets indefinitely.
    clientSocket.setTimeout(TUNNEL_IDLE_TIMEOUT_MS, () => {
      try {
        clientSocket.destroy();
      } catch {
        /* ignore */
      }
    });
    tlsSocket.on('error', (e) => {
      log.debug('intercept TLS error', { host, err: String(e) });
      try {
        clientSocket.destroy();
      } catch {
        /* ignore */
      }
    });
    this.mitm.emit('connection', tlsSocket);
  }

  // --- plain HTTP proxying ------------------------------------------------
  private async handlePlainHttp(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = req.url || '';
    if (!/^https?:\/\//i.test(url)) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('credential-airlock is a forwarding proxy. Configure your client to use it as HTTP(S)_PROXY.\n');
      return;
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      res.writeHead(400).end('bad url');
      return;
    }
    // Honor the request-target scheme. An https:// absolute-form target must go
    // through the TLS-verified upstream path (rejectUnauthorized), NOT be silently
    // downgraded to a cleartext port-80 dial.
    const scheme: 'http' | 'https' = parsed.protocol === 'https:' ? 'https' : 'http';
    const host = canonicalHost(parsed.hostname);
    const port = parseInt(parsed.port || (scheme === 'https' ? '443' : '80'), 10);
    const reqPath = parsed.pathname + parsed.search;
    // Deny-by-default FIRST, before any DNS — symmetric with the CONNECT path
    // (handleConnect checks isHostAllowed before resolving). Otherwise egressBlockReason
    // would dns.lookup() an attacker-chosen non-allowlisted host, leaking a blind-DNS
    // exfiltration channel the CONNECT plane does not have.
    if (!this.deps.policy.isHostAllowed(host)) {
      this.respondDenied(res, 'host not on egress allowlist (deny-by-default)');
      this.deps.audit.append({ event: 'request', host, method: req.method || 'GET', path: reqPath, decision: 'denied', reason: 'host not on egress allowlist (deny-by-default)' });
      return;
    }
    const blocked = await egressBlockReason(host);
    if (blocked) {
      this.respondDenied(res, blocked);
      this.deps.audit.append({ event: 'request', host, method: req.method || 'GET', path: reqPath, decision: 'denied', reason: blocked });
      return;
    }
    await this.handleRequest(req, res, scheme, { host, port, path: reqPath });
  }

  // --- common request pipeline -------------------------------------------
  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    scheme: 'http' | 'https',
    override?: { host: string; port: number; path: string }
  ): Promise<void> {
    const started = Date.now();
    let target: Target;
    let path: string;
    if (override) {
      target = { host: override.host, port: override.port };
      path = override.path;
    } else {
      const t = targets.get(req.socket);
      if (!t) {
        res.writeHead(500).end('no target');
        return;
      }
      target = t;
      path = req.url || '/';
    }
    const method = req.method || 'GET';
    const host = target.host;

    let body: Buffer | null;
    let bodyBytes = 0;
    try {
      const r = await readBody(req);
      body = r.body;
      bodyBytes = r.bytes;
    } catch (e) {
      const busy = e instanceof BodyError && e.kind === 'busy';
      res.writeHead(busy ? 503 : 413, { 'content-type': 'text/plain' });
      res.end(busy ? 'server busy (too many concurrent in-flight requests)\n' : 'request body too large\n');
      this.deps.audit.append({ event: 'request', host, method, path, decision: 'denied', reason: busy ? 'server busy' : 'body too large' });
      return;
    }
    // The buffered request body keeps counting against the in-flight cap until the
    // response is done (it may be pinned across a human-approval wait), so 50
    // concurrent pending ~10MB bodies trip the cap (503) instead of pinning ~500MB.
    res.on('close', () => {
      inFlightBytes -= bodyBytes;
      bodyBytes = 0;
    });

    const contentType = (req.headers['content-type'] as string) || undefined;
    const decision = this.deps.policy.evaluate({ host, method, path, body, contentType });

    if (decision.action === 'deny') {
      this.respondDenied(res, decision.reason);
      this.deps.audit.append({
        event: 'request',
        host,
        method,
        path,
        decision: 'denied',
        ruleId: decision.ruleId,
        reason: decision.reason,
        reqBytes: body?.length || 0,
      });
      return;
    }

    if (decision.action === 'require_approval') {
      const amountField = this.amountForApproval(decision.ruleId, path, body, contentType);
      const { req: ar, decision: wait } = this.deps.approvals.request({
        host,
        method,
        path,
        summary: `${method} https://${host}${path}`,
        amount: amountField,
        ruleId: decision.ruleId,
      });
      this.deps.audit.append({
        event: 'approval',
        host,
        method,
        path,
        decision: 'approval_required',
        ruleId: decision.ruleId,
        reason: 'awaiting human approval',
        detail: { approvalId: ar.id },
      });
      const approved = await wait;
      if (!approved) {
        this.respondDenied(res, 'request was not approved');
        this.deps.audit.append({
          event: 'approval',
          host,
          method,
          path,
          decision: 'rejected',
          ruleId: decision.ruleId,
          detail: { approvalId: ar.id },
        });
        return;
      }
      this.deps.audit.append({
        event: 'approval',
        host,
        method,
        path,
        decision: 'approved',
        ruleId: decision.ruleId,
        detail: { approvalId: ar.id },
      });
      // Charge rate budget only now (approved), not at evaluation time, so denied/
      // expired approvals never burn the bucket.
      const rl = this.deps.policy.getPolicy().rules.find((r) => r.id === decision.ruleId)?.rateLimit;
      if (rl && decision.ruleId && !this.deps.policy.consumeRateForRule(decision.ruleId, rl)) {
        this.respondDenied(res, 'rate limit exceeded');
        this.deps.audit.append({ event: 'request', host, method, path, decision: 'denied', ruleId: decision.ruleId, reason: 'rate limit exceeded (post-approval)' });
        return;
      }
    }

    // Build forward headers, strip hop-by-hop, then inject credentials.
    const fwdHeaders: Headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (HOP_BY_HOP.has(lk)) continue;
      if (lk === 'accept-encoding') continue; // force identity so we can scrub the response body
      fwdHeaders[k] = v;
    }
    let injection;
    try {
      injection = applyInjection(this.deps.vault.getInjectors(), {
        host,
        method,
        path,
        headers: fwdHeaders,
        body,
      });
    } catch (e) {
      // Injection itself threw (e.g. encodeURIComponent on a lone-surrogate value
      // that predates set-time validation). Fail CLOSED — never forward without
      // the intended injection, never hang the agent on an unhandled rejection.
      log.warn('credential injection failed; failing closed', { host, err: String(e) });
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'blocked_by_credential_airlock', reason: 'injection_failed' }));
      }
      this.deps.audit.append({ event: 'request', host, method, path, decision: 'denied', ruleId: decision.ruleId, reason: 'injection_failed' });
      return;
    }

    // CONFIDENTIALITY PRECONDITION: never let a real credential leave over cleartext.
    // The agent must not be able to exfiltrate the key by choosing http:// (or
    // smuggling an http target) — that would put the live key on an unencrypted
    // channel an on-path observer or a rebinding upstream could read, voiding the
    // whole point of the firewall. Loopback dev targets and an explicit opt-in are
    // exempt; everything else fails CLOSED (with an audit record).
    if (
      scheme === 'http' &&
      injection.injected.length > 0 &&
      !isLocalLiteral(host) &&
      process.env.AIRLOCK_ALLOW_CLEARTEXT_EGRESS !== '1'
    ) {
      this.respondDenied(res, 'refusing to inject a credential over cleartext HTTP — use https');
      this.deps.audit.append({
        event: 'request',
        host,
        method,
        path,
        decision: 'denied',
        ruleId: decision.ruleId,
        reason: 'cleartext credential injection refused (use https)',
      });
      return;
    }

    const injected = injection.injected;
    this.forward(scheme, target, method, injection.path, injection.headers, injection.body, res, (status, respBytes, opts) => {
      // `delivered` = the credential actually left toward upstream. On a pre-egress
      // failure (invalid injected header / connect error) nothing was sent, so we
      // must NOT audit it as a credentialed egress — report injected:[] + the
      // reason, so the tamper-evident log never over-claims key exposure.
      const delivered = opts?.delivered !== false;
      const detail: Record<string, unknown> = {};
      if (!delivered) detail.delivered = false;
      if (opts?.clientAborted) detail.clientAborted = true;
      this.deps.audit.append({
        event: 'request',
        host,
        method,
        path,
        decision: 'allowed', // policy allowed it; delivery success is in status/detail
        ruleId: decision.ruleId,
        injected: delivered ? injected : [],
        reqBytes: body?.length || 0,
        ...(status > 0 ? { status } : {}),
        respBytes,
        latencyMs: Date.now() - started,
        ...(opts?.reason ? { reason: opts.reason } : {}),
        ...(Object.keys(detail).length ? { detail } : {}),
      });
    });
  }

  private amountForApproval(
    ruleId: string | undefined,
    path: string,
    body: Buffer | null,
    contentType?: string
  ): { field: string; value: number; currency?: string } | undefined {
    // Use the exact rule that fired (by id), so the card's amount matches enforcement
    // even when the rule uses a glob host like *.stripe.com.
    if (!ruleId) return undefined;
    const rule = this.deps.policy.getPolicy().rules.find((r) => r.id === ruleId);
    if (!rule || !rule.amountLimit) return undefined;
    // Surface the LARGEST amount the upstream could read (body OR query), so a human
    // reviewer is never blinded by a small body value masking a large query value.
    const candidates = [
      extractAmount(body, contentType, rule.amountLimit.field),
      extractAmountFromQuery(path, rule.amountLimit.field),
    ].filter((n): n is number => n !== undefined);
    if (!candidates.length) return undefined;
    return { field: rule.amountLimit.field, value: Math.max(...candidates), currency: rule.amountLimit.currency };
  }

  private respondDenied(res: http.ServerResponse, reason: string): void {
    if (res.headersSent) return;
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'blocked_by_credential_airlock', reason }));
  }

  /**
   * Last-resort guard for an unexpected throw out of the (void-invoked) request
   * handlers. Fail CLOSED: never leave the agent's socket hanging — send a generic
   * 502 (no exception text, which could embed a secret) or destroy if mid-response.
   */
  private failClosedUnexpected(res: http.ServerResponse, e: unknown): void {
    log.error('request handler threw; failing closed', { err: String(e) });
    try {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'blocked_by_credential_airlock', reason: 'internal_error' }));
      } else {
        res.destroy();
      }
    } catch {
      /* ignore */
    }
  }

  private forward(
    scheme: 'http' | 'https',
    target: Target,
    method: string,
    path: string,
    headers: Headers,
    body: Buffer | null,
    res: http.ServerResponse,
    done: (status: number, respBytes: number, opts?: { delivered?: boolean; clientAborted?: boolean; reason?: string }) => void
  ): void {
    const mod = scheme === 'https' ? https : http;
    // Pin the connection's resolution: re-validate the IP Node actually resolves at
    // connect time and fail closed on a private/loopback result (DNS-rebinding TOCTOU).
    // Loopback literals the operator explicitly allowlisted are exempt (opt-in).
    const vetUpstream = !isLocalLiteral(target.host) && process.env.AIRLOCK_ALLOW_INTERNAL_EGRESS !== '1';

    // ---- single terminal authority for this request ----------------------
    // Every terminal event (normal end, upstream RST/abort/timeout, client abort,
    // build/write throw, scrub/res.write throw) routes through settle(), which
    // guarantees: done() is called EXACTLY once (one audit line), res is finalized
    // exactly once, and the response-byte counter is released. This closes the
    // hang-with-no-audit and double-audit classes that scattered done() calls had.
    let settled = false;
    let wroteHead = false; // mirror of "headers have left toward the agent"
    let gotResponse = false; // a response arrived => the credential actually egressed
    let upstream: http.ClientRequest | undefined;
    let releaseResp = (): void => {}; // reassigned once the response allocates the counter

    const settle = (status: number, respBytes: number, opts?: { clientAborted?: boolean; reason?: string }): void => {
      if (settled) return;
      settled = true;
      releaseResp(); // free buffered response bytes (idempotent)
      try {
        upstream?.destroy();
      } catch {
        /* ignore */
      }
      // Finalize res once (unless the client already left). status<=0 means "no
      // status to report" (mid-response teardown / pure abort).
      if (!opts?.clientAborted && !res.destroyed && res.writable) {
        try {
          if (wroteHead || res.headersSent) {
            // Body (if any) was already written by the caller; just finalize.
            res.end();
          } else {
            // No headers sent yet => this is a failure path (we never started a
            // successful response). Always emit the fail-closed JSON error body.
            res.writeHead(status > 0 ? status : 502, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'blocked_by_credential_airlock', reason: opts?.reason || 'upstream_error' }));
          }
        } catch (e) {
          log.debug('finalize response failed', { host: target.host, err: String(e) });
          try {
            res.destroy();
          } catch {
            /* ignore */
          }
        }
      }
      // delivered = the credential left toward upstream. A pre-response failure
      // (build/connect/write) never egressed it; a mid/post-response teardown did.
      done(status, respBytes, { delivered: gotResponse, clientAborted: opts?.clientAborted, reason: opts?.reason });
    };

    // res.writeHead / res.write that can never throw OUT of an event handler
    // (a throw there would escape to uncaughtException, hanging the request).
    const safeWriteHead = (status: number, h: http.OutgoingHttpHeaders): boolean => {
      if (settled || res.headersSent || !res.writable) return false;
      try {
        res.writeHead(status, h);
        wroteHead = true;
        return true;
      } catch (e) {
        log.warn('res.writeHead failed', { host: target.host, err: String(e) });
        settle(502, 0, { reason: 'response_write_failed' });
        return false;
      }
    };
    const safeWrite = (b: Buffer): void => {
      if (settled || !res.writable || b.length === 0) return;
      try {
        res.write(b);
      } catch (e) {
        // A write failure means we cannot complete a body we already committed a
        // content-length for — RST the socket so the agent sees a hard failure
        // instead of hanging on the unmet length. settle then just audits (it skips
        // finalize because res is destroyed).
        log.warn('res.write failed', { host: target.host, err: String(e) });
        try {
          res.destroy();
        } catch {
          /* ignore */
        }
        settle(-1, 0, { reason: 'response_write_failed' });
      }
    };
    // Write our fail-closed 502 body then settle (used for unscrubbable responses).
    const failClosed = (reason: string): void => {
      if (safeWriteHead(502, { 'content-type': 'application/json' })) {
        safeWrite(Buffer.from(JSON.stringify({ error: 'blocked_by_credential_airlock', reason })));
      }
      settle(502, 0, { reason });
    };

    // Client went away before we finished: AUDIT the credentialed egress that
    // occurred (settle with clientAborted), but don't touch the dead socket. On a
    // normal completion settle already ran, so this close handler is a no-op.
    res.on('close', () => {
      if (!settled) settle(-1, 0, { clientAborted: true });
    });

    try {
      upstream = mod.request(
        {
          host: target.host,
          port: target.port,
          method,
          path,
          headers: headers as http.OutgoingHttpHeaders,
          rejectUnauthorized: true, // verify the REAL upstream certificate
          ...(vetUpstream ? { lookup: vettingLookup } : {}),
        },
        (up) => {
          gotResponse = true; // the request (with the credential) reached upstream
          const status = up.statusCode || 502;
          const ce = String(up.headers['content-encoding'] || '').toLowerCase();
          const compressed = /\bbr\b/.test(ce) || /gzip/.test(ce) || /\bdeflate\b/.test(ce);
          const outHeaders: http.OutgoingHttpHeaders = {};
          for (const [k, v] of Object.entries(up.headers)) {
            if (HOP_BY_HOP.has(k.toLowerCase())) continue;
            // Scrub the NAME too: a reflective upstream can echo a secret as a header
            // NAME. DROP the header if its name changes under scrubbing (it embedded a
            // registered secret) or is not a valid HTTP token. Node lowercases incoming
            // response header names (ASCII tokens), so the code-point scrub() suffices —
            // no need for the byte-form scrubLatin1() here (names can't carry >0x7f).
            const name = scrub(k);
            if (name !== k || !HEADER_TOKEN_RE.test(name)) continue;
            outHeaders[name] = scrubHeader(v as string | string[] | undefined) as string | string[];
          }

          // Account buffered response bytes against the shared in-flight cap.
          let counted = 0;
          releaseResp = () => {
            inFlightBytes -= counted;
            counted = 0;
          };
          const account = (n: number): boolean => {
            inFlightBytes += n;
            counted += n;
            return inFlightBytes <= MAX_INFLIGHT_BYTES;
          };
          // THE KEY FIX: every upstream-stream terminal event frees the counter and
          // settles. 'error' fires on an upstream RST mid-body (the ClientRequest does
          // NOT also error in that case); 'close' is the universal backstop so an
          // exotic teardown that emits neither 'end' nor 'error' still finalizes res
          // (no more permanent hang) and still writes one audit line.
          up.on('error', (e) => {
            log.debug('upstream stream error', { host: target.host, err: String(e) });
            releaseResp();
            settle(wroteHead ? -1 : 502, 0, { reason: 'upstream_stream_error' });
          });
          up.on('aborted', () => {
            releaseResp();
            settle(wroteHead ? -1 : 502, 0, { reason: 'upstream_aborted' });
          });
          up.on('close', () => {
            releaseResp();
            settle(wroteHead ? -1 : 502, 0, { reason: 'upstream_closed_early' });
          });

          // HEAD / 204 / 304 carry no body by spec — forward headers (scrubbed) as-is.
          if (method === 'HEAD' || status === 204 || status === 304) {
            if (!safeWriteHead(status, outHeaders)) return;
            up.resume(); // drain any (spec-violating) body bytes
            up.on('end', () => settle(status, 0));
            return;
          }

          if (compressed) {
            // We strip Accept-Encoding upstream, so a compressed reply is a
            // non-conforming server. Buffer (bounded), decompress (output-bounded),
            // scrub, re-emit as identity. If we cannot decompress to scrub it, FAIL
            // CLOSED — a reflective upstream could hide the injected secret in bytes
            // labelled gzip that we cannot inspect.
            const parts: Buffer[] = [];
            let sz = 0;
            let over = false;
            up.on('data', (c: Buffer) => {
              if (settled) return;
              sz += c.length;
              if (over) return;
              if (sz <= MAX_BODY && account(c.length)) parts.push(c);
              else over = true;
            });
            up.on('end', () => {
              if (settled) return;
              if (over) {
                log.warn('compressed response too large to scrub; failing closed (502)', { host: target.host });
                return failClosed('oversize compressed response could not be scrubbed');
              }
              let plain: Buffer;
              try {
                plain = decompress(ce, Buffer.concat(parts));
              } catch {
                log.warn('compressed response could not be decompressed; failing closed (502)', { host: target.host });
                return failClosed('undecodable compressed response could not be scrubbed');
              }
              let scrubbed: Buffer;
              try {
                scrubbed = scrubBuffer(plain);
              } catch (e) {
                log.warn('compressed response could not be scrubbed; failing closed (502)', { host: target.host, err: String(e) });
                return failClosed('response could not be scrubbed');
              }
              delete outHeaders['content-encoding'];
              outHeaders['content-length'] = String(scrubbed.length);
              if (safeWriteHead(status, outHeaders)) safeWrite(scrubbed);
              settle(status, scrubbed.length);
            });
            return;
          }

          // Identity body: byte-preserving scrub regardless of content-type so a
          // reflective upstream cannot echo an injected key back to the agent.
          // Buffer up to MAX_BODY (or until the shared cap is hit); beyond that,
          // switch to a sliding-window stream so a secret spanning a chunk boundary
          // is still caught, nothing is sent raw, and memory stays bounded.
          const win = Math.max(0, maxRedactionLength() - 1);
          const parts: Buffer[] = [];
          let sz = 0;
          let streaming = false;
          let carry = Buffer.alloc(0);
          up.on('data', (c: Buffer) => {
            if (settled) return; // ignore late chunks after a teardown/abort
            sz += c.length; // count all received bytes for the audit metric
            try {
              if (streaming) {
                const scrubbed = scrubBuffer(Buffer.concat([carry, c]));
                const keep = Math.min(win, scrubbed.length);
                safeWrite(scrubbed.subarray(0, scrubbed.length - keep));
                carry = Buffer.from(scrubbed.subarray(scrubbed.length - keep));
                return;
              }
              parts.push(c);
              if (sz > MAX_BODY || !account(c.length)) {
                streaming = true;
                const head = scrubBuffer(Buffer.concat(parts));
                parts.length = 0;
                const keep = Math.min(win, head.length);
                delete outHeaders['content-length'];
                if (!safeWriteHead(status, outHeaders)) return;
                safeWrite(head.subarray(0, head.length - keep));
                carry = Buffer.from(head.subarray(head.length - keep));
                releaseResp(); // parts no longer held; streaming uses only the tiny carry
              }
            } catch (e) {
              log.warn('response scrub/forward failed mid-body; failing closed', { host: target.host, err: String(e) });
              settle(wroteHead ? -1 : 502, 0, { reason: 'response_scrub_failed' });
            }
          });
          up.on('end', () => {
            if (settled) return;
            try {
              if (streaming) {
                safeWrite(scrubBuffer(carry));
                settle(status, sz);
                return;
              }
              const scrubbed = scrubBuffer(Buffer.concat(parts));
              outHeaders['content-length'] = String(scrubbed.length);
              if (safeWriteHead(status, outHeaders)) safeWrite(scrubbed);
              settle(status, scrubbed.length);
            } catch (e) {
              log.warn('response scrub failed at end; failing closed', { host: target.host, err: String(e) });
              settle(wroteHead ? -1 : 502, 0, { reason: 'response_scrub_failed' });
            }
          });
        }
      );
    } catch (e) {
      // mod.request() throws synchronously on an invalid injected header value/name
      // (CR/LF/NUL or a code unit > 0xFF). Fail CLOSED with an audited 502 — and,
      // since no response arrived, gotResponse is false so the audit records that
      // the credential was NOT delivered.
      log.warn('failed to build upstream request (invalid injected header?)', { host: target.host, err: String(e) });
      settle(502, 0, { reason: 'invalid_injected_request' });
      return;
    }

    upstream.on('error', (e) => {
      log.warn('upstream error', { host: target.host, err: String(e) });
      settle(wroteHead ? -1 : 502, 0, { reason: 'upstream_error' });
    });
    // A hostile/slow allowlisted upstream must not pin sockets forever.
    upstream.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
      log.warn('upstream timeout', { host: target.host });
      try {
        upstream?.destroy(new Error('upstream timeout'));
      } catch {
        /* ignore */
      }
    });
    try {
      if (body && body.length) upstream.write(body);
      upstream.end();
    } catch (e) {
      // settle is idempotent, so any async upstream 'error' from destroy() is a no-op.
      log.warn('failed to write upstream request', { host: target.host, err: String(e) });
      settle(502, 0, { reason: 'invalid_injected_request' });
    }
  }
}

function readBody(req: http.IncomingMessage): Promise<{ body: Buffer | null; bytes: number }> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let counted = 0; // bytes we've added to the global in-flight counter
    const release = () => {
      inFlightBytes -= counted;
      counted = 0;
    };
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY) {
        release();
        req.destroy();
        reject(new BodyError('too_large'));
        return;
      }
      inFlightBytes += c.length;
      counted += c.length;
      if (inFlightBytes > MAX_INFLIGHT_BYTES) {
        release();
        req.destroy();
        reject(new BodyError('busy'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      // Do NOT release here. The body Buffer stays resident (and may be pinned for a
      // full human-approval wait), so it must keep counting against the in-flight cap
      // until the whole request completes; the caller releases on response close.
      resolve({ body: chunks.length ? Buffer.concat(chunks) : null, bytes: counted });
    });
    req.on('error', (e) => {
      release();
      reject(e);
    });
  });
}
