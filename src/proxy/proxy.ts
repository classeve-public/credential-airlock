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
import { PolicyEngine, extractAmount } from '../policy/policy';
import { Approvals } from '../policy/approvals';
import { AuditLog } from '../audit/audit';
import { CertAuthority } from '../ca/ca';
import { applyInjection, Headers } from './inject';
import { log, scrub, scrubBuffer, maxRedactionLength } from '../util/logger';
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
function isLocalLiteral(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === 'ip6-localhost' || h === '::1' || /^127\./.test(h);
}

/** Private / loopback / link-local / unspecified address ranges (SSRF inward targets). */
function isPrivateAddress(ip: string): boolean {
  const a = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (a === '::1' || a === '::' || a.startsWith('fe80') || a.startsWith('fc') || a.startsWith('fd')) return true;
  // IPv4-mapped IPv6 e.g. ::ffff:127.0.0.1
  const m = a.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  const v4 = m ? m[1] : net.isIPv4(a) ? a : null;
  if (!v4) return false;
  const o = v4.split('.').map(Number);
  if (o[0] === 127 || o[0] === 0 || o[0] === 10) return true;
  if (o[0] === 169 && o[1] === 254) return true; // link-local
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  return false;
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

/** Scrub any injected/registered secret out of a response header value. */
function scrubHeader(v: string | string[] | undefined): string | string[] | undefined {
  if (v == null) return v;
  return Array.isArray(v) ? v.map((x) => scrub(String(x))) : scrub(String(v));
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
      void this.handleRequest(req, res, 'https');
    });
    this.mitm.on('clientError', (_e, sock) => sock.destroy());

    // The proxy endpoint the agent talks to.
    this.server = http.createServer((req, res) => {
      void this.handlePlainHttp(req, res);
    });
    this.server.on('connect', (req, sock, head) => this.handleConnect(req, sock as net.Socket, head));
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
    const host = idx > 0 ? raw.slice(0, idx) : raw;
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
    const host = parsed.hostname;
    const port = parseInt(parsed.port || '80', 10);
    const blocked = await egressBlockReason(host);
    if (blocked) {
      this.respondDenied(res, blocked);
      this.deps.audit.append({ event: 'request', host, method: req.method || 'GET', path: parsed.pathname + parsed.search, decision: 'denied', reason: blocked });
      return;
    }
    await this.handleRequest(req, res, 'http', { host, port, path: parsed.pathname + parsed.search });
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
    try {
      body = await readBody(req);
    } catch (e) {
      const busy = e instanceof BodyError && e.kind === 'busy';
      res.writeHead(busy ? 503 : 413, { 'content-type': 'text/plain' });
      res.end(busy ? 'server busy (too many concurrent in-flight requests)\n' : 'request body too large\n');
      this.deps.audit.append({ event: 'request', host, method, path, decision: 'denied', reason: busy ? 'server busy' : 'body too large' });
      return;
    }

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
      const amountField = this.amountForApproval(decision.ruleId, body, contentType);
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
    const injection = applyInjection(this.deps.vault.getInjectors(), {
      host,
      method,
      path,
      headers: fwdHeaders,
      body,
    });

    this.forward(scheme, target, method, injection.path, injection.headers, injection.body, res, (status, respBytes) => {
      this.deps.audit.append({
        event: 'request',
        host,
        method,
        path,
        decision: 'allowed',
        ruleId: decision.ruleId,
        injected: injection.injected,
        reqBytes: body?.length || 0,
        status,
        respBytes,
        latencyMs: Date.now() - started,
      });
    });
  }

  private amountForApproval(
    ruleId: string | undefined,
    body: Buffer | null,
    contentType?: string
  ): { field: string; value: number; currency?: string } | undefined {
    // Use the exact rule that fired (by id), so the card's amount matches enforcement
    // even when the rule uses a glob host like *.stripe.com.
    if (!ruleId) return undefined;
    const rule = this.deps.policy.getPolicy().rules.find((r) => r.id === ruleId);
    if (!rule || !rule.amountLimit) return undefined;
    const v = extractAmount(body, contentType, rule.amountLimit.field);
    if (v === undefined) return undefined;
    return { field: rule.amountLimit.field, value: v, currency: rule.amountLimit.currency };
  }

  private respondDenied(res: http.ServerResponse, reason: string): void {
    if (res.headersSent) return;
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'blocked_by_credential_airlock', reason }));
  }

  private forward(
    scheme: 'http' | 'https',
    target: Target,
    method: string,
    path: string,
    headers: Headers,
    body: Buffer | null,
    res: http.ServerResponse,
    done: (status: number, respBytes: number) => void
  ): void {
    const mod = scheme === 'https' ? https : http;
    const upstream = mod.request(
      {
        host: target.host,
        port: target.port,
        method,
        path,
        headers: headers as http.OutgoingHttpHeaders,
        rejectUnauthorized: true, // verify the REAL upstream certificate
      },
      (up) => {
        const status = up.statusCode || 502;
        const ce = String(up.headers['content-encoding'] || '').toLowerCase();
        const compressed = /\bbr\b/.test(ce) || /gzip/.test(ce) || /\bdeflate\b/.test(ce);
        const outHeaders: http.OutgoingHttpHeaders = {};
        for (const [k, v] of Object.entries(up.headers)) {
          if (HOP_BY_HOP.has(k.toLowerCase())) continue;
          outHeaders[k] = scrubHeader(v as string | string[] | undefined) as string | string[];
        }

        // HEAD / 204 / 304 carry no body by spec — forward headers (scrubbed) as-is;
        // never buffer/scrub a body or rewrite content-length (which would corrupt
        // HEAD resource-length and conditional-GET/caching semantics).
        if (method === 'HEAD' || status === 204 || status === 304) {
          res.writeHead(status, outHeaders);
          up.resume(); // drain any (spec-violating) body bytes
          up.on('end', () => {
            res.end();
            done(status, 0);
          });
          return;
        }

        // Account buffered response bytes against the shared in-flight cap, and
        // release on close, so concurrent large responses can't exhaust memory.
        let counted = 0;
        const releaseResp = () => {
          inFlightBytes -= counted;
          counted = 0;
        };
        res.on('close', releaseResp);
        const account = (n: number): boolean => {
          inFlightBytes += n;
          counted += n;
          return inFlightBytes <= MAX_INFLIGHT_BYTES;
        };

        if (compressed) {
          // We strip Accept-Encoding upstream, so a compressed reply is a
          // non-conforming server. Buffer (bounded), decompress (output-bounded),
          // scrub, re-emit as identity — never run scrub on compressed bytes (it
          // is a no-op and would leak), and never corrupt the body with a lossy
          // text round-trip.
          const parts: Buffer[] = [];
          let sz = 0;
          let over = false;
          up.on('data', (c: Buffer) => {
            sz += c.length;
            if (over) return;
            if (sz <= MAX_BODY && account(c.length)) parts.push(c);
            else over = true;
          });
          up.on('end', () => {
            const raw = Buffer.concat(parts);
            // FAIL CLOSED: we stripped Accept-Encoding, so any compressed reply is
            // non-conforming. If we cannot decompress (to scrub) — because it is
            // oversize, a zip bomb, or malformed/fake — we must NEVER forward the
            // raw bytes: a reflective upstream could echo the injected secret in a
            // body labelled gzip that we can't scrub. Drop the body, return 502.
            if (over) {
              log.warn('compressed response too large to scrub; failing closed (502)', { host: target.host });
              if (!res.headersSent) {
                res.writeHead(502, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'blocked_by_credential_airlock', reason: 'oversize compressed response could not be scrubbed' }));
              }
              return done(502, 0);
            }
            let plain: Buffer;
            try {
              plain = decompress(ce, raw);
            } catch {
              log.warn('compressed response could not be decompressed; failing closed (502)', { host: target.host });
              if (!res.headersSent) {
                res.writeHead(502, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'blocked_by_credential_airlock', reason: 'undecodable compressed response could not be scrubbed' }));
              }
              return done(502, 0);
            }
            const scrubbed = scrubBuffer(plain);
            delete outHeaders['content-encoding'];
            outHeaders['content-length'] = String(scrubbed.length);
            res.writeHead(status, outHeaders);
            res.end(scrubbed);
            done(status, scrubbed.length);
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
          sz += c.length; // count all received bytes for the audit metric
          if (streaming) {
            const scrubbed = scrubBuffer(Buffer.concat([carry, c]));
            const keep = Math.min(win, scrubbed.length);
            res.write(scrubbed.subarray(0, scrubbed.length - keep));
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
            res.writeHead(status, outHeaders);
            res.write(head.subarray(0, head.length - keep));
            carry = Buffer.from(head.subarray(head.length - keep));
            releaseResp(); // parts no longer held; streaming uses only the tiny carry
          }
        });
        up.on('end', () => {
          if (streaming) {
            res.end(scrubBuffer(carry));
            return done(status, sz);
          }
          const scrubbed = scrubBuffer(Buffer.concat(parts));
          outHeaders['content-length'] = String(scrubbed.length);
          res.writeHead(status, outHeaders);
          res.end(scrubbed);
          done(status, scrubbed.length);
        });
      }
    );
    upstream.on('error', (e) => {
      log.warn('upstream error', { host: target.host, err: String(e) });
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'upstream_error' }));
      } else {
        res.destroy();
      }
      done(502, 0);
    });
    // A hostile/slow allowlisted upstream must not pin sockets forever.
    upstream.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
      log.warn('upstream timeout', { host: target.host });
      upstream.destroy(new Error('upstream timeout'));
    });
    if (body && body.length) upstream.write(body);
    upstream.end();
  }
}

function readBody(req: http.IncomingMessage): Promise<Buffer | null> {
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
      release();
      resolve(chunks.length ? Buffer.concat(chunks) : null);
    });
    req.on('error', (e) => {
      release();
      reject(e);
    });
  });
}
