/**
 * Local admin/control plane. Bound to 127.0.0.1 ONLY (never network-exposed),
 * token-authenticated, with a Host-header check against DNS-rebinding. There is
 * deliberately NO endpoint that reveals a secret value — secrets are write-only.
 *
 * The static SPA reads the one-time token from the launch URL's ?token= and
 * sends it back in the `x-airlock-token` header on every API call.
 */
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { Runtime } from '../runtime';
import { randomToken, timingSafeEqualStr } from '../util/ids';
import { atomicWrite } from '../util/fsx';
import { log } from '../util/logger';
import { AuditEntry, InjectionSpec, Policy } from '../types';

const PUBLIC_DIR = path.resolve(__dirname, '..', '..', 'public');
const STATIC: Record<string, string> = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/app.js': 'app.js',
  '/style.css': 'style.css',
};
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

export class AdminServer {
  readonly token = randomToken();
  private server: http.Server;
  private sseClients = new Set<http.ServerResponse>();

  constructor(private readonly rt: Runtime) {
    atomicWrite(rt.paths.adminToken, this.token, 0o600);
    this.server = http.createServer((req, res) => {
      this.handle(req, res).catch((e) => {
        log.error('admin handler error', { err: String(e) });
        // Generic message — never reflect raw exception text (it can embed fs paths).
        if (!res.headersSent) this.json(res, 500, { error: 'internal error' });
      });
    });
    // Live updates to all connected dashboards.
    rt.audit.onAppend((e) => this.broadcast('audit', e));
    rt.approvals.onChange(() => this.broadcast('approvals', this.approvalsPayload()));
    rt.launcher.onChange(() => this.broadcast('agents', { agents: this.rt.launcher.allStatuses() }));
  }

  get url(): string {
    return `http://${this.rt.config.adminHost}:${this.rt.config.adminPort}/?token=${this.token}`;
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const onErr = (e: Error) => reject(e);
      this.server.once('error', onErr);
      this.server.listen(this.rt.config.adminPort, this.rt.config.adminHost, () => {
        this.server.removeListener('error', onErr);
        log.info(`admin UI on http://${this.rt.config.adminHost}:${this.rt.config.adminPort}`);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    for (const c of this.sseClients) {
      try {
        c.end();
      } catch {
        /* ignore */
      }
    }
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  // --- security helpers ---------------------------------------------------
  private hostOk(req: http.IncomingMessage): boolean {
    const raw = (req.headers.host || '').trim().toLowerCase();
    let host = raw;
    if (raw.startsWith('[')) {
      const end = raw.indexOf(']');
      host = end > 0 ? raw.slice(1, end) : raw; // [::1]:port -> ::1
    } else if ((raw.match(/:/g) || []).length <= 1) {
      host = raw.split(':')[0]; // host or host:port
    } // else: bare IPv6 literal (multiple colons, no brackets) -> use as-is
    return host === '127.0.0.1' || host === 'localhost' || host === '::1';
  }

  /** Defense-in-depth response headers for every reply (the in-scope adversary
   *  includes a malicious local web page: block framing, MIME-sniffing, referrer
   *  leakage, and inline-script execution). */
  private secHeaders(): Record<string, string> {
    return {
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
      'content-security-policy':
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    };
  }

  private authed(req: http.IncomingMessage, tokenFromQuery?: string): boolean {
    const provided = (req.headers['x-airlock-token'] as string) || tokenFromQuery || '';
    return timingSafeEqualStr(provided, this.token);
  }

  private json(res: http.ServerResponse, code: number, obj: unknown): void {
    const body = JSON.stringify(obj);
    res.writeHead(code, { ...this.secHeaders(), 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(body);
  }

  private async readJsonBody<T>(req: http.IncomingMessage): Promise<T> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const c of req) {
      total += (c as Buffer).length;
      if (total > 2 * 1024 * 1024) throw new Error('request too large');
      chunks.push(c as Buffer);
    }
    if (!chunks.length) return {} as T;
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as T;
  }

  // --- main dispatch ------------------------------------------------------
  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!this.hostOk(req)) {
      this.json(res, 403, { error: 'forbidden host (admin plane is loopback only)' });
      return;
    }
    const u = new URL(req.url || '/', `http://${req.headers.host}`);
    const pathname = u.pathname;
    const method = req.method || 'GET';

    // Public CA cert (not a secret) + static assets.
    if (method === 'GET' && pathname === '/ca.crt') {
      res.writeHead(200, {
        ...this.secHeaders(),
        'content-type': 'application/x-x509-ca-cert',
        'content-disposition': 'attachment; filename="airlock-ca.crt"',
      });
      res.end(this.rt.vault.caCertPem);
      return;
    }
    if (method === 'GET' && STATIC[pathname]) {
      this.serveStatic(res, STATIC[pathname]);
      return;
    }

    // SSE: EventSource cannot set headers, so token comes via query (loopback only).
    if (method === 'GET' && pathname === '/api/events') {
      if (!this.authed(req, u.searchParams.get('token') || undefined)) {
        this.json(res, 401, { error: 'unauthorized' });
        return;
      }
      this.handleSse(req, res);
      return;
    }

    // Everything else under /api requires the token header.
    if (pathname.startsWith('/api/')) {
      if (!this.authed(req)) {
        this.json(res, 401, { error: 'unauthorized (missing or bad x-airlock-token)' });
        return;
      }
      await this.api(method, pathname, u, req, res);
      return;
    }

    this.json(res, 404, { error: 'not found' });
  }

  private serveStatic(res: http.ServerResponse, file: string): void {
    const full = path.join(PUBLIC_DIR, file);
    if (!full.startsWith(PUBLIC_DIR)) {
      this.json(res, 403, { error: 'forbidden' });
      return;
    }
    fs.readFile(full, (err, data) => {
      if (err) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('UI asset not found. Build the UI into ./public.');
        return;
      }
      res.writeHead(200, { ...this.secHeaders(), 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(data);
    });
  }

  // --- API routes ---------------------------------------------------------
  private async api(
    method: string,
    pathname: string,
    u: URL,
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    const segs = pathname.split('/').filter(Boolean); // e.g. ['api','secrets','x','rotate']
    const r = segs[1];

    // /api/status
    if (method === 'GET' && r === 'status') return this.json(res, 200, this.rt.status());

    // /api/secrets
    if (r === 'secrets') {
      if (method === 'GET' && segs.length === 2) return this.json(res, 200, this.rt.vault.listSecrets());
      if (method === 'POST' && segs.length === 2) {
        const b = await this.readJsonBody<{
          name: string;
          placeholder: string;
          allowedHosts: string[];
          injection: InjectionSpec;
          description?: string;
          value: string;
        }>(req);
        if (!b.name || !b.value || !Array.isArray(b.allowedHosts) || !b.allowedHosts.length || !b.injection) {
          return this.json(res, 400, { error: 'name, value, allowedHosts[], injection are required' });
        }
        try {
          this.rt.addOrUpdateSecret({
            name: b.name,
            placeholder: b.placeholder || `__${b.name.toUpperCase()}__`,
            allowedHosts: b.allowedHosts,
            injection: b.injection,
            description: b.description,
            value: b.value,
          });
        } catch (e) {
          // Validation failure (e.g. a value that can't form a valid header) — return
          // the actionable 400 reason, not a generic 500. The validator's messages are
          // fixed strings that never embed the secret value, so they are safe to echo.
          log.warn('secret set rejected', { err: String(e) });
          return this.json(res, 400, { error: e instanceof Error ? e.message : 'invalid secret' });
        }
        this.rt.audit.append({ event: 'admin', reason: `secret '${b.name}' set`, detail: { hosts: b.allowedHosts } });
        return this.json(res, 200, { ok: true });
      }
      if (method === 'POST' && segs.length === 4 && segs[3] === 'rotate') {
        const b = await this.readJsonBody<{ value: string }>(req);
        if (!b.value) return this.json(res, 400, { error: 'value required' });
        const rotName = decodeURIComponent(segs[2]);
        // Distinguish "no such secret" (404) from "value rejected by validation" (400)
        // so the operator gets an accurate, actionable error instead of a blanket 404.
        if (!this.rt.vault.hasSecret(rotName)) return this.json(res, 404, { error: 'no such secret' });
        try {
          this.rt.rotateSecret(rotName, b.value);
        } catch (e) {
          log.warn('secret rotate rejected', { err: String(e) });
          return this.json(res, 400, { error: e instanceof Error ? e.message : 'rotation failed' });
        }
        this.rt.audit.append({ event: 'admin', reason: `secret '${rotName}' rotated` });
        return this.json(res, 200, { ok: true });
      }
      if (method === 'DELETE' && segs.length === 3) {
        try {
          this.rt.deleteSecret(decodeURIComponent(segs[2]));
        } catch (e) {
          log.warn('secret delete failed', { err: String(e) });
          return this.json(res, 404, { error: 'no such secret, or delete failed' });
        }
        this.rt.audit.append({ event: 'admin', reason: `secret '${segs[2]}' deleted` });
        return this.json(res, 200, { ok: true });
      }
    }

    // /api/policy
    if (r === 'policy') {
      if (method === 'GET') return this.json(res, 200, this.rt.getPolicy());
      if (method === 'PUT') {
        const b = await this.readJsonBody<Policy>(req);
        if (!b || !Array.isArray(b.egressAllowlist) || !Array.isArray(b.rules)) {
          return this.json(res, 400, { error: 'invalid policy' });
        }
        this.rt.savePolicy(b);
        this.rt.audit.append({ event: 'admin', reason: 'policy updated' });
        return this.json(res, 200, { ok: true, policy: this.rt.getPolicy() });
      }
    }

    // /api/audit , /api/audit/verify
    if (r === 'audit') {
      if (method === 'GET' && segs.length === 2) {
        const limit = Math.min(2000, Math.max(1, Number(u.searchParams.get('limit')) || 200));
        return this.json(res, 200, this.rt.audit.read(limit));
      }
      if (method === 'GET' && segs[2] === 'verify') return this.json(res, 200, this.rt.audit.verify());
    }

    // /api/approvals
    if (r === 'approvals') {
      if (method === 'GET' && segs.length === 2) return this.json(res, 200, this.approvalsPayload());
      if (method === 'POST' && segs.length === 4) {
        const id = decodeURIComponent(segs[2]);
        if (segs[3] === 'approve') return this.json(res, 200, { ok: this.rt.approvals.approve(id) });
        if (segs[3] === 'deny') return this.json(res, 200, { ok: this.rt.approvals.deny(id) });
      }
    }

    // /api/agents
    if (r === 'agents') {
      if (method === 'GET' && segs.length === 2) {
        return this.json(
          res,
          200,
          this.rt.config.agents.map((a) => ({ ...a, runtime: this.rt.launcher.status(a.id) }))
        );
      }
      if (method === 'POST' && segs.length === 2) {
        const b = await this.readJsonBody<{
          id?: string;
          name: string;
          command: string;
          args?: string[];
          cwd?: string;
          env?: Record<string, string>;
          description?: string;
        }>(req);
        if (!b.name || !b.command) return this.json(res, 400, { error: 'name and command required' });
        const profile = this.rt.upsertAgent({
          id: b.id,
          name: b.name,
          command: b.command,
          args: b.args || [],
          cwd: b.cwd,
          env: b.env,
          description: b.description,
        });
        return this.json(res, 200, profile);
      }
      if (method === 'DELETE' && segs.length === 3) {
        this.rt.removeAgent(decodeURIComponent(segs[2]));
        return this.json(res, 200, { ok: true });
      }
      if (method === 'POST' && segs.length === 4 && segs[3] === 'launch') {
        return this.json(res, 200, this.rt.launchAgent(decodeURIComponent(segs[2])));
      }
      if (method === 'POST' && segs.length === 4 && segs[3] === 'stop') {
        return this.json(res, 200, { ok: this.rt.stopAgent(decodeURIComponent(segs[2])) });
      }
      if (method === 'GET' && segs.length === 4 && segs[3] === 'logs') {
        return this.json(res, 200, { logs: this.rt.launcher.logs(decodeURIComponent(segs[2])) });
      }
    }

    // /api/proxy/start | stop
    if (r === 'proxy' && method === 'POST') {
      if (segs[2] === 'start') {
        await this.rt.startProxy();
        return this.json(res, 200, { ok: true, running: true });
      }
      if (segs[2] === 'stop') {
        await this.rt.stopProxy();
        return this.json(res, 200, { ok: true, running: false });
      }
    }

    // /api/migration/setup
    if (r === 'migration' && method === 'POST' && segs[2] === 'setup') {
      const b = await this.readJsonBody<{ passphrase: string }>(req);
      if (!b.passphrase) return this.json(res, 400, { error: 'passphrase required' });
      try {
        const out = await this.rt.setupMigration(b.passphrase);
        return this.json(res, 200, out); // offlineShare shown once
      } catch (e) {
        log.warn('migration setup failed', { err: String(e) });
        return this.json(res, 400, { error: 'migration setup failed (passphrase must be at least 12 characters; see server log)' });
      }
    }

    this.json(res, 404, { error: 'unknown api route' });
  }

  private approvalsPayload(): { pending: unknown[]; recent: unknown[] } {
    return { pending: this.rt.approvals.listPending(), recent: this.rt.approvals.listRecent() };
  }

  // --- SSE ----------------------------------------------------------------
  private handleSse(req: http.IncomingMessage, res: http.ServerResponse): void {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      connection: 'keep-alive',
    });
    res.write(': connected\n\n');
    this.sseClients.add(res);
    const hb = setInterval(() => {
      try {
        res.write(': hb\n\n');
      } catch {
        /* ignore */
      }
    }, 25000);
    hb.unref?.();
    req.on('close', () => {
      clearInterval(hb);
      this.sseClients.delete(res);
    });
  }

  private broadcast(type: string, data: unknown): void {
    const payload = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const c of this.sseClients) {
      try {
        c.write(payload);
      } catch {
        /* ignore */
      }
    }
  }
}
