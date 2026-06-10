/**
 * Pending human-approval queue. When policy says require_approval, the proxy
 * holds the request and awaits a decision here. A human approves/denies via the
 * local admin UI; unattended requests expire (default 5 min) and are denied.
 */
import { ApprovalRequest } from '../types';
import { randomId } from '../util/ids';

interface Pending {
  req: ApprovalRequest;
  resolve: (approved: boolean) => void;
  timer: NodeJS.Timeout;
}

export class Approvals {
  private pending = new Map<string, Pending>();
  private history: ApprovalRequest[] = [];
  private listeners = new Set<() => void>();

  constructor(private readonly timeoutMs = 300_000, private readonly maxPending = 50) {}

  request(input: Omit<ApprovalRequest, 'id' | 'ts' | 'status' | 'expiresAt'>): {
    req: ApprovalRequest;
    decision: Promise<boolean>;
  } {
    const now = Date.now();
    // Bound the queue: each pending request pins its buffered body (up to MAX_BODY)
    // in proxy memory while it awaits a human. Refuse (deny) once the queue is full
    // so a hijacked agent cannot OOM the firewall by flooding approval requests.
    if (this.pending.size >= this.maxPending) {
      const denied: ApprovalRequest = {
        ...input,
        id: randomId(),
        ts: new Date(now).toISOString(),
        status: 'denied',
        expiresAt: new Date(now).toISOString(),
      };
      this.history.unshift(denied);
      this.history = this.history.slice(0, 100);
      this.notify();
      return { req: denied, decision: Promise.resolve(false) };
    }
    const id = randomId();
    const req: ApprovalRequest = {
      ...input,
      id,
      ts: new Date(now).toISOString(),
      status: 'pending',
      expiresAt: new Date(now + this.timeoutMs).toISOString(),
    };
    let resolve!: (approved: boolean) => void;
    const decision = new Promise<boolean>((r) => (resolve = r));
    const timer = setTimeout(() => this.settle(id, false, 'expired'), this.timeoutMs);
    timer.unref?.();
    this.pending.set(id, { req, resolve, timer });
    this.notify();
    return { req, decision };
  }

  private settle(id: string, approved: boolean, status: 'approved' | 'denied' | 'expired'): void {
    const p = this.pending.get(id);
    if (!p) return;
    clearTimeout(p.timer);
    p.req.status = status;
    this.pending.delete(id);
    this.history.unshift(p.req);
    this.history = this.history.slice(0, 100);
    p.resolve(approved);
    this.notify();
  }

  approve(id: string): boolean {
    if (!this.pending.has(id)) return false;
    this.settle(id, true, 'approved');
    return true;
  }

  deny(id: string): boolean {
    if (!this.pending.has(id)) return false;
    this.settle(id, false, 'denied');
    return true;
  }

  listPending(): ApprovalRequest[] {
    return [...this.pending.values()].map((p) => p.req);
  }

  listRecent(): ApprovalRequest[] {
    return this.history.slice(0, 50);
  }

  onChange(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private notify(): void {
    for (const l of this.listeners) {
      try {
        l();
      } catch {
        /* ignore */
      }
    }
  }
}
