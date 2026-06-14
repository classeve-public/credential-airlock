/**
 * Append-only, hash-chained audit log.
 *
 * Each entry's `hash` = SHA-256(prevHash || canonical(entry-without-hash)).
 * In-place tampering and interior/head deletion break the chain; tail truncation
 * (deleting the most recent entries) is caught by an out-of-band tip anchor
 * (audit.tip.json) holding the latest {seq, hash}, which verify() cross-checks.
 * The log NEVER contains secret values — only secret NAMES that were injected.
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { AuditEntry } from '../types';
import { Paths } from '../config';
import { appendLine, readFileOpt, atomicWrite } from '../util/fsx';
import { scrub } from '../util/logger';

const GENESIS = '0'.repeat(64);
// Bound on-disk growth: rotate the live log past this size, keep N archives, prune older.
const MAX_AUDIT_BYTES = Number(process.env.AIRLOCK_AUDIT_MAX_BYTES) || 16 * 1024 * 1024;
const MAX_AUDIT_ARCHIVES = Number(process.env.AIRLOCK_AUDIT_MAX_ARCHIVES) || 8;
const ARCHIVE_RE = /^audit\.\d+\.jsonl$/;

export type NewEntry = Omit<AuditEntry, 'seq' | 'ts' | 'prevHash' | 'hash'>;

function hashEntry(prevHash: string, core: Omit<AuditEntry, 'hash'>): string {
  const canonical = JSON.stringify(core);
  return crypto.createHash('sha256').update(prevHash).update('\n').update(canonical).digest('hex');
}

export class AuditLog {
  private seq = 0;
  private lastHash = GENESIS;
  private listeners = new Set<(e: AuditEntry) => void>();

  /**
   * @param repair  When true (the default — used by the lock-holding daemon via
   *   `Runtime.openOrInit`/`initNew`, and by tests), the constructor PHYSICALLY
   *   truncates a crash-torn trailing line and (re)syncs the out-of-band tip.
   *   Read-only callers (`Runtime.open`: status / audit --verify / health --deep
   *   / secret list) pass `false`, so merely OPENING the log never mutates a file
   *   that a concurrently running daemon owns. This upholds the append-only and
   *   single-writer invariants: open-time repair is a write, and writes belong to
   *   the lock holder. A non-repair open still reads seq/hash for in-memory
   *   verify(); it just leaves a torn tail for the daemon to fix on its next start.
   */
  constructor(private readonly p: Paths, private readonly repair = true) {
    const buf = readFileOpt(p.audit);
    if (buf && buf.length) {
      // Walk lines tracking byte offsets so we can PHYSICALLY truncate a torn
      // trailing line. Merely skipping it on load is not enough: the next append
      // (open mode 'a') would glue onto the fragment, forking the chain and
      // permanently breaking verify().
      const segs = buf.toString('utf8').split('\n');
      let off = 0;
      let validEnd = 0;
      for (let i = 0; i < segs.length; i++) {
        const seg = segs[i];
        const hasNL = i < segs.length - 1;
        const segBytes = Buffer.byteLength(seg, 'utf8');
        if (seg.trim()) {
          const e = AuditLog.parseLine(seg);
          if (e) {
            this.seq = e.seq;
            this.lastHash = e.hash;
            validEnd = off + segBytes + (hasNL ? 1 : 0);
          }
        }
        off += segBytes + (hasNL ? 1 : 0);
      }
      if (this.repair && validEnd < buf.length) {
        try {
          fs.truncateSync(p.audit, validEnd); // drop crash-torn trailing bytes
        } catch {
          /* best-effort */
        }
      }
    }
    // syncTip() may write the tip or a sticky tamper marker — both are mutations,
    // so only the repair (lock-holding) path performs them.
    if (this.repair) this.syncTip();
  }

  private static parseLine(l: string): AuditEntry | null {
    try {
      return JSON.parse(l) as AuditEntry;
    } catch {
      return null;
    }
  }

  /**
   * Repair the tip on open so a missing/behind tip is not mistaken for tampering.
   * NEVER repair a tip that is AHEAD of the log (tip.seq > seq) — that is evidence
   * of tail truncation and must survive to be reported by verify().
   */
  private syncTip(): void {
    const tipBuf = readFileOpt(this.p.auditTip);
    let tip: { seq: number; hash: string } | null = null;
    if (tipBuf) {
      try {
        tip = JSON.parse(tipBuf.toString('utf8')) as { seq: number; hash: string };
      } catch {
        tip = null;
      }
    }
    if (tip && typeof tip.seq === 'number' && tip.seq > this.seq) {
      // The anchored tip is AHEAD of the durable log => committed entries were
      // removed. Record a STICKY tamper marker so a subsequent append can't
      // launder the chain back to ok. Leave the ahead tip in place too.
      if (!readFileOpt(this.p.auditTamper)) {
        try {
          atomicWrite(
            this.p.auditTamper,
            JSON.stringify({
              detectedAt: new Date().toISOString(),
              tipSeq: tip.seq,
              logSeq: this.seq,
              reason: 'audit tip ahead of log (tail truncation detected)',
            })
          );
        } catch {
          /* best-effort */
        }
      }
      return;
    }
    if (!tip || tip.seq !== this.seq || tip.hash !== this.lastHash) {
      this.writeTip();
    }
  }

  /** Out-of-band tip anchor (light, no fsync — verify()/syncTip tolerate a torn/missing tip). */
  private writeTip(): void {
    try {
      fs.writeFileSync(this.p.auditTip, JSON.stringify({ seq: this.seq, hash: this.lastHash }), { mode: 0o600 });
    } catch {
      /* tip is best-effort; never let it block auditing */
    }
  }

  append(entry: NewEntry): AuditEntry {
    this.rotateIfNeeded();
    return this.writeEntry(entry);
  }

  /**
   * Rotate the live log once it exceeds the size cap: archive it, prune old
   * archives, reset the chain, and write a rollover anchor (seq 1) that records
   * the archived segment's tip hash so the history stays cryptographically linked.
   * Keeping each file a fresh GENESIS chain means verify()/the tip stay simple.
   */
  private rotateIfNeeded(): void {
    let size = 0;
    try {
      size = fs.statSync(this.p.audit).size;
    } catch {
      return;
    }
    if (size < MAX_AUDIT_BYTES) return;
    const archivedTipHash = this.lastHash;
    const archivedSeq = this.seq;
    const archive = path.join(path.dirname(this.p.audit), `audit.${Date.now()}.jsonl`);
    try {
      fs.renameSync(this.p.audit, archive);
    } catch {
      return; // if we can't rotate, keep appending rather than lose auditing
    }
    this.seq = 0;
    this.lastHash = GENESIS;
    this.pruneArchives();
    this.writeEntry({ event: 'system', reason: 'audit log rotated', detail: { rollover: true, archivedSeq, archivedTipHash } });
  }

  private pruneArchives(): void {
    try {
      const dir = path.dirname(this.p.audit);
      const archives = fs.readdirSync(dir).filter((f) => ARCHIVE_RE.test(f)).sort();
      for (const f of archives.slice(0, Math.max(0, archives.length - MAX_AUDIT_ARCHIVES))) {
        try {
          fs.unlinkSync(path.join(dir, f));
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* ignore */
    }
  }

  private writeEntry(entry: NewEntry): AuditEntry {
    this.seq += 1;
    const core: Omit<AuditEntry, 'hash'> = {
      seq: this.seq,
      ts: new Date().toISOString(),
      prevHash: this.lastHash,
      ...entry,
    };
    // Defense-in-depth: scrub any accidentally-included secret material.
    const safeCore = JSON.parse(scrub(JSON.stringify(core))) as Omit<AuditEntry, 'hash'>;
    const hash = hashEntry(this.lastHash, safeCore);
    const full: AuditEntry = { ...safeCore, hash };
    appendLine(this.p.audit, JSON.stringify(full));
    this.lastHash = hash;
    this.writeTip();
    for (const l of this.listeners) {
      try {
        l(full);
      } catch {
        /* listener errors must not break auditing */
      }
    }
    return full;
  }

  onAppend(fn: (e: AuditEntry) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  read(limit = 200): AuditEntry[] {
    const buf = readFileOpt(this.p.audit);
    if (!buf) return [];
    const lines = buf.toString('utf8').split('\n').filter((l) => l.trim());
    const slice = lines.slice(-limit);
    return slice
      .map((l) => AuditLog.parseLine(l))
      .filter((e): e is AuditEntry => e !== null);
  }

  /**
   * Recompute the chain and detect tampering, in-place edits, gaps, AND tail
   * truncation/rollback (via the out-of-band tip). Returns rather than throws.
   */
  verify(): { ok: boolean; entries: number; brokenAt?: number } {
    // A sticky tamper marker (set when the tip was found ahead of the log) means
    // committed entries were deleted; never report ok afterward, even once later
    // appends have grown the chain back past the truncation point.
    if (readFileOpt(this.p.auditTamper)) {
      const b = readFileOpt(this.p.audit);
      const n = b ? b.toString('utf8').split('\n').filter((l) => l.trim()).length : 0;
      return { ok: false, entries: n };
    }
    const buf = readFileOpt(this.p.audit);
    if (!buf) return { ok: true, entries: 0 };
    const lines = buf.toString('utf8').split('\n').filter((l) => l.trim());
    let prev = GENESIS;
    for (let i = 0; i < lines.length; i++) {
      const e = AuditLog.parseLine(lines[i]);
      if (!e) return { ok: false, entries: lines.length, brokenAt: i + 1 };
      const { hash, ...core } = e;
      if (e.seq !== i + 1) return { ok: false, entries: lines.length, brokenAt: e.seq }; // non-contiguous / gap
      if (e.prevHash !== prev) return { ok: false, entries: lines.length, brokenAt: e.seq };
      if (hashEntry(prev, core) !== hash) return { ok: false, entries: lines.length, brokenAt: e.seq };
      prev = hash;
    }
    // Tip check: catches deletion of the most recent entries. Tolerate the benign
    // crash window where the durable log got the latest line but the tip write did
    // not (tip lags by exactly one, with a hash that matches the prior line).
    const tipBuf = readFileOpt(this.p.auditTip);
    if (tipBuf) {
      let tip: { seq: number; hash: string } | null = null;
      try {
        tip = JSON.parse(tipBuf.toString('utf8')) as { seq: number; hash: string };
      } catch {
        tip = null;
      }
      if (!tip) return { ok: false, entries: lines.length };
      const lastHash = lines.length ? prev : GENESIS;
      const okCurrent = tip.seq === lines.length && tip.hash === lastHash;
      let okWindow = false;
      if (!okCurrent && lines.length >= 1 && tip.seq === lines.length - 1) {
        const lastEntry = AuditLog.parseLine(lines[lines.length - 1]);
        okWindow = !!lastEntry && tip.hash === lastEntry.prevHash;
      }
      if (!okCurrent && !okWindow) {
        return { ok: false, entries: lines.length, brokenAt: Math.min(tip.seq, lines.length) + 1 };
      }
    } else if (lines.length) {
      return { ok: false, entries: lines.length }; // tip missing for a non-empty log
    }
    return { ok: true, entries: lines.length };
  }
}
