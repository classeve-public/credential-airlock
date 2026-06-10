/**
 * Minimal structured logger with a secret-redaction safety net.
 *
 * Secrets must NEVER be logged. The proxy/audit code is written to never pass a
 * raw credential to the logger, but as defense-in-depth the vault registers every
 * live secret value here, and every log line is scrubbed before it is emitted.
 */

type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let minLevel: Level = (process.env.AIRLOCK_LOG_LEVEL as Level) || 'info';

// Redaction registry: live secret values that must be scrubbed from all output.
const redactions = new Set<string>();

export function registerRedaction(value: string): void {
  if (!value) return;
  redactions.add(value);
  // Also register the JSON-escaped form, so scrub() catches a secret even after
  // it has been JSON.stringify'd (e.g. a value containing a quote or backslash).
  try {
    const escaped = JSON.stringify(value).slice(1, -1);
    if (escaped !== value) redactions.add(escaped);
  } catch {
    /* ignore */
  }
}

export function clearRedactions(): void {
  redactions.clear();
}

export function scrub(input: string): string {
  let out = input;
  for (const secret of redactions) {
    if (secret && out.includes(secret)) {
      out = out.split(secret).join('***REDACTED***');
    }
  }
  return out;
}

/** Longest registered secret in UTF-8 bytes (for sliding-window streaming scrub). */
export function maxRedactionLength(): number {
  let m = 0;
  for (const s of redactions) {
    const len = Buffer.byteLength(s, 'utf8');
    if (len > m) m = len;
  }
  return m;
}

/**
 * Byte-preserving redaction over a Buffer. Matches each secret's exact UTF-8 byte
 * sequence (via a latin1 round-trip that maps all 256 byte values 1:1), so it
 * works on any content type without corrupting non-secret bytes. Used to scrub
 * proxy RESPONSE bodies so a reflective upstream can't echo an injected key back.
 */
export function scrubBuffer(buf: Buffer): Buffer {
  if (!redactions.size || buf.length === 0) return buf;
  let s = buf.toString('latin1');
  let changed = false;
  for (const secret of redactions) {
    const needle = Buffer.from(secret, 'utf8').toString('latin1');
    if (needle && s.includes(needle)) {
      s = s.split(needle).join('***REDACTED***');
      changed = true;
    }
  }
  return changed ? Buffer.from(s, 'latin1') : buf;
}

function emit(level: Level, msg: string, extra?: Record<string, unknown>): void {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[minLevel]) return;
  const ts = new Date().toISOString();
  let line = `${ts} ${level.toUpperCase().padEnd(5)} ${msg}`;
  if (extra && Object.keys(extra).length) {
    try {
      line += ' ' + JSON.stringify(extra);
    } catch {
      line += ' [unserializable extra]';
    }
  }
  line = scrub(line);
  const stream = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  stream.write(line + '\n');
}

export const log = {
  setLevel(l: Level) {
    minLevel = l;
  },
  debug: (msg: string, extra?: Record<string, unknown>) => emit('debug', msg, extra),
  info: (msg: string, extra?: Record<string, unknown>) => emit('info', msg, extra),
  warn: (msg: string, extra?: Record<string, unknown>) => emit('warn', msg, extra),
  error: (msg: string, extra?: Record<string, unknown>) => emit('error', msg, extra),
};
