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

// Redaction registry: live secret values (and their on-the-wire encodings) that
// must be scrubbed from all output.
const redactions = new Set<string>();
// Derived caches, rebuilt only when the registry changes — so the hot paths
// (scrubBuffer runs PER response-body chunk, scrub PER header/log line) never
// re-encode the needle set on every call.
let latin1Needles: string[] = []; // each redaction's UTF-8 bytes viewed as latin1
let maxRedactionLen = 0; // longest redaction in UTF-8 bytes (sliding-window size)

function rebuildDerived(): void {
  latin1Needles = [];
  maxRedactionLen = 0;
  for (const s of redactions) {
    if (!s) continue;
    const buf = Buffer.from(s, 'utf8');
    latin1Needles.push(buf.toString('latin1'));
    if (buf.length > maxRedactionLen) maxRedactionLen = buf.length;
  }
}

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
  // Also register the on-the-wire latin1 form of the secret's UTF-8 bytes. Node
  // delivers incoming HTTP header values as a latin1/binary string, so a secret
  // containing any byte >= 0x80 would otherwise slip past the contiguous scrub()
  // (which holds the UTF-8 code points). This makes scrub()/scrubHeader catch it.
  try {
    const wire = Buffer.from(value, 'utf8').toString('latin1');
    if (wire !== value) redactions.add(wire);
  } catch {
    /* ignore */
  }
  // Lowercased form: Node lowercases incoming HTTP header names, so a mixed-case
  // secret reflected as a header NAME would otherwise dodge the case-sensitive scrub.
  try {
    const lower = value.toLowerCase();
    if (lower !== value) redactions.add(lower);
  } catch {
    /* ignore */
  }
  // Percent-encoded form: query-mode injection sends encodeURIComponent(value), and a
  // reflective upstream could echo that back — register it so the scrubber catches it.
  try {
    const enc = encodeURIComponent(value);
    if (enc !== value) redactions.add(enc);
  } catch {
    /* ignore */
  }
  rebuildDerived();
}

export function clearRedactions(): void {
  redactions.clear();
  rebuildDerived();
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
  return maxRedactionLen;
}

/**
 * Byte-preserving redaction over a Buffer. Matches each secret's exact UTF-8 byte
 * sequence (via a latin1 round-trip that maps all 256 byte values 1:1), so it
 * works on any content type without corrupting non-secret bytes. Used to scrub
 * proxy RESPONSE bodies so a reflective upstream can't echo an injected key back.
 */
export function scrubBuffer(buf: Buffer): Buffer {
  if (!latin1Needles.length || buf.length === 0) return buf;
  let s = buf.toString('latin1');
  let changed = false;
  for (const needle of latin1Needles) {
    if (needle && s.includes(needle)) {
      s = s.split(needle).join('***REDACTED***');
      changed = true;
    }
  }
  return changed ? Buffer.from(s, 'latin1') : buf;
}

/**
 * Byte-aware redaction for a latin1/binary string (e.g. an incoming HTTP header
 * value, which Node delivers as latin1). Matches each secret's exact UTF-8 wire
 * bytes mapped through latin1, so a non-ASCII secret is redacted from a header a
 * reflective upstream echoes back. Complements scrub() (which matches code points).
 */
export function scrubLatin1(input: string): string {
  if (!latin1Needles.length || !input) return input;
  let out = input;
  for (const needle of latin1Needles) {
    if (needle && out.includes(needle)) out = out.split(needle).join('***REDACTED***');
  }
  return out;
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
