/**
 * Filesystem helpers: atomic writes, restrictive permissions, JSON IO.
 *
 * All state files are written with 0o600 (owner-only) where the platform honors
 * it. Atomic write = write to a temp file then rename, so a crash never leaves a
 * half-written vault.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export function ensureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
  // Best-effort owner-only on POSIX; no-op semantics on Windows ACLs.
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    /* platform may not support chmod */
  }
}

export function atomicWrite(file: string, data: Buffer | string, mode = 0o600): void {
  ensureDir(path.dirname(file));
  const tmp = file + '.tmp-' + crypto.randomBytes(6).toString('hex');
  const fd = fs.openSync(tmp, 'wx', mode);
  try {
    if (typeof data === 'string') fs.writeSync(fd, data);
    else fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
  try {
    fs.chmodSync(file, mode);
  } catch {
    /* ignore on platforms without chmod */
  }
}

export function readFileOpt(file: string): Buffer | null {
  try {
    return fs.readFileSync(file);
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e;
  }
}

export function writeJson(file: string, obj: unknown, mode = 0o600): void {
  atomicWrite(file, JSON.stringify(obj, null, 2), mode);
}

export function readJson<T>(file: string): T | null {
  const buf = readFileOpt(file);
  if (!buf) return null;
  try {
    return JSON.parse(buf.toString('utf8')) as T;
  } catch {
    // Surface a clear, actionable error instead of a raw SyntaxError that would
    // otherwise propagate and brick every command.
    throw new Error(`corrupt or unparseable JSON file: ${file}`);
  }
}

export function exists(file: string): boolean {
  return fs.existsSync(file);
}

/** Append a line to a file durably (fsync), creating it if needed. Audit-only. */
export function appendLine(file: string, line: string): void {
  ensureDir(path.dirname(file));
  // Self-correct a missing trailing newline (e.g. a crash dropped it) so two
  // entries can never be glued onto one physical line and fork the chain. Read
  // the last byte via a READ fd — an append-mode fd is not readable on Windows.
  let needSep = false;
  try {
    const st = fs.statSync(file);
    if (st.size > 0) {
      const rfd = fs.openSync(file, 'r');
      try {
        const tail = Buffer.alloc(1);
        fs.readSync(rfd, tail, 0, 1, st.size - 1);
        needSep = tail[0] !== 0x0a;
      } finally {
        fs.closeSync(rfd);
      }
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  const fd = fs.openSync(file, 'a', 0o600);
  try {
    if (needSep) fs.writeSync(fd, '\n');
    fs.writeSync(fd, line + '\n');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
