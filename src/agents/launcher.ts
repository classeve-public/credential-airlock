/**
 * Agent launcher — the "launch them" toggle.
 *
 * Spawns a registered agent command with the proxy + CA trust pre-wired into its
 * environment, so the agent transparently routes all egress through the airlock
 * and never sees a real key. Captures a bounded log ring buffer per agent.
 */
import { spawn, ChildProcess } from 'child_process';
import { AgentProfile, AgentRuntime } from '../types';
import { log } from '../util/logger';

interface Running {
  child: ChildProcess;
  runtime: AgentRuntime;
  logs: string[];
}

export class AgentLauncher {
  private running = new Map<string, Running>();
  private listeners = new Set<() => void>();

  constructor(private readonly maxLogLines = 500) {}

  launch(profile: AgentProfile, wiredEnv: Record<string, string>): AgentRuntime {
    const existing = this.running.get(profile.id);
    if (existing && existing.runtime.status === 'running') return existing.runtime;

    const env: NodeJS.ProcessEnv = { ...process.env, ...wiredEnv, ...(profile.env || {}) };
    const logs: string[] = [];
    let child: ChildProcess;
    try {
      child = spawn(profile.command, profile.args, {
        cwd: profile.cwd || process.cwd(),
        env,
        // On Windows, npm-installed agent CLIs (npx/claude/aider) are .cmd shims that
        // spawn() cannot launch without a shell. The command is operator-configured
        // (loopback, token-authed), so the shell adds no new injection surface.
        shell: process.platform === 'win32',
        windowsHide: true,
      });
    } catch (e) {
      const rt: AgentRuntime = { id: profile.id, status: 'error', exitCode: null, lastError: String(e) };
      this.running.set(profile.id, { child: undefined as unknown as ChildProcess, runtime: rt, logs });
      this.notify();
      return rt;
    }

    const rt: AgentRuntime = {
      id: profile.id,
      status: 'running',
      pid: child.pid,
      startedAt: new Date().toISOString(),
      exitCode: null,
    };
    const push = (prefix: string) => (d: Buffer) => {
      for (const line of d.toString('utf8').split(/\r?\n/)) {
        if (line) logs.push(`[${prefix}] ${line}`);
      }
      while (logs.length > this.maxLogLines) logs.shift();
      this.notify();
    };
    child.stdout?.on('data', push('out'));
    child.stderr?.on('data', push('err'));
    child.on('error', (e) => {
      rt.status = 'error';
      rt.lastError = String(e);
      log.warn(`agent '${profile.name}' error`, { err: String(e) });
      this.notify();
    });
    child.on('exit', (code) => {
      rt.status = 'exited';
      rt.exitCode = code;
      rt.exitedAt = new Date().toISOString();
      log.info(`agent '${profile.name}' exited`, { code });
      this.notify();
    });

    this.running.set(profile.id, { child, runtime: rt, logs });
    log.info(`launched agent '${profile.name}' (pid ${child.pid}) through the airlock`);
    this.notify();
    return rt;
  }

  stop(id: string): boolean {
    const r = this.running.get(id);
    if (!r || !r.child || r.runtime.status !== 'running') return false;
    try {
      if (process.platform === 'win32' && r.child.pid) {
        spawn('taskkill', ['/pid', String(r.child.pid), '/T', '/F'], { windowsHide: true });
      } else {
        r.child.kill('SIGTERM');
      }
    } catch (e) {
      log.warn('failed to stop agent', { id, err: String(e) });
      return false;
    }
    return true;
  }

  stopAll(): void {
    for (const id of this.running.keys()) this.stop(id);
  }

  status(id: string): AgentRuntime {
    return this.running.get(id)?.runtime || { id, status: 'stopped', exitCode: null };
  }

  logs(id: string): string[] {
    return this.running.get(id)?.logs.slice() || [];
  }

  allStatuses(): Record<string, AgentRuntime> {
    const out: Record<string, AgentRuntime> = {};
    for (const [id, r] of this.running) out[id] = r.runtime;
    return out;
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
