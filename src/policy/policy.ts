/**
 * Policy engine. Deny-by-default at two layers:
 *   1. Egress: the host must match the egress allowlist, or the request is denied.
 *   2. Rules: within an allowed host, the FIRST matching rule's action wins
 *      (allow | deny | require_approval). No matching rule => defaultAction (deny).
 * Rules may carry a rate limit (sliding window) and an amount cap (a hard ceiling
 * on a named numeric body field, e.g. Stripe `amount`).
 */
import { Policy, PolicyDecision, PolicyRule, RateLimit } from '../types';
import { matchAnyHost, matchAnyPath } from '../util/glob';

export interface EvalCtx {
  host: string;
  method: string;
  path: string;
  body: Buffer | null;
  contentType?: string;
}

/**
 * Extract a numeric amount from a request body. Robust against attacker-chosen
 * content-types and leading whitespace/BOM: it does NOT trust the content-type
 * to decide whether to parse — it attempts JSON whenever the body looks like
 * JSON after trimming, and always tries a urlencoded fallback.
 */
export function extractAmount(body: Buffer | null, contentType: string | undefined, field: string): number | undefined {
  if (!body || !body.length) return undefined;
  const text = body.toString('utf8');
  const trimmed = text.replace(/^[﻿\s]+/, '');
  const ct = (contentType || '').toLowerCase();
  if (ct.includes('application/json') || trimmed[0] === '{' || trimmed[0] === '[') {
    try {
      const obj = JSON.parse(trimmed) as unknown;
      const val = field
        .split('.')
        .reduce<unknown>((acc, k) => (acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined), obj);
      const n = typeof val === 'string' ? Number(val) : (val as number);
      if (Number.isFinite(n)) return n as number;
    } catch {
      /* fall through to form parsing */
    }
  }
  try {
    const params = new URLSearchParams(text);
    const all = params.getAll(field);
    // Duplicate keys are ambiguous: URLSearchParams.get() returns the FIRST value,
    // but Stripe/Rack/PHP/Rails take the LAST. Refuse to guess — fail closed.
    if (all.length > 1) return undefined;
    if (all.length === 1) {
      const n = Number(all[0]);
      if (Number.isFinite(n)) return n;
    }
  } catch {
    /* ignore */
  }
  return undefined;
}

/** Extract the amount from a URL query string (an upstream may read it from there too). */
export function extractAmountFromQuery(pathWithQuery: string, field: string): number | undefined {
  const q = pathWithQuery.indexOf('?');
  if (q < 0) return undefined;
  try {
    const params = new URLSearchParams(pathWithQuery.slice(q + 1));
    const key = field.includes('.') ? field.split('.').pop()! : field;
    const all = params.getAll(key);
    if (all.length !== 1) return undefined; // absent or ambiguous duplicate -> not readable
    const n = Number(all[0]);
    return Number.isFinite(n) ? n : undefined;
  } catch {
    return undefined;
  }
}

export class PolicyEngine {
  private buckets = new Map<string, number[]>();

  constructor(private policy: Policy) {}

  setPolicy(p: Policy): void {
    this.policy = p;
  }
  getPolicy(): Policy {
    return this.policy;
  }

  isHostAllowed(host: string): boolean {
    return matchAnyHost(this.policy.egressAllowlist, host);
  }

  private ruleMatches(rule: PolicyRule, ctx: EvalCtx): boolean {
    const hostOk = !rule.match.hosts?.length || matchAnyHost(rule.match.hosts, ctx.host);
    const pathOk = matchAnyPath(rule.match.paths, ctx.path.split('?')[0]);
    const methodOk =
      !rule.match.methods?.length ||
      rule.match.methods.map((m) => m.toUpperCase()).includes(ctx.method.toUpperCase());
    return hostOk && pathOk && methodOk;
  }

  /** Charge a slot against a rule's rate limit post-decision (e.g. after approval). */
  consumeRateForRule(ruleId: string, rl: RateLimit): boolean {
    return this.consumeRate(ruleId, rl.max, rl.windowSec);
  }

  /** Sliding-window rate check. Returns true if the request is within budget (and consumes a slot). */
  private consumeRate(ruleId: string, max: number, windowSec: number): boolean {
    // Fail closed on a misconfigured limit (e.g. windowSec<=0 would otherwise be "unlimited").
    if (!(windowSec > 0) || !(max >= 1)) return false;
    const now = Date.now();
    const windowMs = windowSec * 1000;
    const arr = (this.buckets.get(ruleId) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) {
      this.buckets.set(ruleId, arr);
      return false;
    }
    arr.push(now);
    this.buckets.set(ruleId, arr);
    return true;
  }

  evaluate(ctx: EvalCtx): PolicyDecision {
    if (!this.isHostAllowed(ctx.host)) {
      return { action: 'deny', reason: `host '${ctx.host}' is not on the egress allowlist (deny-by-default)` };
    }
    for (const rule of this.policy.rules) {
      if (!this.ruleMatches(rule, ctx)) continue;

      if (rule.amountLimit) {
        const field = rule.amountLimit.field;
        // Read the amount from the body OR the query string (an attacker could put it
        // in either; the upstream may read either).
        let amt = extractAmount(ctx.body, ctx.contentType, field);
        if (amt === undefined) amt = extractAmountFromQuery(ctx.path, field);
        if (amt !== undefined) {
          if (amt < 0 || amt > rule.amountLimit.max) {
            return {
              action: 'deny',
              ruleId: rule.id,
              reason: `amount ${amt} is outside the allowed range [0, ${rule.amountLimit.max}] on field '${field}'`,
            };
          }
        } else {
          // No readable amount. Fail closed for any request that could carry one —
          // a non-empty body (incl. unparseable encodings, top-level arrays/primitives,
          // non-numeric values) or a mutating method — so the hard ceiling can't be
          // bypassed by hiding/omitting the amount. (Bodyless GET/HEAD: nothing to cap.)
          const mutating = ['POST', 'PUT', 'PATCH'].includes(ctx.method.toUpperCase());
          if ((ctx.body && ctx.body.length) || mutating) {
            return {
              action: 'deny',
              ruleId: rule.id,
              reason: `amount cap on '${field}' could not be read from the request (deny-by-default)`,
            };
          }
        }
      }

      if (rule.action === 'allow' && rule.rateLimit) {
        const ok = this.consumeRate(rule.id, rule.rateLimit.max, rule.rateLimit.windowSec);
        if (!ok) {
          return {
            action: 'deny',
            ruleId: rule.id,
            reason: `rate limit exceeded (${rule.rateLimit.max}/${rule.rateLimit.windowSec}s)`,
          };
        }
      }

      return { action: rule.action, ruleId: rule.id, reason: `matched rule '${rule.id}'` };
    }
    return { action: this.policy.defaultAction, reason: 'no matching rule (deny-by-default)' };
  }
}
