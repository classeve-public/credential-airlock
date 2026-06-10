/**
 * Credential injection: swap dummy placeholders for real secrets, or auto-add
 * configured auth headers/query params.
 *
 * HARD SECURITY BOUND: a secret is injected ONLY toward hosts listed in that
 * secret's allowedHosts. A hijacked agent that sends `__STRIPE_KEY__` to
 * evil.com gets the literal dummy forwarded (and deny-by-default egress will
 * have blocked evil.com long before this anyway). The real key never goes
 * anywhere its own policy doesn't permit.
 */
import { Injector } from '../vault/vault';
import { matchAnyHost } from '../util/glob';

export type Headers = Record<string, string | string[] | undefined>;

export interface RequestCtx {
  host: string;
  method: string;
  path: string; // path + query
  headers: Headers;
  body: Buffer | null;
}

export interface InjectionResult {
  headers: Headers;
  path: string;
  body: Buffer | null;
  injected: string[];
}

const DEFAULT_TEMPLATE = '{{secret}}';

function setHeaderCaseInsensitive(headers: Headers, name: string, value: string): void {
  const lower = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === lower) delete headers[k];
  }
  headers[name] = value;
}

function renderTemplate(template: string, secret: string): string {
  return template.includes('{{secret}}') ? template.split('{{secret}}').join(secret) : secret;
}

export function applyInjection(injectors: Injector[], ctx: RequestCtx): InjectionResult {
  const headers: Headers = { ...ctx.headers };
  let path = ctx.path;
  let body = ctx.body;
  let bodyChanged = false;
  const injected = new Set<string>();

  for (const inj of injectors) {
    // The single most important line in the product: host binding per secret.
    if (!matchAnyHost(inj.allowedHosts, ctx.host)) continue;

    const spec = inj.injection;
    const rendered = renderTemplate(spec.valueTemplate || DEFAULT_TEMPLATE, inj.value);

    if (spec.mode === 'placeholder') {
      const ph = spec.placeholder || inj.placeholder;
      if (!ph) continue;
      let used = false;
      for (const [k, v] of Object.entries(headers)) {
        if (v == null) continue;
        if (Array.isArray(v)) {
          headers[k] = v.map((x) => {
            if (typeof x === 'string' && x.includes(ph)) {
              used = true;
              return x.split(ph).join(inj.value);
            }
            return x;
          });
        } else if (typeof v === 'string' && v.includes(ph)) {
          headers[k] = v.split(ph).join(inj.value);
          used = true;
        }
      }
      if (spec.injectInBody && body && body.includes(ph)) {
        body = Buffer.from(body.toString('utf8').split(ph).join(inj.value), 'utf8');
        bodyChanged = true;
        used = true;
      }
      if (used) injected.add(inj.name);
    } else if (spec.mode === 'header') {
      setHeaderCaseInsensitive(headers, spec.header || 'Authorization', rendered);
      injected.add(inj.name);
    } else if (spec.mode === 'query') {
      const qp = spec.queryParam || 'api_key';
      const sep = path.includes('?') ? '&' : '?';
      path = `${path}${sep}${encodeURIComponent(qp)}=${encodeURIComponent(inj.value)}`;
      injected.add(inj.name);
    }
  }

  if (bodyChanged && body) {
    setHeaderCaseInsensitive(headers, 'content-length', String(body.length));
    // Avoid content-length / chunked conflicts after rewriting the body.
    for (const k of Object.keys(headers)) {
      if (k.toLowerCase() === 'transfer-encoding') delete headers[k];
    }
  }

  return { headers, path, body, injected: [...injected] };
}
