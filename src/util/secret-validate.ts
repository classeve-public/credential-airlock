/**
 * Set-time validation that a secret can be injected CLEANLY. Lives next to the
 * vault write primitive (called from Vault.setSecret / Vault.rotateSecret) so
 * EVERY normal write path — CLI, admin API, rotation — inherits it. The proxy's
 * forward-time try/catch remains the backstop for anything that slips in via a
 * restored legacy/forged vault.
 *
 * The rules mirror exactly what Node's http layer enforces, so a sealed secret
 * can never silently 502-black-hole (or CRLF-smuggle) at forward time:
 *
 *   - header mode      : the rendered header VALUE must be header-safe (no
 *                        CR/LF/NUL/control-except-tab, no code unit >0xFF) and
 *                        the header NAME must be an RFC 7230 token.
 *   - placeholder mode : the value can be spliced into a HEADER too (inject.ts
 *                        replaces the placeholder in headers AND body), so it is
 *                        held to the SAME header-safe rule UNCONDITIONALLY —
 *                        `injectInBody` does not exempt it (a multiline value
 *                        would otherwise smuggle headers when the placeholder
 *                        appears in one).
 *   - query mode       : the value is encodeURIComponent'd, so any byte is safe
 *                        on the wire; we only reject unpaired surrogates (which
 *                        make encodeURIComponent THROW) and a control-char param.
 */
import { InjectionSpec } from '../types';
import { HEADER_TOKEN_RE, INVALID_HEADER_VALUE_RE } from './http-token';

const CTRL_RE = /[\x00-\x1f\x7f]/;

/** True if `s` contains an unpaired UTF-16 surrogate (encodeURIComponent throws on these). */
function hasLoneSurrogate(s: string): boolean {
  try {
    encodeURIComponent(s);
    return false;
  } catch {
    return true; // URIError: malformed (lone surrogate)
  }
}

function assertHeaderValueSafe(value: string, valueTemplate?: string): void {
  // The rendered header value is `template` with `{{secret}}` replaced by `value`
  // (a plain concatenation), so if each piece is header-safe the result is too.
  if (INVALID_HEADER_VALUE_RE.test(value)) {
    throw new Error('secret value would form an invalid HTTP header value (control characters or code points >0xFF)');
  }
  if (valueTemplate && INVALID_HEADER_VALUE_RE.test(valueTemplate)) {
    throw new Error('injection value template would form an invalid HTTP header value');
  }
}

/**
 * Throw a descriptive (value-free) Error if `value` could not be injected cleanly
 * under `injection`. `topPlaceholder` is the secret's top-level placeholder
 * (SecretMeta.placeholder), which inject.ts also uses as a search needle.
 */
export function assertInjectableSecret(value: string, injection?: InjectionSpec, topPlaceholder?: string): void {
  if (!value) throw new Error('secret value must not be empty');
  // A lone surrogate is never a real credential and makes encodeURIComponent throw
  // (query mode) — reject it in every mode up front.
  if (hasLoneSurrogate(value)) {
    throw new Error('secret value must not contain unpaired surrogate code units');
  }
  // The placeholder(s) are search needles, not injected bytes; a control char in
  // one can never match a normal request, so reject it so a mis-set placeholder
  // fails loudly at write time instead of silently never injecting.
  if (topPlaceholder && CTRL_RE.test(topPlaceholder)) {
    throw new Error('placeholder must not contain control characters');
  }
  if (!injection) return;
  if (injection.placeholder && CTRL_RE.test(injection.placeholder)) {
    throw new Error('injection placeholder must not contain control characters');
  }

  if (injection.mode === 'header') {
    const name = injection.header || 'Authorization';
    if (!HEADER_TOKEN_RE.test(name)) throw new Error(`invalid injection header name: '${name}'`);
    assertHeaderValueSafe(value, injection.valueTemplate);
  } else if (injection.mode === 'placeholder') {
    // The placeholder can land in a header (inject.ts replaces it in headers AND
    // body), so the value MUST be a valid header value even when injectInBody is
    // set — a newline here would be a header-injection vector.
    assertHeaderValueSafe(value, injection.valueTemplate);
  } else if (injection.mode === 'query') {
    if (injection.queryParam && CTRL_RE.test(injection.queryParam)) {
      throw new Error('query param name must not contain control characters');
    }
    // The value is percent-encoded, so any (surrogate-free) value is safe on the wire.
  }
}
