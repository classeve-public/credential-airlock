/**
 * HTTP token / header character classes — a ZERO-import leaf module so both the
 * proxy (response-header-name scrub gate) and the set-time secret validator can
 * share one definition and never drift. Keep it dependency-free to avoid import
 * cycles (runtime -> proxy -> ... and vault -> validator both reach this).
 */

/** RFC 7230 header field-name token (the only legal characters in a header name). */
export const HEADER_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * Characters Node's http layer REJECTS in an outgoing header VALUE. Node throws
 * ERR_INVALID_CHAR for any character that is not a TAB and not in 0x20–0x7e or
 * 0x80–0xff — i.e. CR, LF, NUL, the other C0 controls, DEL (0x7f), and any code
 * unit > 0xFF. A secret destined for a header value/template must contain none of
 * these or `http.request` throws at forward time (sealing an undeliverable, and
 * potentially CRLF-smuggling, credential).
 */
export const INVALID_HEADER_VALUE_RE = /[^\t\x20-\x7e\x80-\xff]/;
