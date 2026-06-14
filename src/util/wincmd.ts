/**
 * Windows command-line construction for spawning .cmd/.bat shims via the shell
 * WITHOUT Node's deprecated shell-with-args path (DEP0190).
 *
 * When `shell: true` on Windows, Node concatenates the args array unescaped,
 * which is the footgun DEP0190 warns about. Instead we build a single, correctly
 * MSVCRT-quoted command line and pass it as the lone command string with
 * `shell: true`. The quoting follows the standard CommandLineToArgvW rules that
 * cmd.exe and most programs use.
 *
 * cmd.exe also interprets its own metacharacters (& | < > ( ) ^) before the
 * program's argv parser runs. Inside double quotes cmd treats them as literal, so
 * we force quoting for any argument containing one — this keeps ordinary values
 * like a URL `?a=1&b=2` intact instead of being split into extra commands.
 *
 * KNOWN LIMITATIONS (Windows shell path only; arguments are operator-configured,
 * NOT adversary-controlled — see docs/THREAT-MODEL.md, so these are correctness
 * limits, not a privilege boundary):
 *   - An argument containing BOTH a literal double-quote AND a cmd metacharacter
 *     is not fully neutralized: the embedded quote desyncs cmd's quote-parity,
 *     after which a following metacharacter may be interpreted by cmd. (Metachars
 *     WITHOUT an embedded quote are correctly neutralized by the forced quoting.)
 *   - A literal `%NAME%` is subject to cmd environment expansion even inside
 *     quotes; `%` has no reliable `cmd /c` escape.
 * Avoid `"`+metacharacter combinations and literal `%NAME%` in agent arguments on
 * Windows, or run the agent on a non-Windows host (no shell is used there). The
 * fully general fix is to spawn cmd.exe directly with windowsVerbatimArguments
 * (the cross-spawn approach); deferred to keep the common .cmd-shim path robust.
 */

/** Quote a single argument per the MSVCRT/CommandLineToArgvW convention. */
export function quoteWinArg(arg: string): string {
  // Quote if empty, or if it contains whitespace, a quote, or a cmd.exe
  // metacharacter (neutralized by being inside the double quotes).
  if (arg.length > 0 && !/[ \t\n\v"&|<>()^%]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === '\\') {
      backslashes++;
    } else if (ch === '"') {
      // Escape all pending backslashes (they precede a quote) plus this quote.
      out += '\\'.repeat(backslashes * 2 + 1) + '"';
      backslashes = 0;
    } else {
      out += '\\'.repeat(backslashes) + ch;
      backslashes = 0;
    }
  }
  // Trailing backslashes precede the closing quote, so double them.
  out += '\\'.repeat(backslashes * 2) + '"';
  return out;
}

/** Build a single shell command line from a command + args (Windows). */
export function winCommandLine(command: string, args: string[]): string {
  return [command, ...args].map(quoteWinArg).join(' ');
}
