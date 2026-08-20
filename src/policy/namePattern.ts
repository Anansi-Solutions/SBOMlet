/**
 * The package-name pattern dialect: one compiler, shared by every policy surface that covers a
 * FAMILY of packages by name.
 *
 * `*` fills the rest of one name segment (any run of non-slash characters), `**` reaches across
 * segment boundaries, and a trailing slash is shorthand for the whole scope beneath it (`@cspell/`
 * compiles as `@cspell/**`). Every other character matches literally and the whole name must match.
 * Patterns select a package's canonical DISPLAY name (`@img/sharp-wasm32`), never its purl.
 *
 * Matching is CASE-SENSITIVE. The similarly shaped exclude-glob compiler in target discovery is
 * deliberately case-INsensitive because it matches paths on a case-insensitive filesystem; package
 * names are case-distinct registry identifiers, so the two compilers stay separate.
 */

/** Characters that must be escaped to match literally inside a RegExp. */
const REGEX_SPECIALS = new Set("\\^$.|?+()[]{}");

/**
 * True when the pattern carries a character that can anchor it: anything other than a wildcard, a
 * segment separator, or whitespace.
 */
function hasAnchoringLiteral(pattern: string): boolean {
  return [...pattern].some((ch) => ch !== "*" && ch !== "/" && ch.trim() !== "");
}

/**
 * True when the string uses the dialect, through a `*` wildcard or the trailing-slash scope form,
 * rather than naming one package literally.
 */
export function isGlobPattern(value: string): boolean {
  return value.includes("*") || value.endsWith("/");
}

/**
 * Compile one pattern into an anchored, case-sensitive RegExp over a package display name.
 *
 * @throws Error when nothing in the pattern anchors it. A pattern of wildcards and separators alone
 * would cover every package in the model, turning one line into a blanket acceptance, so it is
 * refused instead of compiled.
 */
export function compileNamePattern(pattern: string): RegExp {
  if (!hasAnchoringLiteral(pattern)) {
    throw new Error(
      `pattern "${pattern}" must contain at least one literal character (a wildcard-only pattern would cover every package)`,
    );
  }

  const glob = pattern.endsWith("/") ? `${pattern}**` : pattern;
  let source = "";
  let index = 0;

  while (index < glob.length) {
    if (glob.startsWith("**", index)) {
      source += ".*";
      index += 2;
    } else if (glob[index] === "*") {
      source += "[^/]*";
      index += 1;
    } else {
      const ch = glob[index] as string;

      source += REGEX_SPECIALS.has(ch) ? `\\${ch}` : ch;
      index += 1;
    }
  }

  return new RegExp(`^${source}$`);
}
