use grep_regex::RegexMatcher;
use std::io::{IsTerminal, Write};

#[cfg(test)]
use crate::matcher::build_matcher;
#[cfg(test)]
use crate::{emit_text_row, emit_text_row_colored, render_buffered_text};

/// --color target state (ColorOut): auto (default), always, never, plus ansi
/// as an rg-compatible alias for always. auto colorizes only when stdout is
/// a TTY. Color applies to `--format text` match spans only; JSON stays
/// machine-clean. GREP_COLORS is parked (not honored): match style is fixed
/// bold-red, byte-probed on rg 15.1.0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ColorWhen {
    Auto,
    Always,
    Never,
}

/// Parse a `--color` value; None means usage error (exit 2 at the call site).
/// `ansi` is an rg-compatible alias for `always`.
pub(crate) fn parse_color_when(s: &str) -> Option<ColorWhen> {
    match s {
        "auto" => Some(ColorWhen::Auto),
        "always" | "ansi" => Some(ColorWhen::Always),
        "never" => Some(ColorWhen::Never),
        _ => None,
    }
}

/// Resolve color for this process. Explicit always wins everywhere (even
/// piped); never wins nowhere; auto follows the stdout TTY only.
pub(crate) fn color_enabled(when: ColorWhen) -> bool {
    match when {
        ColorWhen::Always => true,
        ColorWhen::Never => false,
        ColorWhen::Auto => std::io::stdout().is_terminal(),
    }
}
/// Wrap each non-empty matcher span in `text` with rg's match style
/// (`\x1b[0m\x1b[1m\x1b[31m` … `\x1b[0m`). Zero-width matches are skipped so
/// patterns like `x*` never spray codes; a line with no spans borrows back
/// unchanged. Byte splicing is safe: regex spans are char-boundary aligned.
pub(crate) fn colorize_spans<'a>(
    text: &'a str,
    matcher: &RegexMatcher,
) -> std::borrow::Cow<'a, str> {
    use grep_matcher::Matcher;
    let b = text.as_bytes();
    let mut spans: Vec<(usize, usize)> = vec![];
    let _ = matcher.find_iter(b, |m| {
        if m.start() < m.end() {
            spans.push((m.start(), m.end()));
        }
        true
    });
    if spans.is_empty() {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = Vec::with_capacity(b.len() + spans.len() * 16);
    let mut pos = 0usize;
    for (s, e) in spans {
        out.extend_from_slice(&b[pos..s]);
        out.extend_from_slice(b"\x1b[0m\x1b[1m\x1b[31m");
        out.extend_from_slice(&b[s..e]);
        out.extend_from_slice(b"\x1b[0m");
        pos = e;
    }
    out.extend_from_slice(&b[pos..]);
    // Spans are char-boundary aligned and SGR inserts are ASCII, so the
    // splice stays valid UTF-8 by construction; loud panic if broken.
    std::borrow::Cow::Owned(String::from_utf8(out).expect("colorize splice must stay UTF-8"))
}

pub(crate) const USAGE: &str = "usage: nkg index <path> [--index FILE]\n       nkg serve --index FILE --port PORT\n       nkg [-i] [-v] [-w] [-F] [-m N] [-e PAT] [-f FILE] [-q] [-c] [-l] [-./--hidden] [--no-ignore] [-L/--follow] [-g/--glob GLOB] [-d/--max-depth N] [--max-filesize N] [-A N] [-B N] [-C N] [--group-separator SEP] [--top N] [--format json|text] [--color[=WHEN]] [--stats] [--use-index FILE | --port PORT] [--] <pattern> [path]\n";

pub(crate) fn usage() -> ! {
    eprint!("{USAGE}");
    std::process::exit(2);
}

/// `--help` text (stdout, exit 0). Usage errors still go through `usage()`
/// (stderr, exit 2). Write errors are ignored: help under a closed pipe
/// simply ends the process.
pub(crate) fn print_help() {
    let head = concat!(
        "nkg ",
        env!("CARGO_PKG_VERSION"),
        " — ranked trigram code search\n",
    );
    let opts = concat!(
        "options:\n",
        "  -i, --ignore-case  case-insensitive match\n",
        "  -q, --quiet        suppress stdout, stop at first match\n",
        "  --silent           alias for --quiet\n",
        "  -                  read (standard input) instead of [path]\n",
        "                     (no [path]: search . when stdin is a terminal,\n",
        "                      else search stdin as one unit)\n",
        "  -c, --count        path:count per matching file, path-sorted\n",
        "  -l, --files-with-matches\n",
        "  --stats           print the query plan and candidate counts to\n",
        "                     stderr (indexed searches only)\n",
        "  -m, --max-count N  cap matching lines per file at N (0 matches\n",
        "                     nothing; -c prints capped counts; applies\n",
        "                     per-file before --top; -m2 attached also works)\n",
        "  -e, --regexp PAT   search pattern, OR (repeatable; an inline flag\n",
        "                     like (?i) stays scoped to its pattern; any -e/-f\n",
        "                     makes every positional a path)\n",
        "  -f, --file FILE    patterns from FILE, one per line (repeatable;\n",
        "                     empty line matches every line; - reads stdin;\n",
        "                     missing file exits 2)\n",
        "  -F, --fixed-strings\n",
        "                     treat all patterns literally\n",
        "  -v, --invert-match select non-matching lines (forces full scan\n",
        "                     under --use-index)\n",
        "  -w, --word-regexp  word-boundary match (Unicode word chars)\n",
        "                     (short no-arg flags combine: any cluster of only\n",
        "                     i q c l F v w letters sums its letters)\n",
        "  --no-pcre2, --no-encoding  no-ops: the default engine already satisfies them\n",
        "  --format json|text output rendering (default json; text emits\n",
        "                     path:line:text in rank order — same hits, same\n",
        "                     order as json, no score; ignored under -c/-l/-q)\n",
        "  --color[=WHEN]     highlight match spans in --format text (default auto:\n",
        "                     colorize only when stdout is a tty; always/never force\n",
        "                     or suppress; ansi aliases always; json stays clean;\n",
        "                     GREP_COLORS not honored; --color WHEN consumes WHEN\n",
        "                     when valid, else WHEN is searched as the pattern)\n",
        "  -., --hidden       search hidden files and directories\n",
        "  --no-hidden        cancel --hidden (hidden files skipped by default)\n",
        "  --no-ignore        skip .gitignore/.ignore/.rgignore/exclude files\n",
        "  -L, --follow       follow symbolic links\n",
        "  --no-follow        cancel --follow (symlinks unfollowed by default)\n",
        "  -g, --glob GLOB    include/exclude paths, gitignore-style (repeatable;\n",
        "                     leading ! excludes, neg-only keeps the rest;\n",
        "                     -gGLOB attached also works)\n",
        "  -d, --max-depth N  limit directory traversal depth (-d2 attached also works)\n",
        "  --max-filesize N   skip files larger than N bytes (K/M/G suffixes)\n",
        "  -A, --after-context N\n",
        "                     print N lines after each match (`-A2` also works)\n",
        "  -B, --before-context N\n",
        "                     print N lines before each match (`-B2` also works)\n",
        "  -C, --context N    print N lines around each match (`-C1` also works;\n",
        "                     an explicit -A/-B beats -C on its side)\n",
        "  --group-separator SEP\n",
        "                     separator between disjoint context groups in one\n",
        "                     file (default `--`; empty prints none)\n",
        "  --top N            print only the top N ranked matches\n",
        "  --use-index FILE   load this index file for the query, consulting the\n",
        "                     daemon registered for it first and falling back to a\n",
        "                     local index load when the server is unreachable\n",
        "  --port PORT        query the daemon on PORT instead of searching locally\n",
        "  --                 end the flag scan, so a pattern beginning with -\n",
        "                     is searched literally\n",
        "  --index FILE       for index and serve, use FILE as the index file\n",
        "                     (default: .nkg.bin)\n",
        "  -h, --help         print help to stdout and exit 0\n",
        "  -V, --version      print the version to stdout and exit 0\n",
    );
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    let _ = w.write_all(head.as_bytes());
    let _ = w.write_all(USAGE.as_bytes());
    let _ = w.write_all(opts.as_bytes());
    let _ = w.flush();
}

/// `--version` (stdout, exit 0); same closed-pipe tolerance as help.
pub(crate) fn print_version() {
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    let _ = writeln!(w, "nkg {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod color_tests {
    use super::*;

    fn lit(pat: &str) -> RegexMatcher {
        build_matcher(pat, false).unwrap()
    }

    #[test]
    fn parse_when_values() {
        assert_eq!(parse_color_when("auto"), Some(ColorWhen::Auto));
        assert_eq!(parse_color_when("always"), Some(ColorWhen::Always));
        assert_eq!(parse_color_when("never"), Some(ColorWhen::Never));
        assert_eq!(parse_color_when("ansi"), Some(ColorWhen::Always));
        assert_eq!(parse_color_when("bogus"), None);
        assert_eq!(parse_color_when(""), None);
        assert_eq!(parse_color_when("Always"), None);
    }

    #[test]
    fn enabled_explicit_wins() {
        assert!(color_enabled(ColorWhen::Always));
        assert!(!color_enabled(ColorWhen::Never));
        // Auto follows the TTY only — no assert (environment-dependent).
    }

    #[test]
    fn span_wrap_matches_rg_bytes() {
        // Exact SGR sequence byte-probed on rg 15.1.0 (`--color=always`).
        let m = lit("hello");
        assert_eq!(
            &*colorize_spans("hello world", &m),
            "\x1b[0m\x1b[1m\x1b[31mhello\x1b[0m world"
        );
    }

    #[test]
    fn no_match_borrows_back_verbatim() {
        let m = lit("zzz");
        let out = colorize_spans("hello world", &m);
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*out, "hello world");
    }

    #[test]
    fn zero_width_spans_skipped() {
        // `x*` matches empty everywhere: must emit no codes at all.
        let m = lit("x*");
        let out = colorize_spans("ab", &m);
        assert_eq!(&*out, "ab");
        assert!(!out.bytes().any(|b| b == 0x1b));
    }

    #[test]
    fn multi_span_all_wrapped() {
        let m = lit("o");
        assert_eq!(
            &*colorize_spans("foo boo", &m),
            "f\x1b[0m\x1b[1m\x1b[31mo\x1b[0m\x1b[0m\x1b[1m\x1b[31mo\x1b[0m b\x1b[0m\x1b[1m\x1b[31mo\x1b[0m\x1b[0m\x1b[1m\x1b[31mo\x1b[0m"
        );
    }

    #[test]
    fn colored_row_delegates_framing() {
        // Plain and colored rows share `path:line:` framing; only the text
        // span differs.
        let m = lit("needle");
        let mut plain = Vec::new();
        let mut colored = Vec::new();
        emit_text_row(&mut plain, "a.txt", 7, "a needle here");
        emit_text_row_colored(&mut colored, "a.txt", 7, "a needle here", &m);
        assert_eq!(&plain, b"a.txt:7:a needle here\n");
        assert_eq!(
            &colored,
            b"a.txt:7:a \x1b[0m\x1b[1m\x1b[31mneedle\x1b[0m here\n"
        );
    }

    #[test]
    fn serve_colored_mirrors_plain_shape() {
        // Same rows, same order through the streamed text renderer; only
        // spans wrapped.
        let raw = b"{\"path\":\"a.txt\",\"line\":1,\"text\":\"hi needle\"}\n\
                    {\"path\":\"b.txt\",\"line\":2,\"text\":\"no hit here\"}\n";
        let m = lit("needle");
        let plain = render_buffered_text(raw, None);
        let colored = render_buffered_text(raw, Some(&m));
        assert_eq!(&plain, b"a.txt:1:hi needle\nb.txt:2:no hit here\n");
        assert_eq!(
            &colored,
            b"a.txt:1:hi \x1b[0m\x1b[1m\x1b[31mneedle\x1b[0m\nb.txt:2:no hit here\n"
        );
    }
}
