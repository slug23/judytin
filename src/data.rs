//! The data/code boundary.
//!
//! A MUD client's most dangerous moment is the one where text the *server*
//! sent becomes text the *client* executes. A trigger like
//!
//! ```text
//! #action {%1 tells you %2} {tell %1 got it}
//! ```
//!
//! captures server text into `%1` and puts it inside a command. If that
//! capture is spliced in as plain text and the result is parsed again, a
//! hostile server sends `Bob;#system rm -rf ~ tells you hi` and the client
//! obediently runs it. This is the same bug as SQL injection, and it has
//! the same real fix: never let data cross back into the grammar.
//!
//! The discipline, in three rules:
//!
//! 1. **Escape at the source.** Text arriving from the server is escaped
//!    the moment it enters a script (see [`escape`]) — at trigger captures
//!    and event arguments, the only two doors it has.
//! 2. **Preserve in the middle.** Every parser — the `;` splitter, the `{}`
//!    argument reader, `$variable` and `@function` substitution — copies an
//!    escape sequence through untouched and never acts on the character it
//!    protects. Data can therefore pass through any number of expansion
//!    layers (alias into function into `#delay` body) without ever becoming
//!    syntax.
//! 3. **Unescape only at sinks.** The line sent to the MUD, text printed to
//!    the screen, a filename, an expression to evaluate — these are the
//!    ends of the road, where the bytes stop being a program and become a
//!    value. [`unescape`] runs exactly once, there.
//!
//! Escaping a fixed set of metacharacters is not the security property; the
//! *direction of failure* is. A metacharacter we forgot to escape shows up
//! as a visible stray backslash on screen, not as a shell command. That is
//! why this is a whitelist of characters the escape survives and a single
//! chokepoint for removing it, rather than a blocklist of dangerous input.
//!
//! [`escape`] is deliberately aggressive: it escapes every character that
//! carries meaning anywhere in the language, not merely the ones dangerous
//! in the position the data happens to land in, because that position can
//! change as the text is re-expanded.

/// Characters that mean something to some parser in this client.
///
/// `\` first, because escaping it must not double-escape the rest.
/// `%` is included because captures can be expanded more than once and a
/// literal `%1` arriving from the server must not become a capture slot.
/// `"` is included because the expression language quotes strings with it,
/// and data that can close its own quote can rewrite the comparison around
/// it — enough to steer a scripted decision even without running anything.
/// `[` and `]` are here because `$var[key]` made them syntax. Before that they
/// were ordinary text; now a `]` arriving from a server could close a subscript
/// the player opened, so they escape like every other metacharacter. Note that
/// ANSI sequences contain `[` and reach here through RECEIVED LINE — escaping
/// and unescaping round-trips them, which is why the sink rule matters.
const META: &[char] = &['\\', ';', '{', '}', '$', '@', '#', '%', '"', '[', ']'];

/// Escape server-derived text so no parser downstream reads it as syntax.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if META.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Remove one layer of escaping, at a sink.
///
/// Only sequences this module produces are unescaped: `\;` becomes `;`,
/// while `\n` (or any other non-meta pair) is left alone, so an ordinary
/// Windows path typed by the user survives being sent to the MUD.
pub fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(next) if META.contains(&next) => out.push(next),
            Some(next) => {
                out.push('\\');
                out.push(next);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// True if the text carries no unescaped metacharacter — i.e. running it
/// through a parser cannot produce syntax. Used by tests and by the
/// belt-and-braces check in the trigger path.
#[cfg(test)]
pub fn is_inert(text: &str) -> bool {
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            chars.next();
            continue;
        }
        if META.contains(&c) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_expression_quote() {
        // `#if {"$mob" == "dragon"}` must stay one comparison however
        // hostile $mob is.
        assert_eq!(escape(r#"x" == "x" || ""#), r#"x\" == \"x\" || \""#);
    }

    #[test]
    fn escapes_every_metacharacter() {
        assert_eq!(escape("a;b"), r"a\;b");
        assert_eq!(escape("#system"), r"\#system");
        assert_eq!(escape("${x}"), r"\$\{x\}");
        assert_eq!(escape("@f{}"), r"\@f\{\}");
        assert_eq!(escape("%1"), r"\%1");
        assert_eq!(escape(r"a\b"), r"a\\b");
    }

    #[test]
    fn round_trips() {
        for original in [
            "plain text",
            "a;b",
            "#system rm -rf /",
            r"a\;b",
            "${var}@fn{}%9",
            r"C:\path\to\thing",
            "",
            "…unicode ✓ ök",
        ] {
            assert_eq!(unescape(&escape(original)), original, "round trip: {original}");
        }
    }

    #[test]
    fn unescape_leaves_unknown_pairs_alone() {
        // A user typing a Windows path must not have it mangled.
        assert_eq!(unescape(r"C:\path\to"), r"C:\path\to");
        assert_eq!(unescape(r"\n is not a newline here"), r"\n is not a newline here");
        assert_eq!(unescape(r"trailing \"), r"trailing \");
    }

    #[test]
    fn escaped_text_is_inert() {
        for hostile in [
            "Bob;#system touch /tmp/pwned",
            "x};#run {evil}",
            "$HOME @f{} %0",
            r"already\;escaped",
        ] {
            assert!(is_inert(&escape(hostile)), "not inert: {hostile}");
        }
        assert!(!is_inert("a;b"));
        assert!(is_inert(r"a\;b"));
    }

    #[test]
    fn escaping_is_idempotent_under_round_trip() {
        // Data that passes through two expansion layers is escaped twice and
        // unescaped twice; it must arrive intact, not half-eaten.
        let original = "Bob;#system rm";
        let twice = escape(&escape(original));
        assert_eq!(unescape(&unescape(&twice)), original);
    }
}
