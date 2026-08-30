//! TinTin++-style pattern matching.
//!
//! Supported, following the tt++ PCRE section:
//! - `%1`..`%99` numbered captures (lazy; a trailing one takes the rest)
//! - character classes, all lazy and capturing: `%w`/`%W` word/non-word,
//!   `%d`/`%D` digit/non-digit, `%s`/`%S` space/non-space, `%a` any, `%*`
//!   any-but-newline, `%+` one or more, `%?` zero or one, `%.` exactly one
//! - `%i` / `%I` switch to case-insensitive / sensitive from that point
//! - `^` start anchor, `$` end anchor, `%%` literal percent
//! - `{regex}` embeds a real regular expression, capturing like a wildcard
//!
//! The embedded regex is compiled by the `regex` crate, chosen for its
//! linear-time guarantee: the subject is a line a stranger sent, and a
//! backtracking engine there is a denial of service waiting to be written into
//! somebody's trigger. `\{` is still a literal brace.
//!
//! Unnumbered wildcards are assigned the next free capture index in order
//! of appearance, so they can be used as %1, %2, ... in trigger bodies.

#[derive(Debug, Clone, Copy, PartialEq)]
enum Class {
    Any,      // %a and %* (we match single lines, so they coincide)
    Word,     // %w
    NonWord,  // %W
    Digit,    // %d
    NonDigit, // %D
    Space,    // %s
    NonSpace, // %S
    OnePlus,  // %+  one or more of anything
    ZeroOne,  // %?  zero or one of anything
    One,      // %.  exactly one of anything
}

impl Class {
    fn accepts(self, c: char) -> bool {
        match self {
            Class::Any | Class::OnePlus | Class::ZeroOne | Class::One => true,
            Class::Word => c.is_alphanumeric() || c == '_',
            Class::NonWord => !(c.is_alphanumeric() || c == '_'),
            Class::Digit => c.is_ascii_digit(),
            Class::NonDigit => !c.is_ascii_digit(),
            Class::Space => c.is_whitespace(),
            Class::NonSpace => !c.is_whitespace(),
        }
    }

    fn min_len(self) -> usize {
        match self {
            Class::OnePlus | Class::One => 1,
            _ => 0,
        }
    }

    fn max_len(self) -> usize {
        match self {
            Class::One | Class::ZeroOne => 1,
            _ => usize::MAX,
        }
    }
}

#[derive(Debug, Clone)]
enum Tok {
    Lit(String),
    Wild(Class, u8),
    /// An embedded regular expression, capturing into `n` like a wildcard.
    Re(Box<Re>),
    CaseInsensitive,
    CaseSensitive,
}

/// A compiled `{regex}` group.
///
/// Two forms of the same expression: `head` anchored at the start finds the
/// span the regex would naturally take, which is the answer almost every time;
/// `exact` is anchored at both ends so a span can be tested when the rest of
/// the pattern fails and the match has to give ground.
#[derive(Debug, Clone)]
struct Re {
    head: regex::Regex,
    exact: regex::Regex,
    n: u8,
    /// The source text, for equality and for debugging.
    src: String,
}

// Regex has no PartialEq, and comparing compiled programs is not the question
// anyone is asking: two tokens are the same when they came from the same text.
impl PartialEq for Tok {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Tok::Lit(a), Tok::Lit(b)) => a == b,
            (Tok::Wild(a, i), Tok::Wild(b, j)) => a == b && i == j,
            (Tok::Re(a), Tok::Re(b)) => a.src == b.src && a.n == b.n,
            (Tok::CaseInsensitive, Tok::CaseInsensitive) => true,
            (Tok::CaseSensitive, Tok::CaseSensitive) => true,
            _ => false,
        }
    }
}

/// Compiled size cap. Patterns are written by the player, not the server, so
/// this is a guard against a slip rather than an attack — but an unbounded
/// compile is still a way to lose a client to a typo.
const RE_SIZE_LIMIT: usize = 1 << 20;

/// What scanning `len` bytes costs against the budget. Divided so that an
/// ordinary MUD line stays nearly free while a flood cannot be scanned over
/// and over for nothing.
fn scan_cost(len: usize) -> u64 {
    (len as u64 / 16) + 1
}

/// Build both forms. `(?s)` because judytin matches one line at a time and a
/// `.` that refuses newlines would only surprise people.
fn compile_re(src: &str, n: u8) -> Option<Re> {
    let build = |wrapped: String| {
        regex::RegexBuilder::new(&wrapped)
            .size_limit(RE_SIZE_LIMIT)
            .dot_matches_new_line(true)
            .build()
            .ok()
    };
    Some(Re {
        head: build(format!("^(?:{})", src))?,
        exact: build(format!("^(?:{})$", src))?,
        n,
        src: src.to_string(),
    })
}

#[derive(Debug, Clone)]
pub struct Pattern {
    anchored_start: bool,
    anchored_end: bool,
    toks: Vec<Tok>,
}

pub fn compile(pat: &str) -> Pattern {
    let mut s = pat;
    let anchored_start = s.starts_with('^');
    if anchored_start {
        s = &s[1..];
    }
    let anchored_end = s.ends_with('$') && !s.ends_with("%$") && !s.ends_with("\\$");
    if anchored_end {
        s = &s[..s.len() - 1];
    }
    let mut toks = Vec::new();
    let mut lit = String::new();
    let mut next_idx: u8 = 1;
    let mut used: Vec<u8> = Vec::new();
    let mut chars = s.chars().peekable();

    let flush = |lit: &mut String, toks: &mut Vec<Tok>| {
        if !lit.is_empty() {
            toks.push(Tok::Lit(std::mem::take(lit)));
        }
    };
    let alloc = |used: &mut Vec<u8>, next_idx: &mut u8| -> u8 {
        while used.contains(next_idx) && *next_idx < 99 {
            *next_idx += 1;
        }
        let n = *next_idx;
        used.push(n);
        n
    };

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&n) = chars.peek() {
                chars.next();
                lit.push(n);
            } else {
                lit.push('\\');
            }
            continue;
        }
        if c == '{' {
            // Brace depth, because a regex quantifier is written {2,3}. An
            // escaped brace was already consumed above as a literal.
            let mut depth = 1usize;
            let mut src = String::new();
            let mut closed = false;
            while let Some(n) = chars.next() {
                if n == '\\' {
                    src.push('\\');
                    if let Some(e) = chars.next() {
                        src.push(e);
                    }
                    continue;
                }
                if n == '{' {
                    depth += 1;
                } else if n == '}' {
                    depth -= 1;
                    if depth == 0 {
                        closed = true;
                        break;
                    }
                }
                src.push(n);
            }
            // An unclosed group, or one the regex engine will not accept, is
            // treated as the literal text it was before this feature existed.
            // Silently never matching would be a worse answer than the old one.
            match closed.then(|| compile_re(&src, 0)).flatten() {
                Some(mut re) => {
                    re.n = alloc(&mut used, &mut next_idx);
                    flush(&mut lit, &mut toks);
                    toks.push(Tok::Re(Box::new(re)));
                }
                None => {
                    lit.push('{');
                    lit.push_str(&src);
                    if closed {
                        lit.push('}');
                    }
                }
            }
            continue;
        }
        if c != '%' {
            lit.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('%') => {
                chars.next();
                lit.push('%');
            }
            Some(d) if d.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(d) = chars.peek() {
                    if d.is_ascii_digit() && num.len() < 2 {
                        num.push(*d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let n: u8 = num.parse().unwrap_or(0);
                used.push(n);
                flush(&mut lit, &mut toks);
                toks.push(Tok::Wild(Class::Any, n));
            }
            Some(k) => {
                let class = match k {
                    'w' => Some(Class::Word),
                    'W' => Some(Class::NonWord),
                    'd' => Some(Class::Digit),
                    'D' => Some(Class::NonDigit),
                    's' => Some(Class::Space),
                    'S' => Some(Class::NonSpace),
                    'a' | '*' => Some(Class::Any),
                    '+' => Some(Class::OnePlus),
                    '?' => Some(Class::ZeroOne),
                    '.' => Some(Class::One),
                    _ => None,
                };
                if let Some(class) = class {
                    chars.next();
                    flush(&mut lit, &mut toks);
                    let n = alloc(&mut used, &mut next_idx);
                    toks.push(Tok::Wild(class, n));
                } else if k == 'i' {
                    chars.next();
                    flush(&mut lit, &mut toks);
                    toks.push(Tok::CaseInsensitive);
                } else if k == 'I' {
                    chars.next();
                    flush(&mut lit, &mut toks);
                    toks.push(Tok::CaseSensitive);
                } else {
                    lit.push('%');
                }
            }
            None => lit.push('%'),
        }
    }
    if !lit.is_empty() {
        toks.push(Tok::Lit(lit));
    }
    Pattern { anchored_start, anchored_end, toks }
}

/// A successful match: span start and end (byte offsets in the line) plus
/// the captured wildcards in pattern order.
pub type Match = (usize, usize, Vec<(u8, String)>);

struct Ctx {
    anchored_end: bool,
    /// Remaining match attempts. Backtracking over wildcards costs more
    /// than linear in the line length, and the event loop is
    /// single-threaded, so an unbounded search lets one padded line from a
    /// hostile server freeze the client — including its ability to quit.
    /// Running out means "no match", which is the safe answer: a trigger
    /// that does not fire cannot do anything.
    budget: std::cell::Cell<u64>,
}

/// Generous next to any real MUD line (a full-width line of prose costs a
/// few thousand), small enough that the worst case stays imperceptible.
const MATCH_BUDGET: u64 = 250_000;

impl Ctx {
    /// Charge one unit of work; false once the budget is spent.
    fn charge(&self) -> bool {
        self.charge_n(1)
    }

    /// Charge `n` units.
    ///
    /// A wildcard step is one unit because it inspects one character. A regex
    /// call is not: it scans the whole span it is given, so charging it one
    /// unit lets a long line buy an unbounded amount of work for nothing. The
    /// divisor keeps a regex from looking more expensive than it is while
    /// still making the cost scale with the text.
    fn charge_n(&self, n: u64) -> bool {
        let left = self.budget.get();
        if left < n {
            self.budget.set(0);
            return false;
        }
        self.budget.set(left - n);
        true
    }
}

/// Match `line` against the pattern. On success returns the matched span
/// (byte range in `line`) and the captured wildcards in pattern order.
pub fn find(pat: &Pattern, line: &str) -> Option<Match> {
    let starts: Vec<usize> = if pat.anchored_start {
        vec![0]
    } else {
        let mut v: Vec<usize> = line.char_indices().map(|(i, _)| i).collect();
        v.push(line.len());
        v
    };
    let ctx = Ctx {
        anchored_end: pat.anchored_end,
        budget: std::cell::Cell::new(MATCH_BUDGET),
    };
    for start in starts {
        let mut caps = Vec::new();
        if let Some(consumed) = match_toks(&ctx, &pat.toks, &line[start..], false, &mut caps) {
            return Some((start, start + consumed, caps));
        }
        if ctx.budget.get() == 0 {
            return None; // gave up rather than hang
        }
    }
    None
}

fn lit_strip<'a>(rest: &'a str, lit: &str, ci: bool) -> Option<&'a str> {
    if !ci {
        return rest.strip_prefix(lit);
    }
    let mut r = rest.chars();
    for lc in lit.chars() {
        let rc = r.next()?;
        if !rc.eq_ignore_ascii_case(&lc)
            && rc.to_lowercase().to_string() != lc.to_lowercase().to_string()
        {
            return None;
        }
    }
    Some(r.as_str())
}

/// Returns bytes of `rest` consumed on success.
fn match_toks(
    ctx: &Ctx,
    toks: &[Tok],
    rest: &str,
    ci: bool,
    caps: &mut Vec<(u8, String)>,
) -> Option<usize> {
    match toks.first() {
        None => {
            if ctx.anchored_end && !rest.is_empty() {
                None
            } else {
                Some(0)
            }
        }
        Some(Tok::CaseInsensitive) => match_toks(ctx, &toks[1..], rest, true, caps),
        Some(Tok::CaseSensitive) => match_toks(ctx, &toks[1..], rest, false, caps),
        Some(Tok::Lit(s)) => {
            let r = lit_strip(rest, s, ci)?;
            match_toks(ctx, &toks[1..], r, ci, caps).map(|c| c + (rest.len() - r.len()))
        }
        Some(Tok::Re(re)) => {
            // The span the regex takes on its own terms — greedy or lazy as
            // the author wrote it — is tried first, because it is the answer
            // whenever the rest of the pattern agrees.
            // Scanning `rest` costs about `rest.len()`; see `charge_n`.
            if !ctx.charge_n(scan_cost(rest.len())) {
                return None;
            }
            let natural = re.head.find(rest).map(|m| m.end());
            let mut tried = None;
            if let Some(end) = natural
                && ctx.charge()
            {
                let mark = caps.len();
                caps.push((re.n, rest[..end].to_string()));
                if let Some(c) = match_toks(ctx, &toks[1..], &rest[end..], ci, caps) {
                    return Some(end + c);
                }
                caps.truncate(mark);
                tried = Some(end);
            }
            // It did not, so give ground: any shorter span the regex also
            // accepts exactly. Longest first, so a greedy group stays greedy.
            //
            // Iterated rather than collected: `rest` is a line a stranger sent,
            // and materialising one entry per character would hand them a
            // megabyte of allocation per attempt before the budget below ever
            // got a chance to say no.
            let ends = std::iter::once(rest.len())
                .chain(rest.char_indices().rev().map(|(i, _)| i));
            for end in ends {
                if Some(end) == tried {
                    continue;
                }
                if !ctx.charge_n(scan_cost(end)) {
                    return None;
                }
                if !re.exact.is_match(&rest[..end]) {
                    continue;
                }
                let mark = caps.len();
                caps.push((re.n, rest[..end].to_string()));
                if let Some(c) = match_toks(ctx, &toks[1..], &rest[end..], ci, caps) {
                    return Some(end + c);
                }
                caps.truncate(mark);
            }
            None
        }
        Some(Tok::Wild(class, n)) => {
            let last = toks[1..]
                .iter()
                .all(|t| matches!(t, Tok::CaseInsensitive | Tok::CaseSensitive));
            // candidate split points within the class run
            let mut splits: Vec<usize> = vec![0];
            for (nchars, (i, c)) in rest.char_indices().enumerate() {
                if nchars >= class.max_len() || !class.accepts(c) {
                    break;
                }
                splits.push(i + c.len_utf8());
            }
            // lazy in the middle; greedy when the wildcard ends the pattern
            // (a trailing lazy capture would always be empty, which is
            // useless — tt++ users expect "kill %1" to take the rest)
            if last {
                splits.reverse();
            }
            for (idx, split) in splits.iter().copied().enumerate() {
                let nchars = if last { splits.len() - 1 - idx } else { idx };
                if nchars < class.min_len() {
                    continue;
                }
                if !ctx.charge() {
                    return None;
                }
                let mark = caps.len();
                caps.push((*n, rest[..split].to_string()));
                if let Some(c) = match_toks(ctx, &toks[1..], &rest[split..], ci, caps) {
                    return Some(split + c);
                }
                caps.truncate(mark);
            }
            None
        }
    }
}

/// Convenience: compile-and-match in one call, captures only.
pub fn matches(pattern: &str, line: &str) -> Option<Vec<(u8, String)>> {
    find(&compile(pattern), line).map(|(_, _, caps)| caps)
}

/// Full-string match, for tt++ string comparisons ("$x" == "{bli|bla}"):
/// top-level `|` alternation, wildcards allowed, whole string must match.
pub fn matches_full(pattern: &str, text: &str) -> bool {
    for alt in split_alternation(pattern) {
        let mut pat = String::with_capacity(alt.len() + 2);
        if !alt.starts_with('^') {
            pat.push('^');
        }
        pat.push_str(&alt);
        if !alt.ends_with('$') {
            pat.push('$');
        }
        if find(&compile(&pat), text).is_some() {
            return true;
        }
    }
    false
}

fn split_alternation(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    for c in pattern.chars() {
        match c {
            '{' => {
                depth += 1;
                if depth == 1 && cur.is_empty() {
                    continue; // outer brace wrapper
                }
                cur.push(c);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    continue;
                }
                cur.push(c);
            }
            '|' if depth <= 1 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Replace %0..%99 in `body` with captures, escaping each one as data.
///
/// This is the door server text walks through to reach a script, so it is
/// where rule 1 of the data discipline lives (see [`crate::data`]): the
/// captured text is escaped on the way in, and every parser downstream
/// preserves that escaping, so a capture can never become a command.
/// Use this for anything derived from the server — trigger captures, event
/// arguments. [`expand`] is the unescaped form, for user-authored text.
pub fn expand_data(body: &str, caps: &[(u8, String)], all: &str) -> String {
    let escaped: Vec<(u8, String)> = caps
        .iter()
        .map(|(i, text)| (*i, crate::data::escape(text)))
        .collect();
    expand(body, &escaped, &crate::data::escape(all))
}

/// Replace %0..%99 in `body` with captures. %0 defaults to `all` when the
/// matcher didn't bind it.
///
/// The captures are inserted verbatim, so this is only safe for text the
/// user authored (alias arguments they typed). For anything the server
/// influenced, use [`expand_data`].
pub fn expand(body: &str, caps: &[(u8, String)], all: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.peek() {
                Some('%') => {
                    chars.next();
                    out.push('%');
                }
                Some(d) if d.is_ascii_digit() => {
                    let mut num = String::new();
                    while let Some(d) = chars.peek() {
                        if d.is_ascii_digit() && num.len() < 2 {
                            num.push(*d);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    let idx: u8 = num.parse().unwrap_or(0);
                    if let Some((_, text)) = caps.iter().find(|(i, _)| *i == idx) {
                        out.push_str(text);
                    } else if idx == 0 {
                        out.push_str(all);
                    }
                }
                _ => out.push('%'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_substring() {
        assert!(matches("has arrived", "A goblin has arrived.").is_some());
        assert!(matches("has arrived", "nothing here").is_none());
    }

    #[test]
    fn anchored_both_ends() {
        assert!(matches("^You say", "You say 'hi'").is_some());
        assert!(matches("^You say", "Bob: You say things").is_none());
        assert!(matches("arrived.$", "A goblin has arrived.").is_some());
        assert!(matches("arrived.$", "A goblin has arrived. Twice").is_none());
    }

    #[test]
    fn wildcard_middle_and_trailing() {
        let caps = matches("%1 has arrived.", "A big goblin has arrived.").unwrap();
        assert_eq!(caps, vec![(1, "A big goblin".to_string())]);
        let caps = matches("You see %1", "You see a sword and a shield").unwrap();
        assert_eq!(caps[0].1, "a sword and a shield");
    }

    #[test]
    fn wildcard_lazy_between_literals() {
        let caps = matches("%1 tells you '%2'", "Bob tells you 'hello there'").unwrap();
        assert_eq!(caps[0], (1, "Bob".to_string()));
        assert_eq!(caps[1], (2, "hello there".to_string()));
    }

    #[test]
    fn class_digit_and_word() {
        let caps = matches("You have %d gold", "You have 4200 gold coins").unwrap();
        assert_eq!(caps[0].1, "4200");
        let caps = matches("^%w says", "Bob says hi").unwrap();
        assert_eq!(caps[0].1, "Bob");
        // %d refuses to eat letters
        assert!(matches("^%d gold$", "much gold").is_none());
    }

    #[test]
    fn class_nonspace() {
        let caps = matches("get %S from", "get sword-of-doom from chest").unwrap();
        assert_eq!(caps[0].1, "sword-of-doom");
    }

    #[test]
    fn class_one_and_zeroone() {
        let caps = matches("^ro%.m$", "room").unwrap();
        assert_eq!(caps[0].1, "o");
        assert!(matches("^ro%.m$", "rom").is_none());
        assert!(matches("^ro%?m$", "rom").is_some());
        assert!(matches("^ro%?m$", "room").is_some());
    }

    #[test]
    fn oneplus_requires_content() {
        assert!(matches("^a%+b$", "ab").is_none());
        let caps = matches("^a%+b$", "axyb").unwrap();
        assert_eq!(caps[0].1, "xy");
    }

    #[test]
    fn unnumbered_indexes_allocated_in_order() {
        let caps = matches("%w tells %w", "Bob tells Kim").unwrap();
        assert_eq!(caps[0], (1, "Bob".to_string()));
        assert_eq!(caps[1], (2, "Kim".to_string()));
    }

    #[test]
    fn case_insensitive_toggle() {
        assert!(matches("%iyou say", "YOU SAY hi").is_some());
        assert!(matches("you say", "YOU SAY hi").is_none());
        assert!(matches("%iYOU %Isay", "you SAY").is_none());
        assert!(matches("%iYOU %Isay", "you say").is_some());
        assert!(matches("%iYOU %ISAY", "you SAY").is_some());
    }

    #[test]
    fn percent_escape() {
        assert!(matches("100%% done", "task 100% done").is_some());
    }

    #[test]
    fn full_match_with_alternation() {
        assert!(matches_full("{bli|bla}", "bla"));
        assert!(!matches_full("{bli|bla}", "blab"));
        assert!(matches_full("bli", "bli"));
        assert!(matches_full("b%*i", "bloopi"));
        assert!(!matches_full("", "x"));
        assert!(matches_full("", ""));
    }

    #[test]
    fn find_reports_span() {
        let pat = compile("big %1 here");
        let (a, b, caps) = find(&pat, "one big goblin here now").unwrap();
        assert_eq!(&"one big goblin here now"[a..b], "big goblin here");
        assert_eq!(caps[0].1, "goblin");
    }

    #[test]
    fn an_embedded_regex_captures_like_a_wildcard() {
        let caps = matches("you hit the {\\w+} for {\\d+} damage", "you hit the goblin for 42 damage")
            .expect("should match");
        assert_eq!(caps, vec![(1, "goblin".to_string()), (2, "42".to_string())]);
    }

    #[test]
    fn a_quantifier_brace_does_not_end_the_group() {
        // {2,3} inside the regex is a quantifier, not the closing brace.
        let caps = matches("roll {[0-9]{1,2}}d", "roll 20d").expect("should match");
        assert_eq!(caps, vec![(1, "20".to_string())]);
        assert!(matches("roll {[0-9]{1,2}}d", "roll 200d").is_none());
    }

    #[test]
    fn a_regex_gives_ground_when_the_rest_needs_it() {
        // A greedy group would swallow the trailing literal; the match has to
        // back off to let "end" match, which a single greedy pass cannot do.
        let caps = matches("{.*}end", "beginning and end").expect("should match");
        assert_eq!(caps, vec![(1, "beginning and ".to_string())]);
    }

    #[test]
    fn regexes_and_wildcards_mix() {
        let caps = matches("%1 says {hello|hi}", "Bob says hi").expect("should match");
        assert_eq!(caps, vec![(1, "Bob".to_string()), (2, "hi".to_string())]);
    }

    #[test]
    fn an_escaped_brace_is_still_a_literal_brace() {
        assert!(matches(r"a \{literal\} brace", "a {literal} brace").is_some());
        // ...and the regex reading is not attempted on it.
        assert!(matches(r"a \{literal\} brace", "a x brace").is_none());
    }

    #[test]
    fn a_group_that_is_not_a_regex_stays_the_text_it_was() {
        // Before this feature braces in a pattern were ordinary characters.
        // An unclosed group, or one the engine rejects, must not silently
        // become a pattern that never matches.
        assert!(matches("say {unclosed", "say {unclosed").is_some());
        assert!(matches("nums {[0-9}", "nums {[0-9}").is_some());
    }

    #[test]
    fn a_regex_pattern_cannot_be_made_to_hang() {
        // The subject is a stranger's line. This is the shape that kills a
        // backtracking engine; the regex crate is linear, and the budget
        // catches the enumeration around it.
        let line = "a".repeat(40_000);
        let start = std::time::Instant::now();
        let _ = matches("{(a+)+$}b", &line);
        let _ = matches("{a*a*a*a*a*a*c}", &line);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "matching took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn expand_body() {
        let caps = vec![(1, "Bob".to_string()), (2, "hi".to_string())];
        assert_eq!(expand("say %2, %1! (%0)", &caps, "whole line"), "say hi, Bob! (whole line)");
    }
}
