//! Input parsing: the `;` command separator, `{}` argument grouping,
//! `$variable` substitution, and speedwalk detection.
//!
//! Every parser here obeys rule 2 of the data discipline in [`crate::data`]:
//! a backslash and the character after it are copied through verbatim and
//! never interpreted. That is what stops server-derived text — escaped at
//! the trigger boundary — from becoming syntax no matter how many layers of
//! expansion it passes through. The backslash is removed later, once, at a
//! sink.

#[cfg(test)]
use std::collections::BTreeMap;

/// Whether what has been read so far is a `#nop`, whose argument is prose.
///
/// Only the exact word: `#no` is an ambiguous abbreviation (`#nop`, `#north`)
/// and judytin would not resolve it either.
fn is_comment(cur: &str) -> bool {
    let t = cur.trim_start();
    let Some(rest) = t.strip_prefix('#') else { return false };
    let (word, after) = rest.split_at(rest.len().min(3));
    if !word.eq_ignore_ascii_case("nop") {
        return false;
    }
    // There has to be prose to protect. A bare `#nop` is the do-nothing
    // command and `#nop;look` means two commands, as it always did.
    after.starts_with(char::is_whitespace) && !after.trim().is_empty()
}

/// Split an input line into commands at top-level semicolons. Semicolons
/// inside braces belong to the group; an escaped `\;` is data and is
/// preserved (backslash included) for the sink to resolve.
pub fn split_commands(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // Preserve the escape intact — resolving it here would let
                // data re-enter the grammar on the next parse.
                cur.push('\\');
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            '{' => {
                depth += 1;
                cur.push(c);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            // A `;` ends a command — unless the command is a comment, in
            // which case it is prose and the rest of the line belongs to it.
            //
            // `#nop Only the leader walks; everyone else follows` used to run
            // `everyone else follows` as a command, and connected that goes
            // to the MUD. Three lines of one commented script leaked that way
            // before it was noticed, and a fourth after the pattern was known
            // — the failure is silent, so knowing about it does not help.
            ';' if depth == 0 && !is_comment(&cur) => {
                out.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out.retain(|s| !s.is_empty());
    out
}

/// Split on a separator, ignoring escaped occurrences of it. The escapes
/// themselves are preserved for the sink.
pub fn split_unescaped(text: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push('\\');
            if let Some(next) = chars.next() {
                cur.push(next);
            }
        } else if c == sep {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

/// Pull the next argument off `rest`: either a brace-delimited group (braces
/// removed, nesting honored) or a whitespace-delimited word. Returns
/// (argument, remainder).
pub fn get_arg(rest: &str) -> (String, &str) {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return (String::new(), rest);
    }
    if let Some(stripped) = rest.strip_prefix('{') {
        let mut depth = 1usize;
        let mut chars = stripped.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                // An escaped brace is data and does not open or close a
                // group; skip the character it protects.
                '\\' => {
                    chars.next();
                }
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return (stripped[..i].to_string(), &stripped[i + 1..]);
                    }
                }
                _ => {}
            }
        }
        // unbalanced: take everything
        (stripped.to_string(), "")
    } else {
        match rest.find(char::is_whitespace) {
            Some(i) => (rest[..i].to_string(), &rest[i..]),
            None => (rest.to_string(), ""),
        }
    }
}

/// The final argument of a command: the whole remainder, with one layer of
/// braces removed if it is fully braced.
pub fn get_tail(rest: &str) -> String {
    let rest = rest.trim();
    if rest.starts_with('{') {
        let (arg, remainder) = get_arg(rest);
        if remainder.trim().is_empty() {
            return arg;
        }
    }
    rest.to_string()
}

/// Substitute `$name`, `${name}` and `$name[key]` via `lookup`. An escaped
/// `\$` is data: preserved as-is, never treated as a variable reference.
///
/// Subscripts are read from the template, and an escaped `\]` inside one is
/// data rather than the closing bracket — which is what stops a server whose
/// text landed in `$tbl[%1]` from ending the subscript early and having the
/// remainder read as something else. A subscript may itself contain variables,
/// resolved before the lookup, so `$tbl[$key]` works; the recursion is bounded
/// by the nesting actually written in the template.
pub fn subst_vars_with(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // Preserve escapes: `\$` stays `\$` until a sink resolves it,
            // so escaped data can never name a variable.
            '\\' => {
                out.push('\\');
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            '$' => {
                let mut name = String::new();
                if chars.peek() == Some(&'{') {
                    chars.next();
                    while let Some(&n) = chars.peek() {
                        chars.next();
                        if n == '}' {
                            break;
                        }
                        name.push(n);
                    }
                } else {
                    while let Some(&n) = chars.peek() {
                        if n.is_alphanumeric() || n == '_' {
                            name.push(n);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                // Subscripts, possibly several: $a[b][c] is one name.
                let mut subscripts = String::new();
                while chars.peek() == Some(&'[') {
                    chars.next();
                    let mut key = String::new();
                    let mut depth = 1usize;
                    while let Some(n) = chars.next() {
                        if n == '\\' {
                            // An escaped bracket is data. Keep the pair intact
                            // so the recursive call sees it as data too.
                            key.push('\\');
                            if let Some(esc) = chars.next() {
                                key.push(esc);
                            }
                            continue;
                        }
                        if n == '[' {
                            depth += 1;
                        } else if n == ']' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        key.push(n);
                    }
                    let key = subst_vars_with(&key, lookup);
                    subscripts.push('[');
                    subscripts.push_str(&key);
                    subscripts.push(']');
                }
                if !subscripts.is_empty() {
                    name.push_str(&subscripts);
                }
                if name.is_empty() {
                    out.push('$');
                } else if let Some(v) = lookup(&name) {
                    out.push_str(&v);
                } else {
                    // unknown variables pass through untouched, like tt++
                    out.push('$');
                    out.push_str(&name);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Convenience wrapper over a plain map.
#[cfg(test)]
pub fn subst_vars(text: &str, vars: &BTreeMap<String, String>) -> String {
    subst_vars_with(text, &|name| vars.get(name).cloned())
}

/// If `input` is a speedwalk ("3n2e", "ssw2n", "nesw"), expand it into
/// direction commands. tt++ semantics: with speedwalk on, any input of two
/// or more characters consisting only of [neswud0-9] with at least one
/// direction letter is a walk — yes, that includes words like "news",
/// which is why the config defaults to off.
pub fn speedwalk(input: &str) -> Option<Vec<String>> {
    if input.chars().count() < 2 {
        return None;
    }
    if !input.chars().all(|c| c.is_ascii_digit() || "neswud".contains(c)) {
        return None;
    }
    if !input.chars().any(|c| "neswud".contains(c)) {
        return None;
    }
    let dir = |c: char| match c {
        'n' => "north",
        'e' => "east",
        's' => "south",
        'w' => "west",
        'u' => "up",
        'd' => "down",
        _ => unreachable!(),
    };
    let mut out = Vec::new();
    let mut count = 0usize;
    for c in input.chars() {
        if let Some(d) = c.to_digit(10) {
            count = count * 10 + d as usize;
            if count > 100 {
                return None; // refuse absurd walks
            }
        } else {
            for _ in 0..count.max(1) {
                out.push(dir(c).to_string());
            }
            count = 0;
        }
    }
    if count != 0 {
        return None; // trailing digits: not a walk
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comment_keeps_its_semicolons() {
        // `#nop` takes prose, and prose has semicolons in it. Splitting there
        // used to run the second half as a command, which connected means
        // sending it to the MUD — silently, since a failed game command looks
        // like nothing much.
        assert_eq!(
            split_commands("#nop Only the leader walks; everyone else follows"),
            vec!["#nop Only the leader walks; everyone else follows"]
        );
        assert_eq!(
            split_commands("#nop one; two; three"),
            vec!["#nop one; two; three"]
        );
        // A comment ends at the end of its line, not the end of the script.
        assert_eq!(
            split_commands("look;#nop a; b"),
            vec!["look", "#nop a; b"]
        );
        // Only the exact word. `#no` is ambiguous between #nop and #north,
        // and judytin would not resolve it either.
        assert_eq!(split_commands("#no thing; look"), vec!["#no thing", "look"]);
        // And a bare #nop is still a command that does nothing.
        assert_eq!(split_commands("#nop;look"), vec!["#nop", "look"]);
    }

    #[test]
    fn splits_on_semicolons() {
        assert_eq!(split_commands("n;l dragon;say hi"), vec!["n", "l dragon", "say hi"]);
    }

    #[test]
    fn keeps_braced_semicolons() {
        assert_eq!(
            split_commands("#alias {x} {n;s};look"),
            vec!["#alias {x} {n;s}", "look"]
        );
    }

    #[test]
    fn escaped_semicolon_does_not_split_and_stays_escaped() {
        // The backslash survives the splitter; the sink resolves it.
        assert_eq!(split_commands(r"say hi\; there"), vec![r"say hi\; there"]);
    }

    #[test]
    fn escaped_braces_do_not_open_groups() {
        // Data containing a brace must not shift argument boundaries.
        let (a, rest) = get_arg(r"{say \} still inside} after");
        assert_eq!(a, r"say \} still inside");
        assert_eq!(rest.trim(), "after");
    }

    #[test]
    fn escaped_metacharacters_survive_every_parser() {
        // One escaped payload through the splitter, the argument reader and
        // variable substitution: still inert at the far end.
        let hostile = crate::data::escape("Bob;#system touch /tmp/x");
        let line = format!("tell {hostile} hi");
        let commands = split_commands(&line);
        assert_eq!(commands.len(), 1, "data must not create a command");
        let vars = BTreeMap::new();
        let after = subst_vars(&commands[0], &vars);
        assert!(crate::data::is_inert(&after), "leaked syntax: {after}");
        assert!(after.contains(r"\;"), "escape was stripped: {after}");
    }

    #[test]
    fn args_braced_and_bare() {
        let (a, rest) = get_arg("{two words} rest");
        assert_eq!(a, "two words");
        let (b, rest2) = get_arg(rest);
        assert_eq!(b, "rest");
        assert_eq!(rest2, "");
    }

    #[test]
    fn nested_braces() {
        let (a, rest) = get_arg("{outer {inner} more} tail");
        assert_eq!(a, "outer {inner} more");
        assert_eq!(rest.trim(), "tail");
    }

    #[test]
    fn tail_unwraps_single_group() {
        assert_eq!(get_tail("{say hi;bow}"), "say hi;bow");
        assert_eq!(get_tail("say hi there"), "say hi there");
        assert_eq!(get_tail("{a} {b}"), "{a} {b}");
    }

    #[test]
    fn variables() {
        let mut vars = BTreeMap::new();
        vars.insert("target".to_string(), "goblin".to_string());
        assert_eq!(subst_vars("kill $target now", &vars), "kill goblin now");
        assert_eq!(subst_vars("kill ${target}s", &vars), "kill goblins");
        // The escape is preserved here and resolved at the sink.
        assert_eq!(
            subst_vars(r"costs \$5 and $unknown", &vars),
            r"costs \$5 and $unknown"
        );
    }

    #[test]
    fn subscripts_name_one_variable() {
        let mut vars = BTreeMap::new();
        vars.insert("hp[bob]".to_string(), "30".to_string());
        vars.insert("hp[amy]".to_string(), "45".to_string());
        vars.insert("who".to_string(), "amy".to_string());
        vars.insert("deep[a][b]".to_string(), "nested".to_string());
        assert_eq!(subst_vars("$hp[bob]", &vars), "30");
        // The key is resolved before the lookup, so it can be computed.
        assert_eq!(subst_vars("$hp[$who]", &vars), "45");
        assert_eq!(subst_vars("$deep[a][b]", &vars), "nested");
        // Unknown entries stay literal, as tt++ leaves unknown variables.
        assert_eq!(subst_vars("$hp[nobody]", &vars), "$hp[nobody]");
    }

    #[test]
    fn escaped_data_in_a_subscript_stays_data() {
        // The attack shape: server text lands inside $tbl[...] and tries to
        // close the subscript early so what follows is read as script. Every
        // metacharacter in it arrives escaped, and the scan must carry those
        // pairs through rather than acting on the character underneath.
        let mut vars = BTreeMap::new();
        vars.insert("tbl[safe]".to_string(), "public".to_string());
        vars.insert("tbl[secret]".to_string(), "PRIVATE".to_string());
        // What `escape` would produce from `] $tbl[secret]`.
        let out = subst_vars(r"$tbl[safe\] \$tbl\[secret\]", &vars);
        assert!(
            !out.contains("PRIVATE"),
            "escaped server text reached another entry: {out}"
        );
        assert!(
            !out.contains("public"),
            "the escaped bracket still closed the subscript: {out}"
        );

        // The same characters unescaped are the script author's own, and do
        // resolve — that is the difference the escaping exists to make.
        assert_eq!(subst_vars("$tbl[secret]", &vars), "PRIVATE");
    }

    #[test]
    fn speedwalks() {
        assert_eq!(
            speedwalk("3n2e").unwrap(),
            vec!["north", "north", "north", "east", "east"]
        );
        assert_eq!(
            speedwalk("ssw2n").unwrap(),
            vec!["south", "south", "west", "north", "north"]
        );
        // digitless runs are walks too, per tt++
        assert_eq!(speedwalk("nesw").unwrap(), vec!["north", "east", "south", "west"]);
        assert_eq!(speedwalk("ud").unwrap(), vec!["up", "down"]);
    }

    #[test]
    fn speedwalk_rejects_non_walks() {
        assert_eq!(speedwalk("n"), None); // single char: plain command
        assert_eq!(speedwalk("2"), None); // digits only
        assert_eq!(speedwalk("2n3"), None); // trailing digits
        assert_eq!(speedwalk("send 2"), None); // non-direction chars
        assert_eq!(speedwalk("1u1d").unwrap(), vec!["up", "down"]);
    }
}
