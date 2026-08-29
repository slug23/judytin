//! Input parsing: the `;` command separator, `{}` argument grouping,
//! `$variable` substitution, and speedwalk detection.

#[cfg(test)]
use std::collections::BTreeMap;

/// Split an input line into commands at top-level semicolons. Semicolons
/// inside braces are kept; `\;` is a literal semicolon.
pub fn split_commands(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    if next == ';' {
                        cur.push(';');
                    } else {
                        cur.push('\\');
                        cur.push(next);
                    }
                } else {
                    cur.push('\\');
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
            ';' if depth == 0 => {
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
        for (i, c) in stripped.char_indices() {
            match c {
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

/// Substitute `$name` / `${name}` via `lookup`. `\$` is a literal dollar.
pub fn subst_vars_with(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'$') => {
                chars.next();
                out.push('$');
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
    fn escaped_semicolon() {
        assert_eq!(split_commands(r"say hi\; there"), vec!["say hi; there"]);
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
        assert_eq!(subst_vars(r"costs \$5 and $unknown", &vars), "costs $5 and $unknown");
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
