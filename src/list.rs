//! Lists, which are tables whose keys are 1, 2, 3…
//!
//! judytin stores keyed variables flat: `$inv[2]` is a variable literally named
//! `inv[2]`. A list is that with the keys kept contiguous from 1, which is what
//! lets `#list` talk about position at all.
//!
//! Everything here is a pure function over the variable map, and every
//! operation is expressed as read-items, transform, write-items-back. That
//! makes renumbering automatic — an insert or a delete cannot leave a hole,
//! because the whole run is rewritten from 1 — and it makes the interesting
//! part testable without an App, a socket, or a MUD.

use std::collections::BTreeMap;

pub type Vars = BTreeMap<String, String>;

/// The variable name holding item `i` of `name`.
pub fn key(name: &str, i: usize) -> String {
    format!("{}[{}]", name, i)
}

/// Split `name[sub]` into its parts, if it has that shape. Only the outermost
/// name and the last subscript are of interest: `a[b][2]` is item 2 of the
/// table `a[b]`.
pub fn split_key(k: &str) -> Option<(&str, &str)> {
    let inner = k.strip_suffix(']')?;
    let at = inner.rfind('[')?;
    Some((&inner[..at], &inner[at + 1..]))
}

/// The items of `name`, in order, stopping at the first gap.
///
/// Stopping rather than skipping is the point: a list is a contiguous run, and
/// a hole means the run ended. `inv[1]` and `inv[3]` is a one-item list with a
/// stray variable beside it, not a two-item list.
pub fn items(vars: &Vars, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for i in 1.. {
        match vars.get(&key(name, i)) {
            Some(v) => out.push(v.clone()),
            None => break,
        }
    }
    out
}

pub fn len(vars: &Vars, name: &str) -> usize {
    items(vars, name).len()
}

/// Replace `name`'s items wholesale, renumbering from 1 and removing whatever
/// the previous contents ran to.
pub fn store(vars: &mut Vars, name: &str, new: &[String]) {
    let old = len(vars, name);
    for (i, v) in new.iter().enumerate() {
        vars.insert(key(name, i + 1), v.clone());
    }
    for i in new.len() + 1..=old {
        vars.remove(&key(name, i));
    }
}

/// Turn a written index into a position in `len` items.
///
/// tt++ counts from +1 and lets -1 mean the last item, which is the whole
/// reason this is not just a parse. `allow_end` is for insertion, where one
/// past the end is a legal place to put something and is how appending is
/// spelled. Returns a 1-based position.
pub fn resolve(idx: &str, len: usize, allow_end: bool) -> Option<usize> {
    let n: i64 = idx.trim().parse().ok()?;
    let limit = if allow_end { len + 1 } else { len };
    let pos = if n > 0 {
        n as usize
    } else if n < 0 {
        // -1 is the last item. Counting from the end has to use the same
        // limit, or inserting at -1 could not reach the end position.
        let back = (-n) as usize;
        if back > limit {
            return None;
        }
        limit + 1 - back
    } else {
        return None; // there is no item zero
    };
    (pos >= 1 && pos <= limit).then_some(pos)
}

/// Rewrite the last subscript of `name` when it is a signed index.
///
/// `$inv[+1]` and `$inv[-1]` have to reach `inv[1]` and `inv[<len>]`, and the
/// only place that can happen is where a name is looked up. A key that is not
/// a signed integer is returned untouched, so ordinary keyed variables — and
/// anything a server managed to put in a subscript — are unaffected.
pub fn resolve_name(vars: &Vars, name: &str) -> Option<String> {
    let (base, sub) = split_key(name)?;
    let t = sub.trim();
    // Only signed forms need rewriting; a bare "2" already names inv[2].
    if !(t.starts_with('+') || t.starts_with('-')) {
        return None;
    }
    let pos = resolve(t, len(vars, base), false)?;
    Some(key(base, pos))
}

/// Split `text` on the whole string `sep`, honouring escapes.
///
/// `script::split_unescaped` takes a single character, which is not enough:
/// tt++ separators are strings, and `collapse {, }` followed by `explode {, }`
/// has to come back to the list it started from. An escaped character is
/// copied through as a pair and can never begin a separator, so a separator
/// arriving inside server text cannot cut the text it belongs to.
pub fn split_on(text: &str, sep: &str) -> Vec<String> {
    if sep.is_empty() {
        return vec![text.to_string()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('\\') {
            cur.push('\\');
            let mut it = r.chars();
            if let Some(c) = it.next() {
                cur.push(c);
            }
            rest = it.as_str();
            continue;
        }
        if let Some(r) = rest.strip_prefix(sep) {
            out.push(std::mem::take(&mut cur));
            rest = r;
            continue;
        }
        let mut it = rest.chars();
        if let Some(c) = it.next() {
            cur.push(c);
        }
        rest = it.as_str();
    }
    out.push(cur);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(name: &str, items: &[&str]) -> Vars {
        let mut v = Vars::new();
        store(&mut v, name, &items.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        v
    }

    #[test]
    fn a_run_stops_at_the_first_gap() {
        let mut v = vars("inv", &["sword", "lamp"]);
        v.insert("inv[4]".into(), "orphan".into());
        // 3 is missing, so the list is two long and inv[4] is just a variable.
        assert_eq!(items(&v, "inv"), vec!["sword", "lamp"]);
        assert_eq!(len(&v, "inv"), 2);
    }

    #[test]
    fn storing_renumbers_and_drops_the_tail() {
        let mut v = vars("inv", &["a", "b", "c", "d"]);
        store(&mut v, "inv", &["x".into(), "y".into()]);
        assert_eq!(items(&v, "inv"), vec!["x", "y"]);
        // The old third and fourth entries are gone, not merely unreachable.
        assert!(!v.contains_key("inv[3]"), "a stale entry survived: {v:?}");
        assert!(!v.contains_key("inv[4]"));
    }

    #[test]
    fn indices_count_from_one_and_from_the_end() {
        assert_eq!(resolve("1", 3, false), Some(1));
        assert_eq!(resolve("+2", 3, false), Some(2));
        assert_eq!(resolve("-1", 3, false), Some(3));
        assert_eq!(resolve("-3", 3, false), Some(1));
        // Out of range, and there is no item zero.
        assert_eq!(resolve("4", 3, false), None);
        assert_eq!(resolve("-4", 3, false), None);
        assert_eq!(resolve("0", 3, false), None);
        assert_eq!(resolve("x", 3, false), None);
    }

    #[test]
    fn insertion_may_address_one_past_the_end() {
        // Appending is spelled "insert at len+1", and -1 must reach it too.
        assert_eq!(resolve("4", 3, true), Some(4));
        assert_eq!(resolve("-1", 3, true), Some(4));
        assert_eq!(resolve("5", 3, true), None);
    }

    #[test]
    fn only_signed_subscripts_are_rewritten() {
        let v = vars("inv", &["sword", "lamp", "rope"]);
        assert_eq!(resolve_name(&v, "inv[-1]").as_deref(), Some("inv[3]"));
        assert_eq!(resolve_name(&v, "inv[+1]").as_deref(), Some("inv[1]"));
        // A plain key already names its variable, so it is left alone...
        assert_eq!(resolve_name(&v, "inv[2]"), None);
        // ...as is anything that is not an index at all, which is what keeps
        // ordinary keyed variables working.
        assert_eq!(resolve_name(&v, "hp[bob]"), None);
        assert_eq!(resolve_name(&v, "plain"), None);
    }

    #[test]
    fn splitting_handles_a_multi_character_separator() {
        assert_eq!(split_on("a, b, c", ", "), vec!["a", "b", "c"]);
        assert_eq!(split_on("a;b", ";"), vec!["a", "b"]);
        // Round trip, which is the point: collapse then explode is identity.
        let items = ["one", "two", "three"];
        assert_eq!(split_on(&items.join(" | "), " | "), items);
        // No separator present, and an empty separator, both leave it whole.
        assert_eq!(split_on("abc", ", "), vec!["abc"]);
        assert_eq!(split_on("abc", ""), vec!["abc"]);
    }

    #[test]
    fn an_escaped_separator_does_not_cut() {
        // Server text arrives escaped. A `;` inside it is that server's text,
        // not a boundary the player asked for.
        assert_eq!(split_on(r"safe\;still-safe;next", ";"), vec![r"safe\;still-safe", "next"]);
    }

    #[test]
    fn a_nested_table_is_indexed_at_its_last_level() {
        let mut v = Vars::new();
        store(&mut v, "party[a]", &["grib".into(), "sam".into()]);
        assert_eq!(split_key("party[a][2]"), Some(("party[a]", "2")));
        assert_eq!(resolve_name(&v, "party[a][-1]").as_deref(), Some("party[a][2]"));
    }
}
