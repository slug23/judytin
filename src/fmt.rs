//! The #format engine (also backs #echo). Each %-specifier consumes the
//! next argument. Padding modifiers on %s/%d: %+9s left-pad, %-9s
//! right-pad, %.8s truncate.
//!
//! Deviations from tt++: the more exotic specifiers (%x charset, %S
//! spellcheck, %M metric, %H hash) are not implemented.

use crate::expr;

pub fn format(fmt: &str, args: &[String]) -> Result<String, String> {
    let mut out = String::new();
    let mut arg_i = 0usize;
    let next_arg = |i: &mut usize| -> String {
        let v = args.get(*i).cloned().unwrap_or_default();
        *i += 1;
        v
    };
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // padding / truncation modifiers
        let mut left_pad = false;
        let mut right_pad = false;
        let mut width = 0usize;
        let mut truncate: Option<usize> = None;
        loop {
            match chars.peek().copied() {
                Some('+') => {
                    left_pad = true;
                    chars.next();
                }
                Some('-') => {
                    right_pad = true;
                    chars.next();
                }
                Some('.') => {
                    chars.next();
                    let mut n = 0usize;
                    while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                        n = n * 10 + d as usize;
                        chars.next();
                    }
                    truncate = Some(n);
                }
                Some(d) if d.is_ascii_digit() => {
                    width = width * 10 + d.to_digit(10).unwrap() as usize;
                    chars.next();
                }
                _ => break,
            }
        }
        let Some(spec) = chars.next() else {
            out.push('%');
            break;
        };
        let mut piece = match spec {
            '%' => "%".to_string(),
            's' => next_arg(&mut arg_i),
            'd' => {
                let a = next_arg(&mut arg_i);
                match expr::eval(&a) {
                    Ok(v) => expr::Value::Int(match v {
                        expr::Value::Int(i) => i,
                        expr::Value::Float(f) => f as i64,
                        expr::Value::Str(s) => s.trim().parse().unwrap_or(0),
                    })
                    .display(),
                    Err(_) => a.trim().parse::<i64>().unwrap_or(0).to_string(),
                }
            }
            'f' => {
                let a = next_arg(&mut arg_i);
                let v: f64 = match expr::eval(&a) {
                    Ok(expr::Value::Int(i)) => i as f64,
                    Ok(expr::Value::Float(f)) => f,
                    _ => a.trim().parse().unwrap_or(0.0),
                };
                format!("{:.2}", v)
            }
            'm' => {
                let a = next_arg(&mut arg_i);
                expr::eval(&a)?.display()
            }
            'u' => next_arg(&mut arg_i).to_uppercase(),
            'l' => next_arg(&mut arg_i).to_lowercase(),
            'n' => {
                let a = next_arg(&mut arg_i);
                let mut cs = a.chars();
                match cs.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + cs.as_str(),
                    None => a,
                }
            }
            'r' => next_arg(&mut arg_i).chars().rev().collect(),
            'p' => next_arg(&mut arg_i).trim().to_string(),
            'g' => {
                let a = next_arg(&mut arg_i);
                let n: i64 = a.trim().parse().unwrap_or(0);
                group_thousands(n)
            }
            'L' => next_arg(&mut arg_i).chars().count().to_string(),
            'h' => {
                let a = next_arg(&mut arg_i);
                header(&a, 78)
            }
            't' => {
                let a = next_arg(&mut arg_i);
                strftime_local(&a)
            }
            'T' => {
                let _ = next_arg(&mut arg_i);
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_default()
            }
            'X' => {
                let a = next_arg(&mut arg_i);
                format!("{:X}", a.trim().parse::<i64>().unwrap_or(0))
            }
            'D' => {
                let a = next_arg(&mut arg_i);
                i64::from_str_radix(a.trim().trim_start_matches("0x"), 16)
                    .unwrap_or(0)
                    .to_string()
            }
            other => return Err(format!("unknown format specifier %{}", other)),
        };
        if let Some(t) = truncate {
            piece = piece.chars().take(t).collect();
        }
        let len = piece.chars().count();
        if len < width {
            let pad = " ".repeat(width - len);
            if left_pad || (!right_pad && spec == 'd') {
                piece = pad + &piece;
            } else {
                piece += &pad;
            }
        }
        out.push_str(&piece);
    }
    Ok(out)
}

fn group_thousands(n: i64) -> String {
    let s = n.abs().to_string();
    let mut grouped = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    if n < 0 {
        format!("-{}", grouped)
    } else {
        grouped
    }
}

fn header(text: &str, width: usize) -> String {
    let label = if text.is_empty() {
        String::new()
    } else {
        format!(" {} ", text)
    };
    let len = label.chars().count();
    if len >= width {
        return label;
    }
    let left = (width - len) / 2;
    let right = width - len - left;
    format!("{}{}{}", "#".repeat(left), label, "#".repeat(right))
}

/// Minimal strftime in local time: %Y %m %d %H %M %S %T %F %e %z %Z %%.
///
/// Local, not UTC, because that is what tt++ does and what anyone reading a
/// timestamp assumes. The offset comes from the system's own zone data — see
/// `crate::tz` — and falls back to UTC when the machine cannot say, in which
/// case %Z says so rather than letting the reader assume otherwise.
fn strftime_local(fmt: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (offset, zone) = crate::tz::local_at(now);
    // Shift the instant and then render it as if it were UTC: the civil
    // calendar arithmetic below does not care which zone it is counting in.
    let secs = now + offset as i64;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86400));
    let tod = secs.rem_euclid(86400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&y.to_string()),
            Some('m') => out.push_str(&format!("{:02}", mo)),
            Some('d') => out.push_str(&format!("{:02}", d)),
            Some('e') => out.push_str(&format!("{:2}", d)),
            Some('H') => out.push_str(&format!("{:02}", h)),
            Some('M') => out.push_str(&format!("{:02}", mi)),
            Some('S') => out.push_str(&format!("{:02}", s)),
            Some('T') => out.push_str(&format!("{:02}:{:02}:{:02}", h, mi, s)),
            Some('F') => out.push_str(&format!("{}-{:02}-{:02}", y, mo, d)),
            Some('z') => out.push_str(&crate::tz::offset_name(offset)),
            Some('Z') => out.push_str(&zone),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(fmt: &str, args: &[&str]) -> String {
        format(fmt, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn basic_specifiers() {
        assert_eq!(f("%s world", &["hello"]), "hello world");
        assert_eq!(f("%d gold", &["42"]), "42 gold");
        assert_eq!(f("%u!", &["shout"]), "SHOUT!");
        assert_eq!(f("%l", &["QUIET"]), "quiet");
        assert_eq!(f("%n", &["bob"]), "Bob");
        assert_eq!(f("%r", &["hiya"]), "ayih");
        assert_eq!(f("%p", &["  x  "]), "x");
        assert_eq!(f("%L", &["hello"]), "5");
        assert_eq!(f("100%%", &[]), "100%");
    }

    #[test]
    fn math_and_grouping() {
        assert_eq!(f("%m", &["2 + 3 * 4"]), "14");
        assert_eq!(f("%g", &["1234567"]), "1,234,567");
        assert_eq!(f("%g", &["-1000"]), "-1,000");
        assert_eq!(f("%X", &["255"]), "FF");
        assert_eq!(f("%D", &["ff"]), "255");
    }

    #[test]
    fn padding() {
        assert_eq!(f("[%+5s]", &["ab"]), "[   ab]");
        assert_eq!(f("[%-5s]", &["ab"]), "[ab   ]");
        assert_eq!(f("[%.3s]", &["abcdef"]), "[abc]");
        assert_eq!(f("[%5d]", &["42"]), "[   42]");
    }

    #[test]
    fn header_line() {
        let h = f("%h", &["title"]);
        assert!(h.contains(" title "));
        assert_eq!(h.chars().count(), 78);
    }

    #[test]
    fn time_renders() {
        let t = f("%t", &["%F %T"]);
        assert_eq!(t.len(), 19);
        assert!(t.contains(':') && t.contains('-'));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
    }
}
